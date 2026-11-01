package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Backend 是推理后端。
//
// 抽象成接口的意义：安全产品的分析能力不能绑死在某一家模型服务上。
// 同一套输入，可以交给云端大模型、本地小模型、或纯确定性启发式，
// 上层（接口与界面）完全无差别。
type Backend interface {
	// Name 返回后端标识，用于日志与结果标注。
	Name() string
	// Kind 返回引擎类型：llm / heuristic。
	Kind() string
	// Triage 研判一条告警。
	Triage(ctx context.Context, in *TriageInput) (*TriageResult, error)
	// Translate 把自然语言转成受控查询 DSL。
	Translate(ctx context.Context, nl string, schema *QuerySchema) (*Query, error)
}

// ---------------------------------------------------------------- 确定性启发式后端

// heuristicBackend 是不依赖任何外部服务的分析后端。
//
// 它存在的理由不是"凑数的降级方案"，而是三件真实的事：
//   - 隔离网/内网环境根本没有外网模型可用；
//   - 模型服务抖动时，安全产品不能跟着变瞎；
//   - 它是 LLM 输出的一致性基准——两者结论差异过大时说明有一方出了问题。
type heuristicBackend struct{}

// NewHeuristic 返回确定性分析后端。
func NewHeuristic() Backend { return heuristicBackend{} }

func (heuristicBackend) Name() string { return "heuristic" }
func (heuristicBackend) Kind() string { return "heuristic" }

// 证据分层权重：越靠前的层越"硬"。
var layerWeight = map[string]float64{
	"static":   1.0, // 哈希黑名单、签名校验——几乎不会错
	"rule":     0.85,
	"behavior": 0.7, // 落地即执行
	"keyword":  0.45,
	"lineage":  0.4,
	"persist":  0.8,
}

func (heuristicBackend) Triage(_ context.Context, in *TriageInput) (*TriageResult, error) {
	start := time.Now()

	var reasons []Reason
	var hard, strong, weak []EvidenceItem

	for _, e := range in.Evidence {
		switch {
		case isHardEvidence(e):
			hard = append(hard, e)
		case e.Score >= 25:
			strong = append(strong, e)
		case e.Score > 0:
			weak = append(weak, e)
		}
	}

	// ---- 逐条给出可核对的理由 ----
	if len(hard) > 0 {
		for _, e := range hard {
			reasons = append(reasons, Reason{
				Text:      fmt.Sprintf("%s：%s", e.Name, e.Detail),
				Citations: []string{e.ID},
			})
		}
	}
	for _, e := range strong {
		reasons = append(reasons, Reason{
			Text:      fmt.Sprintf("%s（%d 分）：%s", e.Name, e.Score, e.Detail),
			Citations: []string{e.ID},
		})
	}

	// ---- 组合信号：单个信号弱，凑在一起就是攻击链 ----
	var combo []string
	if hasLayer(in.Evidence, "behavior") && !in.Signed {
		combo = append(combo, "落地即执行 + 无有效签名")
	}
	if hasLayer(in.Evidence, "persist") {
		combo = append(combo, "存在持久化变更")
	}
	if len(in.MITRE) >= 3 {
		combo = append(combo, fmt.Sprintf("覆盖 %d 个 ATT&CK 技术点", len(in.MITRE)))
	}
	if combo != nil {
		var cites []string
		for _, e := range in.Evidence {
			if e.Score >= 25 {
				cites = append(cites, e.ID)
			}
		}
		if len(cites) > 4 {
			cites = cites[:4]
		}
		reasons = append(reasons, Reason{
			Text:      "组合特征：" + strings.Join(combo, "；"),
			Citations: cites,
		})
	}

	// ---- 定级 ----
	verdict, confidence := "inconclusive", 0.35
	switch {
	case len(hard) > 0:
		verdict, confidence = "malicious", 0.9
	case len(strong) >= 2:
		verdict, confidence = "malicious", 0.78
	case len(strong) == 1:
		verdict, confidence = "suspicious", 0.6
	case len(weak) > 0:
		verdict, confidence = "suspicious", 0.45
	case in.Signed && len(in.Evidence) == 0:
		verdict, confidence = "benign", 0.82
		reasons = append(reasons, Reason{
			Text:      "无任何命中信号，且镜像具有有效数字签名",
			Citations: nil,
		})
	case len(in.Evidence) == 0:
		verdict, confidence = "benign", 0.6
		reasons = append(reasons, Reason{
			Text: "无任何命中信号（注意：未签名程序缺少本项判定的正向依据）",
		})
	}

	// 按证据层权重微调置信度：同样 10 分，来自静态层和来自血缘层不是一回事
	if verdict != "benign" && len(in.Evidence) > 0 {
		var weighted, raw float64
		for _, e := range in.Evidence {
			w, ok := layerWeight[e.Layer]
			if !ok {
				w = 0.5
			}
			weighted += w * float64(e.Score)
			raw += float64(e.Score)
		}
		if raw > 0 {
			// 权重 1.0 → 不调整；低于 0.5 → 最多下调 10%
			confidence *= 0.9 + 0.1*clamp01(weighted/raw)
		}
	}

	// 基线样本不足时下调置信度：证据"稀有"的判定力度本来就弱
	if in.Host.BaselineSamples > 0 && in.Host.BaselineSamples < 300 && verdict != "benign" {
		confidence *= 0.8
	}

	// ---- 处置建议 ----
	actions := suggestActions(verdict, in)

	res := &TriageResult{
		Verdict:     verdict,
		Confidence:  round2(confidence),
		Reasoning:   reasons,
		Actions:     actions,
		Narrative:   buildNarrative(in, verdict, hard, strong),
		AttackChain: buildChain(in),
		Model:       "heuristic-v1",
		Engine:      "heuristic",
		LatencyMs:   time.Since(start).Milliseconds(),
	}
	return res, nil
}

// Translate 实现 Backend：用关键词规则把自然语言转成查询。
func (heuristicBackend) Translate(_ context.Context, nl string, schema *QuerySchema) (*Query, error) {
	return schema.Normalize(heuristicTranslate(nl))
}

func isHardEvidence(e EvidenceItem) bool {
	// 哈希黑名单与签名无效属于不可争辩的事实
	if strings.HasPrefix(e.ID, "S-BLACKLIST") && e.Score >= 80 {
		return true
	}
	if strings.Contains(e.Name, "签名无效") {
		return true
	}
	if e.Layer == "rule" && e.Score >= 30 {
		return true
	}
	return false
}

func hasLayer(ev []EvidenceItem, layer string) bool {
	for _, e := range ev {
		if e.Layer == layer && e.Score > 0 {
			return true
		}
	}
	return false
}

func suggestActions(verdict string, in *TriageInput) []Action {
	switch verdict {
	case "malicious":
		a := []Action{{
			Type: "isolate", Target: in.Host.Hostname,
			Detail: "隔离主机网络，阻断横向移动与外联", RequiresApproval: true,
		}}
		if in.ProcessName != "" {
			a = append(a, Action{
				Type: "terminate", Target: fmt.Sprintf("%s (pid 需现场确认)", in.ProcessName),
				Detail: "终止进程；PID 可能已被复用，执行前需重新核对进程名与路径",
				RequiresApproval: true,
			})
		}
		return a
	case "suspicious":
		return []Action{{
			Type: "hunt", Target: in.Hash,
			Detail: "在同网段其它主机上检索相同哈希/命令行，确认是否已扩散",
			RequiresApproval: false,
		}}
	case "benign":
		if in.Hash != "" {
			return []Action{{
				Type: "allowlist", Target: in.Hash,
				Detail: "如确认无误，可按哈希加白以减少重复告警",
				RequiresApproval: true,
			}}
		}
	}
	return nil
}

func buildNarrative(in *TriageInput, verdict string, hard, strong []EvidenceItem) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("主机 %s 上检测到进程 %s", in.Host.Hostname, in.ProcessName))
	if in.CmdLine != "" {
		b.WriteString("（命令行：" + truncate(in.CmdLine, 120) + "）")
	}
	b.WriteString("。")
	if in.User != "" {
		b.WriteString(fmt.Sprintf("运行账号 %s。", in.User))
	}
	b.WriteString(fmt.Sprintf("综合 %d 条证据，", len(in.Evidence)))
	switch verdict {
	case "malicious":
		b.WriteString(fmt.Sprintf("判定为恶意，其中 %d 条为高置信度证据。", len(hard)+len(strong)))
	case "suspicious":
		b.WriteString("倾向可疑，但证据强度不足以下定论，建议进一步排查。")
	case "benign":
		b.WriteString("未发现恶意特征。")
	default:
		b.WriteString("证据不足以定级，建议人工复核。")
	}
	if len(in.Ancestry) > 0 {
		b.WriteString("父进程链：" + in.Ancestry[0].Name)
		if len(in.Ancestry) > 1 {
			b.WriteString(" ← " + in.Ancestry[1].Name)
		}
		b.WriteString("。")
	}
	return b.String()
}

func buildChain(in *TriageInput) []string {
	var chain []string
	if len(in.Ancestry) > 0 {
		chain = append(chain, "初始执行：由 "+in.Ancestry[0].Name+" 拉起")
	}
	for _, e := range in.Evidence {
		switch e.Layer {
		case "behavior":
			chain = append(chain, "投递：镜像文件在可写目录落地后被执行")
		case "persist":
			chain = append(chain, "持久化：建立了开机自启")
		}
	}
	if in.Signed == false && in.Hash != "" {
		chain = append(chain, "规避：无有效数字签名")
	}
	return chain
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

// ---------------------------------------------------------------- OpenAI 兼容后端

// OpenAICompatible 是一个通用后端，适配任何提供 /v1/chat/completions 的服务：
// OpenAI、DeepSeek、通义、Kimi、vLLM、Ollama（内置 OpenAI 兼容层）等。
type OpenAICompatible struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

// NewOpenAICompatible 构造后端。
func NewOpenAICompatible(baseURL, apiKey, model string, timeout time.Duration) *OpenAICompatible {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	return &OpenAICompatible{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{Timeout: timeout},
	}
}

// Name 返回后端标识。
func (o *OpenAICompatible) Name() string { return "openai-compatible:" + o.model }

// Kind 返回引擎类型。
func (o *OpenAICompatible) Kind() string { return "llm" }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	// 要求返回 JSON 对象，避免模型输出"好的，以下是分析："这类前后缀
	ResponseFormat map[string]string `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// chat 发起一次对话请求，返回内容与消耗的 token 数。
func (o *OpenAICompatible) chat(ctx context.Context, sys, user string, maxTokens int) (string, int, error) {
	body := chatRequest{
		Model:       o.model,
		Temperature: 0.1, // 安全研判要稳定，不要创造性
		MaxTokens:   maxTokens,
		Messages: []chatMessage{
			{Role: "system", Content: sys},
			{Role: "user", Content: user},
		},
		ResponseFormat: map[string]string{"type": "json_object"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.baseURL+"/v1/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	res, err := o.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("模型请求失败: %w", err)
	}
	defer res.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return "", 0, err
	}
	if res.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("模型返回 HTTP %d: %s", res.StatusCode, truncate(string(payload), 300))
	}

	var cr chatResponse
	if err := json.Unmarshal(payload, &cr); err != nil {
		return "", 0, fmt.Errorf("模型响应解析失败: %w", err)
	}
	if cr.Error != nil {
		return "", 0, fmt.Errorf("模型错误: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", cr.Usage.TotalTokens, fmt.Errorf("模型未返回内容")
	}
	return cr.Choices[0].Message.Content, cr.Usage.TotalTokens, nil
}

// Triage 实现 Backend。
func (o *OpenAICompatible) Triage(ctx context.Context, in *TriageInput) (*TriageResult, error) {
	start := time.Now()

	// 输入已由 Engine 统一做隔离，这里直接构造提示词。
	// 若直接调用本后端（绕过 Engine），Redactions 为空即等价于不隔离——
	// 这是有意的：隔离是引擎的职责，后端不该有两套实现。
	ignored := in.UntrustedIgnoredHint()
	sys, user := buildTriagePrompt(in, ignored, nil)

	content, tokens, err := o.chat(ctx, sys, user, 1400)
	if err != nil {
		return nil, err
	}

	var out struct {
		Verdict     string   `json:"verdict"`
		Confidence  float64  `json:"confidence"`
		Reasoning   []Reason `json:"reasoning"`
		Actions     []Action `json:"actions"`
		Narrative   string   `json:"narrative"`
		AttackChain []string `json:"attack_chain"`
	}
	if err := json.Unmarshal([]byte(extractJSON(content)), &out); err != nil {
		return nil, fmt.Errorf("模型输出不是合法 JSON: %w", err)
	}

	res := &TriageResult{
		Verdict:          out.Verdict,
		Confidence:       out.Confidence,
		Reasoning:        out.Reasoning,
		Actions:          out.Actions,
		Narrative:        out.Narrative,
		AttackChain:      out.AttackChain,
		UntrustedIgnored: ignored,
		Model:            o.model,
		Engine:           "llm",
		LatencyMs:        time.Since(start).Milliseconds(),
	}
	_ = tokens // token 用量由上层预算器统计
	return res, nil
}

// Translate 实现 Backend。
func (o *OpenAICompatible) Translate(ctx context.Context, nl string, schema *QuerySchema) (*Query, error) {
	sys, user := buildQueryPrompt(nl, schema)
	content, _, err := o.chat(ctx, sys, user, 700)
	if err != nil {
		return nil, err
	}
	var q Query
	if err := json.Unmarshal([]byte(extractJSON(content)), &q); err != nil {
		return nil, fmt.Errorf("模型输出不是合法 JSON: %w", err)
	}
	return schema.Normalize(&q)
}

// extractJSON 从模型输出里取出 JSON 主体。
// 即使要求了 json_object，部分服务仍会加 ```json 围栏或前后缀说明。
func extractJSON(s string) string {
	t := strings.TrimSpace(s)
	if i := strings.Index(t, "```"); i >= 0 {
		t = t[i+3:]
		if j := strings.Index(t, "```"); j >= 0 {
			t = t[:j]
		}
		t = strings.TrimPrefix(t, "json")
	}
	start := strings.Index(t, "{")
	end := strings.LastIndex(t, "}")
	if start >= 0 && end > start {
		return t[start : end+1]
	}
	return t
}

// sortByScoreDesc 便于稳定输出。
func sortByScoreDesc(ev []EvidenceItem) {
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Score > ev[j].Score })
}
