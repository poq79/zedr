// Package uplink 负责探针与服务端之间的所有网络通信。
//
// 设计要点：
//   - 凭证落地在数据目录（0600），重启后无需重新注册；
//   - 告警采用"本地有界队列 + 批量上报"，断网时不阻塞检测主循环；
//   - 队列满时丢弃最旧告警并计数，绝不无限占用内存；
//   - 所有请求带超时，单次失败不影响整体链路。
package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hostguard/internal/model"
	"hostguard/internal/platform/redact"
	"hostguard/internal/platform/rulehash"
)

// Credentials 是注册后持久化的凭证。
type Credentials struct {
	AgentID  string `json:"agent_id"`
	Secret   string `json:"agent_secret"`
	Server   string `json:"server_url"`
	MachineID string `json:"machine_id"`
}

// Client 是服务端 API 客户端。
type Client struct {
	baseURL     string
	enrollToken string
	dataDir     string
	http        *http.Client

	mu    sync.Mutex
	creds *Credentials
	queue []model.AlertEnvelope
	maxQueue int
	dropped  int64

	lastRuleETag string
	// ruleSignKey 非空时强制校验规则包签名（HG_AGENT_RULE_SIGN_KEY）
	ruleSignKey []byte
	// lastRuleVersion 用于版本单调性检查，防止规则包被回滚到更宽松的历史版本
	lastRuleVersion int

	lastIOCEtag    string
	lastIOCVersion int
}

// SetRuleSignKey 设置规则包验签密钥。空值表示不校验（仅记录告警日志）。
func (c *Client) SetRuleSignKey(key []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ruleSignKey = key
}

// New 创建客户端。
func New(baseURL, enrollToken, dataDir string, maxQueue int) *Client {
	if maxQueue <= 0 {
		maxQueue = 5000
	}
	return &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		enrollToken: enrollToken,
		dataDir:     dataDir,
		http: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		queue:    make([]model.AlertEnvelope, 0, 256),
		maxQueue: maxQueue,
	}
}

// LoadCredentials 从数据目录读取已保存的凭证。
func (c *Client) LoadCredentials() bool {
	path := filepath.Join(c.dataDir, "agent.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var creds Credentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		return false
	}
	if creds.AgentID == "" || creds.Secret == "" {
		return false
	}
	c.mu.Lock()
	c.creds = &creds
	c.mu.Unlock()
	return true
}

// Enrolled 返回是否已注册。
func (c *Client) Enrolled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creds != nil
}

// AgentID 返回当前终端 ID。
func (c *Client) AgentID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds == nil {
		return ""
	}
	return c.creds.AgentID
}

// Enroll 调用注册接口并持久化凭证。
func (c *Client) Enroll(ctx context.Context, req model.EnrollRequest) (*model.EnrollResponse, error) {
	req.EnrollToken = c.enrollToken
	var resp model.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/agents/enroll", req, &resp, false); err != nil {
		return nil, err
	}
	if resp.AgentID == "" || resp.AgentSecret == "" {
		return nil, errors.New("服务端返回的注册凭证为空")
	}

	creds := &Credentials{
		AgentID:   resp.AgentID,
		Secret:    resp.AgentSecret,
		Server:    c.baseURL,
		MachineID: req.MachineID,
	}
	if err := c.saveCredentials(creds); err != nil {
		return nil, fmt.Errorf("保存终端凭证失败: %w", err)
	}
	c.mu.Lock()
	c.creds = creds
	c.mu.Unlock()
	return &resp, nil
}

func (c *Client) saveCredentials(creds *Credentials) error {
	if err := os.MkdirAll(c.dataDir, 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(c.dataDir, "agent.json")
	return os.WriteFile(path, raw, 0o600)
}

// Heartbeat 上报心跳并取回待执行指令。
func (c *Client) Heartbeat(ctx context.Context, req model.HeartbeatRequest) (*model.HeartbeatResponse, error) {
	var resp model.HeartbeatResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/agent/heartbeat", req, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Enqueue 把告警放入本地队列（非阻塞）。
func (c *Client) Enqueue(env model.AlertEnvelope) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 统一出口脱敏：命令行可能带安装参数里的密码/令牌，
	// 一旦入队就等于会被写进服务端数据库、管理台页面与导出文件。
	sanitize(&env)
	if len(c.queue) >= c.maxQueue {
		// 丢弃最旧的一条，保留最近的告警
		c.queue = c.queue[1:]
		c.dropped++
	}
	c.queue = append(c.queue, env)
}

// sanitize 对告警内容做脱敏与截断。
//
// 放在入队这个唯一出口，而不是各个检测层：告警来源会越来越多
// （进程检测、持久化变更、后续的文件/网络行为），分散处理必然漏。
func sanitize(env *model.AlertEnvelope) {
	env.CmdLine = redact.CmdLine(env.CmdLine)
	env.ImagePath = redact.Path(env.ImagePath)
	env.Summary = redact.Text(env.Summary)
	env.Title = redact.Text(env.Title)

	env.Evidence.Process.CmdLine = redact.CmdLine(env.Evidence.Process.CmdLine)
	env.Evidence.Process.Path = redact.Path(env.Evidence.Process.Path)
	for i := range env.Evidence.Ancestry {
		env.Evidence.Ancestry[i].Path = redact.Path(env.Evidence.Ancestry[i].Path)
		env.Evidence.Ancestry[i].Cmd = redact.CmdLine(env.Evidence.Ancestry[i].Cmd)
	}
	for i := range env.Evidence.Signals {
		env.Evidence.Signals[i].Note = redact.CmdLine(env.Evidence.Signals[i].Note)
	}
	for i := range env.Evidence.Notes {
		env.Evidence.Notes[i] = redact.Text(env.Evidence.Notes[i])
	}
}

// Pending 返回队列长度。
func (c *Client) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queue)
}

// Dropped 返回因队列溢出丢弃的告警数。
func (c *Client) Dropped() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// Flush 批量上报队列中的告警。
func (c *Client) Flush(ctx context.Context) (int, error) {
	c.mu.Lock()
	if len(c.queue) == 0 {
		c.mu.Unlock()
		return 0, nil
	}
	batch := c.queue
	c.queue = nil
	c.mu.Unlock()

	// 服务端单批上限 500，这里按 200 分批，降低单次失败的影响面
	sent := 0
	for len(batch) > 0 {
		n := len(batch)
		if n > 200 {
			n = 200
		}
		chunk := batch[:n]
		req := model.AlertBatchRequest{Alerts: chunk}
		var resp model.AlertBatchResponse
		if err := c.do(ctx, http.MethodPost, "/api/v1/agent/alerts", req, &resp, true); err != nil {
			// 上报失败：把本批放回队列头部，等待下一轮重试
			c.mu.Lock()
			c.queue = append(chunk, c.queue...)
			if len(c.queue) > c.maxQueue {
				over := len(c.queue) - c.maxQueue
				c.queue = c.queue[over:]
				c.dropped += int64(over)
			}
			c.mu.Unlock()
			return 0, err
		}
		batch = batch[n:]
		sent += len(chunk)
	}
	return sent, nil
}

// FetchRules 拉取规则整包；服务端版本未变时返回 notModified=true。
func (c *Client) FetchRules(ctx context.Context) (*model.RuleBundle, bool, error) {
	c.mu.Lock()
	etag := c.lastRuleETag
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/agent/rules", nil)
	if err != nil {
		return nil, false, err
	}
	c.decorate(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, decodeError(res.StatusCode, body)
	}
	var wrap struct {
		Data model.RuleBundle `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, false, fmt.Errorf("规则包解析失败: %w", err)
	}

	c.mu.Lock()
	key := c.ruleSignKey
	localVer := c.lastRuleVersion
	c.mu.Unlock()

	// 完整性校验：配置了密钥就强制验签，验不过直接拒绝应用。
	// 这一层防的是"下发链路被篡改后悄悄关掉检测"。
	if len(key) > 0 {
		if err := rulehash.Verify(&wrap.Data, key); err != nil {
			return nil, false, fmt.Errorf("规则包校验失败，已拒绝应用: %w", err)
		}
	}

	// 版本单调：拒绝比本地更旧的规则包（重放旧版宽松规则是常见绕过手法）
	if localVer > 0 && wrap.Data.Version < localVer {
		return nil, false, fmt.Errorf("规则包版本回退（本地 %d，收到 %d），已拒绝",
			localVer, wrap.Data.Version)
	}

	c.mu.Lock()
	c.lastRuleETag = res.Header.Get("ETag")
	c.lastRuleVersion = wrap.Data.Version
	c.mu.Unlock()
	return &wrap.Data, false, nil
}

// FetchIOCs 拉取威胁指标整包；服务端版本未变时返回 notModified=true。
// 校验逻辑与 FetchRules 同源：签名 + 版本单调，防篡改与防回滚。
func (c *Client) FetchIOCs(ctx context.Context) (*model.IOCBundle, bool, error) {
	c.mu.Lock()
	etag := c.lastIOCEtag
	key := c.ruleSignKey
	localVer := c.lastIOCVersion
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/agent/iocs", nil)
	if err != nil {
		return nil, false, err
	}
	c.decorate(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, decodeError(res.StatusCode, body)
	}
	var wrap struct {
		Data model.IOCBundle `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, false, fmt.Errorf("IOC 包解析失败: %w", err)
	}

	// 哈希表进入检测引擎前必须过签名：篡改 IOC 可以把恶意样本洗白
	// （删条目）或制造误报风暴（塞垃圾条目），与改规则同级。
	if len(key) > 0 {
		if err := rulehash.VerifyIOCBundle(&wrap.Data, key); err != nil {
			return nil, false, fmt.Errorf("IOC 包校验失败，已拒绝应用: %w", err)
		}
	}
	if localVer > 0 && wrap.Data.Version < localVer {
		return nil, false, fmt.Errorf("IOC 包版本回退（本地 %d，收到 %d），已拒绝",
			localVer, wrap.Data.Version)
	}

	c.mu.Lock()
	c.lastIOCEtag = res.Header.Get("ETag")
	c.lastIOCVersion = wrap.Data.Version
	c.mu.Unlock()
	return &wrap.Data, false, nil
}

// ReportCommandResults 回传指令执行结果。
func (c *Client) ReportCommandResults(ctx context.Context, results []model.CommandResult) error {
	if len(results) == 0 {
		return nil
	}
	var out any
	return c.do(ctx, http.MethodPost, "/api/v1/agent/commands/result",
		map[string]any{"results": results}, &out, true)
}

// PostInventory 上报资产清单差量节，返回服务端确认应用的节名。
//
// sections 为空直接返回：调用方（inventory.Manager）保证差量语义，
// 空批次不该产生网络往返。20s 超时由 http.Client 全局兜底，
// 调用方传 context 控制更细的取消。
func (c *Client) PostInventory(ctx context.Context, sections []model.InventorySection) ([]string, error) {
	if len(sections) == 0 {
		return nil, nil
	}
	var resp model.InventoryAck
	if err := c.do(ctx, http.MethodPost, "/api/v1/agent/inventory",
		model.InventoryReport{Sections: sections}, &resp, true); err != nil {
		return nil, err
	}
	return resp.Applied, nil
}

// ---------------------------------------------------------------- 内部

func (c *Client) decorate(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.mu.Lock()
	creds := c.creds
	c.mu.Unlock()
	if creds != nil {
		req.Header.Set("X-Agent-Id", creds.AgentID)
		req.Header.Set("Authorization", "Bearer "+creds.Secret)
	}
}

func (c *Client) do(ctx context.Context, method, path string, in any, out any, needAuth bool) error {
	if needAuth && !c.Enrolled() {
		return errors.New("终端尚未注册")
	}

	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.decorate(req)

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("请求 %s 失败: %w", path, err)
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return decodeError(res.StatusCode, respBody)
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}

	// 服务端成功响应统一为 {"data": ...}
	var wrap struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respBody, &wrap); err == nil && len(wrap.Data) > 0 {
		return json.Unmarshal(wrap.Data, out)
	}
	return json.Unmarshal(respBody, out)
}

func decodeError(status int, body []byte) error {
	var eb model.ErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Error.Code != "" {
		return fmt.Errorf("%s (HTTP %d, %s)", eb.Error.Message, status, eb.Error.Code)
	}
	return fmt.Errorf("服务端返回 HTTP %d", status)
}
