package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// invHash 计算资产清单 payload 的 SHA-256 十六进制摘要（与探针侧约定一致）。
func invHash(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// invSectionResp 是 GET /api/v1/hosts/{id}/inventory 的响应结构。
type invSectionResp struct {
	Sections []struct {
		Name      string `json:"name"`
		Hash      string `json:"hash"`
		Payload   string `json:"payload"`
		UpdatedAt string `json:"updated_at"`
	} `json:"sections"`
	Total int `json:"total"`
}

// appliedResp 是 POST /api/v1/agent/inventory 的响应结构。
type appliedResp struct {
	Applied []string `json:"applied"`
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestAgentInventoryReportAndQuery 覆盖资产清单垂直切片的完整链路：
// 上报（合法/幂等/各类非法）→ 管理台查询 → 主机删除联动清理 → 鉴权。
func TestAgentInventoryReportAndQuery(t *testing.T) {
	env := newTestEnv(t)
	agent := env.enrollAgent()
	env.agent = agent

	svcPayload := `[{"name":"HostGuard Agent","status":"Running","start_mode":"Auto"}]`
	taskPayload := `[{"path":"\\HostGuard\\agent","action":"secagent.exe"}]`

	invBody := func() map[string]any {
		return map[string]any{
			"sections": []map[string]string{
				{"name": "services", "hash": invHash(svcPayload), "payload": svcPayload},
				{"name": "tasks", "hash": invHash(taskPayload), "payload": taskPayload},
			},
		}
	}

	// 上报前：无凭证的终端请求必须 401
	env.doJSON(http.MethodPost, "/api/v1/agent/inventory", invBody(), http.StatusUnauthorized, "", nil)

	// 合法上报两个节 → applied 含两者
	res := env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", invBody(), http.StatusOK)
	var applied appliedResp
	if err := json.Unmarshal(res.data, &applied); err != nil {
		t.Fatalf("解析 applied 失败: %v，原始: %s", err, truncateForLog(string(res.data)))
	}
	if !containsStr(applied.Applied, "services") || !containsStr(applied.Applied, "tasks") {
		t.Fatalf("applied 应同时包含 services 与 tasks，实际 %v", applied.Applied)
	}

	// 管理台查询（viewer 可读）：两节都在，updated_at 非空
	getInv := func() invSectionResp {
		env.t.Helper()
		var inv invSectionResp
		env.doJSON(http.MethodGet, "/api/v1/hosts/"+agent.AgentID+"/inventory",
			nil, http.StatusOK, env.token, &inv)
		if inv.Total != 2 || len(inv.Sections) != 2 {
			t.Fatalf("期望 2 个清单节，实际 total=%d sections=%d", inv.Total, len(inv.Sections))
		}
		for _, s := range inv.Sections {
			if s.UpdatedAt == "" {
				t.Fatalf("清单节 %s 的 updated_at 不应为空", s.Name)
			}
		}
		return inv
	}

	first := getInv()
	firstUpdated := map[string]string{}
	for _, s := range first.Sections {
		firstUpdated[s.Name] = s.UpdatedAt
	}

	// 幂等：相同 hash 重发 → applied 仍含两者，且 updated_at 不变（未重复写库）
	time.Sleep(5 * time.Millisecond) // 留出时钟余量：若错误地重写，时间戳必变
	res = env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", invBody(), http.StatusOK)
	if err := json.Unmarshal(res.data, &applied); err != nil {
		t.Fatalf("解析 applied 失败: %v", err)
	}
	if !containsStr(applied.Applied, "services") || !containsStr(applied.Applied, "tasks") {
		t.Fatalf("幂等重发后 applied 仍应包含两节，实际 %v", applied.Applied)
	}
	second := getInv()
	for _, s := range second.Sections {
		if firstUpdated[s.Name] != s.UpdatedAt {
			t.Fatalf("相同 hash 重发不应更新 %s 的 updated_at：前 %s 后 %s",
				s.Name, firstUpdated[s.Name], s.UpdatedAt)
		}
	}

	// 非法节名 → 400（节名白名单外）
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", map[string]any{
		"sections": []map[string]string{
			{"name": "kernel", "hash": invHash(svcPayload), "payload": svcPayload},
		},
	}, http.StatusBadRequest)

	// hash 与内容不匹配 → 400
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", map[string]any{
		"sections": []map[string]string{
			{"name": "services", "hash": invHash(`[{"tampered":true}]`), "payload": svcPayload},
		},
	}, http.StatusBadRequest)

	// payload 不是合法 JSON → 400
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", map[string]any{
		"sections": []map[string]string{
			{"name": "services", "hash": invHash("not-json"), "payload": "not-json"},
		},
	}, http.StatusBadRequest)

	// 超过 512KB 的单节 payload → 400（内容仍构造为合法 JSON 并配正确 hash）
	bigPayload := `["` + strings.Repeat("x", 512<<10) + `"]`
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", map[string]any{
		"sections": []map[string]string{
			{"name": "services", "hash": invHash(bigPayload), "payload": bigPayload},
		},
	}, http.StatusBadRequest)

	// 无 token 访问管理台端点 → 401
	env.doJSON(http.MethodGet, "/api/v1/hosts/"+agent.AgentID+"/inventory",
		nil, http.StatusUnauthorized, "", nil)

	// 删除主机 → 清单随之清理，再查应 404
	env.doJSON(http.MethodDelete, "/api/v1/hosts/"+agent.AgentID,
		nil, http.StatusNoContent, env.token, nil)
	env.doJSON(http.MethodGet, "/api/v1/hosts/"+agent.AgentID+"/inventory",
		nil, http.StatusNotFound, env.token, nil)
}

// invRawResp 是清单查询的原始响应（ETag 用例需要响应头与 304 空体）。
type invRawResp struct {
	status int
	header http.Header
	body   []byte
}

// doGetInventory 发起管理台清单查询并返回完整响应。
// doJSON 不暴露响应头，ETag 往返必须自己拿 Header。
func (e *testEnv) doGetInventory(path, ifNoneMatch string) invRawResp {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("GET %s 失败: %v", path, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatalf("读取响应失败: %v", err)
	}
	return invRawResp{status: res.StatusCode, header: res.Header, body: raw}
}

// parseInv 解析 200 响应 data 包装里的清单结构。
func parseInv(t *testing.T, r invRawResp) invSectionResp {
	t.Helper()
	var wrap struct {
		Data invSectionResp `json:"data"`
	}
	if err := json.Unmarshal(r.body, &wrap); err != nil {
		t.Fatalf("解析清单响应失败: %v，原始: %s", err, truncateForLog(string(r.body)))
	}
	return wrap.Data
}

// TestHostInventorySectionFilterAndETag 覆盖查询侧两个增强：
// ?section= 多值过滤（合法/非法）与 ETag / If-None-Match 304 往返。
func TestHostInventorySectionFilterAndETag(t *testing.T) {
	env := newTestEnv(t)
	agent := env.enrollAgent()
	env.agent = agent

	svcPayload := `[{"name":"A","status":"Running","start_mode":"Auto"}]`
	taskPayload := `[{"path":"\\X\\y","action":"z.exe"}]`
	sysPayload := `{"boot_time":"2026-01-01T00:00:00Z"}`

	env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", map[string]any{
		"sections": []map[string]string{
			{"name": "system", "hash": invHash(sysPayload), "payload": sysPayload},
			{"name": "services", "hash": invHash(svcPayload), "payload": svcPayload},
			{"name": "tasks", "hash": invHash(taskPayload), "payload": taskPayload},
		},
	}, http.StatusOK)

	base := "/api/v1/hosts/" + agent.AgentID + "/inventory"

	// 全量：3 节
	rawFull := env.doGetInventory(base, "")
	full := parseInv(t, rawFull)
	if full.Total != 3 || len(full.Sections) != 3 {
		t.Fatalf("全量应返回 3 节，实际 total=%d", full.Total)
	}
	fullETag := rawFull.header.Get("ETag")
	if fullETag == "" {
		t.Fatal("响应缺少 ETag 头")
	}
	etagBody := strings.Trim(fullETag, `"`)
	if len(etagBody) != 16 {
		t.Fatalf("ETag 应为 16 位十六进制（不含引号），实际 %q", fullETag)
	}

	// section=services：只返回该节，total 同步收缩
	r1 := env.doGetInventory(base+"?section=services", "")
	inv1 := parseInv(t, r1)
	if inv1.Total != 1 || len(inv1.Sections) != 1 || inv1.Sections[0].Name != "services" {
		t.Fatalf("section=services 应只返回 1 节 services，实际 %+v", inv1)
	}
	// 口径不同（过滤后内容不同）→ ETag 必须不同，否则缓存会串
	if r1.header.Get("ETag") == fullETag {
		t.Fatal("过滤视图与全量视图的 ETag 不应相同")
	}

	// 多值：逗号分隔 + 重复参数 + 带空格，三种写法都应得到 2 节
	for _, q := range []string{"?section=services,tasks", "?section=services&section=tasks", "?section=services,+tasks"} {
		got := parseInv(t, env.doGetInventory(base+q, ""))
		if got.Total != 2 {
			t.Fatalf("section 过滤 %s 应返回 2 节，实际 total=%d", q, got.Total)
		}
		names := map[string]bool{}
		for _, s := range got.Sections {
			names[s.Name] = true
		}
		if !names["services"] || !names["tasks"] {
			t.Fatalf("section 过滤 %s 结果缺节: %v", q, names)
		}
	}

	// 非法节名 → 400（拼错的节名不允许静默变成"空清单"）
	for _, q := range []string{"?section=kernel", "?section=services,kernel"} {
		raw := env.doJSON(http.MethodGet, base+q, nil, http.StatusBadRequest, env.token, nil)
		if !strings.Contains(string(raw), "节名") {
			t.Fatalf("非法节名的错误信息应提及节名: %s", truncateForLog(string(raw)))
		}
	}

	// ETag 往返：If-None-Match 命中 → 304 且无响应体
	hit := env.doGetInventory(base, fullETag)
	if hit.status != http.StatusNotModified || len(hit.body) != 0 {
		t.Fatalf("If-None-Match 命中应 304 且空体，实际 status=%d body=%s",
			hit.status, truncateForLog(string(hit.body)))
	}
	// 客户端回显格式容忍：弱验证器前缀 / 去引号都应命中
	if env.doGetInventory(base, `W/`+fullETag).status != http.StatusNotModified {
		t.Fatal("W/ 前缀的 If-None-Match 应命中 304")
	}
	if env.doGetInventory(base, etagBody).status != http.StatusNotModified {
		t.Fatal("不带引号的 If-None-Match 应命中 304")
	}

	// 内容变更：services 重报新内容 → 旧 ETag 不再命中（200 + 新 ETag）
	newSvc := `[{"name":"B","status":"Stopped","start_mode":"Manual"}]`
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/inventory", map[string]any{
		"sections": []map[string]string{
			{"name": "services", "hash": invHash(newSvc), "payload": newSvc},
		},
	}, http.StatusOK)
	miss := env.doGetInventory(base, fullETag)
	if miss.status != http.StatusOK {
		t.Fatalf("内容变更后旧 ETag 不应命中，实际 status=%d", miss.status)
	}
	newETag := miss.header.Get("ETag")
	if newETag == "" || newETag == fullETag {
		t.Fatalf("内容变更后 ETag 应更新: old=%s new=%s", fullETag, newETag)
	}
	// 新 ETag 再次往返应命中 304（闭环）
	if env.doGetInventory(base, newETag).status != http.StatusNotModified {
		t.Fatal("新 ETag 的 If-None-Match 应命中 304")
	}
}
