package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
