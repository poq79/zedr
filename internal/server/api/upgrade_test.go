package api

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"zedr/internal/server/service"
)

// 探针自升级的管理台面（api/upgrade.go + sendCommand 角色闸 + EnqueueCommand
// 白名单）。执行语义（清单验签/换装舞步/SCM 重启）在 internal/agent/app/upgrade.go，
// 探针侧零改动；本文件只锁服务端的门禁与元信息契约。

// TestUpgradeAvailable 验证升级物料元信息端点：未启用时 enabled=false
// （前端据此静默隐藏升级入口，而不是报错刷屏），配置了开关与包后返回
// 版本与包大小。
func TestUpgradeAvailable(t *testing.T) {
	env := newTestEnv(t)
	var out struct {
		Enabled bool   `json:"enabled"`
		Version string `json:"version"`
		Size    int64  `json:"size"`
	}
	env.doJSON(http.MethodGet, "/api/v1/upgrade/available", nil, http.StatusOK, env.token, &out)
	if out.Enabled || out.Version != "" {
		t.Fatalf("未配置升级包时 enabled 应为 false: %+v", out)
	}

	pkg := filepath.Join(t.TempDir(), "zedr-agent.exe")
	if err := os.WriteFile(pkg, []byte("fake-agent-binary"), 0o644); err != nil {
		t.Fatalf("写测试升级包失败: %v", err)
	}
	env2 := newTestEnvFull(t, func(d *Deps) {
		d.UpgradeEnabled = true
		d.UpgradeFile = pkg
		d.UpgradeVersion = "9.9.9"
	}, func(c *service.Config) { c.UpgradeEnabled = true })
	env2.doJSON(http.MethodGet, "/api/v1/upgrade/available", nil, http.StatusOK, env2.token, &out)
	if !out.Enabled || out.Version != "9.9.9" || out.Size != int64(len("fake-agent-binary")) {
		t.Fatalf("升级物料元信息不匹配: %+v", out)
	}
}

// TestUpgradeCommandGate 验证 self_upgrade 指令的三道闸，自外向内：
// ① 服务端总开关关 → admin 也被 EnqueueCommand 白名单拦下（403）；
// ② 开关开但角色是 analyst → sendCommand 角色闸拦下（403，升级方向
//    不可逆、收口 admin）；③ 开关开 + admin → 入队 pending，指令历史可查。
func TestUpgradeCommandGate(t *testing.T) {
	env := newTestEnv(t)
	agent := env.enrollAgent()
	env.doJSON(http.MethodPost, "/api/v1/hosts/"+agent.AgentID+"/commands",
		map[string]string{"type": "self_upgrade", "payload": ""},
		http.StatusForbidden, env.token, nil)

	pkg := filepath.Join(t.TempDir(), "zedr-agent.exe")
	if err := os.WriteFile(pkg, []byte("fake"), 0o644); err != nil {
		t.Fatalf("写测试升级包失败: %v", err)
	}
	env2 := newTestEnvFull(t, func(d *Deps) {
		d.UpgradeEnabled = true
		d.UpgradeFile = pkg
		d.UpgradeVersion = "9.9.9"
	}, func(c *service.Config) { c.UpgradeEnabled = true })
	agent2 := env2.enrollAgent()

	// analyst 被角色闸拦下
	env2.doJSON(http.MethodPost, "/api/v1/users", map[string]any{
		"username": "analyst1", "display_name": "分析", "password": "AnalystPass1!", "role": "analyst",
	}, http.StatusOK, env2.token, nil)
	analystToken := env2.login("analyst1", "AnalystPass1!")
	env2.doJSON(http.MethodPost, "/api/v1/hosts/"+agent2.AgentID+"/commands",
		map[string]string{"type": "self_upgrade", "payload": ""},
		http.StatusForbidden, analystToken, nil)

	// admin 入队成功，指令历史里类型/状态/发起人正确
	env2.doJSON(http.MethodPost, "/api/v1/hosts/"+agent2.AgentID+"/commands",
		map[string]string{"type": "self_upgrade", "payload": ""},
		http.StatusOK, env2.token, nil)
	var list struct {
		Items []struct {
			Type      string `json:"type"`
			Status    string `json:"status"`
			CreatedBy string `json:"created_by"`
		} `json:"items"`
	}
	env2.doJSON(http.MethodGet, "/api/v1/commands", nil, http.StatusOK, env2.token, &list)
	found := false
	for _, c := range list.Items {
		if c.Type == "self_upgrade" {
			found = true
			if c.Status != "pending" || c.CreatedBy != "admin" {
				t.Fatalf("self_upgrade 指令状态不正确: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("指令历史里没有 self_upgrade 记录")
	}
}
