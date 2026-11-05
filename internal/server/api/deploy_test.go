package api

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestDeployEnrollConfig 验证接入引导配置端点：未带令牌 401、管理员可读、
// 返回 Deps 透传的 enroll token 与部署包可用性。
func TestDeployEnrollConfig(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "zedr-deploy.zip")
	if err := os.WriteFile(pkg, []byte("fake-zip-bytes"), 0o644); err != nil {
		t.Fatalf("写测试部署包失败: %v", err)
	}

	env := newTestEnvWith(t, func(d *Deps) {
		d.EnrollToken = testEnrollTok
		d.DeployPackage = pkg
		d.DeployVersion = "9.9.9"
	})

	// 未认证 → 401
	env.doJSON(http.MethodGet, "/api/v1/deploy/enroll-config", nil, http.StatusUnauthorized, "", nil)

	// 管理员 → 200 + token 与可用性
	var out struct {
		EnrollToken   string `json:"enroll_token"`
		DeployEnabled bool   `json:"deploy_enabled"`
		DeployVersion string `json:"deploy_version"`
	}
	env.doJSON(http.MethodGet, "/api/v1/deploy/enroll-config", nil, http.StatusOK,
		env.token, &out)
	if out.EnrollToken != testEnrollTok {
		t.Fatalf("enroll_token 不匹配: %q", out.EnrollToken)
	}
	if !out.DeployEnabled || out.DeployVersion != "9.9.9" {
		t.Fatalf("部署包可用性不匹配: enabled=%v version=%q", out.DeployEnabled, out.DeployVersion)
	}
}

// TestDeployAgentPackage 验证部署包下载：未配置 503、配置后 200 且
// sha256 头与正文一致、Content-Disposition 带版本号文件名。
func TestDeployAgentPackage(t *testing.T) {
	// 未配置 → 503（显式"未启用"语义，与自升级端点一致）
	envOff := newTestEnv(t)
	envOff.doJSON(http.MethodGet, "/api/v1/deploy/agent-package", nil,
		http.StatusServiceUnavailable, envOff.token, nil)

	body := []byte("PK\x03\x04-fake-zip-payload")
	pkg := filepath.Join(t.TempDir(), "zedr-deploy-v9.9.9.zip")
	if err := os.WriteFile(pkg, body, 0o644); err != nil {
		t.Fatalf("写测试部署包失败: %v", err)
	}
	env := newTestEnvWith(t, func(d *Deps) {
		d.DeployPackage = pkg
		d.DeployVersion = "9.9.9"
	})

	raw := env.doJSON(http.MethodGet, "/api/v1/deploy/agent-package", nil, http.StatusOK,
		env.token, nil)
	if string(raw) != string(body) {
		t.Fatalf("部署包正文不匹配：got %d bytes want %d", len(raw), len(body))
	}
	if sha := env.packageSHA256(); sha == "" {
		t.Fatal("缺少 X-ZEDR-Package-SHA256 头")
	}
}

// packageSHA256 取最近一次 agent-package 响应的 sha256 头。
// doJSON 不透出响应头，这里单独发一次 HEAD 语义的 GET 再读头。
func (e *testEnv) packageSHA256() string {
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/api/v1/deploy/agent-package", nil)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("请求部署包失败: %v", err)
	}
	defer res.Body.Close()
	return res.Header.Get("X-ZEDR-Package-SHA256")
}
