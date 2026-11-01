package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hostguard/internal/model"
	"hostguard/internal/server/auth"
	"hostguard/internal/server/repository/sqlite"
	"hostguard/internal/server/service"
)

const (
	testAdminPass  = "TestPassw0rd!"
	testEnrollTok  = "unit-test-enroll-token"
	testJWTSecret  = "unit-test-secret-key-must-be-at-least-32-bytes-long"
)

// testEnv 是一套跑在临时 SQLite 上的完整服务端。
type testEnv struct {
	t      *testing.T
	srv    *httptest.Server
	token  string
	agent  *enrollResult
	store  *sqlite.Store
}

type enrollResult struct {
	AgentID string `json:"agent_id"`
	Secret  string `json:"agent_secret"`
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	store, repos, err := sqlite.Open(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	tokens, err := auth.NewManager(testJWTSecret, 15*time.Minute, 24*time.Hour)
	if err != nil {
		t.Fatalf("构造令牌管理器失败: %v", err)
	}

	svc := service.New(repos, tokens, service.Config{
		EnrollToken:       testEnrollTok,
		KillEnabled:       false,
		HeartbeatInterval: 30 * time.Second,
		ScanInterval:      2 * time.Second,
		DupWindow:         5 * time.Minute,
	}, log)

	if _, err := svc.Rule.SeedBuiltins(t.Context()); err != nil {
		t.Fatalf("播种规则失败: %v", err)
	}
	if _, _, err := svc.Auth.BootstrapAdmin(t.Context(), "admin", testAdminPass); err != nil {
		t.Fatalf("创建管理员失败: %v", err)
	}

	router := Router(Deps{
		Services:     svc,
		Tokens:       tokens,
		Log:          log,
		WebFS:        nil,
		AllowOrigins: []string{"http://localhost:8080"},
		RateRPS:      1000,
		RateBurst:    1000,
		Ready:        func() error { return nil },
		Version:      "test",
		StartedAt:    time.Now(),
		Bus:          svc.Bus,
	})

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	env := &testEnv{t: t, srv: srv, store: store}
	env.token = env.login("admin", testAdminPass)
	return env
}

// login 登录并返回访问令牌。
func (e *testEnv) login(user, pass string) string {
	e.t.Helper()
	var out sessionResp
	e.doJSON(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": user, "password": pass}, http.StatusOK, "", &out)
	return out.AccessToken
}

// doJSON 发起请求并断言状态码，可选解析响应里的 data 字段。
func (e *testEnv) doJSON(method, path string, body any, wantStatus int, token string, out any) []byte {
	e.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatalf("序列化请求体失败: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatalf("读取响应失败: %v", err)
	}

	if res.StatusCode != wantStatus {
		e.t.Fatalf("%s %s 期望状态 %d，实际 %d，响应: %s",
			method, path, wantStatus, res.StatusCode, truncateForLog(string(raw)))
	}

	if out != nil && len(raw) > 0 {
		var wrap struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &wrap); err == nil && len(wrap.Data) > 0 {
			if err := json.Unmarshal(wrap.Data, out); err != nil {
				e.t.Fatalf("解析 data 失败: %v，原始: %s", err, truncateForLog(string(raw)))
			}
		}
	}
	return raw
}

func truncateForLog(s string) string {
	if len(s) > 400 {
		return s[:400] + "..."
	}
	return s
}

// enrollAgent 注册一个测试终端。
func (e *testEnv) enrollAgent() *enrollResult {
	e.t.Helper()
	var out enrollResult
	e.doJSON(http.MethodPost, "/api/v1/agents/enroll", model.EnrollRequest{
		EnrollToken: testEnrollTok,
		MachineID:   "TEST-MACHINE-0001",
		Hostname:    "TEST-HOST",
		OSVersion:   "Windows Test",
		Arch:        "amd64",
		Version:     "test",
	}, http.StatusOK, "", &out)
	return &out
}

// ---------------------------------------------------------------- 用例

func TestHealthAndReadiness(t *testing.T) {
	env := newTestEnv(t)
	for _, p := range []string{"/health", "/ready"} {
		raw := env.doJSON(http.MethodGet, p, nil, http.StatusOK, "", nil)
		if !bytes.Contains(raw, []byte(`"status"`)) {
			t.Fatalf("%s 响应缺少 status 字段: %s", p, raw)
		}
	}
}

func TestLoginFailures(t *testing.T) {
	env := newTestEnv(t)

	// 密码错误：统一文案，不泄露账号是否存在
	raw := env.doJSON(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": "admin", "password": "wrong-pass"},
		http.StatusUnauthorized, "", nil)
	if bytes.Contains(raw, []byte("password")) && bytes.Contains(raw, []byte("wrong-pass")) {
		t.Fatal("错误响应不应回显请求中的密码")
	}

	// 用户不存在同样返回 401
	env.doJSON(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": "ghost", "password": "whatever"},
		http.StatusUnauthorized, "", nil)

	// 缺字段 → 400
	env.doJSON(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": "admin"}, http.StatusBadRequest, "", nil)
}

func TestAuthRequired(t *testing.T) {
	env := newTestEnv(t)
	env.doJSON(http.MethodGet, "/api/v1/dashboard", nil, http.StatusUnauthorized, "", nil)
	env.doJSON(http.MethodGet, "/api/v1/dashboard", nil, http.StatusUnauthorized, "invalid-token", nil)
}

func TestDashboardAndRules(t *testing.T) {
	env := newTestEnv(t)

	var dash struct {
		TotalHosts int `json:"total_hosts"`
	}
	env.doJSON(http.MethodGet, "/api/v1/dashboard", nil, http.StatusOK, env.token, &dash)

	var rules struct {
		Total int `json:"total"`
		Items []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
			Builtin bool   `json:"builtin"`
		} `json:"items"`
	}
	env.doJSON(http.MethodGet, "/api/v1/rules", nil, http.StatusOK, env.token, &rules)
	if rules.Total < 30 {
		t.Fatalf("内置规则数量不足: %d", rules.Total)
	}
	if !rules.Items[0].Builtin {
		t.Fatal("内置规则应标记 builtin=true")
	}
}

func TestEnrollAndAlertIngest(t *testing.T) {
	env := newTestEnv(t)

	// 错误的注册令牌必须被拒
	env.doJSON(http.MethodPost, "/api/v1/agents/enroll", model.EnrollRequest{
		EnrollToken: "bad-token", MachineID: "X", Hostname: "X",
	}, http.StatusUnauthorized, "", nil)

	agent := env.enrollAgent()
	if agent.AgentID == "" || agent.Secret == "" {
		t.Fatal("注册未返回凭证")
	}

	// 终端上报：无凭证必须 401
	env.doJSON(http.MethodPost, "/api/v1/agent/heartbeat",
		model.HeartbeatRequest{Hostname: "TEST-HOST"}, http.StatusUnauthorized, "", nil)

	// 带凭证心跳
	hb := map[string]any{"hostname": "TEST-HOST", "proc_count": 100, "cpu_percent": 1.5}
	env.agent = agent
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/heartbeat", hb, http.StatusOK)

	// 上报告警
	batch := model.AlertBatchRequest{Alerts: []model.AlertEnvelope{{
		Fingerprint: "fp-0001",
		Title:       "测试告警：伪装系统进程",
		Summary:     "单元测试构造",
		Verdict:     model.VerdictMalicious,
		Severity:    model.SeverityCritical,
		Score:       88,
		PID:         4242,
		PPID:        4,
		ProcessName: "svchost.exe",
		ImagePath:   `C:\Users\public\svchost.exe`,
		CmdLine:     "svchost.exe -k netsvcs",
		ProcUser:    "TEST\\user",
		RuleIDs:     []string{"HG-016"},
		MITRE:       []string{"T1036.005"},
		OccurredAt:  time.Now(),
	}}}
	res := env.doAgentJSON(http.MethodPost, "/api/v1/agent/alerts", batch, http.StatusOK)

	var batchResp model.AlertBatchResponse
	if err := json.Unmarshal(res.data, &batchResp); err != nil {
		t.Fatalf("解析上报结果失败: %v", err)
	}
	if batchResp.Accepted != 1 {
		t.Fatalf("期望接收 1 条，实际 %+v", batchResp)
	}

	// 再次上报同指纹 → 应被聚合去重
	res = env.doAgentJSON(http.MethodPost, "/api/v1/agent/alerts", batch, http.StatusOK)
	if err := json.Unmarshal(res.data, &batchResp); err != nil {
		t.Fatalf("解析上报结果失败: %v", err)
	}
	if batchResp.Duplicates != 1 {
		t.Fatalf("同指纹告警应被聚合，实际 %+v", batchResp)
	}

	// 管理台应能查到这条告警
	var list struct {
		Total int `json:"total"`
		Items []struct {
			ID          string `json:"id"`
			ProcessName string `json:"process_name"`
			Severity    string `json:"severity"`
			HostCount   int    `json:"host_count"`
			Duplicate   int    `json:"duplicate"`
			Evidence    struct {
				Process struct {
					Name string `json:"name"`
				} `json:"process"`
			} `json:"evidence"`
		} `json:"items"`
	}
	env.doJSON(http.MethodGet, "/api/v1/alerts", nil, http.StatusOK, env.token, &list)
	if list.Total != 1 {
		t.Fatalf("期望 1 条告警（已聚合），实际 %d", list.Total)
	}
	if list.Items[0].ProcessName != "svchost.exe" {
		t.Fatalf("告警进程名不符: %s", list.Items[0].ProcessName)
	}
	if list.Items[0].Duplicate != 1 {
		t.Fatalf("重复计数应为 1，实际 %d", list.Items[0].Duplicate)
	}

	// 处置告警
	alertID := list.Items[0].ID
	env.doJSON(http.MethodPost, "/api/v1/alerts/"+alertID+"/status",
		map[string]string{"status": "false_positive", "note": "单元测试"},
		http.StatusNoContent, env.token, nil)

	var got struct {
		Status    string `json:"status"`
		HandledBy string `json:"handled_by"`
	}
	env.doJSON(http.MethodGet, "/api/v1/alerts/"+alertID, nil, http.StatusOK, env.token, &got)
	if got.Status != "false_positive" {
		t.Fatalf("处置状态未生效: %s", got.Status)
	}
	if got.HandledBy != "admin" {
		t.Fatalf("处置人记录错误: %s", got.HandledBy)
	}
}

func TestRBACAndValidation(t *testing.T) {
	env := newTestEnv(t)

	// 创建只读账号
	env.doJSON(http.MethodPost, "/api/v1/users", map[string]any{
		"username": "viewer1", "display_name": "只读", "password": "ViewerPass1!", "role": "viewer",
	}, http.StatusOK, env.token, nil)

	viewerToken := env.login("viewer1", "ViewerPass1!")

	// 只读可查
	env.doJSON(http.MethodGet, "/api/v1/alerts", nil, http.StatusOK, viewerToken, nil)

	// 只读不可改
	env.doJSON(http.MethodPost, "/api/v1/allowlist",
		map[string]string{"type": "hash", "value": "x"},
		http.StatusForbidden, viewerToken, nil)

	// 只读不可建账号（admin only）
	env.doJSON(http.MethodPost, "/api/v1/users", map[string]any{
		"username": "x2", "password": "ViewerPass1!", "role": "viewer",
	}, http.StatusForbidden, viewerToken, nil)

	// 非法白名单类型
	env.doJSON(http.MethodPost, "/api/v1/allowlist",
		map[string]string{"type": "nonsense", "value": "v"},
		http.StatusBadRequest, env.token, nil)

	// 非法 hash 长度
	env.doJSON(http.MethodPost, "/api/v1/allowlist",
		map[string]string{"type": "hash", "value": "abc"},
		http.StatusBadRequest, env.token, nil)

	// 未知字段应被拒绝（严格解析）
	env.doJSON(http.MethodPost, "/api/v1/allowlist",
		map[string]any{"type": "hash", "value": "a", "evil": 1},
		http.StatusBadRequest, env.token, nil)
}

func TestKillCommandRequiresServerOptIn(t *testing.T) {
	env := newTestEnv(t)
	agent := env.enrollAgent()

	// 服务端未开启主动处置时，terminate 必须被拒绝
	env.doJSON(http.MethodPost, "/api/v1/hosts/"+agent.AgentID+"/commands",
		map[string]string{"type": "terminate", "payload": `{"pid":123,"name":"x.exe"}`},
		http.StatusForbidden, env.token, nil)

	// 只读类指令始终允许
	env.doJSON(http.MethodPost, "/api/v1/hosts/"+agent.AgentID+"/commands",
		map[string]string{"type": "rescan"}, http.StatusOK, env.token, nil)
}

func TestAuditTrail(t *testing.T) {
	env := newTestEnv(t)
	env.doJSON(http.MethodPost, "/api/v1/allowlist",
		map[string]string{"type": "hash", "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "note": "测试"},
		http.StatusOK, env.token, nil)

	var audit struct {
		Items []struct {
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"items"`
	}
	env.doJSON(http.MethodGet, "/api/v1/audit", nil, http.StatusOK, env.token, &audit)
	found := false
	for _, it := range audit.Items {
		if it.Action == "allowlist.add" {
			found = true
		}
	}
	if !found {
		t.Fatal("审计日志未记录白名单新增")
	}
}

// ---------------------------------------------------------------- 终端请求辅助

type agentResponse struct {
	status int
	data   json.RawMessage
}

// doAgentJSON 以终端身份发起带凭证的请求。
func (e *testEnv) doAgentJSON(method, path string, body any, wantStatus int) agentResponse {
	e.t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatalf("序列化失败: %v", err)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Id", e.agent.AgentID)
	req.Header.Set("Authorization", "Bearer "+e.agent.Secret)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("请求失败: %v", err)
	}
	defer res.Body.Close()

	respBody, _ := io.ReadAll(res.Body)
	if res.StatusCode != wantStatus {
		e.t.Fatalf("%s %s 期望 %d 实际 %d: %s", method, path, wantStatus, res.StatusCode, truncateForLog(string(respBody)))
	}

	var wrap struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(respBody, &wrap)
	return agentResponse{status: res.StatusCode, data: wrap.Data}
}
