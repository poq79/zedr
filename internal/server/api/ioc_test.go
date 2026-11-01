package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"hostguard/internal/model"
	"hostguard/internal/platform/rulehash"
)

const testIOC1 = "aa01010101010101010101010101010101010101010101010101010101010101"
const testIOC2 = "bb02020202020202020202020202020202020202020202020202020202020202"

// TestIOCManagementAndDelivery 端到端验证威胁指标库：
// 增删校验/去重 → 终端拉取整包带签名 → 版本随内容递增 →
// 清空后终端能感知（版本继续递增、包为空）。
func TestIOCManagementAndDelivery(t *testing.T) {
	env := newTestEnv(t)
	agent := env.enrollAgent()
	env.agent = agent

	// 非法哈希被拒
	env.doJSON(http.MethodPost, "/api/v1/iocs",
		map[string]string{"hash": "not-a-hash", "note": "x"}, http.StatusBadRequest, env.token, nil)

	// 合法新增
	var added struct {
		ID   string `json:"id"`
		Hash string `json:"hash"`
	}
	env.doJSON(http.MethodPost, "/api/v1/iocs",
		map[string]string{"hash": testIOC1, "note": "演练样本"}, http.StatusOK, env.token, &added)
	if added.ID == "" || added.Hash != testIOC1 {
		t.Fatalf("新增 IOC 返回异常: %+v", added)
	}

	// 重复新增 → 409
	env.doJSON(http.MethodPost, "/api/v1/iocs",
		map[string]string{"hash": strings.ToUpper(testIOC1)}, http.StatusConflict, env.token, nil)

	// 大小写归一：大写小写同一条
	var list struct {
		Total int `json:"total"`
		Items []struct {
			ID   string `json:"id"`
			Hash string `json:"hash"`
		} `json:"items"`
	}
	env.doJSON(http.MethodGet, "/api/v1/iocs", nil, http.StatusOK, env.token, &list)
	if list.Total != 1 {
		t.Fatalf("大小写归一后应只有 1 条，实际 %d", list.Total)
	}

	// 再加一条（用于测试删除路径）
	var added2 struct {
		ID string `json:"id"`
	}
	env.doJSON(http.MethodPost, "/api/v1/iocs",
		map[string]string{"hash": testIOC2}, http.StatusOK, env.token, &added2)

	// ---- 终端拉取：签名必须可校验 ----
	res := env.doAgentJSON(http.MethodGet, "/api/v1/agent/iocs", nil, http.StatusOK)
	var bundle model.IOCBundle
	if err := json.Unmarshal(res.data, &bundle); err != nil {
		t.Fatalf("解析 IOC 包失败: %v", err)
	}
	if len(bundle.IOCs) != 2 {
		t.Fatalf("IOC 包应含 2 条，实际 %d", len(bundle.IOCs))
	}
	key := rulehash.DeriveKey([]byte(testJWTSecret), "rule-signing")
	if err := rulehash.VerifyIOCBundle(&bundle, key); err != nil {
		t.Fatalf("IOC 包验签失败: %v", err)
	}
	if bundle.Version < 2 {
		t.Fatalf("两次新增后版本应 ≥2，实际 %d", bundle.Version)
	}
	verAfterAdd := bundle.Version

	// 篡改包内容必须验签失败
	tampered := bundle
	tampered.IOCs = tampered.IOCs[:1]
	if err := rulehash.VerifyIOCBundle(&tampered, key); err == nil {
		t.Fatal("篡改后的 IOC 包不应通过验签")
	}

	// ---- 删除 + 清空感知 ----
	env.doJSON(http.MethodDelete, "/api/v1/iocs/"+added2.ID, nil, http.StatusNoContent, env.token, nil)
	env.doJSON(http.MethodDelete, "/api/v1/iocs/"+added.ID, nil, http.StatusNoContent, env.token, nil)

	res = env.doAgentJSON(http.MethodGet, "/api/v1/agent/iocs", nil, http.StatusOK)
	var emptyBundle model.IOCBundle
	if err := json.Unmarshal(res.data, &emptyBundle); err != nil {
		t.Fatalf("解析空 IOC 包失败: %v", err)
	}
	if len(emptyBundle.IOCs) != 0 {
		t.Fatalf("清空后 IOC 包应为空，实际 %d 条", len(emptyBundle.IOCs))
	}
	if emptyBundle.Version <= verAfterAdd {
		t.Fatalf("删除后版本应继续递增（%d → %d），否则终端感知不到清空",
			verAfterAdd, emptyBundle.Version)
	}
	if err := rulehash.VerifyIOCBundle(&emptyBundle, key); err != nil {
		t.Fatalf("空包也应通过验签: %v", err)
	}
}
