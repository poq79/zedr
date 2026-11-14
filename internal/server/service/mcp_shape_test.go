package service

// mcp_shape_test.go：host_live 模型上下文整形的契约锁——超预算响应必须
// 保持 JSON 合法、保留计数语义与截断说明，绝不产生断头 JSON。

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestShapeForModelSmallPassthrough(t *testing.T) {
	body := []byte(`{"items":[1,2,3],"total":3}`)
	out, shaped := shapeForModel(body)
	if shaped {
		t.Fatal("小响应不应整形")
	}
	if string(out) != string(body) {
		t.Fatal("小响应应原样透传")
	}
}

func TestShapeForModelItemsTruncated(t *testing.T) {
	// 造 200 条大条目（每条 ~400B → 总 ~80KB > 48KB 预算）
	items := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		items = append(items, fmt.Sprintf(`{"name":"svc-%03d","path":"C:\\Program Files\\a\\%s.exe","state":"running"}`,
			i, strings.Repeat("x", 340)))
	}
	body := []byte(`{"items":[` + strings.Join(items, ",") + `],"total":200,"truncated":false}`)
	out, shaped := shapeForModel(body)
	if !shaped {
		t.Fatalf("应触发整形（%dB）", len(body))
	}
	if len(out) > mcpLiveShapeBudget {
		t.Fatalf("整形后仍超预算：%d", len(out))
	}
	var doc struct {
		Items     []json.RawMessage `json:"items"`
		Total     int               `json:"total"`
		Truncated bool              `json:"truncated"`
		AIShaped  bool              `json:"ai_shaped"`
		AINote    string            `json:"ai_note"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("整形后不是合法 JSON: %v", err)
	}
	if !doc.AIShaped || doc.AINote == "" {
		t.Fatal("缺 ai_shaped/ai_note 标记")
	}
	if doc.Total != 200 {
		t.Fatalf("total 语义字段丢失: %d", doc.Total)
	}
	if len(doc.Items) == 0 || len(doc.Items) >= 200 {
		t.Fatalf("保留条数异常: %d", len(doc.Items))
	}
}

func TestShapeForModelNoItemsFallback(t *testing.T) {
	big := `{"blob":"` + strings.Repeat("z", 100<<10) + `"}`
	out, shaped := shapeForModel([]byte(big))
	if !shaped {
		t.Fatal("应触发整形")
	}
	var doc struct {
		AIShaped bool   `json:"ai_shaped"`
		RawHead  string `json:"raw_head"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("兜底输出不是合法 JSON: %v", err)
	}
	if !doc.AIShaped || doc.RawHead == "" {
		t.Fatal("兜底缺 ai_shaped/raw_head")
	}
}

func TestShapeForModelGarbageFallback(t *testing.T) {
	out, shaped := shapeForModel([]byte("\xff\xfe not json at all " + strings.Repeat("x", 100<<10)))
	if !shaped {
		t.Fatal("非 JSON 大响应应走兜底")
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("兜底输出不是合法 JSON: %v", err)
	}
}
