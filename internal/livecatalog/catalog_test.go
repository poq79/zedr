package livecatalog

import (
	"reflect"
	"strings"
	"testing"
)

// 表完整性锁：本表是三方（探针 mux / 服务端白名单 / MCP 工具描述）派生的
// 唯一事实源，任何一条写歪都会被三处同时放大，这里按结构不变量逐项锁死。

// cateOrder 是规范分组序（与 catalog 表的物理顺序一致）。
var cateOrder = []string{CateOps, CateFS, CateEvidence, CateProc, CateNet, CateSys}

var cateCounts = map[string]int{
	CateOps:      3,
	CateFS:       7,
	CateEvidence: 2,
	CateProc:     6,
	CateNet:      3,
	CateSys:      11,
}

// totalEndpoints：全表条目数。任务书文字写"31"，但分组枚举
// ops3+fs7+evidence2+proc6+net3+sys11=32，以逐条枚举为准（每条都有
// 明确契约，不可裁剪），这里按枚举口径锁定 32。
const totalEndpoints = 32

func kindAllowed(k string) bool {
	switch k {
	case KindString, KindInt, KindBool, KindPath, KindEnum, KindMulti:
		return true
	}
	return false
}

func costAllowed(c string) bool {
	return c == CostFast || c == CostMedium || c == CostSlow
}

func cateAllowed(c string) bool {
	for _, want := range cateOrder {
		if c == want {
			return true
		}
	}
	return false
}

// TestCatalogIntegrity 逐条校验结构不变量（任务书校验项 1/4 + 描述非空）。
func TestCatalogIntegrity(t *testing.T) {
	seen := make(map[string]bool, totalEndpoints)
	for _, ep := range All() {
		if ep.Name == "" {
			t.Fatalf("发现空 name 的条目（cate=%s summary=%s）", ep.Cate, ep.Summary)
		}
		if seen[ep.Name] {
			t.Fatalf("端点名重复: %s", ep.Name)
		}
		seen[ep.Name] = true
		if strings.ContainsAny(ep.Name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ ") {
			t.Errorf("端点 %q 应全小写且无空格", ep.Name)
		}
		if !cateAllowed(ep.Cate) {
			t.Errorf("端点 %s 的 category %q 不在六类白名单", ep.Name, ep.Cate)
		}
		if !costAllowed(ep.Cost) {
			t.Errorf("端点 %s 的 cost %q 不在 fast|medium|slow", ep.Name, ep.Cost)
		}
		if ep.TimeoutMs < 3000 || ep.TimeoutMs > 180000 {
			t.Errorf("端点 %s 的 timeout_ms=%d 超出 [3000,180000]", ep.Name, ep.TimeoutMs)
		}
		if ep.Summary == "" {
			t.Errorf("端点 %s 缺 summary", ep.Name)
		}
		if ep.Output == "" {
			t.Errorf("端点 %s 缺 output 说明", ep.Name)
		}
		for _, p := range ep.Params {
			if !kindAllowed(p.Kind) {
				t.Errorf("端点 %s 参数 %s 的 kind %q 不在白名单", ep.Name, p.Name, p.Kind)
			}
			if p.Desc == "" {
				// 所有参数都要求 Desc：可选参数没有用法说明对 MCP 生成
				// 的工具描述同样是黑洞，不比必填参数情有可原
				t.Errorf("端点 %s 参数 %s 缺 desc", ep.Name, p.Name)
			}
			if p.Default != "" && p.Required {
				t.Errorf("端点 %s 参数 %s 同时带 default 与 required（互斥：有默认值即不必填）", ep.Name, p.Name)
			}
			if p.Max < 0 {
				t.Errorf("端点 %s 参数 %s 的 max=%d 为负", ep.Name, p.Name, p.Max)
			}
		}
	}
}

// TestCatalogCounts 锁总数与分组计数（任务书校验项 6 + 分组口径）。
func TestCatalogCounts(t *testing.T) {
	all := All()
	if len(all) != totalEndpoints {
		t.Fatalf("条目总数 = %d, 期望 %d", len(all), totalEndpoints)
	}
	got := make(map[string]int, len(cateCounts))
	for _, ep := range all {
		got[ep.Cate]++
	}
	if !reflect.DeepEqual(got, cateCounts) {
		t.Fatalf("分组计数 = %v, 期望 %v", got, cateCounts)
	}
}

// TestCatalogExposureFlags 锁出站面开关口径（任务书校验项 2/3）：
// AI=false 必须恰好是 fs/read 与 collect（内容出站面不进 MCP 工具清单）；
// FileRead 只属于 fs/read 与 fs/grep；Collect 只属于 collect。
func TestCatalogExposureFlags(t *testing.T) {
	for _, ep := range All() {
		wantAI := ep.Name != "fs/read" && ep.Name != "collect"
		if ep.AI != wantAI {
			t.Errorf("端点 %s 的 ai=%v, 期望 %v（仅 fs/read 与 collect 为 false）", ep.Name, ep.AI, wantAI)
		}
		if ep.FileRead && ep.Name != "fs/read" && ep.Name != "fs/grep" {
			t.Errorf("端点 %s 不应带 fileread（只有 fs/read 与 fs/grep 是内容出站面）", ep.Name)
		}
		if ep.Collect && ep.Name != "collect" {
			t.Errorf("端点 %s 不应带 collect 标记", ep.Name)
		}
	}
	for _, name := range []string{"fs/read", "fs/grep"} {
		ep, ok := Get(name)
		if !ok || !ep.FileRead {
			t.Errorf("%s 应带 fileread=true", name)
		}
	}
	if ep, ok := Get("collect"); !ok || !ep.Collect {
		t.Errorf("collect 应带 collect=true")
	}
}

// TestCatalogOrder 锁规范序（任务书校验项 5 前半）：
// 分组连续且按 cateOrder 排列、组内顺序两次调用完全一致——
// 服务端白名单派生与 MCP tools/list 的输出顺序都依赖这份稳定性。
func TestCatalogOrder(t *testing.T) {
	a, b := All(), All()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("两次 All() 结果不一致（顺序不稳定）")
	}
	pos := 0 // 当前所在分组下标；只许前进，保证分组连续
	for _, ep := range a {
		for pos < len(cateOrder) && cateOrder[pos] != ep.Cate {
			pos++
		}
		if pos >= len(cateOrder) {
			t.Fatalf("分组顺序被破坏：在 %s 之后又出现 %s", cateOrder[len(cateOrder)-1], ep.Cate)
		}
	}
}

// TestGet 锁按名查找语义（任务书校验项 5 后半）：
// 命中返回完整条目；未命中返回零值+false；同名前缀不得误命中。
func TestGet(t *testing.T) {
	ep, ok := Get("fs/stat")
	if !ok {
		t.Fatal("Get(\"fs/stat\") 未命中")
	}
	if ep.Cate != CateFS || ep.TimeoutMs != 10000 {
		t.Fatalf("Get(\"fs/stat\") 返回条目与表不符: %+v", ep)
	}
	// "fs" 必须精确命中列表端点本身，而不是 fs/* 前缀族里的某一个
	ep, ok = Get("fs")
	if !ok || !strings.HasPrefix(ep.Summary, "目录列表") {
		t.Fatalf("Get(\"fs\") 应精确命中目录列表端点, got ok=%v summary=%q", ok, ep.Summary)
	}
	// Endpoint 内含 []Param 不可比较，零值语义用关键字段判空代替
	if got, ok := Get("不存在的端点"); ok || got.Name != "" {
		t.Fatalf("未命中应返回零值+false, got %+v ok=%v", got, ok)
	}
}

// TestExpectedNames 锁全量名单：改名即测试失败，强迫同步所有消费方口径。
var expectedNames = []string{
	// ops
	"ping", "info", "_catalog",
	// fs
	"fs", "fs/stat", "fs/read", "fs/hash", "fs/search", "fs/grep", "ads",
	// evidence
	"analyze", "collect",
	// proc
	"processes", "procinfo", "handles", "handleowners", "threads", "memscan",
	// net
	"netstat", "peers", "netinfo",
	// sys
	"registry", "evtlog", "tasks", "services", "drivers", "sessions", "usn",
	"baseline", "accounts", "persistence", "recon",
}

func TestExpectedNames(t *testing.T) {
	got := make(map[string]bool, totalEndpoints)
	for _, ep := range All() {
		got[ep.Name] = true
	}
	for _, want := range expectedNames {
		if !got[want] {
			t.Errorf("缺少端点 %s", want)
		}
	}
	if len(got) != len(expectedNames) {
		for name := range got {
			known := false
			for _, want := range expectedNames {
				if name == want {
					known = true
					break
				}
			}
			if !known {
				t.Errorf("表里多出未登记端点 %s（加入 expectedNames 并补齐契约）", name)
			}
		}
	}
}

// TestTimeoutsMatchProxyBudget 抽查 TimeoutMs 与服务端代理预算表
// （service.LiveEndpoints）的关键口径一致：catalog 是派生源，预算改了
// 这里不同步就是两套数字。全量对齐由消费方接线测试覆盖（避免本包
// import 服务端包破坏"探针可独立引用"的纯数据约束）。
func TestTimeoutsMatchProxyBudget(t *testing.T) {
	cases := map[string]int{
		"ping":    5000,
		"fs/read": 20000,
		"collect": 120000,
		"usn":     20000,
		"recon":   40000,
	}
	for name, want := range cases {
		ep, ok := Get(name)
		if !ok {
			t.Fatalf("端点 %s 不存在", name)
		}
		if ep.TimeoutMs != want {
			t.Errorf("%s timeout_ms=%d, 与服务端代理预算 %d 不一致", name, ep.TimeoutMs, want)
		}
	}
}
