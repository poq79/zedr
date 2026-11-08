package liveapi

// netinfo_test.go：/netinfo 的段解析纯单测 + 真机冒烟（结构完整性 +
// ip 可解析性 + sections 过滤语义）。winapi 五段采集依赖真实系统表，
// 离线只测参数解析，非 Windows 直接 skip 真机部分。

import (
	"net"
	"net/http"
	"reflect"
	"runtime"
	"testing"
)

func TestParseNetinfoSections(t *testing.T) {
	// 空 = 全五段（规范序）
	wanted, invalid := parseNetinfoSections("")
	if !reflect.DeepEqual(wanted, []string{"arp", "routes", "dns", "adapters", "shares"}) {
		t.Errorf("空参数应返回全五段规范序: %v", wanted)
	}
	if len(invalid) != 0 {
		t.Errorf("空参数不应有 invalid: %v", invalid)
	}

	// 大小写/空白容忍，去重，输出仍按规范序（不随请求顺序漂移）
	wanted, invalid = parseNetinfoSections(" dns , ARP,dns,BOGUS1")
	if !reflect.DeepEqual(wanted, []string{"arp", "dns"}) {
		t.Errorf("去重+规范序不符: %v", wanted)
	}
	if !reflect.DeepEqual(invalid, []string{"bogus1"}) {
		t.Errorf("非法段应原样小写记录: %v", invalid)
	}

	// 纯非法/纯分隔符：wanted 空、无 panic
	wanted, invalid = parseNetinfoSections(",,")
	if len(wanted) != 0 || len(invalid) != 0 {
		t.Errorf("纯分隔符应双空: %v %v", wanted, invalid)
	}
	wanted, invalid = parseNetinfoSections("foo,bar")
	if len(wanted) != 0 || !reflect.DeepEqual(invalid, []string{"foo", "bar"}) {
		t.Errorf("纯非法段: %v %v", wanted, invalid)
	}
}

// TestNetinfoRealSmoke 真机冒烟：默认全段无 panic、各段结构成立、
// arp/routes 的 ip 字段可解析或为空；sections=arp 只返回 arp 段。
func TestNetinfoRealSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	h := http.HandlerFunc((&server{}).handleNetinfo)

	code, body := doGet(t, h, "/netinfo")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)

	gotSections, _ := d["sections"].([]any)
	if len(gotSections) != 5 {
		t.Fatalf("默认应返回 5 段: %v", gotSections)
	}
	// 每段要么是数组、要么是 null（null 必须在 errors 里有说明）
	errs, _ := d["errors"].(map[string]any)
	for _, sec := range []string{"arp", "routes", "dns", "adapters", "shares"} {
		v, ok := d[sec]
		if !ok {
			t.Errorf("默认请求缺少段 %s", sec)
			continue
		}
		if v == nil {
			if errs == nil || errs[sec] == nil {
				t.Errorf("段 %s 为 null 但 errors 无说明", sec)
			}
			continue
		}
		if _, ok := v.([]any); !ok {
			t.Errorf("段 %s 应为数组: %T", sec, v)
		}
	}

	// arp/routes 的 ip 可解析或为空（winapi 侧已保证点分十进制，
	// 这里防回归：出现主机名/畸形串直接失败）
	if arp, ok := d["arp"].([]any); ok {
		for i, raw := range arp {
			m, _ := raw.(map[string]any)
			ip, _ := m["ip"].(string)
			if ip != "" && net.ParseIP(ip) == nil {
				t.Errorf("arp[%d].ip 不可解析: %q", i, ip)
			}
			if state, _ := m["state"].(string); state == "" {
				t.Errorf("arp[%d].state 不应为空", i)
			}
			if _, ok := m["if_index"].(float64); !ok {
				t.Errorf("arp[%d].if_index 应为数字: %T", i, m["if_index"])
			}
		}
		if n := len(arp); n > netinfoListCap {
			t.Errorf("arp 条数应 ≤ %d 实得 %d", netinfoListCap, n)
		}
	}
	if routes, ok := d["routes"].([]any); ok {
		for i, raw := range routes {
			m, _ := raw.(map[string]any)
			dest, _ := m["dest"].(string)
			if dest != "" && net.ParseIP(dest) == nil {
				t.Errorf("routes[%d].dest 不可解析: %q", i, dest)
			}
		}
	}

	// sections=arp 只返回 arp 段：其余段键不出现
	code, body = doGet(t, h, "/netinfo?sections=arp")
	if code != http.StatusOK {
		t.Fatalf("sections=arp 期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	if got, _ := d["sections"].([]any); len(got) != 1 || got[0] != "arp" {
		t.Errorf("sections 应为 [arp]: %v", d["sections"])
	}
	if _, ok := d["arp"]; !ok {
		t.Error("arp 段键应存在（数组或 null）")
	}
	for _, absent := range []string{"routes", "dns", "adapters", "shares"} {
		if _, ok := d[absent]; ok {
			t.Errorf("未请求的段 %s 不应出现在响应里", absent)
		}
	}

	// 混入非法段：合法段照常、非法段进 errors.sections
	code, body = doGet(t, h, "/netinfo?sections=arp,nope")
	if code != http.StatusOK {
		t.Fatalf("sections=arp,nope 期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	if got, _ := d["sections"].([]any); len(got) != 1 || got[0] != "arp" {
		t.Errorf("非法段应被忽略: %v", d["sections"])
	}
	errs, _ = d["errors"].(map[string]any)
	if errs == nil {
		t.Fatal("非法段应在 errors 里说明")
	}
	if msg, _ := errs["sections"].(string); msg == "" {
		t.Errorf("errors.sections 不应为空: %v", errs)
	}
}
