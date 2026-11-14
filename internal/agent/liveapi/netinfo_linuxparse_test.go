// 本测试文件 NEUTRAL：/netinfo Linux 侧解析纯逻辑在 Windows 上跑。
// 夹具：testdata/proc-net-arp、testdata/proc-net-route、testdata/resolv.conf
// （内核文档/proc(5) 口径样例）。
package liveapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseProcNetArpFixture(t *testing.T) {
	rows := parseProcNetArp(mustFixture(t, "proc-net-arp"))
	if len(rows) != 4 {
		t.Fatalf("期望 4 行（表头/残行跳过）实得 %d: %+v", len(rows), rows)
	}
	if rows[0].IP != "192.168.1.1" || rows[0].MAC != "aa:bb:cc:dd:ee:01" ||
		rows[0].Flags != 0x2 || rows[0].Device != "eth0" {
		t.Errorf("第 1 行口径不符: %+v", rows[0])
	}
	if rows[1].Flags != 0x6 { // ATF_PERM|ATF_COM
		t.Errorf("第 2 行 flags 口径不符: %+v", rows[1])
	}
	if rows[2].Flags != 0x0 || rows[2].Device != "wlan0" {
		t.Errorf("incomplete 条目口径不符: %+v", rows[2])
	}
}

func TestParseProcNetRouteFixture(t *testing.T) {
	rows := parseProcNetRoute(mustFixture(t, "proc-net-route"))
	if len(rows) != 4 {
		t.Fatalf("期望 4 行实得 %d: %+v", len(rows), rows)
	}
	if rows[0].Iface != "eth0" || rows[0].Dest != 0 || rows[0].Metric != 100 {
		t.Errorf("默认路由口径不符: %+v", rows[0])
	}
	if rows[1].Mask == 0 { // 192.168.1.0/24 的掩码不是 0
		t.Errorf("第 2 行掩码不应为 0: %+v", rows[1])
	}

	// hexLEIP 还原：__be32 按 %08X 打印后的小端整数字节展开。
	// 192.168.1.254 网络序 C0 A8 01 FE → LE u32 0xFE01A8C0（夹具第 1 行）。
	if got := hexLEIP(rows[0].Gateway); got != "192.168.1.254" {
		t.Errorf("默认网关还原不符: %q", got)
	}
	if got := hexLEIP(rows[1].Dest); got != "192.168.1.0" {
		t.Errorf("直连网段还原不符: %q", got)
	}
	if got := hexLEIP(rows[1].Mask); got != "255.255.255.0" {
		t.Errorf("掩码还原不符: %q", got)
	}
	if got := hexLEIP(rows[2].Gateway); got != "192.168.0.1" {
		t.Errorf("wlan0 网关还原不符: %q", got)
	}
	if got := hexLEIP(rows[3].Dest); got != "10.10.10.0" {
		t.Errorf("eth1 网段还原不符: %q", got)
	}
	if got := hexLEIP(rows[3].Mask); got != "255.0.0.0" {
		t.Errorf("eth1 掩码还原不符: %q", got)
	}
}

func TestParseResolvConfFixture(t *testing.T) {
	rows := parseResolvConf(mustFixture(t, "resolv.conf"))
	// 文件顺序保留：search×2 → nameserver×2 → domain×1；options 跳过
	if len(rows) != 5 {
		t.Fatalf("期望 5 条实得 %d: %+v", len(rows), rows)
	}
	want := "search:corp.example.com,search:lab.example.com," +
		"nameserver:10.0.0.53,nameserver:10.0.0.54,domain:fallback.example.com"
	got := make([]string, len(rows))
	for i, r := range rows {
		got[i] = r.Type + ":" + r.Name
	}
	if strings.Join(got, ",") != want {
		t.Errorf("resolv.conf 口径不符:\n got  %s\n want %s", strings.Join(got, ","), want)
	}
}

func TestLinuxNetinfoShapes(t *testing.T) {
	// 形状锁：Linux 投影用的结构与 Windows netinfo_shapes.go 共享同一
	// 定义，这里锁 json tag（前端零改动渲染的前提）。
	lockTags := func(t *testing.T, v any, keys ...string) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var probe map[string]any
		if err := json.Unmarshal(b, &probe); err != nil {
			t.Fatal(err)
		}
		if len(probe) != len(keys) {
			t.Errorf("%T 字段数 %d != %d: %s", v, len(probe), len(keys), b)
		}
		for _, k := range keys {
			if _, ok := probe[k]; !ok {
				t.Errorf("%T 缺少字段 %q: %s", v, k, b)
			}
		}
	}
	lockTags(t, netinfoArpItem{}, "ip", "mac", "if_index", "state")
	lockTags(t, netinfoRouteItem{}, "dest", "mask", "gateway", "if_index", "metric")
	lockTags(t, netinfoDnsItem{}, "name", "type", "data", "ttl")
	lockTags(t, netinfoAdapterItem{}, "name", "mac", "ips", "gateway", "dns", "oper_state")
	lockTags(t, netinfoShareItem{}, "name", "path", "remark")
}
