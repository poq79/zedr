package linuxinv

// linuxinv_test.go — 资产清单节纯逻辑单测（无构建标签，Windows 上跑）。
//
// 策略：节函数本身读 /proc、/etc（Windows 上必然失败 → Manager 跳过），
// 所以单测覆盖的是"文件文本 → 节 payload"的纯解析层；只有 startup
// 注入与 Manager 的接线走真对象冒烟。fixture 按内核文档与发行版惯例
// 手写，实机校准项见各文件头注。

import (
	"log/slog"
	"strings"
	"testing"

	"zedr/internal/agent/inventory"
)

func TestParseDpkgStatusPkg(t *testing.T) {
	data := []byte(`Package: curl
Status: install ok installed
Version: 7.88.1-10
Installed-Size: 1234

Package: zsh
Status: deinstall ok config-files
Version: 5.9-4

Package: nginx
Status: install ok half-installed
Version: 1.22.1-9

Package: openssh-server
Description: secure shell server
 continuation line
Status: install ok installed
Version: 1:9.2p1-1

`)
	got := parseDpkgStatus(data)
	if len(got) != 2 {
		t.Fatalf("应保留 2 条 installed，got %d: %+v", len(got), got)
	}
	if got[0].Name != "curl" || got[0].Version != "7.88.1-10" || got[0].SizeKB != 1234 {
		t.Errorf("curl 解析错误: %+v", got[0])
	}
	if got[1].Name != "openssh-server" || got[1].Version != "1:9.2p1-1" {
		t.Errorf("openssh-server 解析错误: %+v", got[1])
	}
}

func TestPackagesPayloadTopN(t *testing.T) {
	// topN 截断 + notes 注记 + 名称序稳定
	pkgs := make([]invPackage, 0, packagesTopN+2)
	for i := 0; i < packagesTopN+2; i++ {
		pkgs = append(pkgs, invPackage{Name: strings.Repeat("z", 1) + string(rune('a'+i%26)) + string(rune(i)), Version: "1.0"})
	}
	payload := packagesPayload("dpkg", pkgs, nil)
	if payload["total"].(int) != packagesTopN+2 {
		t.Errorf("total 应是全量计数: %v", payload["total"])
	}
	top := payload["top"].([]invPackage)
	if len(top) != packagesTopN {
		t.Errorf("top 应截断到 %d，got %d", packagesTopN, len(top))
	}
	if len(payload["notes"].([]string)) == 0 {
		t.Error("截断时应有 notes 注记")
	}
	small := packagesPayload("dpkg", []invPackage{{Name: "curl", Version: "1"}}, nil)
	if len(small["notes"].([]string)) != 0 {
		t.Error("未截断不应有 notes")
	}
}

func TestParseRpmQAPkg(t *testing.T) {
	data := []byte("bash\t5.2.15\t1234567\n\ncurl\t7.88.1\t999999\n")
	got := parseRpmQA(data)
	if len(got) != 2 || got[0].Name != "bash" || got[0].SizeKB != 1234567/1024 {
		t.Errorf("rpm 输出解析错误: %+v", got)
	}
}

func TestParseProcNetListener(t *testing.T) {
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 010AA8C0:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 24 4 30 10 -1\n"
	rows := parseProcNet("tcp", tcp)
	if len(rows) != 2 {
		t.Fatalf("应 2 行，got %d", len(rows))
	}
	if rows[0].LocalPort != 8080 || rows[0].State != "0A" || rows[0].Inode != 12345 {
		t.Errorf("LISTEN 行解析错误: %+v", rows[0])
	}
	if rows[1].Inode != 12346 {
		t.Errorf("ESTAB 行解析错误: %+v", rows[1])
	}
}

func TestParseHexSockaddrLinuxinv(t *testing.T) {
	// 与 hygiene 侧解析器同口径的锚定测试（两份实现分叉会在这里暴露）
	ip, port, ok := parseHexSockaddr("0100007F:1F90")
	if !ok || ip != "127.0.0.1" || port != 8080 {
		t.Errorf("v4 解析错误: %q %d %v", ip, port, ok)
	}
	v6, p6, ok := parseHexSockaddr("00000000000000000000000001000000:006F")
	if !ok || v6 != "::1" || p6 != 111 {
		t.Errorf("v6 解析错误: %q %d %v", v6, p6, ok)
	}
}

func TestParseStatStarttime(t *testing.T) {
	// agent uptime 依赖 /proc/self/stat 第 22 字段（comm 后偏移 19）
	data := []byte("999 (zedr-agent) S 1 999 999 0 -1 4194560 123 0 0 0 100 20 0 0 20 5 1 0 42424242 98765432 9999 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 4 0 0 0 0 0\n")
	v, ok := parseStatStarttime(data)
	if !ok || v != 42424242 {
		t.Errorf("starttime 解析错误: %d %v", v, ok)
	}
}

func TestParseUnitDescription(t *testing.T) {
	data := []byte(`[Unit]
Description=Z-EDR Agent
After=network.target
# Description=fake comment

[Service]
ExecStart=/usr/bin/zedr-agent
`)
	if got := parseUnitDescription(data); got != "Z-EDR Agent" {
		t.Errorf("Description 提取错误: %q", got)
	}
	if got := parseUnitDescription([]byte("[Service]\nExecStart=/x\n")); got != "" {
		t.Errorf("无 [Unit] 段应返回空: %q", got)
	}
}

func TestParsePasswdUsers(t *testing.T) {
	data := []byte(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
svc:x:100:100::/home/svc:/bin/false
deploy:x:1000:1000:Deploy:/home/deploy:/bin/bash
app:x:1001:1001::/home/app:/bin/sh
`)
	// root/deploy/app 三个可登录（/bin/sh 是真 shell）；nologin/false 剔除
	sudo := map[string]bool{"deploy": true}
	out := parsePasswd(data, sudo, nil)
	if len(out) != 3 {
		t.Fatalf("应 3 个可登录账户，got %d: %+v", len(out), out)
	}
	if out[0].Name != "root" || out[0].UID != 0 || out[0].Shell != "/bin/bash" {
		t.Errorf("root 解析错误: %+v", out[0])
	}
	if !out[1].Sudo {
		t.Errorf("deploy 在 sudo 组应标 sudo: %+v", out[1])
	}
	if out[0].Sudo || out[2].Sudo {
		t.Errorf("不在 sudo 组的账户不应标 sudo: %+v", out)
	}
}

func TestGroupMembers(t *testing.T) {
	data := []byte("root:x:0:\nsudo:x:27:deploy,ops\nwheel:x:10:adm\n")
	got := parseGroup(data, []string{"sudo", "wheel"})
	if !got["deploy"] || !got["ops"] || !got["adm"] || got["root"] {
		t.Errorf("组成员解析错误: %v", got)
	}
	if non := parseGroup(data, []string{"sudo"}); non["adm"] {
		t.Errorf("未要求的组不应计入: %v", non)
	}
}

func TestRegisterAllSmoke(t *testing.T) {
	// 接线冒烟：startup 注入 + Manager 注册计数。其余节读 /proc、/etc
	// 的行为分两档（都符合"诚实降级"设计）：
	//   - system/listeners/services/agent/users：/proc 缺失 → error →
	//     Manager 跳过（Windows 上不可见）；
	//   - packages/tasks：纯文本枚举失败也能给出"事实本身"——packages
	//     返回 manager:"unknown"+notes，tasks 返回空数组（真 Linux 上
	//     无 cron 配置也是合法状态）。
	m := inventory.New(slog.Default())
	called := false
	RegisterAll(m, slog.Default(), func() (any, error) {
		called = true
		return map[string]any{"items": []any{
			map[string]any{"kind": "cron", "location": "/etc/cron.d/x", "value": "/usr/local/bin/x"},
		}}, nil
	})
	// 7 个固定节 + startup = 8
	if got := m.Count(); got != 8 {
		t.Errorf("应注册 8 节，got %d", got)
	}
	secs := m.Snapshot()
	byName := map[string]string{}
	for _, s := range secs {
		byName[s.Name] = s.Payload
	}
	if _, ok := byName["startup"]; !ok || !called {
		t.Fatalf("startup 节应产出且注入点被调用，got %v", byName)
	}
	if !strings.Contains(byName["startup"], "/etc/cron.d/x") {
		t.Errorf("startup 注入 payload 异常: %s", byName["startup"])
	}
	// Windows 上的降级行为锚定：packages 诚实标注 unknown（不冒充 0 包）
	if byName["packages"] == "" || !strings.Contains(byName["packages"], `"manager":"unknown"`) {
		t.Errorf("packages 节在无包管理器环境应返回 unknown 口径: %v", byName["packages"])
	}
}

func TestRegisterAllNilStartup(t *testing.T) {
	m := inventory.New(slog.Default())
	RegisterAll(m, slog.Default(), nil)
	if got := m.Count(); got != 7 {
		t.Errorf("无 startup 注入应注册 7 节，got %d", got)
	}
}
