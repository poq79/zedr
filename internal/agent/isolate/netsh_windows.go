//go:build windows

package isolate

import (
	"fmt"
	"os/exec"
	"strings"
)

// netshFW 用 netsh advfirewall 操作 Windows 防火墙。选它而不是 WFP
// COM/新依赖的理由见 RESEARCH-HOST-ISOLATION §2：block 压过 allow 的
// 语义用"补集掏空"绕开，netsh 全版本在位、零依赖、无 CGO。
type netshFW struct{}

// NewNetshFW 返回 netsh 执行面（生产路径）。
func NewNetshFW() Firewall { return netshFW{} }

func runNetsh(args ...string) (string, error) {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	return string(out), err
}

func (netshFW) AddBlock(name, direction, cidr string) error {
	dir := "in"
	if direction == "out" {
		dir = "out"
	}
	_, err := runNetsh("advfirewall", "firewall", "add", "rule",
		"name="+name, "dir="+dir, "action=block", "remoteip="+cidr)
	return err
}

// DeleteByPrefix 删除名字以 prefix 开头的全部规则。netsh 只支持按精确
// 名单条删除/查询，先 show rule name=all 解析出匹配名再逐个删。
// 规则名在本包是确定性编号，正常路径 name 精确匹配即完成。
func (netshFW) DeleteByPrefix(prefix string) (int, error) {
	names, err := netshListNames()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if _, err := runNetsh("advfirewall", "firewall", "delete", "rule", "name="+name); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ListByPrefix 返回现存隔离规则名（防风暴语义同 DeleteByPrefix）。
func (netshFW) ListByPrefix(prefix string) ([]string, error) {
	names, err := netshListNames()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, name := range names {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	return out, nil
}

// netshListNames 解析 `netsh advfirewall firewall show rule name=all`
// 输出里的规则名行。中文系统输出行首是"规则名称:"——按冒号切，取
// 第一段含英文规则名约定的行（隔离规则名全 ASCII，逐行匹配前缀即可，
// 不依赖语言标头）。
func netshListNames() ([]string, error) {
	out, err := runNetsh("advfirewall", "firewall", "show", "rule", "name=all")
	if err != nil {
		return nil, fmt.Errorf("netsh show rule: %w（%s）", err, firstLine(out))
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(strings.TrimSpace(line), "\r")
		// 规则名行特征：以 ZEDR-ISOLATION- 开头（跳过语言无关的解析）
		if strings.Contains(line, "ZEDR-ISOLATION-") {
			// "规则名称:        ZEDR-ISOLATION-IN-000" / "Rule Name:  ZEDR-..."
			if idx := strings.Index(line, "ZEDR-ISOLATION-"); idx >= 0 {
				name := strings.TrimSpace(line[idx:])
				names = append(names, name)
			}
		}
	}
	return names, nil
}

// ProfileStates 逐 profile 查询启停态。netsh 输出随系统语言变化
//（中文"状态 启用/关闭"，英文 "State ON/OFF"）——判定只看关键词，
// "ON"/"启用"（大小写不敏感 ON 会误伤? OFF 不含 ON；启用不含关）。
func (netshFW) ProfileStates() (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range fwProfiles {
		res, err := runNetsh("advfirewall", "show", p+"profile", "state")
		if err != nil {
			return nil, fmt.Errorf("netsh show %sprofile: %w", p, err)
		}
		out[p] = profileStateOn(res)
	}
	return out, nil
}

func (netshFW) SetProfileEnabled(profile string, on bool) error {
	state := "off"
	if on {
		state = "on"
	}
	_, err := runNetsh("advfirewall", "set", profile+"profile", "state", state)
	return err
}

// profileStateOn 从单 profile 的 show state 输出判定是否启用。
// 中英文各两种："启用"/"ON" = on；"关闭"/"OFF" = off。
func profileStateOn(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.Contains(l, "启用") || strings.Contains(l, "on"):
			return true
		case strings.Contains(l, "关闭") || strings.Contains(l, "off"):
			return false
		}
	}
	return false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
