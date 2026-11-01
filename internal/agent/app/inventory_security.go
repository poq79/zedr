package agentapp

// 安全姿态三节的清单 builder（defender/firewall/accounts）。
// 字段名即线协议（snake_case）；winapi 类型无 json tag，
// 在这里做唯一的翻译点——与 adapters/services/tasks 的映射策略一致。

import "hostguard/internal/agent/winapi"

type invFirewallProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type invAccount struct {
	Name string `json:"name"`
	SID  string `json:"sid,omitempty"`
}

// invDefenderSection 组装 defender 节：排除项 + 实时保护状态。
// 排除列表是"给恶意软件开门"的落盘证据，排除项新增走 critical 告警。
func (a *Agent) invDefenderSection() (any, error) {
	d, err := winapi.DefenderStatus()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"exclusion_paths":      d.ExclusionPaths,
		"exclusion_processes":  d.ExclusionProcesses,
		"exclusion_extensions": d.ExclusionExtensions,
		"realtime_state":       d.RealtimeState,
	}, nil
}

// invFirewallSection 组装 firewall 节：三张配置档的开关状态。
func (a *Agent) invFirewallSection() (any, error) {
	profs, err := winapi.FirewallProfiles()
	if err != nil {
		return nil, err
	}
	out := make([]invFirewallProfile, 0, len(profs))
	for _, p := range profs {
		out = append(out, invFirewallProfile{Name: p.Name, Enabled: p.Enabled})
	}
	return map[string]any{"profiles": out}, nil
}

// invAccountsSection 组装 accounts 节：本地管理员组成员清单。
// 成员增减是权限提升（T1098）的资产侧证据。
func (a *Agent) invAccountsSection() (any, error) {
	admins, err := winapi.LocalAdmins()
	if err != nil {
		return nil, err
	}
	out := make([]invAccount, 0, len(admins))
	for _, m := range admins {
		out = append(out, invAccount{Name: m.Name, SID: m.SID})
	}
	return map[string]any{"items": out}, nil
}
