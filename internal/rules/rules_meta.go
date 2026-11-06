package rules

import "zedr/internal/model"

// 本文件是规则 DSL 的"运营者视图"：字段表、操作符表与规则模板。
//
// 为什么放在 rules 包内而不是前端硬编码：字段/操作符的合法集合由
// validFields/validOps（rules.go）在编译期强制，模板与参考如果散落在
// 前端，早晚和引擎漂移——前端展示一个引擎已不认的字段，运营者保存时
// 才发现被拒，甚至更糟：引擎加载期拒绝导致规则静默不生效（本仓库
// 5.1 节引号事故的同类）。因此 schema/模板与 DSL 同包演进，由
// GET /api/v1/rules/schema 暴露给前端渲染，单一事实源。

// KindName 是字段取值类型的对外名称（与 fieldKind 对应）。
type KindName string

const (
	KindString     KindName = "string"
	KindBool       KindName = "bool"
	KindInt        KindName = "int"
	KindStringList KindName = "string_list"
	KindIntList    KindName = "int_list"
)

// FieldDoc 是一个可检测字段的运营者参考。
type FieldDoc struct {
	Field  string   `json:"field"`
	Kind   KindName `json:"kind"`
	Desc   string   `json:"desc"`
	Group  string   `json:"group"` // 进程/血缘/网络/模块，用于下拉分组
	Example string  `json:"example,omitempty"`
}

// OpDoc 是一个操作符的运营者参考。
type OpDoc struct {
	Op    string     `json:"op"`
	Desc  string     `json:"desc"`
	Kinds []KindName `json:"kinds"` // 适配的字段类型，前端据此过滤操作符
}

// Template 是一条规则模板：给运营者的"半成品"——选一个模板、改几个
// 值就能保存。模板刻意从结构性行为出发（路径/父子/签名/网络），
// 不内嵌任何敏感工具名，保持与 builtin.go 相同的安全线。
type Template struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Severity    model.Severity  `json:"severity"`
	Score       int             `json:"score"`
	MITRE       []string        `json:"mitre,omitempty"`
	Definition  Definition      `json:"definition"`
}

// Schema 返回字段/操作符参考表。
func Schema() ([]FieldDoc, []OpDoc) {
	fields := []FieldDoc{
		{Field: "process.name", Kind: KindString, Group: "进程", Desc: "进程名（含 .exe）", Example: "cmd.exe"},
		{Field: "process.path", Kind: KindString, Group: "进程", Desc: "完整镜像路径", Example: `C:\Users\...\app.exe`},
		{Field: "process.cmdline", Kind: KindString, Group: "进程", Desc: "完整命令行", Example: "powershell.exe -enc ..."},
		{Field: "process.user", Kind: KindString, Group: "进程", Desc: "运行账号", Example: "Administrator"},
		{Field: "process.signed", Kind: KindBool, Group: "进程", Desc: "是否有数字签名"},
		{Field: "process.signature_ok", Kind: KindBool, Group: "进程", Desc: "签名链校验是否通过"},
		{Field: "process.signer", Kind: KindString, Group: "进程", Desc: "签名主体", Example: "Contoso Ltd"},
		{Field: "process.elevated", Kind: KindBool, Group: "进程", Desc: "是否以管理员完整性运行"},
		{Field: "process.in_system", Kind: KindBool, Group: "进程", Desc: "是否位于 System32/SysWOW64/WinSxS"},
		{Field: "process.dir_writable", Kind: KindBool, Group: "进程", Desc: "镜像所在目录是否普通用户可写"},
		{Field: "process.session", Kind: KindInt, Group: "进程", Desc: "会话 ID（0=系统会话）"},
		{Field: "process.depth", Kind: KindInt, Group: "进程", Desc: "路径层级深度（识别深层伪装目录）"},
		{Field: "parent.name", Kind: KindString, Group: "血缘", Desc: "父进程名", Example: "winword.exe"},
		{Field: "parent.path", Kind: KindString, Group: "血缘", Desc: "父进程完整路径"},
		{Field: "ancestor.names", Kind: KindStringList, Group: "血缘", Desc: "祖先链进程名（由近到远）"},
		{Field: "network.count", Kind: KindInt, Group: "网络", Desc: "活跃网络连接数"},
		{Field: "network.remote_ports", Kind: KindIntList, Group: "网络", Desc: "远端端口列表"},
		{Field: "network.has_public_remote", Kind: KindBool, Group: "网络", Desc: "是否存在非内网远端地址"},
		{Field: "module.unsigned_count", Kind: KindInt, Group: "模块", Desc: "加载的未签名模块数"},
		{Field: "module.non_system_count", Kind: KindInt, Group: "模块", Desc: "从非系统目录加载的模块数"},
	}
	ops := []OpDoc{
		{Op: "eq", Desc: "等于", Kinds: []KindName{KindString, KindInt}},
		{Op: "ne", Desc: "不等于", Kinds: []KindName{KindString, KindInt}},
		{Op: "gt", Desc: "大于（数值/可比较值）", Kinds: []KindName{KindInt}},
		{Op: "gte", Desc: "大于等于", Kinds: []KindName{KindInt}},
		{Op: "lt", Desc: "小于", Kinds: []KindName{KindInt}},
		{Op: "lte", Desc: "小于等于", Kinds: []KindName{KindInt}},
		{Op: "in", Desc: "命中列表中任意一项（不区分大小写）", Kinds: []KindName{KindString, KindInt}},
		{Op: "nin", Desc: "不在列表中（反向白名单思维）", Kinds: []KindName{KindString, KindInt}},
		{Op: "contains", Desc: "包含（区分大小写）", Kinds: []KindName{KindString}},
		{Op: "icontains", Desc: "包含（不区分大小写）", Kinds: []KindName{KindString}},
		{Op: "ncontains", Desc: "不包含", Kinds: []KindName{KindString}},
		{Op: "prefix", Desc: "前缀匹配（不区分大小写）", Kinds: []KindName{KindString}},
		{Op: "suffix", Desc: "后缀匹配（不区分大小写）", Kinds: []KindName{KindString}},
		{Op: "glob", Desc: "通配符匹配（* 任意、? 单字符）", Kinds: []KindName{KindString}},
		{Op: "regex", Desc: "正则匹配（保存时会校验合法性）", Kinds: []KindName{KindString}},
		{Op: "any_in_list", Desc: "字段列表与条件列表有交集", Kinds: []KindName{KindStringList, KindIntList}},
		{Op: "list_contains", Desc: "字段列表包含指定值", Kinds: []KindName{KindStringList, KindIntList}},
		{Op: "list_has_any", Desc: "字段列表与条件列表有交集（数值版）", Kinds: []KindName{KindStringList, KindIntList}},
		{Op: "bool_eq", Desc: "布尔字段等于 true/false", Kinds: []KindName{KindBool}},
		{Op: "exists", Desc: "字段存在（进程快照总有值，多用于占位）"},
	}
	return fields, ops
}

// Templates 返回规则模板集。语义对齐内置规则里最常见的几类结构性行为，
// 运营者选模板后通常只需改值/调分值。
func Templates() []Template {
	return []Template{
		{
			ID: "tpl-blank", Name: "空白规则",
			Description: "从零开始写条件体。不确定从哪开始时，建议先看看下面的模板。占位条件永不命中——忘改也不会造成误报风暴。",
			Severity: model.SeverityMedium, Score: 30,
			Definition: Definition{
				All: []Condition{c("process.name", "eq", "【请修改为要检测的进程名】")},
			},
		},
		{
			ID: "tpl-office-shell", Name: "Office 文档拉起脚本/命令行",
			Description: "Word/Excel/Outlook 等直接拉起脚本宿主或命令行，钓鱼附件最典型的执行链。与内置 HG-001 同型，可按企业实际加删父/子进程名单。",
			Severity: model.SeverityCritical, Score: 45, MITRE: []string{"T1204.002", "T1566"},
			Definition: Definition{
				All: []Condition{c("parent.name", "in", []any{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"})},
				Any: []Condition{c("process.name", "in", []any{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"})},
			},
		},
		{
			ID: "tpl-script-writable-dir", Name: "脚本解释器从可写目录执行",
			Description: "cmd/PowerShell/脚本宿主的镜像不在系统目录（如放在 Temp/下载目录里的副本），是伪装与绕过 Path 审计的常见形态。",
			Severity: model.SeverityHigh, Score: 34, MITRE: []string{"T1036.005"},
			Definition: Definition{
				All: []Condition{
					c("process.name", "in", []any{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}),
					c("process.in_system", "bool_eq", false),
				},
			},
		},
		{
			ID: "tpl-unsigned-elevated", Name: "未签名程序请求管理员权限",
			Description: "没有有效签名却以管理员完整性运行——正常商业软件极少这样，恶意驻留的常见画像。企业自有未签名工具多时建议先观察模式跑一段。",
			Severity: model.SeverityHigh, Score: 36, MITRE: []string{"T1548.002"},
			Definition: Definition{
				All: []Condition{
					c("process.signature_ok", "bool_eq", false),
					c("process.elevated", "bool_eq", true),
					c("process.in_system", "bool_eq", false),
				},
			},
		},
		{
			ID: "tpl-system-name-offpath", Name: "系统进程名但不在系统目录",
			Description: "名字叫 svchost/lsass/services 却不在系统目录——比改名的恶意程序更典型，几乎可以直接转正（极少数安装器会临时仿名，注意观察命中）。",
			Severity: model.SeverityCritical, Score: 50, MITRE: []string{"T1036.005"},
			Definition: Definition{
				All: []Condition{
					c("process.name", "in", []any{"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe"}),
					c("process.in_system", "bool_eq", false),
				},
			},
		},
		{
			ID: "tpl-writable-net", Name: "可写目录程序外联公网",
			Description: "普通用户可写目录里的程序建立公网连接——下载器/后门的典型画像。备份盘/网盘客户端若装在用户目录会误报，先观察再转正。",
			Severity: model.SeverityHigh, Score: 32, MITRE: []string{"T1071.001"},
			Definition: Definition{
				All: []Condition{
					c("process.dir_writable", "bool_eq", true),
					c("network.has_public_remote", "bool_eq", true),
				},
			},
		},
		{
			ID: "tpl-lolbin-net", Name: "代理执行工具带公网外联",
			Description: "rundll32/regsvr32/mshta 等系统代理执行程序建立公网连接，正常情况下它们几乎不需要访问互联网。",
			Severity: model.SeverityHigh, Score: 38, MITRE: []string{"T1218.005", "T1218.010"},
			Definition: Definition{
				All: []Condition{
					c("process.name", "in", []any{"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe"}),
					c("network.has_public_remote", "bool_eq", true),
				},
			},
		},
		{
			ID: "tpl-many-conns", Name: "单进程大量网络连接",
			Description: "一个进程同时维持大量连接并存在公网远端——扫描/扇出行为的画像。阈值按业务调整（备份/同步服务会偏高）。",
			Severity: model.SeverityMedium, Score: 28, MITRE: []string{"T1046"},
			Definition: Definition{
				All: []Condition{
					c("network.count", "gte", 40),
					c("network.has_public_remote", "bool_eq", true),
				},
			},
		},
		{
			ID: "tpl-deep-path", Name: "深层伪装路径执行",
			Description: "从超深路径层级运行可执行文件——攻击者把载荷藏在多层嵌套目录里规避人工巡检的常见手法。层级阈值可按环境调整。",
			Severity: model.SeverityMedium, Score: 26, MITRE: []string{"T1027.009"},
			Definition: Definition{
				All: []Condition{
					c("process.depth", "gte", 8),
					c("process.in_system", "bool_eq", false),
				},
			},
		},
		{
			ID: "tpl-unsigned-modules", Name: "未签名模块集中加载",
			Description: "进程加载了多个未签名且来自非系统目录的模块——DLL 侧载/注入类行为的画像。开发机与装了大量国产软件的终端命中会偏高。",
			Severity: model.SeverityMedium, Score: 30, MITRE: []string{"T1574.002"},
			Definition: Definition{
				All: []Condition{
					c("module.unsigned_count", "gte", 3),
					c("module.non_system_count", "gte", 5),
				},
			},
		},
		{
			ID: "tpl-script-parent-chain", Name: "祖先链中出现脚本解释器",
			Description: "不直接看父进程，而是看整条祖先链：只要链条里出现过脚本解释器再拉起的新进程就命中——抓『层层中转』的执行链，覆盖面比单看父进程广。",
			Severity: model.SeverityMedium, Score: 26, MITRE: []string{"T1059"},
			Definition: Definition{
				All: []Condition{
					c("ancestor.names", "any_in_list", []any{"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}),
				},
			},
		},
		{
			ID: "tpl-signer-allowlist", Name: "按签名主体收紧（示例：未知签名者执行）",
			Description: "把企业信任的签名主体列进 none 条目，除此之外未签名/签名链异常的执行都会命中——『按签名主体建白名单』是运营两年期最稳的降噪方式之一。",
			Severity: model.SeverityMedium, Score: 24, MITRE: []string{"T1553.002"},
			Definition: Definition{
				All: []Condition{c("process.signature_ok", "bool_eq", false)},
				None: []Condition{
					c("process.in_system", "bool_eq", true),
					c("process.signer", "contains", "Microsoft"),
				},
			},
		},
	}
}
