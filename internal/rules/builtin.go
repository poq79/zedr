package rules

import (
	"encoding/json"

	"zedr/internal/ioc"
	"zedr/internal/model"
)

// Builtin 是一条内置规则（随程序发布，可在服务端启用/禁用但不可删除）。
type Builtin struct {
	ID          string
	Name        string
	Description string
	Severity    model.Severity
	Score       int
	MITRE       []string
	Definition  Definition
}

// JSON 返回规则条件体的 JSON 字符串。
func (b Builtin) JSON() string {
	raw, err := json.Marshal(b.Definition)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func c(field, op string, value any) Condition { return Condition{Field: field, Op: op, Value: value} }

// 常用进程集合
var (
	officeParents = []any{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "visio.exe", "onenote.exe", "msaccess.exe"}
	shellChildren = []any{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe"}
	systemNames   = []any{"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe", "explorer.exe", "dllhost.exe"}
	// 工具名以 base64 存放，避免产物被本地文件扫描误判为恶意样本（见 internal/ioc）
	credTools = ioc.SA("bWltaWthdHouZXhl", "bWltaWRvZ3ouZXhl", "bGF6YWduZS5leGU=", "cHdkdW1wLmV4ZQ==", "cHdkdW1wNy5leGU=", "Z3NlY2R1bXAuZXhl", "bmFub2R1bXAuZXhl", "c2FmZXR5a2F0ei5leGU=", "c2hhcnBkdW1wLmV4ZQ==", "d2NlLmV4ZQ==", "Y2Fpbi5leGU=")
	scanTools = ioc.SA("bm1hcC5leGU=", "bmNhdC5leGU=", "bmMuZXhl", "bmV0c2Nhbi5leGU=", "YWR2YW5jZWRfaXBfc2Nhbm5lci5leGU=", "ZnNjYW4uZXhl", "bWFzc2Nhbi5leGU=", "YW5ncnlpcC5leGU=")
	lateralTools = ioc.SA("cHNleGVjLmV4ZQ==", "cHNleGVzdmMuZXhl", "cGFleGVjLmV4ZQ==", "cGxpbmsuZXhl", "d21pZXhlYy5leGU=", "c21iZXhlYy5leGU=", "Y3JhY2ttYXBleGVjLmV4ZQ==")
	writableDirs  = []any{"\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\", "\\windows\\tasks\\", "\\perflogs\\"}
)

// Builtins 返回内置规则集（对齐 MITRE ATT&CK 常见技术）。
func Builtins() []Builtin {
	return []Builtin{
		{
			ID: "HG-001", Name: "Office 文档拉起命令解释器",
			Description: "Word/Excel/Outlook 等文档程序直接拉起 cmd、powershell 或脚本宿主，是钓鱼附件最典型的执行链（T1204.002 用户执行→恶意文件 / T1566 钓鱼）。",
			Severity: model.SeverityCritical, Score: 45, MITRE: []string{"T1204.002", "T1566"},
			Definition: Definition{
				All: []Condition{c("parent.name", "in", officeParents)},
				Any: []Condition{c("process.name", "in", shellChildren)},
			},
		},
		{
			ID: "HG-002", Name: "PowerShell 使用编码/隐藏参数",
			Description: "使用 -EncodedCommand 或隐藏窗口执行 PowerShell，是绕过命令行审计的常见手法（T1059.001 / T1027 混淆）。",
			Severity: model.SeverityHigh, Score: 32, MITRE: []string{"T1059.001", "T1027"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("cG93ZXJzaGVsbC5leGU=", "cHdzaC5leGU="))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("LWVuY29kZWRjb21tYW5k")),
					c("process.cmdline", "icontains", ioc.S("LWVuYyA=")),
					c("process.cmdline", "icontains", ioc.S("LXdpbmRvd3N0eWxlIGhpZGRlbg==")),
					c("process.cmdline", "icontains", ioc.S("LXcgaGlkZGVu")),
					c("process.cmdline", "icontains", ioc.S("LW5vbmludGVyYWN0aXZl")),
				},
			},
		},
		{
			ID: "HG-003", Name: "PowerShell 内存下载执行",
			Description: "命令行包含 DownloadString / IEX / WebClient 等无文件落地下载执行原语（T1059.001 / T1105 入口工具传输）。",
			Severity: model.SeverityCritical, Score: 42, MITRE: []string{"T1059.001", "T1105"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("cG93ZXJzaGVsbC5leGU=", "cHdzaC5leGU="))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("ZG93bmxvYWRzdHJpbmc=")),
					c("process.cmdline", "icontains", ioc.S("ZG93bmxvYWRmaWxl")),
					c("process.cmdline", "icontains", ioc.S("aW52b2tlLWV4cHJlc3Npb24=")),
					c("process.cmdline", "icontains", ioc.S("aWV4KA==")),
					c("process.cmdline", "icontains", ioc.S("aWV4IA==")),
					c("process.cmdline", "icontains", ioc.S("ZnJvbWJhc2U2NHN0cmluZw==")),
					c("process.cmdline", "icontains", ioc.S("bmV0LndlYmNsaWVudA==")),
					c("process.cmdline", "icontains", ioc.S("aW52b2tlLXdlYnJlcXVlc3Q=")),
				},
			},
		},
		{
			ID: "HG-004", Name: "certutil 用于下载或解码",
			Description: "certutil 本是证书工具，被大量用于 -urlcache/-decode 下载与解码载荷（T1140 去混淆 / T1105）。",
			Severity: model.SeverityHigh, Score: 34, MITRE: []string{"T1140", "T1105"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("Y2VydHV0aWwuZXhl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("LXVybGNhY2hl")),
					c("process.cmdline", "icontains", ioc.S("LXZlcmlmeWN0bA==")),
					c("process.cmdline", "icontains", ioc.S("LWRlY29kZQ==")),
					c("process.cmdline", "icontains", ioc.S("aHR0cA==")),
				},
			},
		},
		{
			ID: "HG-005", Name: "bitsadmin 后台传输",
			Description: "滥用 BITS 服务下载文件，可绕过代理与部分网络监控（T1197 BITS 作业）。",
			Severity: model.SeverityHigh, Score: 30, MITRE: []string{"T1197"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("Yml0c2FkbWluLmV4ZQ=="))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("L3RyYW5zZmVy")),
					c("process.cmdline", "icontains", ioc.S("YWRkZmlsZQ==")),
				},
			},
		},
		{
			ID: "HG-006", Name: "mshta 执行远程 HTA/脚本",
			Description: "mshta 加载 http(s) 或 javascript:/vbscript: 协议内容，是无文件攻击常用载体（T1218.005）。",
			Severity: model.SeverityHigh, Score: 36, MITRE: []string{"T1218.005"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("bXNodGEuZXhl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("aHR0cA==")),
					c("process.cmdline", "icontains", ioc.S("amF2YXNjcmlwdDo=")),
					c("process.cmdline", "icontains", ioc.S("dmJzY3JpcHQ6")),
				},
			},
		},
		{
			ID: "HG-007", Name: "rundll32 从用户可写目录加载 DLL",
			Description: "rundll32 从 Temp/AppData/Downloads 等可写目录加载模块，是 DLL 侧加载与代理执行的典型形态（T1218.011）。",
			Severity: model.SeverityHigh, Score: 34, MITRE: []string{"T1218.011"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("cnVuZGxsMzIuZXhl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", "\\temp\\"),
					c("process.cmdline", "icontains", "\\appdata\\"),
					c("process.cmdline", "icontains", "\\downloads\\"),
					c("process.cmdline", "icontains", "\\users\\public\\"),
					c("process.cmdline", "icontains", "\\programdata\\"),
				},
			},
		},
		{
			ID: "HG-008", Name: "regsvr32 远程脚本 (Squiblydoo)",
			Description: "regsvr32 加载 scrobj.dll 并执行远程脚本，可完全绕过应用白名单（T1218.010）。",
			Severity: model.SeverityCritical, Score: 40, MITRE: []string{"T1218.010"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("cmVnc3ZyMzIuZXhl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("c2Nyb2JqLmRsbA==")),
					c("process.cmdline", "icontains", ioc.S("L2k6aHR0cA==")),
				},
			},
		},
		{
			ID: "HG-009", Name: "删除卷影副本（勒索前置）",
			Description: "删除 VSS 卷影副本使受害者无法恢复，是勒索软件加密前的标配动作（T1490 抑制系统恢复）。",
			Severity: model.SeverityCritical, Score: 50, MITRE: []string{"T1490"},
			Definition: Definition{
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("ZGVsZXRlIHNoYWRvd3M=")),
					c("process.cmdline", "icontains", ioc.S("c2hhZG93Y29weSBkZWxldGU=")),
					c("process.cmdline", "icontains", ioc.S("cmVzaXplIHNoYWRvd3N0b3JhZ2U=")),
					c("process.cmdline", "icontains", ioc.S("ZGVsZXRlIGNhdGFsb2c=")),
				},
			},
		},
		{
			ID: "HG-010", Name: "篡改启动恢复配置",
			Description: "bcdedit 关闭恢复模式或引导策略，配合勒索使用（T1490）。",
			Severity: model.SeverityHigh, Score: 35, MITRE: []string{"T1490"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("YmNkZWRpdC5leGU="))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("cmVjb3ZlcnllbmFibGVkIG5v")),
					c("process.cmdline", "icontains", ioc.S("Ym9vdHN0YXR1c3BvbGljeQ==")),
					c("process.cmdline", "icontains", ioc.S("aWdub3JlYWxsZmFpbHVyZXM=")),
				},
			},
		},
		{
			ID: "HG-011", Name: "关闭 Defender 实时防护",
			Description: "通过 Set-MpPreference / Add-MpPreference 排除或关闭实时监控，是防御规避的第一步（T1562.001）。",
			Severity: model.SeverityCritical, Score: 45, MITRE: []string{"T1562.001"},
			Definition: Definition{
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("c2V0LW1wcHJlZmVyZW5jZQ==")),
					c("process.cmdline", "icontains", ioc.S("ZGlzYWJsZXJlYWx0aW1lbW9uaXRvcmluZw==")),
					c("process.cmdline", "icontains", ioc.S("ZGlzYWJsZXJlYWx0aW1lbW9uaXRvcmluZw==")),
					c("process.cmdline", "icontains", ioc.S("YWRkLW1wcHJlZmVyZW5jZQ==")),
					c("process.cmdline", "icontains", ioc.S("LWV4Y2x1c2lvbnBhdGg=")),
				},
			},
		},
		{
			ID: "HG-012", Name: "关闭系统防火墙",
			Description: "netsh 关闭防火墙，为横向移动与回连放通端口（T1562.004）。",
			Severity: model.SeverityHigh, Score: 30, MITRE: []string{"T1562.004"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("bmV0c2guZXhl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("YWR2ZmlyZXdhbGwgc2V0")),
					c("process.cmdline", "icontains", ioc.S("ZmlyZXdhbGwgc2V0IG9wbW9kZSBkaXNhYmxl")),
					c("process.cmdline", "icontains", ioc.S("c3RhdGUgb2Zm")),
				},
			},
		},
		{
			ID: "HG-013", Name: "创建计划任务实现持久化",
			Description: "schtasks 创建任务，是持久化最常用的手段之一（T1053.005）。",
			Severity: model.SeverityMedium, Score: 22, MITRE: []string{"T1053.005"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("c2NodGFza3MuZXhl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("L2NyZWF0ZQ==")),
					c("process.cmdline", "icontains", ioc.S("LWNyZWF0ZQ==")),
				},
			},
		},
		{
			ID: "HG-014", Name: "创建服务并指向可写目录",
			Description: "sc create 的 binPath 指向 Temp/AppData 等用户可写目录，是服务型持久化的高危形态（T1543.003）。",
			Severity: model.SeverityCritical, Score: 40, MITRE: []string{"T1543.003"},
			Definition: Definition{
				All: []Condition{
					c("process.cmdline", "icontains", ioc.S("YmlucGF0aA==")),
					c("process.cmdline", "icontains", ioc.S("Y3JlYXRl")),
				},
				Any: []Condition{
					c("process.cmdline", "icontains", "\\temp\\"),
					c("process.cmdline", "icontains", "\\appdata\\"),
					c("process.cmdline", "icontains", "\\users\\public\\"),
					c("process.cmdline", "icontains", "\\programdata\\"),
				},
			},
		},
		{
			ID: "HG-015", Name: "本地账号创建或加入管理员组",
			Description: "net user /add 或 net localgroup administrators 添加成员，是权限维持的前置动作（T1136.001 / T1098）。",
			Severity: model.SeverityHigh, Score: 35, MITRE: []string{"T1136.001", "T1098"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("bmV0LmV4ZQ==", "bmV0MS5leGU="))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("dXNlcg==")),
					c("process.cmdline", "icontains", ioc.S("bG9jYWxncm91cA==")),
				},
				None: []Condition{c("process.cmdline", "icontains", ioc.S("dmlldw=="))},
			},
		},
		{
			ID: "HG-016", Name: "系统进程在非系统目录运行（伪装）",
			Description: "svchost/lsass/services 等核心进程只应从 System32/SysWOW64 运行，出现在其它路径基本可判定为伪装（T1036.005）。",
			Severity: model.SeverityCritical, Score: 55, MITRE: []string{"T1036.005"},
			Definition: Definition{
				All: []Condition{
					c("process.name", "in", systemNames),
					c("process.in_system", "eq", false),
				},
			},
		},
		{
			ID: "HG-017", Name: "凭据窃取工具",
			Description: "命中已知凭据抓取工具的进程名。改名即可绕过，因此必须叠加血缘与哈希判定才能兜住变种（T1003）。",
			Severity: model.SeverityCritical, Score: 50, MITRE: []string{"T1003"},
			Definition: Definition{
				Any: []Condition{c("process.name", "in", credTools)},
			},
		},
		{
			ID: "HG-018", Name: "内存转储工具读取 lsass",
			Description: "对 lsass 进程做全内存转储，等价于明文凭据窃取（T1003.001）。",
			Severity: model.SeverityCritical, Score: 50, MITRE: []string{"T1003.001"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("cHJvY2R1bXAuZXhl", "cHJvY2R1bXA2NC5leGU="))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("bHNhc3M=")),
					c("process.cmdline", "icontains", ioc.S("LW1h")),
				},
			},
		},
		{
			ID: "HG-019", Name: "内网扫描/资产探测工具",
			Description: "已知网络扫描器在办公终端上出现，通常是横向移动的侦察阶段（T1046）。",
			Severity: model.SeverityHigh, Score: 30, MITRE: []string{"T1046"},
			Definition: Definition{
				Any: []Condition{c("process.name", "in", scanTools)},
			},
		},
		{
			ID: "HG-020", Name: "远程执行与横向移动工具",
			Description: "已知远程执行组件在本机运行，常被用于远程落地与横向移动（T1021 / T1570）。",
			Severity: model.SeverityHigh, Score: 38, MITRE: []string{"T1021", "T1570"},
			Definition: Definition{
				Any: []Condition{c("process.name", "in", lateralTools)},
			},
		},
		{
			ID: "HG-021", Name: "未签名程序以管理员权限从可写目录运行",
			Description: "无签名 + 用户可写目录 + 高完整性，三者叠加是落地型恶意样本的典型组合（T1036 / T1548）。",
			Severity: model.SeverityHigh, Score: 32, MITRE: []string{"T1036", "T1548"},
			Definition: Definition{
				All: []Condition{
					c("process.signed", "eq", false),
					c("process.dir_writable", "eq", true),
					c("process.elevated", "eq", true),
				},
				None: []Condition{c("process.in_system", "eq", true)},
			},
		},
		{
			ID: "HG-022", Name: "挖矿特征命令行",
			Description: "命令行包含矿池协议或矿工参数（T1496 资源劫持）。",
			Severity: model.SeverityCritical, Score: 48, MITRE: []string{"T1496"},
			Definition: Definition{
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("c3RyYXR1bSt0Y3A=")),
					c("process.cmdline", "icontains", ioc.S("c3RyYXR1bStzc2w=")),
					c("process.cmdline", "icontains", ioc.S("eG1yaWc=")),
					c("process.cmdline", "icontains", ioc.S("LS1kb25hdGUtbGV2ZWw=")),
					c("process.cmdline", "icontains", ioc.S("bWluZXJnYXRl")),
					c("process.cmdline", "icontains", ioc.S("bmljZWhhc2g=")),
				},
			},
		},
		{
			ID: "HG-023", Name: "注册表 Run 键持久化",
			Description: "reg add 写入 CurrentVersion\\Run，是用户态持久化的经典路径（T1547.001）。",
			Severity: model.SeverityMedium, Score: 24, MITRE: []string{"T1547.001"},
			Definition: Definition{
				// 不绑定 process.name：攻击者常用命令解释器代理执行 reg add，
				// 只认 reg.exe 会被整条绕过。改为按命令行特征判定。
				All: []Condition{
					c("process.cmdline", "icontains", ioc.S("cmVnIGFkZA==")),
				},
				Any: []Condition{
					c("process.cmdline", "icontains", "\\currentversion\\run"),
					c("process.cmdline", "icontains", "\\currentversion\\runonce"),
				},
			},
		},
		{
			ID: "HG-024", Name: "向启动目录投放可执行文件",
			Description: "命令行中出现 Startup 启动目录写入或复制，是低技术门槛的持久化方式（T1547.001）。",
			Severity: model.SeverityMedium, Score: 22, MITRE: []string{"T1547.001"},
			Definition: Definition{
				Any: []Condition{
					c("process.cmdline", "icontains", "\\start menu\\programs\\startup"),
					c("process.cmdline", "icontains", "\\startup\\"),
				},
			},
		},
		{
			ID: "HG-025", Name: "双扩展名伪装可执行文件",
			Description: "形如 invoice.pdf.exe 的进程名，利用系统隐藏扩展名欺骗用户（T1036.007）。",
			Severity: model.SeverityHigh, Score: 32, MITRE: []string{"T1036.007"},
			Definition: Definition{
				All: []Condition{
					c("process.name", "regex", `(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rar|mp4)\s*\.(exe|scr|com|bat|cmd|js|vbs|hta|pif)$`),
				},
			},
		},
		{
			ID: "HG-026", Name: "从回收站等异常位置执行",
			Description: "从 $Recycle.Bin 或深层伪装目录执行程序，属于典型的落地规避手法（T1036）。",
			Severity: model.SeverityMedium, Score: 20, MITRE: []string{"T1036"},
			Definition: Definition{
				Any: []Condition{
					c("process.path", "icontains", ioc.S("JHJlY3ljbGUuYmlu")),
					c("process.path", "icontains", "\\perflogs\\"),
				},
			},
		},
		{
			ID: "HG-027", Name: "可信进程加载未签名模块（注入线索）",
			Description: "自身有有效签名的进程却加载了未签名模块，是 DLL 注入与侧加载的强信号（T1055 / T1574.002）。",
			Severity: model.SeverityHigh, Score: 35, MITRE: []string{"T1055", "T1574.002"},
			Definition: Definition{
				All: []Condition{
					c("process.signature_ok", "eq", true),
					c("module.unsigned_count", "gt", 0),
				},
			},
		},
		{
			ID: "HG-028", Name: "浏览器拉起重命令解释器",
			Description: "浏览器直接派生出 cmd/powershell，通常是 drive-by 下载后的执行阶段（T1204.002）。",
			Severity: model.SeverityHigh, Score: 30, MITRE: []string{"T1204.002"},
			Definition: Definition{
				All: []Condition{c("parent.name", "in", ioc.SA("Y2hyb21lLmV4ZQ==", "bXNlZGdlLmV4ZQ==", "ZmlyZWZveC5leGU=", "aWV4cGxvcmUuZXhl", "YnJhdmUuZXhl"))},
				Any: []Condition{c("process.name", "in", ioc.SA("Y21kLmV4ZQ==", "cG93ZXJzaGVsbC5leGU=", "cHdzaC5leGU=", "bXNodGEuZXhl", "d3NjcmlwdC5leGU="))},
			},
		},
		{
			ID: "HG-029", Name: "wmic 远程创建进程",
			Description: "wmic 以 /node: 远程创建进程，是横向移动的常见手段（T1047）。",
			Severity: model.SeverityHigh, Score: 34, MITRE: []string{"T1047"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("d21pYy5leGU=", "d21pcHJ2c2UuZXhl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("L25vZGU6")),
					c("process.cmdline", "icontains", ioc.S("cHJvY2VzcyBjYWxsIGNyZWF0ZQ==")),
				},
			},
		},
		{
			ID: "HG-030", Name: "从网络共享路径执行",
			Description: "镜像位于 UNC 网络共享路径，常与横向移动的落地即执行配合（T1021.002）。",
			Severity: model.SeverityHigh, Score: 33, MITRE: []string{"T1021.002"},
			Definition: Definition{
				All: []Condition{c("process.path", "prefix", `\\`)},
			},
		},
		{
			ID: "HG-031", Name: "无签名程序从临时目录执行",
			Description: "Temp/AppData 下的无签名可执行文件，单看不足以定罪，但作为基线偏差信号参与评分（T1036）。",
			Severity: model.SeverityLow, Score: 12, MITRE: []string{"T1036"},
			Definition: Definition{
				All: []Condition{
					c("process.dir_writable", "eq", true),
					c("process.signed", "eq", false),
					c("process.in_system", "eq", false),
				},
			},
		},
		{
			ID: "HG-032", Name: "脚本宿主脚本来自可写目录",
			Description: "wscript/cscript 执行的脚本位于用户可写目录，多为钓鱼附件释放的 VBS/JS（T1059.005 / T1059.007）。",
			Severity: model.SeverityMedium, Score: 26, MITRE: []string{"T1059.005", "T1059.007"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("d3NjcmlwdC5leGU=", "Y3NjcmlwdC5leGU="))},
				Any: []Condition{c("process.cmdline", "icontains", "\\temp\\"), c("process.cmdline", "icontains", "\\appdata\\"), c("process.cmdline", "icontains", "\\downloads\\")},
			},
		},
		{
			ID: "HG-033", Name: "PowerShell 隐藏窗口并外联",
			Description: "隐藏窗口运行并同时存在公网连接，是 C2 回连的高置信组合（T1059.001 / T1071）。",
			Severity: model.SeverityCritical, Score: 44, MITRE: []string{"T1059.001", "T1071"},
			Definition: Definition{
				All: []Condition{
					c("process.name", "in", ioc.SA("cG93ZXJzaGVsbC5leGU=", "cHdzaC5leGU=")),
					c("network.has_public_remote", "eq", true),
				},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("aGlkZGVu")),
					c("process.cmdline", "icontains", ioc.S("LW5vcA==")),
					c("process.cmdline", "icontains", ioc.S("YnlwYXNz")),
				},
			},
		},
		{
			ID: "HG-034", Name: "关闭审计或清空日志",
			Description: "wevtutil 清空日志、auditpol 关闭审计，是反取证动作（T1070.001）。",
			Severity: model.SeverityCritical, Score: 42, MITRE: []string{"T1070.001"},
			Definition: Definition{
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("d2V2dHV0aWwgY2w=")),
					c("process.cmdline", "icontains", ioc.S("Y2xlYXItbG9n")),
					c("process.cmdline", "icontains", ioc.S("YXVkaXRwb2w=")),
				},
			},
		},
		{
			ID: "HG-035", Name: "卸载或篡改安全软件服务",
			Description: "通过 sc delete / taskkill 针对安全产品服务，属于防御规避（T1562.001）。",
			Severity: model.SeverityCritical, Score: 40, MITRE: []string{"T1562.001"},
			Definition: Definition{
				All: []Condition{c("process.cmdline", "icontains", ioc.S("ZGVsZXRl"))},
				Any: []Condition{
					c("process.cmdline", "icontains", ioc.S("d2luZGVmZW5k")),
					c("process.cmdline", "icontains", ioc.S("bXBzc3Zj")),
					c("process.cmdline", "icontains", ioc.S("c2Vuc2U=")),
					c("process.cmdline", "icontains", ioc.S("d2RuaXNzdmM=")),
				},
			},
		},
		{
			ID: "HG-036", Name: "隐藏用户或影子账号",
			Description: "通过注册表在登录界面隐藏账号，属于持久化与隐匿（T1564.002）。",
			Severity: model.SeverityHigh, Score: 32, MITRE: []string{"T1564.002"},
			Definition: Definition{
				Any: []Condition{
					c("process.cmdline", "icontains", "\\winlogon\\specialaccounts"),
					c("process.cmdline", "icontains", ioc.S("dXNlcmxpc3Q=")),
				},
			},
		},
	}
}
