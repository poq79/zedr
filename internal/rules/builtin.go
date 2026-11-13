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
	credTools    = ioc.SA("bWltaWthdHouZXhl", "bWltaWRvZ3ouZXhl", "bGF6YWduZS5leGU=", "cHdkdW1wLmV4ZQ==", "cHdkdW1wNy5leGU=", "Z3NlY2R1bXAuZXhl", "bmFub2R1bXAuZXhl", "c2FmZXR5a2F0ei5leGU=", "c2hhcnBkdW1wLmV4ZQ==", "d2NlLmV4ZQ==", "Y2Fpbi5leGU=")
	scanTools    = ioc.SA("bm1hcC5leGU=", "bmNhdC5leGU=", "bmMuZXhl", "bmV0c2Nhbi5leGU=", "YWR2YW5jZWRfaXBfc2Nhbm5lci5leGU=", "ZnNjYW4uZXhl", "bWFzc2Nhbi5leGU=", "YW5ncnlpcC5leGU=")
	lateralTools = ioc.SA("cHNleGVjLmV4ZQ==", "cHNleGVzdmMuZXhl", "cGFleGVjLmV4ZQ==", "cGxpbmsuZXhl", "d21pZXhlYy5leGU=", "c21iZXhlYy5leGU=", "Y3JhY2ttYXBleGVjLmV4ZQ==")
	writableDirs = []any{"\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\", "\\windows\\tasks\\", "\\perflogs\\"}
)

// Builtins 返回内置规则集（对齐 MITRE ATT&CK 常见技术）。
func Builtins() []Builtin {
	return []Builtin{
		{
			ID: "HG-001", Name: "Office 文档拉起命令解释器",
			Description: "Word/Excel/Outlook 等文档程序直接拉起 cmd、powershell 或脚本宿主，是钓鱼附件最典型的执行链（T1204.002 用户执行→恶意文件 / T1566 钓鱼）。",
			Severity:    model.SeverityCritical, Score: 45, MITRE: []string{"T1204.002", "T1566"},
			Definition: Definition{
				All: []Condition{c("parent.name", "in", officeParents)},
				Any: []Condition{c("process.name", "in", shellChildren)},
			},
		},
		{
			ID: "HG-002", Name: "PowerShell 使用编码/隐藏参数",
			Description: "使用 -EncodedCommand 或隐藏窗口执行 PowerShell，是绕过命令行审计的常见手法（T1059.001 / T1027 混淆）。",
			Severity:    model.SeverityHigh, Score: 32, MITRE: []string{"T1059.001", "T1027"},
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
			Severity:    model.SeverityCritical, Score: 42, MITRE: []string{"T1059.001", "T1105"},
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
			Severity:    model.SeverityHigh, Score: 34, MITRE: []string{"T1140", "T1105"},
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
			Severity:    model.SeverityHigh, Score: 30, MITRE: []string{"T1197"},
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
			Severity:    model.SeverityHigh, Score: 36, MITRE: []string{"T1218.005"},
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
			Severity:    model.SeverityHigh, Score: 34, MITRE: []string{"T1218.011"},
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
			Severity:    model.SeverityCritical, Score: 40, MITRE: []string{"T1218.010"},
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
			Severity:    model.SeverityCritical, Score: 50, MITRE: []string{"T1490"},
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
			Severity:    model.SeverityHigh, Score: 35, MITRE: []string{"T1490"},
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
			Severity:    model.SeverityCritical, Score: 45, MITRE: []string{"T1562.001"},
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
			Severity:    model.SeverityHigh, Score: 30, MITRE: []string{"T1562.004"},
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
			Severity:    model.SeverityMedium, Score: 22, MITRE: []string{"T1053.005"},
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
			Severity:    model.SeverityCritical, Score: 40, MITRE: []string{"T1543.003"},
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
			Severity:    model.SeverityHigh, Score: 35, MITRE: []string{"T1136.001", "T1098"},
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
			Severity:    model.SeverityCritical, Score: 55, MITRE: []string{"T1036.005"},
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
			Severity:    model.SeverityCritical, Score: 50, MITRE: []string{"T1003"},
			Definition: Definition{
				Any: []Condition{c("process.name", "in", credTools)},
			},
		},
		{
			ID: "HG-018", Name: "内存转储工具读取 lsass",
			Description: "对 lsass 进程做全内存转储，等价于明文凭据窃取（T1003.001）。",
			Severity:    model.SeverityCritical, Score: 50, MITRE: []string{"T1003.001"},
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
			Severity:    model.SeverityHigh, Score: 30, MITRE: []string{"T1046"},
			Definition: Definition{
				Any: []Condition{c("process.name", "in", scanTools)},
			},
		},
		{
			ID: "HG-020", Name: "远程执行与横向移动工具",
			Description: "已知远程执行组件在本机运行，常被用于远程落地与横向移动（T1021 / T1570）。",
			Severity:    model.SeverityHigh, Score: 38, MITRE: []string{"T1021", "T1570"},
			Definition: Definition{
				Any: []Condition{c("process.name", "in", lateralTools)},
			},
		},
		{
			ID: "HG-021", Name: "未签名程序以管理员权限从可写目录运行",
			Description: "无签名 + 用户可写目录 + 高完整性，三者叠加是落地型恶意样本的典型组合（T1036 / T1548）。",
			Severity:    model.SeverityHigh, Score: 32, MITRE: []string{"T1036", "T1548"},
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
			Severity:    model.SeverityCritical, Score: 48, MITRE: []string{"T1496"},
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
			Severity:    model.SeverityMedium, Score: 24, MITRE: []string{"T1547.001"},
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
			Severity:    model.SeverityMedium, Score: 22, MITRE: []string{"T1547.001"},
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
			Severity:    model.SeverityHigh, Score: 32, MITRE: []string{"T1036.007"},
			Definition: Definition{
				All: []Condition{
					c("process.name", "regex", `(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rar|mp4)\s*\.(exe|scr|com|bat|cmd|js|vbs|hta|pif)$`),
				},
			},
		},
		{
			ID: "HG-026", Name: "从回收站等异常位置执行",
			Description: "从 $Recycle.Bin 或深层伪装目录执行程序，属于典型的落地规避手法（T1036）。",
			Severity:    model.SeverityMedium, Score: 20, MITRE: []string{"T1036"},
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
			Severity:    model.SeverityHigh, Score: 35, MITRE: []string{"T1055", "T1574.002"},
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
			Severity:    model.SeverityHigh, Score: 30, MITRE: []string{"T1204.002"},
			Definition: Definition{
				All: []Condition{c("parent.name", "in", ioc.SA("Y2hyb21lLmV4ZQ==", "bXNlZGdlLmV4ZQ==", "ZmlyZWZveC5leGU=", "aWV4cGxvcmUuZXhl", "YnJhdmUuZXhl"))},
				Any: []Condition{c("process.name", "in", ioc.SA("Y21kLmV4ZQ==", "cG93ZXJzaGVsbC5leGU=", "cHdzaC5leGU=", "bXNodGEuZXhl", "d3NjcmlwdC5leGU="))},
			},
		},
		{
			ID: "HG-029", Name: "wmic 远程创建进程",
			Description: "wmic 以 /node: 远程创建进程，是横向移动的常见手段（T1047）。",
			Severity:    model.SeverityHigh, Score: 34, MITRE: []string{"T1047"},
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
			Severity:    model.SeverityHigh, Score: 33, MITRE: []string{"T1021.002"},
			Definition: Definition{
				All: []Condition{c("process.path", "prefix", `\\`)},
			},
		},
		{
			ID: "HG-031", Name: "无签名程序从临时目录执行",
			Description: "Temp/AppData 下的无签名可执行文件，单看不足以定罪，但作为基线偏差信号参与评分（T1036）。",
			Severity:    model.SeverityLow, Score: 12, MITRE: []string{"T1036"},
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
			Severity:    model.SeverityMedium, Score: 26, MITRE: []string{"T1059.005", "T1059.007"},
			Definition: Definition{
				All: []Condition{c("process.name", "in", ioc.SA("d3NjcmlwdC5leGU=", "Y3NjcmlwdC5leGU="))},
				Any: []Condition{c("process.cmdline", "icontains", "\\temp\\"), c("process.cmdline", "icontains", "\\appdata\\"), c("process.cmdline", "icontains", "\\downloads\\")},
			},
		},
		{
			ID: "HG-033", Name: "PowerShell 隐藏窗口并外联",
			Description: "隐藏窗口运行并同时存在公网连接，是 C2 回连的高置信组合（T1059.001 / T1071）。",
			Severity:    model.SeverityCritical, Score: 44, MITRE: []string{"T1059.001", "T1071"},
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
			Severity:    model.SeverityCritical, Score: 42, MITRE: []string{"T1070.001"},
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
			Severity:    model.SeverityCritical, Score: 40, MITRE: []string{"T1562.001"},
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
			Severity:    model.SeverityHigh, Score: 32, MITRE: []string{"T1564.002"},
			Definition: Definition{
				Any: []Condition{
					c("process.cmdline", "icontains", "\\winlogon\\specialaccounts"),
					c("process.cmdline", "icontains", ioc.S("dXNlcmxpc3Q=")),
				},
			},
		},

		// ------------------------------------------------ Linux 行为规则
		// 与 Windows 规则共用同一 DSL 与求值器；只消费 Linux 侧真实会产出
		// 的字段（process.name=comm / cmdline / path / parent.name / user /
		// elevated / dir_writable），不用签名、注册表等 Windows 专属字段。
		// 进程名集合用 Linux comm 口径（无 .exe 后缀），Windows 舰队里同名
		// 的 .exe 进程天然不会误配。
		{
			// 选题：下载器管道直提 shell 是 Linux 入侵载荷的第一投放形态
			//（systemd/cron/漏洞利用都会以 sh -c 形态在 cmdline 里留下
			// 完整管道串）。条件收紧的原因：单看下载或单看管道都太宽
			//（合法安装脚本与运维天天在用），必须"shell 进程 + 下载工具
			// 词 + 管道直提 shell 词"三者同时成立才报。即便如此官方安装
			// 脚本仍会命中，定级 High 并在描述里写明需人工复核，
			// 不做 Critical——误报成本（值班信任度）高于漏报成本。
			ID: "HG-037", Name: "命令解释器管道下载执行",
			Description: "命令行同时出现下载工具与管道直提 shell——下载内容不经落盘直接交给 shell 解释，是 Linux 入侵载荷最常见的投放形态（T1059.004 / T1105）；官方安装脚本也会命中，请人工复核来源。",
			Severity:    model.SeverityHigh, Score: 34, MITRE: []string{"T1059.004", "T1105"},
			Definition: Definition{
				All: []Condition{
					// 只认 shell 进程：完整管道串只会出现在解释它的 shell 的
					// cmdline 里（下载器自身只看得到 URL）。交互式终端里手敲
					// 的管道不在任何 cmdline 上，是设计内盲区（链引擎兜底）。
					c("process.name", "in", ioc.SA("c2g=", "YmFzaA==", "ZGFzaA==", "enNo", "a3No", "YXNo")),
					// 下载工具词边界锚定，避免 URL 路径里恰好含工具名误配；
					// (?i) 兼容大小写变体。
					c("process.cmdline", "regex", ioc.S("KD9pKShefFsgXSkoY3VybHx3Z2V0KShbIF18JCk=")),
					// 管道直提：| 与 shell 之间允许空格与可选的绝对路径前缀；
					// 尾随 [^a-z] 边界防管道进 ssh 这类非 shell 词误配。
					c("process.cmdline", "regex", ioc.S("W3xdWyBdKigvYmluLyk/KHNofGJhc2h8enNofGRhc2h8a3NofGFzaCkoW15hLXpdfCQp")),
				},
			},
		},
		{
			// 选题：编码载荷经解码直提 shell 是绕过命令行审计的标准变体
			//（本体命令行只见编码串）。收紧：解码参数与管道直提 shell
			// 必须同时出现——解码落盘是安装器常见操作（解码资源文件），
			// 单独解码不报，防误报。
			ID: "HG-038", Name: "base64 解码管道执行",
			Description: "命令行同时出现 base64 解码参数与管道直提 shell——编码载荷在内存中解码并立即执行，是绕过命令行审计的常见变体（T1140 / T1059.004）。",
			Severity:    model.SeverityHigh, Score: 34, MITRE: []string{"T1140", "T1059.004"},
			Definition: Definition{
				All: []Condition{
					// 解码到 stdout 的两种主流写法；[ ]+ 容忍多空格。
					c("process.cmdline", "regex", ioc.S("KD9pKWJhc2U2NFsgXSsoLWR8LS1kZWNvZGUp")),
					c("process.cmdline", "regex", ioc.S("W3xdWyBdKigvYmluLyk/KHNofGJhc2h8enNofGRhc2h8a3NofGFzaCkoW15hLXpdfCQp")),
				},
			},
		},
		{
			// 选题：bash 内建网络设备重定向与输出重定向/exec 的组合是反弹
			// shell 的教科书形态（T1059.004）——正常运维几乎不会在命令行
			// 里引用该内建设备，是零配置成本的高信号组合，定级 Critical。
			ID: "HG-039", Name: "Shell 内建反连形态",
			Description: "命令行同时出现 bash 内建网络重定向设备与输出重定向或 exec 组合——这是反弹 shell 的教科书形态，正常运维几乎不会在命令行里引用该设备（T1059.004）。",
			Severity:    model.SeverityCritical, Score: 45, MITRE: []string{"T1059.004"},
			Definition: Definition{
				All: []Condition{
					c("process.cmdline", "icontains", ioc.S("L2Rldi90Y3Av")),
				},
				Any: []Condition{
					// >& 覆盖交互式反连写法；exec 覆盖文件描述符变体；
					// 0<& 覆盖输入重定向变体。三者任一即构成组合信号。
					c("process.cmdline", "icontains", ioc.S("PiY=")),
					c("process.cmdline", "icontains", ioc.S("MDwm")),
					c("process.cmdline", "icontains", ioc.S("ZXhlYyA=")),
				},
			},
		},
		{
			// 选题：动态链接器预加载配置是用户态 rootkit 的首选持久化位
			//（每个动态链接进程启动都会加载，一行即全局注入，T1574.006），
			// 与持久化基线层的预加载枚举互为双保险：基线层 5min 轮询，
			// 规则层在进程扫描（2s）内先报。阈值：正常运行不引用该配置
			// 路径，命令行出现它几乎必然是写入尝试，再叠加写入形态
			//（重定向/tee/echo/cp/mv/touch）任一，定级 Critical。
			ID: "HG-040", Name: "动态链接预加载劫持",
			Description: "向动态链接器预加载配置文件写入条目——每个动态链接进程启动都会加载它，一行即可全局注入，是用户态最高价值的持久化位之一（T1574.006）。",
			Severity:    model.SeverityCritical, Score: 44, MITRE: []string{"T1574.006"},
			Definition: Definition{
				All: []Condition{
					c("process.cmdline", "icontains", ioc.S("bGQuc28ucHJlbG9hZA==")),
				},
				Any: []Condition{
					c("process.cmdline", "contains", ioc.S("Pg==")),
					c("process.cmdline", "icontains", ioc.S("dGVlIA==")),
					c("process.cmdline", "icontains", ioc.S("ZWNobyA=")),
					c("process.cmdline", "icontains", ioc.S("Y3Ag")),
					c("process.cmdline", "icontains", ioc.S("bXYg")),
					c("process.cmdline", "icontains", ioc.S("dG91Y2gg")),
				},
			},
		},
		{
			// 选题：向 SSH 授权密钥文件追加公钥 = 免口令持久化后门
			//（T1098.004），与持久化基线层的授权密钥枚举互为双保险。
			// 阈值：必须叠加写入形态（重定向/echo/tee/cp/mv/install）——
			// 管理员只读查看（cat/less 不带重定向）不报，读与写在命令行
			// 上可区分。手动加 key 的合法运维仍会命中，定级 High 需复核。
			ID: "HG-041", Name: "SSH 授权密钥写入",
			Description: "经 echo/重定向等写入形态操作 SSH 授权密钥文件——追加公钥即获得无须口令的持久化入口（T1098.004）；管理员手动添加密钥也会命中，请结合写入来源人工复核。",
			Severity:    model.SeverityHigh, Score: 32, MITRE: []string{"T1098.004"},
			Definition: Definition{
				All: []Condition{
					c("process.cmdline", "icontains", ioc.S("YXV0aG9yaXplZF9rZXlz")),
				},
				Any: []Condition{
					c("process.cmdline", "contains", ioc.S("Pg==")),
					c("process.cmdline", "icontains", ioc.S("ZWNobyA=")),
					c("process.cmdline", "icontains", ioc.S("dGVlIA==")),
					c("process.cmdline", "icontains", ioc.S("Y3Ag")),
					c("process.cmdline", "icontains", ioc.S("bXYg")),
					c("process.cmdline", "icontains", ioc.S("aW5zdGFsbCA=")),
				},
			},
		},
		{
			// 选题：ssh 反向转发（-R）与动态 SOCKS（-D）是建隧道回传、绕行
			// 出口的行业标准手法（T1572）。阈值保守的原因：本地转发 -L 与
			// 纯登录不报，只认 -R/-D 且锚定进程名 ssh；远程运维调试也会用
			// -R/-D，定级 High 而非 Critical，靠目标地址人工复核补足。
			ID: "HG-042", Name: "SSH 反向/动态隧道",
			Description: "ssh 以反向转发或动态 SOCKS 转发运行，常用于把内网端口回传给外部或建立绕行通道（T1572）；运维远程调试也会使用，请结合目标地址人工复核。",
			Severity:    model.SeverityHigh, Score: 30, MITRE: []string{"T1572"},
			Definition: Definition{
				All: []Condition{
					// 进程名锚定 ssh（Linux comm 无 .exe 后缀，Windows 舰队的
					// 同名二进制不会误配）；组合选项写法（如 -nR/-ND）由
					// [a-z]* 通配覆盖，-p/-i/-L/-N 等其他选项不匹配。
					c("process.name", "in", ioc.SA("c3No")),
					c("process.cmdline", "regex", ioc.S("KD9pKShefFsgXSktW2Etel0qW3JkXQ==")),
				},
			},
		},
		{
			// 选题：对可执行文件置 setuid/setgid 位（T1548.001）配合可写
			// 目录落地的新文件，可完成无凭据提权；真实攻击里几乎总是
			// 语义写法（+s）或数字写法（4755 族）。阈值保守的原因：包管理
			// 器在系统目录的合法置位极多（postinst 大量 chmod），用 None
			// 排除系统目录前缀——宁可漏掉系统目录下的异常置位（基线层与
			// 资产侦查兜底），也不给包管理日常制造误报。"新落地"维度规则
			// DSL 无法表达（只看得到进程字段），落地信号由 DROP-001 补足。
			ID: "HG-043", Name: "setuid 置位可执行文件",
			Description: "chmod 对可执行文件置 setuid/setgid 位，配合可写目录内新落地的文件可完成无凭据提权（T1548.001）；包管理器在系统目录的合法置位已排除，其余命中请人工复核。",
			Severity:    model.SeverityHigh, Score: 30, MITRE: []string{"T1548.001"},
			Definition: Definition{
				All: []Condition{
					c("process.cmdline", "icontains", ioc.S("Y2htb2Q=")),
				},
				Any: []Condition{
					// +s 是 u+s/g+s/o+s 的公共子串；4755/6755/2755/7755 是
					// setuid/setgid 实际会出现的数字位组合（首位非 0）。
					c("process.cmdline", "icontains", ioc.S("K3M=")),
					c("process.cmdline", "icontains", ioc.S("NDc1NQ==")),
					c("process.cmdline", "icontains", ioc.S("Njc1NQ==")),
					c("process.cmdline", "icontains", ioc.S("Mjc1NQ==")),
					c("process.cmdline", "icontains", ioc.S("Nzc1NQ==")),
				},
				None: []Condition{
					// 发行版维护脚本（postinst）的合法置位集中在系统目录
					// 前缀下；/lib 前缀同时覆盖 /lib64 与 /usr/lib 之外的
					// 分裂布局（usrmerge 前的发行版）。
					c("process.cmdline", "icontains", ioc.S("L3Vzci8=")),
					c("process.cmdline", "icontains", ioc.S("L2xpYg==")),
				},
			},
		},
		{
			// 选题：把下载器写进 cron 配置是持久化 + 载荷更新的一体化形态
			//（T1053.003 / T1105），挖矿木马的"一行式"安装命令几乎都是
			// 这个形状。阈值：cron 配置位置与下载工具必须同时出现在同一
			// 命令行——合法软件写 cron 任务不含下载工具，仅下载不涉及
			// cron，两个维度单独看都太宽。定级 High：企业环境里确有
			// "下载配置再写 cron"的合法自动化，需人工复核。
			ID: "HG-044", Name: "计划任务一行式下载持久化",
			Description: "命令行同时出现 cron 配置位置与下载工具——把下载器写进计划任务实现周期性拉取与持久化，是挖矿木马一行式安装的标准形态（T1053.003 / T1105）。",
			Severity:    model.SeverityHigh, Score: 36, MITRE: []string{"T1053.003", "T1105"},
			Definition: Definition{
				All: []Condition{
					// cron 的四类常见配置位置；[.] 字符类表达字面点号，
					// 与正则的点号通配区分开。
					c("process.cmdline", "regex", ioc.S("Y3Jvbih0YWJ8Wy5dZHxbLl1kYWlseXxbLl1ob3VybHkp")),
					c("process.cmdline", "regex", ioc.S("KD9pKShefFsgXSkoY3VybHx3Z2V0KShbIF18JCk=")),
				},
			},
		},
	}
}
