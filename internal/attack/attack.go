// Package attack 维护 MITRE ATT&CK Enterprise 的战术/技术展示目录。
//
// 为什么只收录一个子集而不是全量 ATT&CK：全量有 600+ 技术，大多数与
// Windows 主机检测无关，全量矩阵会让热力图变成一片"无覆盖"的噪声。
// 这里只收录本产品检测链路（内置规则/关键词/静态指纹/落地即执行）
// 实际会产生的技术编号，另加少量常见技术作为扩展位。
// 目录之外的技术编号（例如自定义规则里出现的新编号）不会丢弃——
// 聚合时落入"未分类"战术，保证数据完整性，目录可随规则演进补充。
package attack

import "strings"

// Tactic 是 ATT&CK 战术（矩阵的列）。
type Tactic struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	NameZh string `json:"name_zh"`
}

// Technique 是 ATT&CK 技术（矩阵的格子）。
type Technique struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	NameZh   string `json:"name_zh"`
	TacticID string `json:"tactic_id"`
}

// UncategorizedTacticID 是目录外技术的兜底战术 ID。
// 一个技术可以属于多个战术，这里登记的是主战术（ATT&CK 页面的
// 规范顺序第一位），保证矩阵中每个技术只出现一格。
const UncategorizedTacticID = "uncategorized"

// tactics 按 ATT&CK Enterprise 的规范顺序排列。
var tactics = []Tactic{
	{"TA0043", "Reconnaissance", "侦察"},
	{"TA0042", "Resource Development", "资源开发"},
	{"TA0001", "Initial Access", "初始访问"},
	{"TA0002", "Execution", "执行"},
	{"TA0003", "Persistence", "持久化"},
	{"TA0004", "Privilege Escalation", "权限提升"},
	{"TA0005", "Defense Evasion", "防御规避"},
	{"TA0006", "Credential Access", "凭证访问"},
	{"TA0007", "Discovery", "发现"},
	{"TA0008", "Lateral Movement", "横向移动"},
	{"TA0009", "Collection", "收集"},
	{"TA0011", "Command and Control", "命令与控制"},
	{"TA0010", "Exfiltration", "渗出"},
	{"TA0040", "Impact", "影响"},
}

// uncategorized 是目录外技术的兜底战术（展示名在聚合层填充）。
var uncategorized = Tactic{ID: UncategorizedTacticID, Name: "Uncategorized", NameZh: "未分类"}

// techniques 是技术目录，覆盖内置规则、关键词层、静态指纹层与
// 落地即执行层实际会产生的全部编号（保持与 detect 层同步）。
var techniques = map[string]Technique{
	// ---- 凭证访问 ----
	"T1003":     {"T1003", "OS Credential Dumping", "操作系统凭证转储", "TA0006"},
	"T1003.001": {"T1003.001", "LSASS Memory", "LSASS 内存转储", "TA0006"},
	"T1555":     {"T1555", "Credentials from Password Stores", "从密码存储提取凭证", "TA0006"},
	// ---- 横向移动 ----
	"T1021":     {"T1021", "Remote Services", "远程服务", "TA0008"},
	"T1021.002": {"T1021.002", "SMB/Admin Shares", "SMB/管理共享", "TA0008"},
	"T1570":     {"T1570", "Lateral Tool Transfer", "横向工具传输", "TA0008"},
	// ---- 防御规避 ----
	"T1027":     {"T1027", "Obfuscated Files or Information", "文件与信息混淆", "TA0005"},
	"T1036":     {"T1036", "Masquerading", "伪装", "TA0005"},
	"T1036.005": {"T1036.005", "Match Legitimate Name or Location", "匹配合法名称或位置", "TA0005"},
	"T1036.007": {"T1036.007", "Double File Extension", "双扩展名", "TA0005"},
	"T1055":     {"T1055", "Process Injection", "进程注入", "TA0005"},
	"T1070":     {"T1070", "Indicator Removal", "指标抹除", "TA0005"},
	"T1070.001": {"T1070.001", "Clear Windows Event Logs", "清除 Windows 事件日志", "TA0005"},
	"T1140":     {"T1140", "Deobfuscate/Decode Files or Information", "解码文件或信息", "TA0005"},
	"T1197":     {"T1197", "BITS Jobs", "BITS 作业", "TA0005"},
	"T1218.005": {"T1218.005", "Mshta", "Mshta 执行", "TA0005"},
	"T1218.010": {"T1218.010", "Regsvr32", "Regsvr32 执行", "TA0005"},
	"T1218.011": {"T1218.011", "Rundll32", "Rundll32 执行", "TA0005"},
	"T1553.002": {"T1553.002", "Code Signing", "代码签名滥用", "TA0005"},
	"T1562.001": {"T1562.001", "Impair Defenses", "削弱防御", "TA0005"},
	"T1562.004": {"T1562.004", "Disable or Modify System Firewall", "禁用或修改系统防火墙", "TA0005"},
	"T1564.002": {"T1564.002", "Hidden Users", "隐藏用户", "TA0005"},
	"T1564.003": {"T1564.003", "Hidden Window", "隐藏窗口", "TA0005"},
	"T1620":     {"T1620", "Reflective Code Loading", "反射式代码加载", "TA0005"},
	// ---- 执行 ----
	"T1047":     {"T1047", "Windows Management Instrumentation", "WMI 执行", "TA0002"},
	"T1053.005": {"T1053.005", "Scheduled Task", "计划任务", "TA0002"},
	"T1059":     {"T1059", "Command and Scripting Interpreter", "命令与脚本解释器", "TA0002"},
	"T1059.001": {"T1059.001", "PowerShell", "PowerShell 执行", "TA0002"},
	"T1059.005": {"T1059.005", "Visual Basic", "Visual Basic 执行", "TA0002"},
	"T1059.007": {"T1059.007", "JavaScript/JScript", "JavaScript/JScript 执行", "TA0002"},
	"T1204":     {"T1204", "User Execution", "用户执行", "TA0002"},
	"T1204.002": {"T1204.002", "Malicious File", "恶意文件", "TA0002"},
	// ---- 持久化 ----
	"T1098":     {"T1098", "Account Manipulation", "账户操纵", "TA0003"},
	"T1136.001": {"T1136.001", "Local Account", "新建本地账户", "TA0003"},
	"T1543.003": {"T1543.003", "Windows Service", "Windows 服务", "TA0003"},
	"T1547.001": {"T1547.001", "Registry Run Keys / Startup Folder", "注册表 Run 键/启动目录", "TA0003"},
	"T1574.002": {"T1574.002", "DLL Side-Loading", "DLL 侧加载", "TA0003"},
	// ---- 权限提升 ----
	"T1548": {"T1548", "Abuse Elevation Control Mechanism", "滥用权限控制机制", "TA0004"},
	// ---- 发现 ----
	"T1046": {"T1046", "Network Service Discovery", "网络服务发现", "TA0007"},
	"T1057": {"T1057", "Process Discovery", "进程发现", "TA0007"},
	// ---- 初始访问 ----
	"T1566": {"T1566", "Phishing", "网络钓鱼", "TA0001"},
	// ---- 命令与控制 ----
	"T1071": {"T1071", "Application Layer Protocol", "应用层协议", "TA0011"},
	"T1105": {"T1105", "Ingress Tool Transfer", "入站工具传输", "TA0011"},
	"T1572": {"T1572", "Protocol Tunneling", "协议隧道", "TA0011"},
	// ---- 影响 ----
	"T1490": {"T1490", "Inhibit System Recovery", "阻碍系统恢复", "TA0040"},
	"T1496": {"T1496", "Resource Hijacking", "资源劫持", "TA0040"},
}

// Tactics 返回全部战术（含未分类兜底，按规范顺序，未分类在最后）。
func Tactics() []Tactic {
	out := make([]Tactic, 0, len(tactics)+1)
	out = append(out, tactics...)
	out = append(out, uncategorized)
	return out
}

// LookupTechnique 查询技术目录；ok=false 表示目录外编号（聚合层应归入未分类）。
func LookupTechnique(id string) (Technique, bool) {
	t, ok := techniques[strings.TrimSpace(id)]
	return t, ok
}

// AllTechniques 返回目录全量技术（无序），供聚合层构建矩阵格子全集。
func AllTechniques() map[string]Technique {
	out := make(map[string]Technique, len(techniques))
	for k, v := range techniques {
		out[k] = v
	}
	return out
}

// TacticName 按战术 ID 取展示名（供未分类兜底与测试使用）。
func TacticName(id string) (Tactic, bool) {
	if id == UncategorizedTacticID {
		return uncategorized, true
	}
	for _, t := range tactics {
		if t.ID == id {
			return t, true
		}
	}
	return Tactic{}, false
}

// NormalizeTech 规范技术编号格式（大写、去空白），容错自定义规则里的小写。
func NormalizeTech(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}
