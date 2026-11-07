package detect

import (
	"sort"
	"strings"

	"zedr/internal/ioc"
	"zedr/internal/model"
)

// keywordMatcher 是第 2 层检测：Aho-Corasick 多模式匹配。
//
// 单条正则匹配 200 个关键词需要 O(n*m)；AC 自动机一次扫描即可
// 同时命中所有模式，复杂度 O(n + 命中数)，这是报告里"摊薄单条事件成本"的具体落地。
type keywordMatcher struct {
	patterns []kwPattern
	ac       *ahoCorasick
	names    map[string]kwPattern // 进程名精确匹配表
	index    map[string]kwPattern // 模式 token -> 模式
}

// kwPattern 是一个关键词信号。
type kwPattern struct {
	ID    string
	Token string // 小写
	Score int
	Name  string
	Note  string
	MITRE string
}

func newKeywordMatcher() *keywordMatcher {
	return keywordMatcherFrom(keywordPatterns())
}

// keywordMatcherFrom 用给定模式表构建匹配器（内置表与运营者动态
// 情报关键词共用一套 AC 管线）。
func keywordMatcherFrom(patterns []kwPattern) *keywordMatcher {
	m := &keywordMatcher{
		patterns: patterns,
		names:    make(map[string]kwPattern, 64),
		index:    make(map[string]kwPattern, 128),
	}
	tokens := make([]string, 0, len(m.patterns))
	for _, p := range m.patterns {
		if strings.HasPrefix(p.ID, "N-") { // N- 前缀表示按进程名匹配
			m.names[p.Token] = p
			continue
		}
		tokens = append(tokens, p.Token)
	}
	m.ac = newAhoCorasick(tokens)
	for _, p := range m.patterns {
		m.index[p.Token] = p
	}
	return m
}

// matchPatterns 返回命中的原始模式（供命中计数等调用方使用）。
// 求值口径与 match 逐条对齐（含自匹配保护），代价是多一次 AC 扫描——
// 动态表小、频率为每次进程评估一次，可接受。
func (m *keywordMatcher) matchPatterns(procName, cmdline string) []kwPattern {
	var out []kwPattern
	seen := make(map[string]struct{})
	if p, ok := m.names[strings.ToLower(procName)]; ok {
		seen[p.ID] = struct{}{}
		out = append(out, p)
	}
	if cmdline == "" {
		return out
	}
	lc := strings.ToLower(cmdline)
	self := strings.ToLower(procName)
	for _, token := range m.ac.FindAll(lc) {
		p, ok := m.index[token]
		if !ok || token == self {
			continue
		}
		if _, dup := seen[p.ID]; dup {
			continue
		}
		seen[p.ID] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (m *keywordMatcher) match(procName, cmdline string) []model.Signal {
	var out []model.Signal
	seen := make(map[string]struct{})

	// 1) 进程名硬信号
	if p, ok := m.names[strings.ToLower(procName)]; ok {
		out = append(out, model.Signal{
			Layer: "keyword", ID: p.ID, Name: p.Name, Score: p.Score, Note: p.Note, MITRE: p.MITRE,
		})
		seen[p.ID] = struct{}{}
	}

	// 2) 命令行多模式匹配
	if cmdline == "" {
		return out
	}
	lc := strings.ToLower(cmdline)
	// 自匹配保护：进程自身的名字出现在自己的命令行里是常态
	// （例如 lsass.exe 的命令行就是它自己的路径），不能算"引用了该对象"。
	self := strings.ToLower(procName)
	for _, token := range m.ac.FindAll(lc) {
		p, ok := m.index[token]
		if !ok {
			continue
		}
		if token == self {
			continue
		}
		if _, dup := seen[p.ID]; dup {
			continue
		}
		seen[p.ID] = struct{}{}
		out = append(out, model.Signal{
			Layer: "keyword", ID: p.ID, Name: p.Name, Score: p.Score, Note: p.Note, MITRE: p.MITRE,
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// ---------------------------------------------------------------- AC 自动机

type acNode struct {
	next map[byte]int
	fail int
	out  []string // 在此节点结束的模式
}

type ahoCorasick struct {
	nodes []acNode
}

func newAhoCorasick(patterns []string) *ahoCorasick {
	ac := &ahoCorasick{nodes: []acNode{{next: make(map[byte]int)}}}

	for _, p := range patterns {
		if p == "" {
			continue
		}
		cur := 0
		for i := 0; i < len(p); i++ {
			c := p[i]
			nxt, ok := ac.nodes[cur].next[c]
			if !ok {
				ac.nodes = append(ac.nodes, acNode{next: make(map[byte]int)})
				nxt = len(ac.nodes) - 1
				ac.nodes[cur].next[c] = nxt
			}
			cur = nxt
		}
		ac.nodes[cur].out = append(ac.nodes[cur].out, p)
	}

	// BFS 构建 fail 指针
	queue := make([]int, 0, len(ac.nodes))
	for _, child := range ac.nodes[0].next {
		ac.nodes[child].fail = 0
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for c, child := range ac.nodes[cur].next {
			f := ac.nodes[cur].fail
			for f != 0 {
				if n, ok := ac.nodes[f].next[c]; ok {
					f = n
					break
				}
				f = ac.nodes[f].fail
			}
			if f == 0 {
				if n, ok := ac.nodes[0].next[c]; ok && n != child {
					f = n
				}
			}
			ac.nodes[child].fail = f
			if len(ac.nodes[f].out) > 0 {
				ac.nodes[child].out = append(ac.nodes[child].out, ac.nodes[f].out...)
			}
			queue = append(queue, child)
		}
	}
	return ac
}

// FindAll 返回文本中命中的全部模式（去重）。
func (ac *ahoCorasick) FindAll(s string) []string {
	if ac == nil || len(s) == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	cur := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		for cur != 0 {
			if n, ok := ac.nodes[cur].next[c]; ok {
				cur = n
				goto matched
			}
			cur = ac.nodes[cur].fail
		}
		if n, ok := ac.nodes[0].next[c]; ok {
			cur = n
		}
	matched:
		for _, p := range ac.nodes[cur].out {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------- 内置关键词

// 进程名等 IOC 以 base64 存放（原因见 internal/ioc），运行时解码。
func keywordPatterns() []kwPattern {
	return []kwPattern{
		// ---- 进程名硬信号（改名即失效，但零误报）----
		{ID: "N-001", Token: ioc.S("bWltaWthdHouZXhl"), Score: 55, Name: "已知凭据窃取工具", Note: "进程名与已知凭据抓取工具一致", MITRE: "T1003"},
		{ID: "N-002", Token: ioc.S("bGF6YWduZS5leGU="), Score: 50, Name: "已知多源凭据收集器", MITRE: "T1555"},
		{ID: "N-003", Token: ioc.S("cHdkdW1wLmV4ZQ=="), Score: 50, Name: "已知哈希导出工具", MITRE: "T1003"},
		{ID: "N-004", Token: ioc.S("Z3NlY2R1bXAuZXhl"), Score: 48, Name: "已知哈希导出工具（变种）", MITRE: "T1003"},
		{ID: "N-005", Token: ioc.S("bmFub2R1bXAuZXhl"), Score: 50, Name: "已知 LSASS 内存转储工具", MITRE: "T1003.001"},
		{ID: "N-006", Token: ioc.S("c2FmZXR5a2F0ei5leGU="), Score: 50, Name: "已知 LSASS 内存转储工具（变种）", MITRE: "T1003.001"},
		{ID: "N-007", Token: ioc.S("eG1yaWcuZXhl"), Score: 55, Name: "已知挖矿程序", MITRE: "T1496"},
		{ID: "N-008", Token: ioc.S("bWluZXJkLmV4ZQ=="), Score: 50, Name: "已知挖矿程序（旧版）", MITRE: "T1496"},
		{ID: "N-009", Token: ioc.S("bm1hcC5leGU="), Score: 30, Name: "网络扫描器", MITRE: "T1046"},
		{ID: "N-010", Token: ioc.S("ZnNjYW4uZXhl"), Score: 40, Name: "内网批量扫描器", MITRE: "T1046"},
		{ID: "N-011", Token: ioc.S("cHNleGVjLmV4ZQ=="), Score: 35, Name: "远程执行工具", MITRE: "T1021.002"},
		{ID: "N-012", Token: ioc.S("cHNleGVzdmMuZXhl"), Score: 40, Name: "远程执行服务端组件", MITRE: "T1021.002"},
		{ID: "N-013", Token: ioc.S("bWltaWRvZ3ouZXhl"), Score: 50, Name: "凭据窃取工具改名变种", Note: "经典改名绕过样本：进程名不完全一致但家族特征明显", MITRE: "T1036"},
		{ID: "N-014", Token: ioc.S("Y29iYWx0c3RyaWtlLmV4ZQ=="), Score: 50, Name: "已知远控框架客户端", MITRE: "T1071"},
		{ID: "N-015", Token: ioc.S("bmV0Y2F0LmV4ZQ=="), Score: 30, Name: "通用网络连接工具", MITRE: "T1059"},
		{ID: "N-016", Token: ioc.S("cHJvY2Vzc2hhY2tlci5leGU="), Score: 15, Name: "进程管理双用途工具", Note: "运维常用，仅作低权参考", MITRE: "T1057"},

		// ---- 命令行关键词 ----
		{ID: "K-001", Token: ioc.S("LWVuY29kZWRjb21tYW5k"), Score: 22, Name: "PowerShell 编码命令", Note: "Base64 编码的命令行是绕过审计的常用手法", MITRE: "T1059.001"},
		{ID: "K-002", Token: ioc.S("LWVuYyA="), Score: 16, Name: "PowerShell -enc 简写", MITRE: "T1059.001"},
		{ID: "K-003", Token: ioc.S("ZG93bmxvYWRzdHJpbmc="), Score: 24, Name: "内存下载执行 DownloadString", MITRE: "T1105"},
		{ID: "K-004", Token: ioc.S("aW52b2tlLWV4cHJlc3Npb24="), Score: 22, Name: "Invoke-Expression 动态执行", MITRE: "T1059.001"},
		{ID: "K-005", Token: ioc.S("aWV4KA=="), Score: 22, Name: "IEX 动态执行", MITRE: "T1059.001"},
		{ID: "K-006", Token: ioc.S("ZnJvbWJhc2U2NHN0cmluZw=="), Score: 20, Name: "Base64 解码执行", MITRE: "T1140"},
		{ID: "K-007", Token: ioc.S("bmV0LndlYmNsaWVudA=="), Score: 18, Name: "WebClient 网络请求", MITRE: "T1105"},
		{ID: "K-008", Token: ioc.S("aW52b2tlLXdlYnJlcXVlc3Q="), Score: 14, Name: "Invoke-WebRequest 下载", MITRE: "T1105"},
		{ID: "K-009", Token: ioc.S("LXdpbmRvd3N0eWxlIGhpZGRlbg=="), Score: 20, Name: "隐藏窗口执行", Note: "正常运维极少使用", MITRE: "T1564.003"},
		{ID: "K-010", Token: ioc.S("LXcgaGlkZGVu"), Score: 18, Name: "隐藏窗口执行（简写）", MITRE: "T1564.003"},
		{ID: "K-011", Token: ioc.S("Y2VydHV0aWwgLXVybGNhY2hl"), Score: 26, Name: "certutil 下载文件", MITRE: "T1105"},
		{ID: "K-012", Token: ioc.S("Y2VydHV0aWwgLWRlY29kZQ=="), Score: 22, Name: "certutil 解码载荷", MITRE: "T1140"},
		{ID: "K-013", Token: ioc.S("Yml0c2FkbWluIC90cmFuc2Zlcg=="), Score: 26, Name: "BITS 后台传输", MITRE: "T1197"},
		{ID: "K-014", Token: ioc.S("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3M="), Score: 45, Name: "删除卷影副本", Note: "勒索软件标配前置动作", MITRE: "T1490"},
		{ID: "K-015", Token: ioc.S("ZGVsZXRlIHNoYWRvd3MgL2FsbA=="), Score: 45, Name: "删除全部卷影副本", MITRE: "T1490"},
		{ID: "K-016", Token: ioc.S("cmVzaXplIHNoYWRvd3N0b3JhZ2U="), Score: 30, Name: "收缩卷影存储", MITRE: "T1490"},
		{ID: "K-017", Token: ioc.S("cmVjb3ZlcnllbmFibGVkIG5v"), Score: 35, Name: "关闭系统恢复", MITRE: "T1490"},
		{ID: "K-018", Token: ioc.S("c2V0LW1wcHJlZmVyZW5jZQ=="), Score: 34, Name: "修改 Defender 策略", MITRE: "T1562.001"},
		{ID: "K-019", Token: ioc.S("ZGlzYWJsZXJlYWx0aW1lbW9uaXRvcmluZw=="), Score: 40, Name: "关闭 Defender 实时防护", MITRE: "T1562.001"},
		{ID: "K-020", Token: ioc.S("YWRkLW1wcHJlZmVyZW5jZQ=="), Score: 30, Name: "添加 Defender 排除项", MITRE: "T1562.001"},
		{ID: "K-021", Token: ioc.S("LWV4Y2x1c2lvbnBhdGg="), Score: 26, Name: "添加杀软排除路径", MITRE: "T1562.001"},
		{ID: "K-022", Token: ioc.S("d2V2dHV0aWwgY2w="), Score: 38, Name: "清空事件日志", Note: "反取证行为", MITRE: "T1070.001"},
		{ID: "K-023", Token: ioc.S("Y2xlYXItZXZlbnRsb2c="), Score: 34, Name: "清空事件日志", MITRE: "T1070.001"},
		{ID: "K-024", Token: ioc.S("c2NodGFza3MgL2NyZWF0ZQ=="), Score: 18, Name: "创建计划任务", MITRE: "T1053.005"},
		{ID: "K-025", Token: ioc.S("c2MgY3JlYXRl"), Score: 18, Name: "创建系统服务", MITRE: "T1543.003"},
		{ID: "K-026", Token: ioc.S("YmlucGF0aD0="), Score: 14, Name: "指定服务二进制路径", MITRE: "T1543.003"},
		{ID: "K-027", Token: "\\currentversion\\run", Score: 18, Name: "写入注册表自启动项", MITRE: "T1547.001"},
		{ID: "K-028", Token: ioc.S("c3RyYXR1bSt0Y3A="), Score: 45, Name: "矿池协议 stratum+tcp", MITRE: "T1496"},
		{ID: "K-029", Token: ioc.S("c3RyYXR1bStzc2w="), Score: 45, Name: "矿池协议 stratum+ssl", MITRE: "T1496"},
		{ID: "K-030", Token: ioc.S("LS1kb25hdGUtbGV2ZWw="), Score: 30, Name: "矿工参数 donate-level", MITRE: "T1496"},
		{ID: "K-031", Token: ioc.S("bmV0IGxvY2FsZ3JvdXAgYWRtaW5pc3RyYXRvcnM="), Score: 22, Name: "修改管理员组成员", MITRE: "T1098"},
		{ID: "K-032", Token: ioc.S("cmVnc3ZyMzIgL2k6aHR0cA=="), Score: 42, Name: "regsvr32 远程脚本加载", MITRE: "T1218.010"},
		{ID: "K-033", Token: ioc.S("c2Nyb2JqLmRsbA=="), Score: 32, Name: "脚本宿主组件加载", MITRE: "T1218.010"},
		{ID: "K-034", Token: ioc.S("d21pYyBwcm9jZXNzIGNhbGwgY3JlYXRl"), Score: 26, Name: "WMIC 创建进程", MITRE: "T1047"},
		{ID: "K-035", Token: ioc.S("amF2YXNjcmlwdDo="), Score: 30, Name: "javascript 协议执行", MITRE: "T1218.005"},
		{ID: "K-036", Token: ioc.S("dmJzY3JpcHQ6"), Score: 30, Name: "vbscript 协议执行", MITRE: "T1218.005"},
		{ID: "K-037", Token: ioc.S("YW1zaXV0aWxz"), Score: 40, Name: "AMSI 绕过", MITRE: "T1562.001"},
		{ID: "K-038", Token: ioc.S("YW1zaS5kbGw="), Score: 20, Name: "引用 AMSI 模块", MITRE: "T1562.001"},
		{ID: "K-039", Token: ioc.S("cmVmbGVjdGl2ZWxvYWQ="), Score: 30, Name: "反射式加载程序集", MITRE: "T1620"},
		{ID: "K-040", Token: ioc.S("cG93ZXJzaGVsbCAtbm9w"), Score: 12, Name: "PowerShell 无配置文件启动", MITRE: "T1059.001"},
		{ID: "K-041", Token: ioc.S("LWV4ZWN1dGlvbnBvbGljeSBieXBhc3M="), Score: 22, Name: "绕过执行策略", MITRE: "T1059.001"},
		{ID: "K-042", Token: ioc.S("bHNhc3MuZXhl"), Score: 26, Name: "命令行引用 lsass", Note: "对 lsass 直接操作多为凭据窃取", MITRE: "T1003.001"},
		{ID: "K-043", Token: ioc.S("cHJvY2R1bXA="), Score: 26, Name: "内存转储工具调用", MITRE: "T1003.001"},
		{ID: "K-044", Token: ioc.S("LW1hIA=="), Score: 8, Name: "全内存转储参数", MITRE: "T1003.001"},
		{ID: "K-045", Token: "\\startup\\", Score: 16, Name: "写入启动目录", MITRE: "T1547.001"},
		{ID: "K-046", Token: ioc.S("Y2lwaGVyIC93Og=="), Score: 20, Name: "擦除磁盘空闲空间", Note: "常与反取证配合", MITRE: "T1070"},
		{ID: "K-047", Token: ioc.S("d2JhZG1pbiBkZWxldGU="), Score: 40, Name: "删除备份目录", MITRE: "T1490"},
		{ID: "K-048", Token: ioc.S("YmNkZWRpdCAvc2V0"), Score: 20, Name: "修改引导配置", MITRE: "T1490"},
		{ID: "K-049", Token: ioc.S("bmdyb2s="), Score: 24, Name: "内网穿透工具", MITRE: "T1572"},
		{ID: "K-050", Token: ioc.S("Y2hpc2Vs"), Score: 24, Name: "隧道工具", MITRE: "T1572"},
	}
}
