// Package livecatalog 是探针实时隧道只读调查端点的单一事实源（catalog）。
//
// 为什么存在：隧道内端点的"路由名 / 参数契约 / 超时预算 / 开关要求"此前
// 分散在三处（探针 liveapi 的 mux 注册、服务端 livequery.go 的白名单预算表、
// MCP host_live 工具描述），任何一处改动都要人肉同步其余两处，漂移即事故
// （探针加了端点、服务端白名单没放行 = 静默 404；预算两边不一致 = truncated
// 语义被代理先掐）。本包把三方共用的描述收敛为一份纯数据表：
//
//   - 探针侧（internal/agent/liveapi）：mux 路由构建与参数钳制的对照基准；
//   - 服务端（internal/server/service/livequery.go）：代理白名单/预算表的派生源；
//   - MCP（internal/mcp）：host_live 只读工具描述（tools/list）的生成源。
//
// 硬约束（违反即返工）：本包被探针与服务端两侧同时 import，必须保持纯数据
// ——只允许标准库 time/strings/fmt/sort，禁止任何系统调用 / windows 依赖 /
// 第三方依赖；条目描述里不得出现明文攻击命令行（AGENTS.md §5.1 IOC 纪律，
// 编译产物会被本机安全产品拦截）。
//
// 口径以各 handler 实码为准（internal/agent/liveapi/*.go 与
// internal/server/service/livequery.go 的 LiveEndpoints）；改 handler 的
// 参数/上限/预算时必须同步改这里，catalog_test.go 会锁住结构完整性。
package livecatalog

// 参数类型（Param.Kind）白名单。multi 表示参数可重复出现（如 collect 的 p=）。
const (
	KindString = "string"
	KindInt    = "int"
	KindBool   = "bool"
	KindPath   = "path" // 绝对路径，走 validateFSPath/parseRegPath 同款校验
	KindEnum   = "enum" // 取值来自固定清单，清单写进 Desc
	KindMulti  = "multi"
)

// 端点分类（Endpoint.Cate）。调查动线从运维面到系统面，分组顺序即规范序。
const (
	CateOps      = "ops"      // 连通性与目录自述
	CateFS       = "fs"       // 文件系统
	CateEvidence = "evidence" // 取证（深度分析/打包出站）
	CateProc     = "proc"     // 进程与进程取证
	CateNet      = "net"      // 网络面
	CateSys      = "sys"      // 系统配置面（注册表/日志/任务/服务/账户…）
)

// 成本档（Endpoint.Cost）：给模型与前端排序调用用——先便宜后昂贵，
// 能用 fast 回答的问题不要发起 slow 调用。
const (
	CostFast   = "fast"
	CostMedium = "medium"
	CostSlow   = "slow"
)

// Param 描述一个查询参数。
type Param struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // string|int|bool|path|enum|multi（multi=可重复）
	Required bool   `json:"required,omitempty"`
	Default  string `json:"default,omitempty"`
	Max      int    `json:"max,omitempty"` // 数值上限/长度上限/条数上限（语义见 Desc）
	Desc     string `json:"desc"`          // 一句话用法
}

// Endpoint 描述一个隧道内只读调查端点（单一事实源：
// 探针 mux 构建 / 服务端白名单派生 / MCP 工具描述生成 三方共用）。
type Endpoint struct {
	Name      string  `json:"name"`     // 路由名 = 隧道内路径（如 "fs/stat"）
	Cate      string  `json:"category"` // fs|proc|net|sys|evidence|ops
	Summary   string  `json:"summary"`  // 一句话中文说明
	Params    []Param `json:"params,omitempty"`
	Output    string  `json:"output"`     // 返回键形态说明
	AI        bool    `json:"ai"`         // 对 MCP host_live 开放
	Cost      string  `json:"cost"`       // fast|medium|slow（帮模型排序调用）
	TimeoutMs int     `json:"timeout_ms"` // 服务端代理预算
	// FileRead/Collect 对应服务端两层子开关（默认关）：
	// 内容出站面（fs/read、fs/grep）与取证打包（collect）是信息暴露面最大
	// 的端点，与处置类同纪律——总开关放不过，必须现场显式开。
	FileRead bool `json:"fileread,omitempty"` // 需 HG_SERVER_LIVEQUERY_FILEREAD
	Collect  bool `json:"collect,omitempty"`  // 需 HG_SERVER_LIVEQUERY_COLLECT
}

// catalog 规范序全量表：按 Cate 分组（ops → fs → evidence → proc → net → sys），
// 组内按调查动线排定稳定序（All() 两次调用结果必须逐字段一致，测试锁定）。
// 共享切片：All() 直接返回本切片，消费方只读不改写——服务端白名单与 MCP
// 工具描述都从这份切片派生，原地改写会跨面污染其他消费方。
//
// AI=false 仅两处（fs/read、collect）：文件内容字节流与取证 zip 属内容出站面，
// 不进 MCP 模型可见工具清单，人工操作面显式开子开关后才可达。
var catalog = []Endpoint{
	// ---- ops（3）：连通性与目录自述 ----
	{
		Name:      "ping",
		Cate:      CateOps,
		Summary:   "探针连通性探活",
		Output:    "ok/version/uptime_sec/hostname",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 5000,
	},
	{
		Name:      "info",
		Cate:      CateOps,
		Summary:   "探针实时运行时状态（进程数/CPU/内存/采集器）",
		Output:    "version/hostname/uptime_sec/proc_count/cpu_percent/mem_mb/scan_interval/collector",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 5000,
	},
	{
		Name:      "_catalog",
		Cate:      CateOps,
		Summary:   "本目录自述：列出全部可用端点及其参数契约",
		Output:    "endpoints[]按分类分组",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 5000,
	},

	// ---- fs（7）：文件系统调查 ----
	{
		Name:    "fs",
		Cate:    CateFS,
		Summary: "目录列表（目录优先+名称排序，游标分页）",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "绝对路径，需含盘符；拒绝设备命名空间与 .. 段"},
			{Name: "cursor", Kind: KindString, Desc: "分页游标，取上一页返回的 next_cursor（o<offset> 形态）"},
			{Name: "limit", Kind: KindInt, Default: "200", Max: 500, Desc: "单页条目数"},
		},
		Output:    "path/entries[]/next_cursor",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 15000,
	},
	{
		Name:    "fs/stat",
		Cate:    CateFS,
		Summary: "单路径元数据查询（不存在是 200 exists:false，不是 404）",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "绝对路径，需含盘符"},
		},
		Output:    "exists/size/is_dir/hidden/system/readonly/reparse/mtime_unix",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:    "fs/read",
		Cate:    CateFS,
		Summary: "文件内容分段读取（预览口径；内容出站面，默认关）",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "绝对路径，需含盘符"},
			{Name: "offset", Kind: KindInt, Desc: "起始字节偏移（缺省 0）"},
			{Name: "limit", Kind: KindInt, Default: "65536", Max: 524288, Desc: "本次读取字节数（默认 64KB，上限 512KB）"},
		},
		Output:    "字节流 + X-ZEDR-File-Size/X-ZEDR-Truncated 响应头",
		AI:        false, // 内容出站面：不进 MCP 工具清单，需 HG_SERVER_LIVEQUERY_FILEREAD
		Cost:      CostMedium,
		TimeoutMs: 20000,
		FileRead:  true,
	},
	{
		Name:    "fs/hash",
		Cate:    CateFS,
		Summary: "文件 SHA-256 与 Authenticode 签名状态（≤2GB）",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "文件绝对路径（目录拒绝）"},
		},
		Output:    "sha256/size/authenticode{state,subject}",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 30000,
	},
	{
		Name:    "fs/search",
		Cate:    CateFS,
		Summary: "目录限深通配符搜索（狩猎场景，命中项带快速指纹）",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "搜索起点目录"},
			{Name: "pattern", Kind: KindString, Required: true, Desc: "通配符模式（* / ?），匹配叶子文件名；空串拒绝"},
			{Name: "depth", Kind: KindInt, Default: "2", Max: 4, Desc: "搜索深度"},
			{Name: "limit", Kind: KindInt, Default: "100", Max: 200, Desc: "命中条数上限"},
		},
		Output:    "entries[]带quick{pe,ads,hidden,system}/truncated",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 35000,
	},
	{
		Name:    "fs/grep",
		Cate:    CateFS,
		Summary: "单文件内容查找；二进制文件拒绝并提示用 analyze",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "文件绝对路径"},
			{Name: "pattern", Kind: KindString, Required: true, Max: 200, Desc: "正则表达式，≤200 字符"},
			{Name: "max", Kind: KindInt, Default: "50", Max: 50, Desc: "最大匹配行数"},
		},
		Output:    "matches[{line_no,line,offset}]/scanned_bytes/truncated",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 15000,
		FileRead:  true, // 内容出站面：需 HG_SERVER_LIVEQUERY_FILEREAD
	},
	{
		Name:    "ads",
		Cate:    CateFS,
		Summary: "NTFS 备用数据流枚举与 MotW 下载来源解析",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "文件绝对路径（目录没有数据流语义）"},
		},
		Output:    "streams[]/zone{zone_id,zone_name,referrer_url,host_url,download_time}",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},

	// ---- evidence（2）：深度取证（昂贵/出站面单独把门）----
	{
		Name:    "analyze",
		Cate:    CateEvidence,
		Summary: "二进制深度分析（多哈希/PE 结构/导入分类/加壳提示/字符串采样，≤64MB）",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "文件绝对路径"},
		},
		Output:    "md5/sha1/sha256/pe{sections熵,imphash,imports7类}/version_resource/packer_hints/strings五类各≤10",
		AI:        true,
		Cost:      CostSlow,
		TimeoutMs: 30000,
	},
	{
		Name:    "collect",
		Cate:    CateEvidence,
		Summary: "多文件取证打包为 zip 流（全程不落盘，manifest 是完整性唯一事实源）",
		Params: []Param{
			{Name: "p", Kind: KindMulti, Required: true, Max: 16, Desc: "取证对象绝对路径，可重复（?p=路径1&p=路径2），去重后 ≤16 个；任一路径非法整体 400"},
		},
		Output:    "zip流+__zedr_manifest.json{files[{path,zip_name,size,sha256}],errors,truncated}",
		AI:        false, // 内容出站面：不进 MCP 工具清单，需 HG_SERVER_LIVEQUERY_COLLECT
		Cost:      CostSlow,
		TimeoutMs: 120000,
		Collect:   true,
	},

	// ---- proc（6）：进程与进程取证 ----
	{
		Name:    "processes",
		Cate:    CateProc,
		Summary: "进程快照列表（采集层实时表）",
		Params: []Param{
			{Name: "limit", Kind: KindInt, Default: "300", Max: 2000, Desc: "返回条数上限"},
		},
		Output:    "items[]",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:    "procinfo",
		Cate:    CateProc,
		Summary: "单进程详情（命令行/会话/连接/模块/执行文件画像，进程↔文件↔网络交叉枢纽）",
		Params: []Param{
			{Name: "pid", Kind: KindInt, Required: true, Desc: "正整数（0 拒绝）"},
		},
		Output:    "exists/name/path/cmdline(脱敏)/user/ppid/session_id/elevated/started_at_unix/connections/modules≤64/exec_info",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:    "handles",
		Cate:    CateProc,
		Summary: "单进程句柄表（类型直方图 + 安全类型句柄名称解析）",
		Params: []Param{
			{Name: "pid", Kind: KindInt, Required: true, Desc: "正整数；0 与 4（System）拒绝"},
			{Name: "type", Kind: KindString, Desc: "按对象类型过滤（File/Key/Section 等），空=全部"},
			{Name: "limit", Kind: KindInt, Default: "1000", Max: 5000, Desc: "返回条数上限"},
		},
		Output:    "items[]/types(类型直方图)/note/truncated",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 5000,
	},
	{
		Name:    "handleowners",
		Cate:    CateProc,
		Summary: "全系统 File 句柄反查：谁打开了这个文件",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "目标文件绝对路径（目录句柄不在 File 扫描范围）"},
		},
		Output:    "owners[]/scanned/resolved/note",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 10000,
	},
	{
		Name:    "threads",
		Cate:    CateProc,
		Summary: "单进程线程列表（起始地址/模块归属/匿名执行线索）",
		Params: []Param{
			{Name: "pid", Kind: KindInt, Required: true, Desc: "正整数；0 与 4（System）拒绝"},
		},
		Output:    "items[{tid,start_address,module,in_anonymous_exec}]/note",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 5000,
	},
	{
		Name:    "memscan",
		Cate:    CateProc,
		Summary: "进程地址空间元数据巡检（受保护进程打不开时跳过）",
		Params: []Param{
			{Name: "pid", Kind: KindInt, Required: true, Desc: "正整数；0 与 4（System）拒绝"},
		},
		Output:    "counts/regions≤200/suspicious≤20（仅地址空间元数据，不含内存内容）",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 10000,
	},

	// ---- net（3）：网络面 ----
	{
		Name:      "netstat",
		Cate:      CateNet,
		Summary:   "TCP/UDP 连接表 + 归属进程富化（已退出进程显式标注）",
		Output:    "items[]带proc_name/path/user/cmdline(脱敏)/proc_elevated/remote_class",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:      "peers",
		Cate:      CateNet,
		Summary:   "外联对端聚合（谁在跟这台机器说话）",
		Output:    "counts/peers[]≤200/by_process≤50（仅ESTABLISHED）",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 5000,
	},
	{
		Name:    "netinfo",
		Cate:    CateNet,
		Summary: "网络面快照（ARP/路由/DNS 缓存/网卡/SMB 共享，分段独立降级）",
		Params: []Param{
			{Name: "sections", Kind: KindEnum, Default: "arp,routes,dns,adapters,shares", Desc: "逗号分隔选段，空=全部五段；非法段名忽略并记入 errors"},
		},
		Output:    "各段数组，失败段null+errors",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},

	// ---- sys（11）：系统配置面 ----
	{
		Name:    "registry",
		Cate:    CateSys,
		Summary: "注册表键只读枚举（子键+值，EXPAND_SZ 带展开原文）",
		Params: []Param{
			{Name: "path", Kind: KindPath, Required: true, Desc: "如 HKLM\\SOFTWARE\\Microsoft\\...；根键限 HKLM/HKCU/HKU/HKCR"},
			{Name: "max_subkeys", Kind: KindInt, Default: "200", Max: 1000, Desc: "子键枚举上限"},
			{Name: "max_values", Kind: KindInt, Default: "100", Max: 500, Desc: "值枚举上限"},
		},
		Output:    "exists/subkeys[]/values[{name,type,data,expanded?}]",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:    "evtlog",
		Cate:    CateSys,
		Summary: "事件日志按需查询（通道/事件ID/时间窗，新→旧反向读）",
		Params: []Param{
			{Name: "channel", Kind: KindString, Required: true, Max: 200, Desc: "日志通道名，如 Security / System"},
			{Name: "ids", Kind: KindString, Max: 32, Desc: "逗号分隔事件 ID，≤32 个（拼进 XPath 的服务端硬约束）"},
			{Name: "minutes", Kind: KindInt, Default: "60", Max: 1440, Desc: "时间窗（分钟，距今）"},
			{Name: "max", Kind: KindInt, Default: "20", Max: 200, Desc: "返回条数上限"},
		},
		Output:    "count/items[{record_id,time_created,event_id,level,data}]/truncated",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 20000,
	},
	{
		Name:    "tasks",
		Cate:    CateSys,
		Summary: "计划任务全量详情（含禁用任务/触发器/动作/运行级别）",
		Params: []Param{
			{Name: "filter", Kind: KindString, Desc: "子串匹配完整任务路径（大小写不敏感），空=全部"},
			{Name: "limit", Kind: KindInt, Default: "200", Max: 500, Desc: "返回条数上限"},
		},
		Output:    "items[{path,name,state,enabled,run_level,triggers[],actions[]}]/total/truncated",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 15000,
	},
	{
		Name:    "services",
		Cate:    CateSys,
		Summary: "服务实时全量（Windows=Win32 服务；Linux=systemd unit，state 为启用口径）",
		Params: []Param{
			{Name: "filter", Kind: KindString, Desc: "子串匹配服务名或显示名（大小写不敏感），空=全部"},
			{Name: "state", Kind: KindString, Desc: "按状态精确过滤，词汇按平台：Windows=running/stopped，Linux=enabled/disabled（传错词汇得到诚实空集），空=全部"},
			{Name: "limit", Kind: KindInt, Default: "200", Max: 500, Desc: "返回条数上限"},
		},
		Output:    "items[{name,display_name,state,start_mode,path_name,account}]/total/truncated",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:    "drivers",
		Cate:    CateSys,
		Summary: "已加载内核驱动列表（rootkit/驱动持久化画像，默认不验签）",
		Params: []Param{
			{Name: "verify", Kind: KindBool, Default: "false", Desc: "true=对前 50 个驱动逐一 Authenticode 验签（显式慢通道）"},
		},
		Output:    "items[{name,path,size,mtime_unix,signed?,signer?}]/verified_count",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 15000,
	},
	{
		Name:      "sessions",
		Cate:      CateSys,
		Summary:   "当前活动登录会话（排查横向移动的第一手登录痕迹）",
		Output:    "items[{logon_id,username,domain,logon_type_name,session,logon_time,auth_package}]",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:    "usn",
		Cate:    CateSys,
		Summary: "卷级最近文件活动（USN journal 回溯，覆盖探针停机窗口）",
		Params: []Param{
			{Name: "volume", Kind: KindString, Default: "C:", Desc: "盘符形态（C: / C / C:\\ 均可），限固定 NTFS 卷"},
			{Name: "minutes", Kind: KindInt, Default: "10", Max: 120, Desc: "回溯时间窗（分钟）"},
			{Name: "name", Kind: KindString, Desc: "叶子文件名子串过滤；USN 只有叶子名无目录信息"},
			{Name: "ext", Kind: KindString, Desc: "扩展名过滤（自动补点，如 exe → .exe）"},
			{Name: "max", Kind: KindInt, Default: "200", Max: 1000, Desc: "保留最近匹配条数"},
		},
		Output:    "journal{first_usn,next_usn}/scanned/matched/items[{usn,ts_unix,name,reasons[]}]/truncated",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 20000,
	},
	{
		Name:      "baseline",
		Cate:      CateSys,
		Summary:   "十项安全基线体检（读事实不下结论，读取失败如实标注）",
		Output:    "items[]十项(pass/warn/fail/info)/score",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:      "accounts",
		Cate:      CateSys,
		Summary:   "本机账户清单 + 管理员名单 + 密码策略",
		Output:    "users[]/administrators[]/policy",
		AI:        true,
		Cost:      CostFast,
		TimeoutMs: 10000,
	},
	{
		Name:      "persistence",
		Cate:      CateSys,
		Summary:   "持久化总览（Autoruns 风格：服务/计划任务/五类启动项，启用态）",
		Output:    "items[]（source=service/task/startup）/counts/truncated",
		AI:        true,
		Cost:      CostMedium,
		TimeoutMs: 15000,
	},
	{
		Name:    "recon",
		Cate:    CateSys,
		Summary: "资产侦查六类检测（Web/AI harness/DB/远程访问/开发工具/虚拟化）",
		Params: []Param{
			{Name: "categories", Kind: KindEnum, Default: "web,ai,db,remote,dev,virt", Desc: "逗号分隔类目，空=全部六类；未知类目 400"},
			{Name: "probe", Kind: KindBool, Default: "true", Desc: "仅接受 0/1；false=纯被动（不发起回环探测请求）"},
		},
		Output:    "六类资产侦查结果/30s内部预算",
		AI:        true,
		Cost:      CostSlow,
		TimeoutMs: 40000,
	},
}

// All 返回全部端点（规范序：按 Cate 分组、组内稳定序）。
// 返回包级共享切片，消费方只读——不要 append/改写（需要修改时自行拷贝）。
func All() []Endpoint {
	return catalog
}

// Get 按路由名取端点；name 即隧道内路径（如 "fs/stat"）。
// 表只有 32 条，线性扫描足够，不值得维护第二份索引（两份数据必然漂移）。
func Get(name string) (Endpoint, bool) {
	for _, ep := range catalog {
		if ep.Name == name {
			return ep, true
		}
	}
	return Endpoint{}, false
}
