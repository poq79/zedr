// Package drill 检测演练（Detection Drill）执行器。
//
// 目的：私有化交付验收与升级后回归——管理员在服务端对一台主机发起演练，
// 探针本地执行受控自测（全部自造样本：echo+回环 ping、TEST-NET SYN、
// demand 空服务、Run 键写删、删自家诱饵），让各检测层真实触发，
// 结果随指令回执回传。全程零真实恶意样本、零真实外联。
//
// 设计约束：
//   - 本包不 import agentapp（组合根与执行器互相依赖会锁死测试）；
//     依赖全部经 Deps 注入，由 agentapp 在指令分发处接线。
//   - 步骤同步执行，总预算 150s 硬顶：handleCommands 是同步回执模型，
//     演练期间心跳顺延，150s 远小于服务端侧任何超时判定。
//   - 判定口径是"期望规则出现在本步骤开始之后的新告警里"——只看增量，
//     不碰历史告警，避免上一次演练或真实攻击的残留命中造成假阳性。
//   - 前置不满足（采集开关关、无诱饵）记 skipped 而不是失败：
//     演练报告要回答"测了什么、结果如何"，"没测"和"没测出来"必须可区分。
package drill

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"zedr/internal/platform/redact"
)

// 步骤名（服务端白名单同名单，见 internal/server/api/drill.go 注释）。
const (
	StepProcChain   = "proc_chain"    // 采集管线健康检查：新进程可见
	StepPortScan    = "port_scan"     // 网络行为检测 NW-001/NW-004
	StepServiceEvt  = "service_event" // 事件日志层 E1：服务安装事件 EVT-SVCINST
	StepRegRun      = "reg_run"       // 持久化检测：P-001（基线层）/ HG-023（规则层）
	StepCanaryTouch = "canary_touch"  // 勒索防御：诱饵删除 FILE-CANARY
)

// PipelineSentinel 是 proc_chain 的 expected_rule 占位：该步骤验证的是
// 采集管线本身（新进程出现在进程表），不对应任何规则 ID。
const PipelineSentinel = "__pipeline__"

// detachedProcess 是 CREATE_NO_WINDOW（0x08000000），与 cmd/desktop 的
// spawn 先例一致：子进程拿一个不可见的控制台。演练 v1 曾用
// DETACHED_PROCESS（0x8），cmd/sc/reg 都正常、唯独 powershell.exe 会
// 163ms 内静默 exit 0（无控制台时初始化直接放弃），port_scan 步骤三轮
// E2E 全空转后定位到此处——拉控制台程序一律 CREATE_NO_WINDOW。
const detachedProcess = 0x08000000

// 预算与节奏。
const (
	// TotalBudget 是整场演练的硬顶。五步窗口之和（190s）刻意超出它：
	// 命中通常远早于窗口上限；真超预算时剩余步骤记 skipped，
	// 演练不允许无限占用同步回执链路。
	TotalBudget = 150 * time.Second

	// syncWait 是 sc/reg 这类同步子命令的执行上限。
	syncWait = 15 * time.Second

	// cleanupWait 是清理动作（sc delete / reg delete）的独立预算：
	// 判断窗口的 ctx 可能已超时，清理必须用新鲜预算，否则半途而废的
	// 演练会在目标机器上留下残留服务/注册表值——那比演练失败更糟。
	cleanupWait = 15 * time.Second
)

// pollEvery 与进程扫描节奏（2s）对齐：轮询再密也只是空转。
// var 而非 const 仅为一件事：单测可缩短节奏验证命中/超时判定，生产代码不写它。
var pollEvery = 2 * time.Second

// stepBudget 各步骤的独立判定窗口。
func stepBudget(name string) time.Duration {
	switch name {
	case StepProcChain:
		return 10 * time.Second
	case StepPortScan, StepServiceEvt:
		return 60 * time.Second
	case StepRegRun, StepCanaryTouch:
		return 30 * time.Second
	}
	return 10 * time.Second
}

// ---------------------------------------------------------------- 数据模型

// StepResult 是单步演练结果（随 CommandResult.Result 回传，服务端按同
// 形状解析成结构化步骤结果）。
type StepResult struct {
	Name         string `json:"name"`
	ExpectedRule string `json:"expected_rule"`
	Hit          bool   `json:"hit"`
	LatencyMs    int64  `json:"latency_ms"`
	AlertID      string `json:"alert_id,omitempty"`
	Note         string `json:"note,omitempty"`

	// skipped 标记"前置不满足未执行"（Note 以 "skipped: " 开头说明原因）。
	// 不进 JSON：外层 Report.Skipped 已承载名单，重复字段徒增回执体积
	// （服务端对回执有长度钳制，能省则省）。
	skipped bool
}

// AlertView 是判定所需的告警投影（agentapp 从 state.Store.Alerts 映射）。
type AlertView struct {
	ID         string
	RuleIDs    []string
	OccurredAt time.Time
}

// ProcView 是判定所需的进程投影（agentapp 从 state.Store.Procs 映射）。
type ProcView struct {
	PID  uint32
	Name string
}

// Deps 是执行器依赖（agentapp 接线注入；nil 字段对应步骤记 skipped）。
type Deps struct {
	// AlertsSince 返回 OccurredAt 不早于 t 的本地告警。
	AlertsSince func(t time.Time) []AlertView
	// ProcSnapshot 返回当前进程表快照（采集管线产物）。
	ProcSnapshot func() []ProcView
	// CanaryFile 返回一个存在的诱饵文件路径；空串 = 无可用诱饵
	// （勒索防御关闭或诱饵尚未放置）。
	CanaryFile func() string
	// EvtLogEnabled 对应 HG_AGENT_EVTLOG（E1 事件日志接入）。
	EvtLogEnabled bool
	// NetWatchEnabled 对应 HG_AGENT_NETWATCH（NW-001~005）。
	NetWatchEnabled bool
	Log             *slog.Logger
	SelfPID         uint32
}

// Report 是整场演练报告（写入 CommandResult.Result 的 JSON 结构）。
type Report struct {
	Steps   []StepResult `json:"steps"`
	Skipped []string     `json:"skipped,omitempty"`
}

// ---------------------------------------------------------------- 白名单与 payload

// AllSteps 返回全部步骤名（固定执行顺序：先查采集管线，再查网络/事件/
// 持久化层，最后查文件层）。
func AllSteps() []string {
	return []string{StepProcChain, StepPortScan, StepServiceEvt, StepRegRun, StepCanaryTouch}
}

// IsValidStep 白名单判定。
func IsValidStep(name string) bool {
	for _, s := range AllSteps() {
		if s == name {
			return true
		}
	}
	return false
}

// ParsePayload 解析指令 payload（{"steps":[...]}）。空 payload / 空数组 = 全跑。
// 服务端已做过白名单校验，这里再校验一次：指令链路上服务端只是第一道门，
// 探针不能假设上游永远正确（老服务端/手工造的指令都可能带脏步骤名）。
func ParsePayload(raw string) ([]string, error) {
	var p struct {
		Steps []string `json:"steps"`
	}
	if s := strings.TrimSpace(raw); s != "" {
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			return nil, fmt.Errorf("payload 不是合法 JSON: %w", err)
		}
	}
	if len(p.Steps) == 0 {
		return AllSteps(), nil
	}
	seen := make(map[string]struct{}, len(p.Steps))
	out := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		s = strings.TrimSpace(s)
		if !IsValidStep(s) {
			return nil, fmt.Errorf("未知步骤 %q（可用: %s）", s, strings.Join(AllSteps(), ", "))
		}
		if _, dup := seen[s]; dup {
			continue // 重复步骤重跑没有信息增量，只会拉长总耗时
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

// BuildReport 汇总演练报告（收集被跳过的步骤名）。
func BuildReport(steps []StepResult) Report {
	r := Report{Steps: steps}
	for _, s := range steps {
		if s.skipped {
			r.Skipped = append(r.Skipped, s.Name)
		}
	}
	return r
}

// MarshalReport 序列化报告（写入 CommandResult.Result）。
func MarshalReport(r Report) string {
	b, err := json.Marshal(r)
	if err != nil {
		return "" // 仅基本类型字段，实际不可达；回执空串好过半截 JSON
	}
	return string(b)
}

// ---------------------------------------------------------------- 执行

// Run 顺序执行步骤并返回逐步结果。steps 为空时全跑。
func Run(ctx context.Context, steps []string, deps Deps) []StepResult {
	if len(steps) == 0 {
		steps = AllSteps()
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	total, cancel := context.WithTimeout(ctx, TotalBudget)
	defer cancel()

	out := make([]StepResult, 0, len(steps))
	for _, name := range steps {
		if total.Err() != nil {
			out = append(out, skip(name, "演练总预算（150s）已耗尽，本步未执行"))
			continue
		}
		res := runStep(total, name, deps)
		deps.Log.Info("drill_step", "step", name, "hit", res.Hit,
			"latency_ms", res.LatencyMs, "note", res.Note)
		out = append(out, res)
	}
	return out
}

func runStep(parent context.Context, name string, deps Deps) StepResult {
	ctx, cancel := context.WithTimeout(parent, stepBudget(name))
	defer cancel()
	start := time.Now()
	switch name {
	case StepProcChain:
		return stepProcChain(ctx, start, deps)
	case StepPortScan:
		return stepPortScan(ctx, start, deps)
	case StepServiceEvt:
		return stepServiceEvt(ctx, start, deps)
	case StepRegRun:
		return stepRegRun(ctx, start, deps)
	case StepCanaryTouch:
		return stepCanaryTouch(ctx, start, deps)
	default:
		return skip(name, "未知步骤（本探针版本不支持）")
	}
}

// skip 构造"前置不满足"结果：Hit=false + skipped 标记，不算失败——
// 报告要能区分"没测"与"测了没中"。
func skip(name, why string) StepResult {
	return StepResult{Name: name, ExpectedRule: expectedRuleOf(name), Note: "skipped: " + why, skipped: true}
}

func expectedRuleOf(name string) string {
	switch name {
	case StepProcChain:
		return PipelineSentinel
	case StepPortScan:
		return "NW-001/NW-004"
	case StepServiceEvt:
		return "EVT-SVCINST"
	case StepRegRun:
		// P-001（持久化基线层）与 HG-023（规则层）是同一条 T1547.001 的两条
		// 检测路径：regwatch 开启时 P-001 秒级，否则等 5min 轮询；
		// HG-023 在进程扫描（2s）内必现。命中任一即算该步通过。
		return "P-001/HG-023"
	case StepCanaryTouch:
		return "FILE-CANARY"
	}
	return ""
}

// ---------------------------------------------------------------- 五个步骤

// stepProcChain 采集管线健康检查：拉起一个活 5s 左右的 cmd.exe，
// 轮询进程表确认"新进程被采集管线捕获"。这是唯一不匹配规则的步骤。
func stepProcChain(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepProcChain, ExpectedRule: PipelineSentinel}
	if deps.ProcSnapshot == nil {
		return skip(StepProcChain, "ProcSnapshot 未接线")
	}
	// 基线：演练前已存在的 PID 不算"新出现"。
	base := make(map[uint32]struct{}, 512)
	for _, p := range deps.ProcSnapshot() {
		base[p.PID] = struct{}{}
	}
	// 自造样本：echo 后跟 6 次回环 ping（约 5s），把 cmd.exe 生命周期
	// 撑过采集轮询周期，规避用户态轮询固有的 TOCTOU 盲区（仓库 5.3 的教训）。
	if _, err := spawnDetached("cmd", "/c", "echo zedr-drill & ping -n 6 127.0.0.1 >nul"); err != nil {
		res.Note = "spawn 失败: " + err.Error()
		return res
	}
	var observed uint32
	hitAt, ok := awaitHit(ctx, func() bool {
		for _, p := range deps.ProcSnapshot() {
			if p.PID == deps.SelfPID {
				continue // 自身/自身子树之外才叫"新被捕获"
			}
			if _, seen := base[p.PID]; seen {
				continue
			}
			if strings.EqualFold(p.Name, "cmd.exe") {
				observed = p.PID
				return true
			}
		}
		return false
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	if ok {
		res.Note = fmt.Sprintf("新 cmd.exe（PID %d）已出现在进程表，采集管线健康", observed)
	} else {
		res.Note = "10s 内未观察到新 cmd.exe——采集管线可能停摆或样本过快退出"
	}
	return res
}

// stepPortScan 网络行为检测：向 TEST-NET-3 保留网段（RFC 5737，不可路由）
// 的 20 个端口发起仅 SYN 的连接尝试，零数据传输。Connect 全部失败正是
// 期望形态——NW-001（端口扇出）与 NW-004（无响应）都按失败采样，
// 默认阈值（扇出 ≥12 端口 / 无响应 ≥15 次）20 次尝试足够触发。
func stepPortScan(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepPortScan, ExpectedRule: "NW-001/NW-004"}
	if !deps.NetWatchEnabled {
		return skip(StepPortScan, "HG_AGENT_NETWATCH 未启用，网络行为检测不可用")
	}
	if deps.AlertsSince == nil {
		return skip(StepPortScan, "AlertsSince 未接线")
	}
	// 为什么不套 cmd /c：Go 对含空格参数的引号包装会被 cmd /c 剥掉外层，
	// PowerShell 拿到未加引号的多 token 脚本直接解析失败（实测 exit 255）；
	// 直接拉起 powershell 由 Go 负责整体引号，脚本原样到达。
	// 为什么必须两波：netwatch 对首次 sighting 的进程只记基线不记事件
	//（防启动风暴）。瞬时把全部 SYN 发完，等采样器第一次看到时整批
	// 落进基线，永远零事件——v1/v2 E2E 未命中的根因。第一波 20 端口
	// 只为建基线，停 6s（≥3 个采样 tick）后第二波 60 个全新端口才
	// 会计入扇出：60 > NW-001 默认阈值 40（2026-11-14 上调）留余量。
	// BeginConnect 挂住不关：串行阻塞 Connect 到不可路由地址要等完整
	// SYN 超时（~21s/端口），60s 窗口只够摸 3 个端口。
	script := `$ss=@(); foreach($p in 44100..44119){ $c=New-Object Net.Sockets.TcpClient; $ss+=$c; $null=$c.BeginConnect('203.0.113.9',$p,$null,$null) }; Start-Sleep -Seconds 6; foreach($p in 44300..44359){ $c=New-Object Net.Sockets.TcpClient; $ss+=$c; $null=$c.BeginConnect('203.0.113.9',$p,$null,$null) }; Start-Sleep -Seconds 15; foreach($c in $ss){ try{$c.Close()}catch{} }`
	if _, err := spawnDetached("powershell", "-NoProfile", "-Command", script); err != nil {
		res.Note = "spawn 失败: " + err.Error()
		return res
	}
	var hit AlertView
	hitAt, ok := awaitHit(ctx, func() bool {
		a, found := deps.alertHit(start, "NW-001", "NW-004")
		if found {
			hit = a
		}
		return found
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	res.AlertID = hit.ID
	if ok {
		res.Note = "对 TEST-NET-3 不可路由网段的 SYN 扇出已被网络行为检测捕获（零真实外联）"
	} else {
		res.Note = "60s 内未出现 NW-001/NW-004 告警（阈值未达到或 netwatch 采样异常）"
	}
	return res
}

// drillServiceName / drillSvcPath 是演练自造服务：demand 启动类型（创建后
// 不启动）、binpath 指向不存在的文件——服务安装事件（System 7045）照发，
// 而服务本身永远不会运行任何代码。
const (
	drillServiceName = "zedr-drill-evt"
	drillSvcPath     = `C:\Temp\zedr-drill-evt.exe`
	drillRegValue    = "zedr-drill"
	drillRunKey      = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
)

// stepServiceEvt 事件日志层：创建一个 demand 空服务，等 E1 消费到
// 服务安装事件。finally 必删服务——演练不允许在目标机器留残留。
func stepServiceEvt(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepServiceEvt, ExpectedRule: "EVT-SVCINST"}
	if !deps.EvtLogEnabled {
		return skip(StepServiceEvt, "E1 事件日志接入未启用（HG_AGENT_EVTLOG），服务安装事件不可见")
	}
	if deps.AlertsSince == nil {
		return skip(StepServiceEvt, "AlertsSince 未接线")
	}
	cleanup := func() {
		// 清理用独立预算：走到这里时判断 ctx 可能已超时
		cctx, ccancel := context.WithTimeout(context.Background(), cleanupWait)
		defer ccancel()
		if _, err := runSync(cctx, "sc.exe", "delete", drillServiceName); err != nil {
			deps.warn("drill_cleanup_failed", "what", "sc delete "+drillServiceName, "err", err.Error())
		}
	}
	out, err := runSync(ctx, "sc.exe", "create", drillServiceName,
		"binpath=", drillSvcPath, "start=", "demand")
	if err != nil {
		cleanup() // 半创建成功也要清：残留 demand 服务是配置漂移
		res.Note = "sc create 失败: " + tailLine(out, err)
		return res
	}
	defer cleanup()

	var hit AlertView
	hitAt, ok := awaitHit(ctx, func() bool {
		a, found := deps.alertHit(start, "EVT-SVCINST")
		if found {
			hit = a
		}
		return found
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	res.AlertID = hit.ID
	if ok {
		res.Note = "服务安装事件（System 7045）已被 E1 事件日志层捕获，服务已删除"
	} else {
		res.Note = "60s 内未出现 EVT-SVCINST 告警（E1 游标轮询 30s/tick，事件可能落后于窗口）"
	}
	return res
}

// stepRegRun 持久化检测：写 HKLM Run 键（T1547.001 经典路径），等
// P-001（基线层）或 HG-023（规则层）命中，finally 必删注册表值。
func stepRegRun(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepRegRun, ExpectedRule: expectedRuleOf(StepRegRun)}
	if deps.AlertsSince == nil {
		return skip(StepRegRun, "AlertsSince 未接线")
	}
	cleanup := func() {
		cctx, ccancel := context.WithTimeout(context.Background(), cleanupWait)
		defer ccancel()
		if _, err := runSync(cctx, "reg.exe", "delete", drillRunKey, "/v", drillRegValue, "/f"); err != nil {
			deps.warn("drill_cleanup_failed", "what", "reg delete "+drillRegValue, "err", err.Error())
		}
	}
	out, err := runSync(ctx, "reg.exe", "add", drillRunKey,
		"/v", drillRegValue, "/t", "REG_SZ", "/d", drillSvcPath, "/f")
	if err != nil {
		cleanup() // 写入失败（如非管理员）也清一次，幂等
		res.Note = "reg add 失败（需要管理员/SYSTEM 权限）: " + tailLine(out, err)
		return res
	}
	defer cleanup()

	var hit AlertView
	hitAt, ok := awaitHit(ctx, func() bool {
		a, found := deps.alertHit(start, "P-001", "HG-023")
		if found {
			hit = a
		}
		return found
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	res.AlertID = hit.ID
	if ok {
		res.Note = "Run 键写入已被捕获（" + strings.Join(hit.RuleIDs, ",") + "）；注册表值已删除"
	} else {
		res.Note = "30s 内未出现 P-001/HG-023 告警（P-001 走持久化层 5min 轮询，regwatch 关闭时尤其滞后）"
	}
	return res
}

// stepCanaryTouch 勒索防御：删除一个探针自放的诱饵文件，等 FILE-CANARY
// 命中。诱饵由探针自检静默重建，演练不留缺口。
func stepCanaryTouch(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepCanaryTouch, ExpectedRule: "FILE-CANARY"}
	if deps.CanaryFile == nil {
		return skip(StepCanaryTouch, "CanaryFile 未接线")
	}
	if deps.AlertsSince == nil {
		return skip(StepCanaryTouch, "AlertsSince 未接线")
	}
	canary := deps.CanaryFile()
	if canary == "" {
		return skip(StepCanaryTouch, "未找到可用诱饵（HG_AGENT_FILE_DEFENSE 关闭或诱饵尚未放置）")
	}
	if err := os.Remove(canary); err != nil {
		res.Note = "删除诱饵失败: " + err.Error()
		return res
	}
	var hit AlertView
	hitAt, ok := awaitHit(ctx, func() bool {
		a, found := deps.alertHit(start, "FILE-CANARY")
		if found {
			hit = a
		}
		return found
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	res.AlertID = hit.ID
	if ok {
		res.Note = "诱饵删除已被勒索防御捕获；诱饵将由探针 30s 自检静默重建（" + redact.Path(canary) + "）"
	} else {
		res.Note = "30s 内未出现 FILE-CANARY 告警（USN/文件监控可能未覆盖诱饵目录）"
	}
	return res
}

// ---------------------------------------------------------------- 依赖与轮询原语

// alertHit 在"步骤开始之后"的新告警里找期望规则。
func (d Deps) alertHit(since time.Time, rules ...string) (AlertView, bool) {
	if d.AlertsSince == nil {
		return AlertView{}, false
	}
	for _, a := range d.AlertsSince(since) {
		for _, got := range a.RuleIDs {
			for _, want := range rules {
				if got == want {
					return a, true
				}
			}
		}
	}
	return AlertView{}, false
}

// awaitHit 每 2s 轮询一次 found，命中立即返回；ctx 到期判未命中。
// 先查一次再进 tick：判定动作本身可能已完成（采集是异步流水线）。
func awaitHit(ctx context.Context, found func() bool) (time.Time, bool) {
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	if found() {
		return time.Now(), true
	}
	for {
		select {
		case <-ctx.Done():
			return time.Time{}, false
		case <-ticker.C:
			if found() {
				return time.Now(), true
			}
		}
	}
}

// spawnDetached 拉起不共享控制台的子进程并后台回收（不 Wait 会泄漏
// 进程句柄——探针是长驻进程，积少成多）。
func spawnDetached(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { _ = cmd.Wait() }()
	return cmd, nil
}

// runSync 同步执行一个快速子命令（sc/reg），DETACHED 启动避免闪现控制台。
// 单独给 syncWait 预算：sc/reg 极端情况（SCM 卡死）不能吃掉整个判定窗口。
func runSync(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, syncWait)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// warn 空安全的日志（步骤可被单测直接驱动，Deps.Log 可能缺省）。
func (d Deps) warn(msg string, kv ...any) {
	if d.Log != nil {
		d.Log.Warn(msg, kv...)
	}
}

func elapsedMs(start, hitAt time.Time, hit bool) int64 {
	if hit {
		return hitAt.Sub(start).Milliseconds()
	}
	return time.Since(start).Milliseconds()
}

// tailLine 从子命令输出里取最后一个非空行（sc/reg 的报错在末行），
// 拼上错误本身；截断防超长输出撑爆回执。
func tailLine(out string, err error) string {
	s := strings.TrimSpace(err.Error())
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			s = t
		}
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}
