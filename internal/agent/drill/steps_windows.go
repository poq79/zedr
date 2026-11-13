//go:build windows

// 五个演练步骤的 Windows 实现（自 cmd/powershell/sc/reg 全部走系统自带工具，
// 零真实恶意样本）。Linux 口径见 steps_linux.go；调度与报告结构在 drill.go。
package drill

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"zedr/internal/platform/redact"
)

// drillServiceName / drillSvcPath 是演练自造服务与 Run 键值共用的样本路径：
// demand 启动类型（创建后不启动）、binpath 指向不存在的文件——服务安装事件
// （System 7045）照发，而服务本身永远不会运行任何代码；同一路径用作 Run 键
// 值（REG_SZ 数据不执行）。
const (
	drillServiceName = "zedr-drill-evt"
	drillSvcPath     = `C:\Temp\zedr-drill-evt.exe`
	drillRegValue    = "zedr-drill"
	drillRunKey      = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
)

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
// 的端口发起仅 SYN 的连接尝试，零数据传输。Connect 全部失败正是
// 期望形态——NW-001（端口扇出）与 NW-004（无响应）都按失败采样。
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
// 逻辑平台无关（读 deps.CanaryFile + 删除 + awaitHit），按平台文件对称
// 存放：两份实现必须保持一致（对齐 steps_linux.go 同名函数）。
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

// tailLine 从子命令输出里取最后一个非空行（sc/reg 的报错在末行），
// 拼上错误本身；截断防超长输出撑爆回执。仅 Windows 步骤使用
// （Linux 步骤是进程内文件操作，无子命令输出可解析）。
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
