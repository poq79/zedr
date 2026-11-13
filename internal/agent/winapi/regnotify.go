//go:build windows
// +build windows

// regnotify.go：自启动注册表键的实时变更通知（RegNotifyChangeKeyValue）。
//
// 为什么需要它：persist.go 的持久化监控是周期轮询 diff，攻击者从写入
// 自启动项到下一轮扫描之间有一个最长一个轮询周期的可见窗口。本文件把
// 这个窗口压到秒级：RegNotifyChangeKeyValue 在键被修改的瞬间唤醒守护
// goroutine，上层据此触发一次即时重扫（重扫/告警归上层接线，本文件
// 只做"通知"；周期轮询保持不变，作为兜底）。
//
// 实现口径（对契约"阻塞模式"的偏离，实测依据见 armNotifyAsync 注释）：
// 挂载用异步形态（变更经每守护一个的事件送达），等待用
// WaitForSingleObject + 500ms 超时循环。阻塞形态（asynchronous=FALSE）
// 在内核上两头都不成立：THREAD_AGNOSTIC 挂不上（ERROR_INVALID_PARAMETER，
// 2026-11 Windows Server 2022 实测，并非"仅老系统"），降级后的线程绑定
// 形态在关句柄取消时偶发永久不返回（真机复现）。事件形态下等待自带
// 超时兜底，Close 的退出保证不再依赖"关句柄必然中止阻塞调用"。
//
// 用法（契约）：
//
//	w, err := winapi.StartRegWatch(winapi.DefaultRegWatchKeys(), onChange, log)
//	defer w.Close()
//
// onChange 的参数是键的显示路径（HKLM\... / HKCU\... / HKEY_USERS\<SID>\...），
// 可能从多个 goroutine 并发触发；同键 1s 内的重复通知已在本层合并，
// 但更粗的消抖/去重是调用方的责任。
//
// 线程成本：守护 goroutine 阻塞在 WaitForSingleObject 上，每个守护键
// 仍然占住一个 OS 线程（默认约 1MB 栈保留 + 一个内核等待对象，几乎不
// 耗 CPU；500ms 的等待超时每键每秒只唤醒 2 次）。DefaultRegWatchKeys
// 刻意把键数压在 ~10 个（6 固定 + 2×已加载用户数），扩表前先评估线程
// 预算，或改造成"多事件单线程 WaitForMultipleObjects"。
//
// 诚实边界——以下变更语义覆盖不到，周期轮询兜底仍然必要：
//   - RegRestoreKey（hive 还原）：官方文档（RegRestoreKey Remarks）明言
//     RegNotifyChangeKeyValue 检测不到它做的修改；
//   - 通知是"边沿 + 无细节"：只告知"这个键变过"，不告知哪个值变了，
//     也没有历史可补——由一次性语义必然导出，从上一通知返回到重新挂上
//     之间的变更不会补报（重挂间隙是本 API 的固有竞态）；
//   - 守护尚未挂上（键打开失败退避重试期间、goroutine 启动初期）发生的
//     变更收不到；
//   - hive 加载/卸载（RegLoadKey/RegUnLoadKey）是否会触发父键通知文档
//     未作承诺——用户 hive 在守护启动后才加载的情形靠重试队列补挂，
//     不指望父键通知。
package winapi

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// 变更过滤器：值集变化（LAST_SET，增/删/改值）+ 子键增删（NAME）。
// 不订阅 ATTRIBUTES/SECURITY——自启动项检测只关心"谁会被执行"，
// 安全描述符变化只会放大噪声。
const regNotifyFilter = windows.REG_NOTIFY_CHANGE_LAST_SET | windows.REG_NOTIFY_CHANGE_NAME

const (
	// 键打开失败的重试退避：5s 起指数翻倍，5min 封顶。封顶值与 persist
	// 的轮询节奏对齐——退到顶就相当于退化成"多一轮周期轮询"，不会更差。
	regRetryBase = 5 * time.Second
	regRetryMax  = 5 * time.Minute

	// 等待变更的事件超时：唯一作用是让守护周期性醒来看一眼 closed 标志，
	// 使 Close 的退出保证不依赖"关句柄中止未决注册"的内核语义（实测该
	// 语义对非线程绑定注册不可靠）。500ms → Close 最坏 500ms 后完成，
	// 每键每秒 2 次唤醒，开销可忽略。
	regPollInterval = 500 * time.Millisecond

	// 同键重复通知的合并窗口：一次安装器可能连改十几次值，直发会把
	// 上层重扫打爆。1s 是"重扫几乎肯定已覆盖本批写入"与"延迟可忽略"
	// 之间的折中。注意这是限流不是排空：窗口内落掉的这次通知不会补发，
	// 恰好落在被合并窗口里、且在上层重扫读数之后才写入的变更，要等
	// 周期轮询兜底——这是刻意接受的小残差，换上层不被风暴打死。
	regMergeWindow = time.Second
)

// regPollMs 是 regPollInterval 的毫秒整数（WaitForSingleObject 的参数口径）。
const regPollMs = uint32(regPollInterval / time.Millisecond)

// persist 枚举口径里的用户 Run/RunOnce 路径（大小写与 persist.go 一致，
// 注册表路径不区分大小写，这里保持书写一致便于对照）。
const (
	regRunPath     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	regRunOncePath = `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
)

// RegWatchKey 描述一个被守护的注册表键。
type RegWatchKey struct {
	// Hive 是预置根句柄：windows.HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER /
	// HKEY_USERS（类型沿用 syscall.Handle，与探针既有注册表代码口径一致）。
	Hive syscall.Handle
	// Path 是相对 hive 的子键路径（如 `Software\Microsoft\...\Run`）。
	Path string
	// Subtree 为 true 时监听整个子树（IFEO 根键用；Run 这类叶子键 false）。
	Subtree bool
}

// DefaultRegWatchKeys 返回与 persist 枚举口径一致的自启动守护键集。
//
// 键位对照（对照 persist.go 的注册表部分）：
//   - HKLM\...\Run、RunOnce 与 HKLM\WOW6432Node\...\Run、RunOnce：
//     与 enumerateRegistryRun 的四个 HKLM 根一致；
//   - Winlogon：与 enumerateWinlogon 一致（Shell/Userinit/Taskman/AppSetup
//     都是该键的值，值变化由 LAST_SET 覆盖）；
//   - IFEO 根键：与 enumerateIFEO 一致，Subtree=true——Debugger 写在各
//     可执行名子键下，子键增删也要看见；
//   - 用户 Run/RunOnce：persist 枚举走 HKCU，但探针以 SYSTEM 运行时
//     HKCU 是 SYSTEM 自己的 hive，守护它会盯错对象。这里改为枚举
//     HKEY_USERS 直接子键，挑出已加载的真实用户 hive：跳过 _Classes
//     与系统态 hive（.DEFAULT/S-1-5-18/19/20/每服务 SID），再用"有无
//     Software 子键"剔除未加载的条目。注意 Software 子键检查单独
//     不够——2026-11 本机实测系统态 hive 同样带 Software 子键，
//     照单全收会把键集撑到 18 个（见 loadedUserRunKeys 注释）。
//
// 线程预算：键数 = 6 固定 + 2×已加载用户数，单用户机器 ~8 个。刻意不
// 守护 Services/计划任务：前者子键数量太大（数百个 Services 子键，每个
// 守护一个线程不可接受），后者不是注册表键；两者仍由 persist 周期轮询
// 覆盖。
func DefaultRegWatchKeys() []RegWatchKey {
	keys := []RegWatchKey{
		{Hive: syscall.Handle(windows.HKEY_LOCAL_MACHINE), Path: regRunPath},
		{Hive: syscall.Handle(windows.HKEY_LOCAL_MACHINE), Path: regRunOncePath},
		{Hive: syscall.Handle(windows.HKEY_LOCAL_MACHINE),
			Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
		{Hive: syscall.Handle(windows.HKEY_LOCAL_MACHINE),
			Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
		{Hive: syscall.Handle(windows.HKEY_LOCAL_MACHINE),
			Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`},
		{Hive: syscall.Handle(windows.HKEY_LOCAL_MACHINE),
			Path:    `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
			Subtree: true},
	}
	return append(keys, loadedUserRunKeys()...)
}

// loadedUserRunKeys 枚举 HKEY_USERS 下当前已加载用户 hive 的 Run/RunOnce。
//
// 枚举失败（理论上只在权限异常时发生）返回 nil 而不是 error：键集是
// 尽力而为的默认值，缺了用户 hive 还有 HKLM 侧守护与周期轮询兜底。
// 同理，中途枚举出错按枚举结束处理，不做半途重试。
func loadedUserRunKeys() []RegWatchKey {
	var h windows.Handle
	// subkey 传 nil 打开 HKEY_USERS 本体（列它的直接子键）
	if err := windows.RegOpenKeyEx(windows.HKEY_USERS, nil, 0,
		windows.KEY_ENUMERATE_SUB_KEYS, &h); err != nil {
		return nil
	}
	defer windows.RegCloseKey(h)

	var out []RegWatchKey
	for i := uint32(0); ; i++ {
		// SID 字符串最长 184 字符（S-1-5-80-* 服务 SID 也远小于此），256 足够
		const maxNameLen = 256
		nameBuf := make([]uint16, maxNameLen)
		nameLen := uint32(maxNameLen)
		if err := windows.RegEnumKeyEx(h, i, &nameBuf[0], &nameLen,
			nil, nil, nil, nil); err != nil {
			break // ERROR_NO_MORE_ITEMS 或真实错误：都按枚举结束处理
		}
		sid := windows.UTF16ToString(nameBuf[:nameLen])
		if strings.HasSuffix(strings.ToLower(sid), "_classes") {
			continue // 每用户 Classes 视图，自启动项不在里面
		}
		// 系统态 hive 显式排除。只靠"有无 Software 子键"过滤在本机实测
		// 不成立：.DEFAULT/S-1-5-18/19/20/每服务 hive（S-1-5-80-*）全都
		// 带 Software 子键，收进来是 5 个几乎不会真实执行 Run 键的守护
		// （白占 10 个常驻线程）。契约意图是"当前已加载用户"，即域账户
		// （S-1-5-21-*）；2026-11 本机实测过滤后恰好剩真实交互用户，
		// 单用户机器键集 8 个，落在 ~10 的线程预算内。
		if sid == ".DEFAULT" || sid == "S-1-5-18" ||
			sid == "S-1-5-19" || sid == "S-1-5-20" ||
			strings.HasPrefix(sid, "S-1-5-80-") {
			continue
		}
		// "有 Software 子键" = 该 hive 已加载且有完整配置；未加载的
		// 离境用户/损坏条目在这里被剔除。
		probe, err := windows.UTF16PtrFromString(sid + `\Software`)
		if err != nil {
			continue
		}
		var sk windows.Handle
		if err := windows.RegOpenKeyEx(windows.HKEY_USERS, probe, 0,
			windows.KEY_QUERY_VALUE, &sk); err != nil {
			continue // 未加载（离境用户）或权限不足：跳过
		}
		windows.RegCloseKey(sk)

		hive := syscall.Handle(windows.HKEY_USERS)
		out = append(out,
			RegWatchKey{Hive: hive, Path: sid + `\` + regRunPath},
			RegWatchKey{Hive: hive, Path: sid + `\` + regRunOncePath})
	}
	return out
}

// RegWatch 是一组处于守护状态的注册表键。非 nil 时调用方必须 Close。
type RegWatch struct {
	mu       sync.Mutex
	closed   bool
	stop     chan struct{} // 关闭即唤醒所有退避等待
	onChange func(string)
	log      *slog.Logger
	lastFire map[string]time.Time // 同键 1s 合并窗口的"上次回调时刻"
	guards   []*regGuard
	wg       sync.WaitGroup
}

// regGuard 是单个键的守护状态。
//
// "重试队列"按"每键一个 goroutine + 各自退避"实现，而不是共享队列：
// 打开/重挂都在自己的 goroutine 里完成，省掉一层队列同步；打开失败的
// 键只占一个挂起的 goroutine（退避定时器，无 OS 线程），直到成功或
// Close。
type regGuard struct {
	key     RegWatchKey
	display string         // 显示路径，也是 lastFire/日志的主键
	h       syscall.Handle // 当前打开的键句柄；0=未打开（只在持 w.mu 时读写）
	armed   chan struct{}  // 首次挂载前关闭（测试消除启动竞态用，见 waitGuardArmed）
}

// StartRegWatch 为每个键启动一个守护 goroutine，键发生变更时调用
// onChange(显示路径)。
//
// 行为约定：
//   - onChange 可能从多个 goroutine 并发触发、可能高频（本层只做同键
//     1s 合并），去抖/合并是调用方的责任；
//   - onChange 里不要同步调用 Close：Close 会等待全部守护 goroutine
//     退出，回调内同步 Close 会互相等待；
//   - 单个键打不开（权限不足/用户 hive 未加载）不阻塞整体：该键进
//     重试队列按 5s→5min 指数退避重试，成功后复位；全部键都打不开时
//     返回错误且不起任何 goroutine（此时无需 Close）；
//   - 每个守护占一个 OS 线程（见文件头注释），键数量要克制。
func StartRegWatch(keys []RegWatchKey, onChange func(keyPath string), log *slog.Logger) (*RegWatch, error) {
	if onChange == nil {
		return nil, errors.New("regwatch: onChange 回调不能为空")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if len(keys) == 0 {
		return nil, errors.New("regwatch: 未提供任何守护键")
	}

	// 先同步探活一遍（RegOpenKeyEx 微秒级）：拿到"至少一个键能用"的
	// 判定，避免"全部键打不开"时起一组永远不会成功的守护 goroutine
	// 却无人能 Close。探活失败的键仍会交给守护 goroutine 退避重试——
	// 探活只解决"是否值得启动"，不代替重试（ hive 可能在启动后才加载）。
	live := 0
	var firstErr error
	for _, k := range keys {
		h, err := openNotifyKey(k)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		windows.RegCloseKey(windows.Handle(h))
		live++
	}
	if live == 0 {
		return nil, fmt.Errorf("regwatch: 全部 %d 个键都无法以 KEY_NOTIFY 打开（首错: %v）",
			len(keys), firstErr)
	}

	w := &RegWatch{
		stop:     make(chan struct{}),
		onChange: onChange,
		log:      log,
		lastFire: make(map[string]time.Time, len(keys)),
	}
	for _, k := range keys {
		g := &regGuard{
			key:     k,
			display: displayPath(k),
			armed:   make(chan struct{}),
		}
		w.guards = append(w.guards, g)
		w.wg.Add(1)
		go w.guardLoop(g)
	}
	log.Info("regwatch: 自启动键实时守护已启动",
		"keys", len(keys), "preopened", live)
	return w, nil
}

// Close 停止全部守护并释放句柄。幂等；返回后不会再有 onChange 触发，
// 全部守护 goroutine 已退出（最坏等待一个 500ms 的轮询周期）。
//
// 取消不依赖"关句柄中止未决注册"：Close 关闭键句柄（内核对合法注册
// 通常会随句柄关闭终止并信号事件），但守护的等待自带 500ms 超时，
// 无论内核是否及时终止注册都能按时退出——实测关句柄对非线程绑定的
// 未决注册偶发不生效，不能作为唯一取消手段（见 armNotifyAsync 注释）。
// 存在固有极小窗口：goroutine 刚通过 closed 检查、尚未进入挂载调用，
// 此时句柄被关，挂载会落在已关闭的句柄值上；只有句柄值被回收复用才
// 可能命中，后果是一次错误键上的多余通知（无内存安全问题）。
func (w *RegWatch) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.stop) // 唤醒所有退避等待
	for _, g := range w.guards {
		w.closeGuardHandleLocked(g)
	}
	w.mu.Unlock()
	w.wg.Wait()
}

// guardLoop 是单个键的守护循环：打开键 → 挂异步通知 → 等事件 → 变更即
// 回调并重挂。退出条件只有 Close（其余一切故障都走退避重试）。
func (w *RegWatch) guardLoop(g *regGuard) {
	defer w.wg.Done()

	// 每个守护一个自动复位事件：变更经它送达。事件与键句柄生命周期
	// 解耦，Close 关句柄不影响它，守护的退出由超时+closed 保证有界。
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		// 事件创建失败意味着该键完全无法守护：记日志后放弃此键
		// （其余键不受影响——与"单键失败不阻塞整体"的契约一致）。
		w.log.Error("regwatch: 创建等待事件失败，放弃该键",
			"path", g.display, "err", err.Error())
		return
	}
	defer windows.CloseHandle(ev)

	backoff := regRetryBase
	for {
		if w.isClosed() {
			return
		}
		h, err := openNotifyKey(g.key)
		if err != nil {
			// 键打不开：用户 hive 尚未加载（登录中）/权限不足/键被删除。
			// 指数退避重试，成功后复位。
			w.log.Debug("regwatch: 键打开失败，退避重试",
				"path", g.display, "err", err.Error(), "retry_after", backoff.String())
			if !w.sleep(backoff) {
				return
			}
			backoff = min(backoff*2, regRetryMax)
			continue
		}

		// 打开成功：登记句柄（Close 负责关闭它）并清掉事件上的陈旧信号
		// （上一次注册被中止时可能已把事件置位，不清会让新挂载立即
		// 产生一次假触发）。
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			windows.RegCloseKey(windows.Handle(h))
			return
		}
		g.h = h
		select {
		case <-g.armed:
		default:
			close(g.armed)
		}
		w.mu.Unlock()
		windows.ResetEvent(ev)

		for {
			// 每次挂载前重新读句柄与 closed：Close 可能在两次挂载之间
			// 关掉了句柄，用旧值重挂会落在回收后的句柄上。
			w.mu.Lock()
			h := g.h
			closed := w.closed
			w.mu.Unlock()
			if closed || h == 0 {
				return // Close 已接管句柄收尾
			}

			if err := armNotifyAsync(h, g.key.Subtree, ev); err != nil {
				// 挂载失败：句柄多半已失效（键被删除 / hive 卸载）→
				// 重开。退避防"打开成功但挂载立即失败"的热旋。
				w.log.Debug("regwatch: 挂载失败，重开键",
					"path", g.display, "err", err.Error())
				w.mu.Lock()
				if w.closed {
					w.mu.Unlock()
					return
				}
				w.closeGuardHandleLocked(g)
				w.mu.Unlock()
				if !w.sleep(backoff) {
					return
				}
				backoff = min(backoff*2, regRetryMax)
				break
			}

			// 等待变更。注册在超时后依然在位（不重挂——同一 hKey 重挂
			// 会堆叠未决通知，之后每个都信号一次事件，产生连环假触发），
			// 只有事件真正触发（本次一次性注册已被变更消费）才重挂。
			armed := true
			for armed {
				s, werr := windows.WaitForSingleObject(ev, regPollMs)
				if w.isClosed() {
					return
				}
				switch {
				case werr != nil || s == uint32(windows.WAIT_FAILED):
					// 等待失败：句柄/事件异常 → 重开
					w.log.Debug("regwatch: 等待失败，重开键",
						"path", g.display, "wait_err", fmt.Sprint(werr), "status", s)
					w.mu.Lock()
					if w.closed {
						w.mu.Unlock()
						return
					}
					w.closeGuardHandleLocked(g)
					w.mu.Unlock()
					if !w.sleep(backoff) {
						return
					}
					backoff = min(backoff*2, regRetryMax)
					armed = false // 跳出内层 → 外层重开
				case s == uint32(windows.WAIT_OBJECT_0):
					// 变更发生。一次成功的挂载走到触发，说明键活着，
					// 退避复位。
					backoff = regRetryBase
					w.fire(g.display)
					armed = false // 跳出内层 → 重挂
				default:
					// WAIT_TIMEOUT：注册仍在位，继续等同一个事件
				}
			}
		}
	}
}

// armNotifyAsync 以异步形态在 h 上挂一次变更通知：注册立即返回，变更
// 经 ev 送达（一次性——触发即失效，调用方循环重挂）。同一 hKey 同时
// 只允许一个未决通知——顺序重挂即可，绝不在上一注册未消费前再挂同一个键。
//
// 为什么必须是事件形态而不是阻塞形态（2026-11 Windows Server 2022
// 10.0.20348 真机实测，文档与直觉都在这里失真）：
//  1. 阻塞形态（asynchronous=FALSE, event=NULL）挂 THREAD_AGNOSTIC 直接
//     ERROR_INVALID_PARAMETER——该 flag 与阻塞形态不兼容，"Win8+ 即支持"
//     的说法只对异步形态成立；
//  2. 降级成线程绑定的阻塞形态后，"关句柄中止阻塞调用"这一经典取消
//     手法不可靠：50 次采样探针 100% 能解除，但多键并发 Close 的真机
//     场景下复现过 goroutine 永久卡死在 RegNotifyChangeKeyValue 里
//     （Close 的 wg.Wait 随之挂死）。事件形态下注册即返回、等待自带
//     超时，两个问题同时消失。
func armNotifyAsync(h syscall.Handle, subtree bool, ev windows.Handle) error {
	// THREAD_AGNOSTIC：注册生命周期不绑定发起线程（Go 的 goroutine 会在
	// OS 线程间迁移，线程退出时线程绑定的未决通知会被丢弃/信号）。
	err := windows.RegNotifyChangeKeyValue(windows.Handle(h), subtree,
		regNotifyFilter|windows.REG_NOTIFY_THREAD_AGNOSTIC, ev, true)
	if err == windows.ERROR_INVALID_PARAMETER {
		// 老系统（Win7 及更早）不认识该标志：降级为线程绑定模式重挂一次。
		// 降级后果：注册与发起线程共存亡——但异步形态下线程先退出时
		// 内核会信号事件（MSDN 明言该行为），守护醒来重挂即可自愈，
		// 不会像阻塞形态那样永久挂死；"线程绝不迁移"在老系统上是
		// 最佳努力而非保证，属有意识的兼容取舍。
		err = windows.RegNotifyChangeKeyValue(windows.Handle(h), subtree,
			regNotifyFilter, ev, true)
	}
	return err
}

// openNotifyKey 以 KEY_NOTIFY 打开守护键（RegNotifyChangeKeyValue 文档
// 要求的最小权限）。不开写权限、不顺手用 KEY_ALL_ACCESS：最小权限既
// 是惯例也让"非 SYSTEM 环境下的降级运行"保持真实。
func openNotifyKey(k RegWatchKey) (syscall.Handle, error) {
	p, err := windows.UTF16PtrFromString(k.Path)
	if err != nil {
		return 0, fmt.Errorf("regwatch: 路径非法 %q: %w", k.Path, err)
	}
	var h windows.Handle
	if err := windows.RegOpenKeyEx(windows.Handle(k.Hive), p, 0,
		windows.KEY_NOTIFY, &h); err != nil {
		return 0, err
	}
	return syscall.Handle(h), nil
}

// fire 触发回调，带同键 1s 合并窗口。不持锁调用 onChange：回调属于
// 调用方代码，可能耗时甚至再入 RegWatch；closed 检查与 lastFire 更新
// 在同一把锁下，保证 Close 之后不再有新的回调发起。
func (w *RegWatch) fire(display string) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	now := time.Now()
	if last, ok := w.lastFire[display]; ok && now.Sub(last) < regMergeWindow {
		w.mu.Unlock()
		w.log.Debug("regwatch: 同键重复通知，已合并", "path", display)
		return
	}
	w.lastFire[display] = now
	cb := w.onChange
	w.mu.Unlock()
	cb(display)
}

// sleep 退避等待；Close 时立即返回 false（守护应当退出）。
func (w *RegWatch) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-w.stop:
		return false
	case <-t.C:
		return true
	}
}

func (w *RegWatch) isClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

// closeGuardHandleLocked 关闭守护当前持有的键句柄（必须持 w.mu）。
// g.h==0 表示已被 Close 或守护自己关过，跳过以防双重关闭。
func (w *RegWatch) closeGuardHandleLocked(g *regGuard) {
	if g.h != 0 {
		windows.RegCloseKey(windows.Handle(g.h))
		g.h = 0
	}
}

// displayPath 生成 onChange 回调与日志使用的显示路径。
func displayPath(k RegWatchKey) string {
	var root string
	switch windows.Handle(k.Hive) {
	case windows.HKEY_LOCAL_MACHINE:
		root = "HKLM"
	case windows.HKEY_CURRENT_USER:
		root = "HKCU"
	case windows.HKEY_USERS:
		root = "HKEY_USERS"
	case windows.HKEY_CLASSES_ROOT:
		root = "HKCR"
	default:
		root = fmt.Sprintf("hive(0x%x)", uintptr(k.Hive))
	}
	if k.Path == "" {
		return root
	}
	return root + `\` + k.Path
}

// waitExited 等待全部守护 goroutine 退出（供测试确认 Close 生效）。
func (w *RegWatch) waitExited(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// waitGuardArmed 等待指定显示路径的键完成首次通知挂载前的就绪点。
// 回执点是守护即将发起首次挂载的时刻（注册本身立即完成，但测试仍留
// 短暂宽限覆盖调度与 syscall 进入延迟）。键尚在重试退避中时超时返回 false。
func (w *RegWatch) waitGuardArmed(display string, timeout time.Duration) bool {
	w.mu.Lock()
	var armed chan struct{}
	for _, g := range w.guards {
		if g.display == display {
			armed = g.armed
			break
		}
	}
	w.mu.Unlock()
	if armed == nil {
		return false
	}
	select {
	case <-armed:
		return true
	case <-time.After(timeout):
		return false
	}
}
