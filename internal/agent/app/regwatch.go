//go:build windows
// +build windows

// regwatch 接线层：注册表自启动键实时通知 → 防抖 → 立即重扫持久化项。
//
// 语义是"事件驱动 + 轮询兜底"双层：通知把 persist 的 5min 周期窗口缩到
// 秒级，但通知本身是"边沿、无细节、可能漏"（winapi/regnotify.go 的诚实
// 边界：一次性语义固有竞态、RegRestoreKey 不可见、挂载就位前的变更收不到）
// ——所以 scanPersistence 的周期轮询原样保留，本层只负责"快"，不负责"全"。
package agentapp

import (
	"context"
	"time"

	"zedr/internal/agent/winapi"
)

// regWatchDebounce 是合并窗口：安装器/组策略刷新可能连改十几次 Run 键，
// 首个事件后等 3s 让同批变更落定，再做一次重扫（不是每次事件都扫——
// scanPersistence 全量枚举 7 类位置约 200ms，风暴时会放大成秒级 CPU）。
const regWatchDebounce = 3 * time.Second

// startRegWatch 启动守护并把事件接到重扫循环。
func (a *Agent) startRegWatch(ctx context.Context) {
	events := make(chan string, 1)
	rw, err := winapi.StartRegWatch(winapi.DefaultRegWatchKeys(), func(key string) {
		// 已有待处理事件就丢弃本次——反正是同批变更，重扫一次全覆盖
		select {
		case events <- key:
		default:
		}
	}, a.log)
	if err != nil {
		a.log.Warn("regwatch_disabled", "err", err)
		return
	}
	go a.regWatchLoop(ctx, rw, events)
	a.log.Info("regwatch_started", "note", "自启动注册表键实时守护已启动，变更将触发即时重扫")
}

// regWatchLoop 消费通知事件：首事件起等 3s 合并窗口（窗口内新事件只更新
// 日志键，不延长窗口——有界等待比无限顺延可预测），然后立即重扫。
func (a *Agent) regWatchLoop(ctx context.Context, rw *winapi.RegWatch, events chan string) {
	defer rw.Close()
	for {
		var key string
		select {
		case <-ctx.Done():
			return
		case key = <-events:
		}
		deadline := time.After(regWatchDebounce)
		for {
			select {
			case k := <-events:
				key = k // 只留最后一条做日志；重扫是全量的，合并几次无差别
			case <-deadline:
				a.log.Info("regwatch_trigger", "key", key)
				// 定向重扫：事件只会来自注册表键，只扫注册表三节
				//（全量 ~160ms 里服务/任务占大头；5min 周期轮询保持全量）
				a.scanPersistenceRegistryOnly()
				goto next
			case <-ctx.Done():
				return
			}
		}
	next:
	}
}
