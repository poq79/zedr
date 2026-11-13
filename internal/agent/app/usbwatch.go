//go:build windows
// +build windows

// usbwatch 接线层：可移动介质监控（摆渡链 T1091）。
//
// 三段式：① 周期 diff 可移动卷 → 接入告警（含 USBSTOR 历史佐证）；
// ② 新卷根目录动态挂 RDCW 临时监控（AddDir）——落地事件直接进现有
// 落地索引，"USB 落地即执行"由既有 dropLayer 自动覆盖，零新检测逻辑；
// ③ 卷拔出 → watchLoop 因句柄失效自动退出，此处清理已知集。
//
// 诚实边界：
//   - 卷到达的感知粒度是 30s 轮询 diff（不是设备级即时事件）——对
//     "插入后立刻自动执行"的攻击有最多 30s 的盲窗；
//   - 首轮只建基线不告警（探针重启瞬间已在位的 U 盘不是"新接入"）；
//   - 只覆盖 DRIVE_REMOVABLE；USB 固定盘（外置 SSD 报 FIXED）走
//     FixedNTFSVolumes 的 USN 通道覆盖，两路不重复；
//   - 空读卡器也返回 REMOVABLE 类型，对根目录操作失败按卷不可用降级。
package agentapp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

const usbPollInterval = 30 * time.Second

// usbwatchLoop 是可移动卷巡检循环（usbKnown 为单 goroutine 状态）。
func (a *Agent) usbwatchLoop(ctx context.Context) {
	known := map[string]bool{}
	baselined := false

	ticker := time.NewTicker(usbPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cur := winapi.RemovableVolumes()
		curSet := map[string]bool{}
		for _, v := range cur {
			curSet[strings.ToUpper(v)] = true
		}

		if !baselined {
			// 首轮建基线：重启瞬间已在位的卷不是"新接入"
			baselined = true
			a.usbVolumes.Store(int64(len(curSet)))
			known = map[string]bool{}
			for v := range curSet {
				known[v] = true
			}
			continue
		}

		for v := range curSet {
			if !known[v] {
				known[v] = true
				a.onUsbArrive(v)
			}
		}
		for v := range known {
			if !curSet[v] {
				delete(known, v) // 卷拔出：watchLoop 句柄失效自动退出
				a.log.Info("usb_volume_removed", "volume", v)
			}
		}
		a.usbVolumes.Store(int64(len(curSet)))
	}
}

// onUsbArrive 处理新卷到达：告警（带 USBSTOR 历史佐证）+ 动态挂监控。
func (a *Agent) onUsbArrive(vol string) {
	a.log.Warn("usb_volume_arrived", "volume", vol)

	// 动态挂卷根监控：落地事件直接进现有索引与"落地即执行"链路。
	// fw 关闭时只告警不挂监控（能力降级如实）。
	watched := false
	if a.fw != nil {
		if err := a.fw.AddDir(vol + `\`); err != nil {
			a.log.Warn("usb_watch_failed", "volume", vol, "err", err)
		} else {
			watched = true
			a.log.Info("usb_watch_started", "volume", vol)
		}
	}

	// USBSTOR 历史：这台机器"曾经见过"多少 USB 存储设备——首次见到的
	// 新设备比"常用 U 盘再次插入"更值得人工看一眼。
	devs := winapi.UsbStorDevices()
	summary := fmt.Sprintf("可移动介质 %s 接入（%d 秒内感知）。本机 USB 存储设备历史 %d 台。"+
		"接入后的落地/执行行为已纳入既有检测链路（落地即执行、勒索速率）；"+
		"摆渡攻击（T1091）的常见形态是 U 盘投放样本并被自动/人工执行。",
		vol, usbPollInterval/time.Second, len(devs))
	if !watched {
		summary += "；注意：文件监控未启用，该卷的落地行为不可见。"
	}
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("usb:arrive:%s:%d", vol, time.Now().Truncate(time.Hour).Unix()),
		Title:       "可移动介质接入 " + vol,
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    model.SeverityMedium,
		Score:       45,
		ProcUser:    "SYSTEM/USBWATCH",
		RuleIDs:     []string{"USB-ARRIVE"},
		MITRE:       []string{"T1091"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "usbwatch", ID: "USB-ARRIVE", Name: "可移动介质接入",
				Score: 45, Note: summary, MITRE: "T1091",
			}},
			Notes: []string{
				"volume=" + vol,
				fmt.Sprintf("usbstor_history=%d", len(devs)),
				fmt.Sprintf("watching=%v", watched),
			},
		},
		OccurredAt: time.Now(),
	})
}
