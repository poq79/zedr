// 本文件实现探针自升级（④）的策略层：指令处理（handleSelfUpgrade）与
// 启动时换装（applyPendingUpgrade）。从 app.go 拆出的原因：升级是横跨
// "指令通道 + 文件舞步 + 进程生命周期"的独立能力，塞在 app.go 里会让
// 组装文件失去主线。
//
// ══ 完整时序（服务模式，推荐部署形态）══
//
//  1. 心跳取回 self_upgrade 指令 → handleSelfUpgrade：
//     拉清单（验签）→ 版本比较（仅接受更新）→ 下载到 <data>/upgrade.exe.new
//     （sha256 校验）→ 写 <data>/upgrade.pending.json → 换装舞步
//     （current→.old 备份、.new→current、尽力删 .old）→ 置退出标志。
//  2. handleCommands 把回执上报给服务端（回执在退出前送达，服务端不会把
//     指令挂在"已下发无回执"）→ maybeExitForUpgrade：尽力 flush 告警队列
//     （2s 预算）→ os.Exit(0)。
//  3. 进程未上报 SERVICE_STOPPED 即退出，SCM 视为异常终止，按恢复策略
//     （5s/10s/30s，见 cmd/agent/service_recovery.go）在 5s 内重启——这次
//     起来的就是新版本二进制（换装在退出前已完成）。
//
// 前台模式同样 exit，但没有任何东西会拉起：开发调试需手动重启（刻意
// 不在前台做自动拉起——绕过用户的终端会话自拉起进程是恶意软件行为）。
//
// ══ 为什么换装放在退出前而不是"重启后再换" ══
//
// 若只写标记等下次启动再换：SCM 拉起的仍是旧二进制，它换完文件后继续
// 以旧代码运行——一个长期不重启的服务永远激活不了新版本。在退出前完成
// 舞步，SCM 拉起即新版本，一次重启生效。applyPendingUpgrade 保留为
// "舞步中途被杀"的恢复路径（标记先于舞步写入，任何中断状态都可续上）。
package agentapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"

	"zedr/internal/model"
)

// 升级数据文件名（落盘在数据目录；.old 备份与目标二进制同目录）。
const (
	upgradeBinaryName  = "upgrade.exe.new"
	upgradePendingName = "upgrade.pending.json"
	upgradeOldSuffix   = ".old"
)

// pendingUpgrade 是换装标记文件的内容。
// 先写标记、再做文件舞步：两次 rename 之间进程被杀时，启动恢复靠它续上。
type pendingUpgrade struct {
	Target   string    `json:"target"`            // 当前运行 exe 的绝对路径（换装对象）
	New      string    `json:"new"`               // 已通过 sha256 校验的新二进制
	Version  string    `json:"version,omitempty"` // 目标版本（日志与排查用）
	StagedAt time.Time `json:"staged_at,omitempty"`
}

// ---------------------------------------------------------------- 指令处理

// handleSelfUpgrade 处理 self_upgrade 指令。任一步失败都以 failed 回执，
// 探针继续跑旧版本——升级失败的最坏结果就是"没升成"，绝不接受"升坏了"。
func (a *Agent) handleSelfUpgrade(ctx context.Context, c model.Command) model.CommandResult {
	res := model.CommandResult{CommandID: c.ID}
	// 双层开关的终端侧：服务端可以下指令，终端不开就不执行（对齐
	// terminate/quarantine 先例——现场排障时可以只关终端侧）
	if !a.cfg.UpgradeEnabled {
		res.Status = "failed"
		res.Result = "终端未启用自升级（HG_AGENT_UPGRADE_ENABLED=false）"
		return res
	}

	m, notModified, err := a.up.FetchUpgradeManifest(ctx)
	if err != nil {
		res.Status = "failed"
		res.Result = "拉取升级清单失败: " + err.Error()
		return res
	}
	if notModified || m == nil {
		res.Result = "服务端无可用更新"
		return res
	}

	cur := a.cfg.Version
	if compareVersions(m.Version, cur) <= 0 {
		// 只接受更新：回滚到旧版本必须走运维通道（清单签名 + 明确意图），
		// 不给"重放旧清单把探针降级到有漏洞版本"留门
		res.Result = fmt.Sprintf("已是最新版本（当前 %s，服务端 %s）", cur, m.Version)
		return res
	}

	exe, err := os.Executable()
	if err != nil {
		res.Status = "failed"
		res.Result = "定位当前可执行文件失败: " + err.Error()
		return res
	}

	newBin := a.cfg.Path(upgradeBinaryName)
	if err := a.up.DownloadUpgradeBinary(ctx, newBin, m); err != nil {
		res.Status = "failed"
		res.Result = "下载升级包失败: " + err.Error()
		a.log.Warn("self_upgrade_download_failed", "err", err, "command", c.ID)
		return res
	}

	p := pendingUpgrade{Target: exe, New: newBin, Version: m.Version, StagedAt: time.Now()}
	// 标记先于舞步：下面任何一步被杀，重启后的 applyPendingUpgrade 都能续上
	if err := writePendingUpgrade(a.cfg.Path(upgradePendingName), p); err != nil {
		res.Status = "failed"
		res.Result = "写升级标记失败: " + err.Error()
		return res
	}
	deferredOld, err := performUpgradeSwap(p)
	if err != nil {
		// 舞步内部已回滚（.old 还原为 current）；删标记防止下次启动重试
		_ = os.Remove(a.cfg.Path(upgradePendingName))
		res.Status = "failed"
		res.Result = "换装失败（已回滚到当前版本）: " + err.Error()
		a.log.Warn("self_upgrade_swap_failed", "err", err, "command", c.ID)
		return res
	}
	_ = os.Remove(a.cfg.Path(upgradePendingName)) // 换装完成，标记即完成使命
	if deferredOld {
		a.log.Warn("self_upgrade_old_cleanup_deferred",
			"hint", "旧版本备份 .old 仍被本进程持有，下次启动自动清理")
	}

	// 级别用 warn：版本切换是审计关心的运维事件，即使服务端此刻收不到
	// 这条日志，本地文件里也有据可查
	a.log.Warn("self_upgrade_ready", "from", cur, "to", m.Version,
		"target", filepath.Base(exe), "command", c.ID)
	a.upgradeExit.Store(true)
	res.Result = fmt.Sprintf("升级包 v%s 已完成换装并通过校验，探针即将重启进入新版本（当前 %s）",
		m.Version, cur)
	return res
}

// maybeExitForUpgrade 在指令回执上报完成后检查是否需要为换装退出进程。
// 放在回执之后而不是 handleSelfUpgrade 内部直接 exit：进程在回执送达前
// 消失，服务端会把这个指令永远挂在"已下发、无回执"。
func (a *Agent) maybeExitForUpgrade() {
	if !a.upgradeExit.CompareAndSwap(true, false) {
		return
	}
	// 尽力把队列里已产生的告警送出去（2s 预算）：换装及时性优先，
	// 送不完的留在下一次运行——队列在内存里，exit 即失，可接受
	if a.up.Pending() > 0 && a.up.Enrolled() {
		fctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = a.up.Flush(fctx)
		cancel()
	}
	mode := "foreground"
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		mode = "service"
	}
	a.log.Warn("self_upgrade_exiting", "mode", mode,
		"hint", "服务模式由 SCM 恢复策略 5s 内拉起新版本；前台模式需手动重启")
	os.Exit(0)
}

// ---------------------------------------------------------------- 换装舞步

// performUpgradeSwap 执行换装舞步：current→.old 备份、.new→current、
// 尽力删 .old。两次 rename 相邻执行，中间不插入任何可失败的 IO——
// 这是把"进程在两步之间死掉、target 路径缺失"的窗口压到最小的全部手段。
//
// 返回 deferredOld=true 表示 .old 删除失败（运行中进程仍持有旧镜像，
// Windows 上删除必失败，属预期）：备份会留到下次启动清理。
func performUpgradeSwap(p pendingUpgrade) (deferredOld bool, err error) {
	old := p.Target + upgradeOldSuffix
	if err := os.Rename(p.Target, old); err != nil {
		return false, fmt.Errorf("备份当前二进制失败: %w", err)
	}
	if err := swapNewOntoTarget(p.New, p.Target); err != nil {
		// 回滚保安装：宁可放弃这次升级，也不能让探针路径上没有二进制
		_ = os.Rename(old, p.Target)
		return false, fmt.Errorf("新二进制就位失败: %w", err)
	}
	if err := os.Remove(old); err != nil {
		return true, nil
	}
	return false, nil
}

// swapNewOntoTarget 把新二进制移动到目标路径。优先 rename（同卷瞬时完成）；
// 数据目录与安装目录可能不同卷，rename 失败时退化为"复制到目标目录
// 临时名 + rename"——目标目录内的 rename 是原子的，不会出现半个文件。
func swapNewOntoTarget(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开新二进制失败: %w", err)
	}
	defer in.Close()

	tmp := dst + ".incoming"
	out, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("创建换装临时文件失败: %w", err)
	}
	_, cpErr := io.Copy(out, in)
	clErr := out.Close()
	if cpErr == nil {
		cpErr = clErr
	}
	if cpErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("复制新二进制失败: %w", cpErr)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("换装临时文件就位失败: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- 启动换装

// applyPendingUpgrade 在 New() 最早期运行：完成（或续上）上次未竟的换装。
// 状态机覆盖标记文件可能留下的全部中断态；失败只告警不阻断启动——
// 探针跑旧版本是安全态，因换装问题起不来不是。
func applyPendingUpgrade(cfg *Config, log *slog.Logger) {
	// 无标记也先清一次上次换装遗留的备份：正常流程里 .old 在旧进程退出后
	// 才删得掉，能活到这里的 .old 已无人持有
	if exe, err := os.Executable(); err == nil {
		if err := os.Remove(exe + upgradeOldSuffix); err == nil {
			log.Info("self_upgrade_old_cleaned", "old", exe+upgradeOldSuffix)
		}
	}

	p, ok, err := readPendingUpgrade(cfg.Path(upgradePendingName))
	if err != nil {
		log.Warn("self_upgrade_pending_invalid", "err", err,
			"hint", "标记文件损坏，删除以避免每次启动重复告警")
		_ = os.Remove(cfg.Path(upgradePendingName))
		return
	}
	if !ok {
		return // 常态：没有待应用的升级
	}

	switch {
	case !fileExists(p.Target):
		// 舞步第一步完成、第二步未完成时 target 路径缺失（服务模式下
		// 进程根本起不来，能走到这里的只有前台手动拉起等边缘场景）
		if fileExists(p.New) {
			if err := swapNewOntoTarget(p.New, p.Target); err == nil {
				_ = os.Remove(p.Target + upgradeOldSuffix)
				_ = os.Remove(cfg.Path(upgradePendingName))
				log.Info("self_upgrade_applied", "version", p.Version,
					"note", "续上了被中断的换装")
				return
			}
		}
		old := p.Target + upgradeOldSuffix
		if fileExists(old) {
			if err := os.Rename(old, p.Target); err == nil {
				_ = os.Remove(cfg.Path(upgradePendingName))
				log.Warn("self_upgrade_rolled_back", "target", p.Target,
					"note", "换装中断且新二进制缺失，已从备份还原旧版本")
				return
			}
		}
		log.Warn("self_upgrade_unrecoverable", "target", p.Target, "new", p.New,
			"hint", "换装中断且无法自动恢复，需人工检查安装目录")
		_ = os.Remove(cfg.Path(upgradePendingName))

	case !fileExists(p.New):
		// 换装已完成（.new 已就位到 target），标记是残留：清掉即可
		_ = os.Remove(cfg.Path(upgradePendingName))
		log.Info("self_upgrade_marker_resolved", "version", p.Version,
			"note", "标记残留但换装已完成")

	default:
		// 标记已写、舞步未开始（上次进程在写标记后、换装前被杀）：
		// 续做舞步。失败保留标记，下次启动重试（瞬时锁会自愈）
		deferredOld, err := performUpgradeSwap(p)
		if err != nil {
			log.Warn("self_upgrade_swap_failed", "err", err,
				"hint", "已回滚，标记保留，下次启动重试")
			return
		}
		_ = os.Remove(cfg.Path(upgradePendingName))
		if deferredOld {
			log.Warn("self_upgrade_old_cleanup_deferred")
		}
		log.Info("self_upgrade_applied", "version", p.Version, "target", p.Target)
	}
}

// writePendingUpgrade / readPendingUpgrade 是标记文件的唯一读写口。
func writePendingUpgrade(path string, p pendingUpgrade) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func readPendingUpgrade(path string) (pendingUpgrade, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pendingUpgrade{}, false, nil
		}
		return pendingUpgrade{}, false, err
	}
	var p pendingUpgrade
	if err := json.Unmarshal(raw, &p); err != nil {
		return pendingUpgrade{}, false, err
	}
	if p.Target == "" || p.New == "" {
		return pendingUpgrade{}, false, errors.New("标记缺少 target 或 new 字段")
	}
	return p, true, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// ---------------------------------------------------------------- 版本比较

// compareVersions 逐段比较点分版本号：>0 表示 a 更新，<0 表示 b 更新，
// 0 表示相同。允许 "v" 前缀；段按十进制整数比较、缺位补 0（"1.2"=="1.2.0"）；
// 段内含非数字字符时该段退化为字符串比较（预发布号如 "1.0.0-rc1" 的
// 完整 semver 序不追求，只保证数字版本单调可判——清单下发用纯数字段）。
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		ai, aerr := strconv.Atoi(av)
		bi, berr := strconv.Atoi(bv)
		if aerr == nil && berr == nil {
			if ai != bi {
				if ai > bi {
					return 1
				}
				return -1
			}
			continue
		}
		if c := strings.Compare(av, bv); c != 0 {
			return c
		}
	}
	return 0
}
