// 本文件实现探针自升级的网络侧（④）：升级清单拉取（ETag 协商 + 验签）
// 与二进制下载（限量 + sha256 校验 + 落盘原子性）。
//
// 签名复用 platform/rulehash 的 SignUpgradeManifest/VerifyUpgradeManifest，
// payload 公式：`upgv1|<version>|<sha256hex>|<size>|`（注意 size 之后还有一个
// 分隔竖线，与 rulehash.go 的 upgradePayload 实现保持一字节一致）。
// 服务端 api 侧签清单时必须逐字节产出同样的 payload，任何一侧改动需两侧同步。
//
// 与 FetchRules/FetchIOCs 同源的两条纪律：
//   - 配置了签名密钥就强制验签，验不过拒绝应用（防下发链路被篡改成
//     "推送一个恶意二进制"——这是升级通道比规则通道更不可退让的原因）；
//   - 未配置密钥时放行（与规则包同一信任姿态，由 HG_AGENT_UPGRADE_ENABLED
//     的 SecurityWarning 在启动时提示），sha256 校验仍然兜底传输完整性。
package uplink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"hostguard/internal/model"
	"hostguard/internal/platform/rulehash"
)

// maxUpgradeBinarySize 是升级包体积硬上限。当前探针二进制约 15MB，
// 64MB 留足余量的同时，防止异常/恶意响应把磁盘或内存吃穿。
const maxUpgradeBinarySize = 64 << 20

// upgradeHTTP 是下载专用客户端：默认共享客户端 20s 总超时对大文件下载
// 太紧（慢链路下载 15MB 就会中途失败，造成"永远升不了级"的怪现象）。
// 独立实例避免动全局超时。
var upgradeHTTP = &http.Client{
	Timeout: 10 * time.Minute,
	Transport: &http.Transport{
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
	},
}

// FetchUpgradeManifest 拉取自升级包描述（GET /api/v1/agent/upgrade/manifest）。
// 服务端版本未变（ETag 命中 304）时返回 notModified=true、清单为 nil。
func (c *Client) FetchUpgradeManifest(ctx context.Context) (*model.UpgradeManifest, bool, error) {
	c.mu.Lock()
	etag := c.lastUpgradeETag
	key := c.ruleSignKey
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/api/v1/agent/upgrade/manifest", nil)
	if err != nil {
		return nil, false, err
	}
	c.decorate(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, decodeError(res.StatusCode, body)
	}
	var wrap struct {
		Data model.UpgradeManifest `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, false, fmt.Errorf("升级清单解析失败: %w", err)
	}

	// 字段健康检查：缺版本或哈希的清单没有意义，直接拒绝而不是让
	// 调用方在半路撞上空值
	m := &wrap.Data
	if m.Version == "" || len(m.SHA256) != 64 {
		return nil, false, fmt.Errorf("升级清单缺少 version 或 sha256（版本 %q，哈希长 %d）",
			m.Version, len(m.SHA256))
	}

	// 配置了密钥就强制验签：升级通道的签名是"这个二进制可执行"的
	// 最后一道闸，验不过宁可放弃升级（探针继续跑旧版本是安全的）
	if len(key) > 0 {
		if err := rulehash.VerifyUpgradeManifest(m, key); err != nil {
			return nil, false, fmt.Errorf("升级清单校验失败，已拒绝: %w", err)
		}
	}

	c.mu.Lock()
	c.lastUpgradeETag = res.Header.Get("ETag")
	c.mu.Unlock()
	return m, false, nil
}

// DownloadUpgradeBinary 下载升级二进制到 dst，下载完成后校验 sha256，
// 任何失败都清掉落盘文件再返回错误——绝不把半截/被篡改的文件留在
// 换装路径上（applyPendingUpgrade 会无条件信任 pending 标记里的 .new）。
//
// 体积双重限制：清单声明 Size 超限先拒绝；响应流再按硬上限截断读入，
// 防止"清单说小、实际灌大"的绕过。写盘走 .part 临时文件，校验通过
// 才 rename 到 dst，保证 dst 出现即可用。
func (c *Client) DownloadUpgradeBinary(ctx context.Context, dst string, m *model.UpgradeManifest) error {
	if m == nil {
		return errors.New("升级清单为空")
	}
	if m.Size > maxUpgradeBinarySize {
		return fmt.Errorf("清单声明升级包 %d 字节，超过上限 %d", m.Size, maxUpgradeBinarySize)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/api/v1/agent/upgrade/binary", nil)
	if err != nil {
		return err
	}
	c.decorate(req)

	res, err := upgradeHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("下载升级包失败: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
		return decodeError(res.StatusCode, body)
	}

	tmp := dst + ".part"
	cleanup := func() { _ = os.Remove(tmp) }

	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	hash := sha256.New()
	// 多读 1 字节用于探测超限：恰好 max 时合法，max+1 说明服务端违约
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(res.Body, maxUpgradeBinarySize+1))
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return fmt.Errorf("写入升级包失败: %w", err)
	}
	if n > maxUpgradeBinarySize {
		cleanup()
		return fmt.Errorf("升级包超过 %d 字节硬上限，已中止", maxUpgradeBinarySize)
	}
	if m.Size > 0 && n != int64(m.Size) {
		cleanup()
		return fmt.Errorf("升级包大小与清单不符（清单 %d，实际 %d）", m.Size, n)
	}

	sum := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(sum, m.SHA256) {
		cleanup()
		return fmt.Errorf("升级包 sha256 校验失败（清单 %s，实际 %s），已删除", m.SHA256, sum)
	}

	if err := os.Rename(tmp, dst); err != nil {
		cleanup()
		return fmt.Errorf("升级包就位失败: %w", err)
	}
	return nil
}
