package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"

	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/rulehash"
)

// availableUpgrade 面向管理台的升级物料元信息：是否启用、目标版本、包大小。
// 与探针侧 manifest 端点的区别：这条给前端渲染"升级探针"入口与确认弹窗，
// 未启用时返回 enabled=false 而不是 503——前端按"功能未启用"静默隐藏入口。
// size 用 stat 而不是整包哈希：这里只要展示量级，manifest 端点才承担完整性。
func (h *adminHandler) availableUpgrade(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"enabled": false, "version": "", "size": int64(0)}
	if h.deps.UpgradeEnabled && h.deps.UpgradeFile != "" && h.deps.UpgradeVersion != "" {
		if st, err := os.Stat(h.deps.UpgradeFile); err == nil && !st.IsDir() {
			resp["enabled"] = true
			resp["version"] = h.deps.UpgradeVersion
			resp["size"] = st.Size()
		}
	}
	httpx.WriteJSON(w, r, http.StatusOK, resp)
}

// upgradeManifest 下发探针自升级包描述（版本/哈希/大小 + HMAC 签名）。
// 未配置 HG_SERVER_UPGRADE_FILE/HG_SERVER_UPGRADE_VERSION 时返回 503——
// 这是显式"未启用"语义，探针侧收到后按无升级处理而不是报错刷屏。
func (h *agentHandler) upgradeManifest(w http.ResponseWriter, r *http.Request) {
	if h.deps.UpgradeFile == "" || h.deps.UpgradeVersion == "" {
		httpx.WriteError(w, r, apperr.Unavailable("服务端未配置升级包"))
		return
	}
	f, err := os.Open(h.deps.UpgradeFile)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	defer f.Close()
	hsh := sha256.New()
	size, err := io.Copy(hsh, f)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	m := model.UpgradeManifest{
		Version: h.deps.UpgradeVersion,
		SHA256:  hex.EncodeToString(hsh.Sum(nil)),
		Size:    size,
	}
	if err := rulehash.SignUpgradeManifest(&m, h.deps.RuleSignKey); err != nil {
		h.deps.Log.ErrorContext(r.Context(), "upgrade_sign_failed", "err", err)
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	etag := `"` + m.SHA256[:16] + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	httpx.WriteJSON(w, r, http.StatusOK, m)
}

// upgradeBinary 下发升级二进制本体（完整性由 manifest 的 sha256 保证，
// 签名只覆盖 manifest——二进制下载走同源内网通道 + 哈希终验）。
func (h *agentHandler) upgradeBinary(w http.ResponseWriter, r *http.Request) {
	if h.deps.UpgradeFile == "" {
		httpx.WriteError(w, r, apperr.Unavailable("服务端未配置升级包"))
		return
	}
	f, err := os.Open(h.deps.UpgradeFile)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	defer f.Close()
	hsh := sha256.New()
	size, err := io.Copy(hsh, f)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	sha := hex.EncodeToString(hsh.Sum(nil))
	etag := `"` + sha[:16] + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", itoa(int(size)))
	_, _ = io.Copy(w, f)
}
