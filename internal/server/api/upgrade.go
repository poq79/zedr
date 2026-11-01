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
