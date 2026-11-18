package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// upgradeMaterialReady 是批量升级端点的公共前置：总开关 + 物料三件齐 +
// 包文件实际可读。批次发起来时把"包不可读"拦在门外，而不是让每台探针
// 下载时失败、污染波次统计。
func (h *adminHandler) upgradeMaterialReady() (version string, err error) {
	if !h.deps.UpgradeEnabled {
		return "", apperr.Forbidden("服务端未启用探针自升级（HG_SERVER_UPGRADE_ENABLED）")
	}
	if h.deps.UpgradeFile == "" || h.deps.UpgradeVersion == "" {
		return "", apperr.Unavailable("服务端未配置升级包（HG_SERVER_UPGRADE_FILE/VERSION）")
	}
	if st, serr := os.Stat(h.deps.UpgradeFile); serr != nil || st.IsDir() {
		return "", apperr.Unavailable("升级包文件不可读，请检查 HG_SERVER_UPGRADE_FILE 路径")
	}
	return h.deps.UpgradeVersion, nil
}

// startFleetUpgrade 发起批量升级（adminOnly）。body 可空 = 全部终端；
// {"agent_ids":[...]} 指定子集。编排语义见 service/upgrade.go。
func (h *adminHandler) startFleetUpgrade(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	version, err := h.upgradeMaterialReady()
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var req struct {
		AgentIDs []string `json:"agent_ids"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("请求体读取失败"))
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			httpx.WriteError(w, r, apperr.Invalid("请求体格式错误: %v", err))
			return
		}
	}

	snap, err := h.deps.Services.Upgrade.StartFleet(r.Context(), req.AgentIDs, version, p.Username)
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("%s", err.Error()))
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "upgrade.fleet.start",
		snap.ID, fmt.Sprintf("target=%s queued=%d/%d", snap.TargetVersion, snap.QueueRemain, snap.Total),
		httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, snap)
}

// fleetUpgradeStatus 当前/最近一次批次快照；无批次返回 null。
func (h *adminHandler) fleetUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, r, http.StatusOK, h.deps.Services.Upgrade.Snapshot())
}

// abortFleetUpgrade 中止批次（已下发未执行的指令不召回，快照如实保留 pending）。
func (h *adminHandler) abortFleetUpgrade(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	snap, err := h.deps.Services.Upgrade.Abort()
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("%s", err.Error()))
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "upgrade.fleet.abort",
		snap.ID, "", httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, snap)
}

// resumeFleetUpgrade 恢复熔断暂停的批次（人工放行）。
func (h *adminHandler) resumeFleetUpgrade(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	snap, err := h.deps.Services.Upgrade.Resume()
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("%s", err.Error()))
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "upgrade.fleet.resume",
		snap.ID, "", httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, snap)
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
