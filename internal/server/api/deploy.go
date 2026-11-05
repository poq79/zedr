package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// deploy.go 是"接入新主机"部署引导的两个管理台端点（adminOnly + 审计）：
//
//	enroll-config  展示当前生效的 enroll token + 部署包可用性（引导页数据源）
//	agent-package  下发部署包 zip（探针 + 托盘 + 官方安装脚本）
//
// 与 agent 自升级端点（agentAuth，面向已装探针）的差异：这两个面向"还没装
// 探针的新机器"，消费方是管理员浏览器，走 JWT；token 是预共享注册凭据，
// 展示与下载都进审计流（与实时查询同一纪律）。

// deployEnrollConfig 返回接入引导需要的配置：enroll token + 部署包可用性。
// 服务端无法可靠推断自己在目标机器视角的可达地址（NAT/多网卡/反代），
// 管理台 URL 由前端用当前 origin 预填并允许修改，这里不下发。
func (h *adminHandler) deployEnrollConfig(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username,
		"deploy.enroll_config_read", "", "", httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"enroll_token":   h.deps.EnrollToken,
		"deploy_enabled": h.deps.DeployPackage != "",
		"deploy_version": h.deps.DeployVersion,
	})
}

// deployAgentPackage 下发部署包 zip。带 sha256 头 + ETag（与 upgradeBinary
// 同语义：浏览器下载后可对照校验，安装脚本在包内 README 提示核对命令）。
func (h *adminHandler) deployAgentPackage(w http.ResponseWriter, r *http.Request) {
	if h.deps.DeployPackage == "" {
		httpx.WriteError(w, r, apperr.Unavailable(
			"服务端未配置部署包（HG_SERVER_DEPLOY_PACKAGE），请先在服务端打包并配置路径"))
		return
	}
	f, err := os.Open(h.deps.DeployPackage)
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
	p := principal(r)
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username,
		"deploy.package_download", filepath.Base(h.deps.DeployPackage), sha[:16], httpx.ClientIP(r))

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	name := "zedr-deploy.zip"
	if h.deps.DeployVersion != "" {
		name = "zedr-deploy-v" + h.deps.DeployVersion + ".zip"
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("X-ZEDR-Package-SHA256", sha)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", itoa(int(size)))
	_, _ = io.Copy(w, f)
}
