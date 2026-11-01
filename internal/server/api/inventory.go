package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/server/domain"
	"zedr/internal/server/service"
)

// saveInventory 探针上报主机资产清单（分节、hash 幂等）。
// 终端身份来自 agentAuth 中间件注入的上下文，agent_id 不从请求体取。
func (h *agentHandler) saveInventory(w http.ResponseWriter, r *http.Request) {
	a := agentFrom(r.Context())
	var req struct {
		Sections []service.InventorySection `json:"sections"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	applied, err := h.deps.Services.Agent.SaveInventory(r.Context(), a.ID, req.Sections)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"applied": applied})
}

// inventoryQuerySections 是查询过滤的节名白名单，与 service 层上报白名单
// （service.inventorySectionNames）保持同一组节名。查询侧收敛节名的理由
// 与上报侧一致：拼错节名如果静默返回空清单，分析师会误读成"主机没有服务"，
// 必须显式 400。
var inventoryQuerySections = map[string]struct{}{
	"system":    {},
	"adapters":  {},
	"listeners": {},
	"services":  {},
	"tasks":     {},
	"startup":   {},
	"agent":     {},
	"defender":  {},
	"firewall":  {},
	"accounts":  {},
}

// getHostInventory 管理台查询主机资产清单。
//
// 支持 ?section= 按节过滤（多值：逗号分隔或重复参数，如
// ?section=services,tasks 或 ?section=services&section=tasks）；
// 非法节名整体 400，不做部分过滤。
//
// 响应带 ETag（按返回节的 (name,hash) 排序拼接后 SHA-256 前 16 位）：
// 管理台轮询场景下内容不变即命中 If-None-Match，返回 304 省流量。
// 清单 payload 本身可达数百 KB，终端多、页面多时这笔开销值得省。
func (h *adminHandler) getHostInventory(w http.ResponseWriter, r *http.Request) {
	sections, err := h.deps.Services.Agent.GetInventory(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	if raw := r.URL.Query()["section"]; len(raw) > 0 {
		want := make(map[string]struct{})
		for _, part := range raw {
			for _, name := range strings.Split(part, ",") {
				name = strings.TrimSpace(name)
				if _, ok := inventoryQuerySections[name]; !ok {
					httpx.WriteError(w, r, apperr.Invalid("非法的清单节名: %s", name))
					return
				}
				want[name] = struct{}{}
			}
		}
		filtered := make([]domain.HostInventorySection, 0, len(sections))
		for _, s := range sections {
			if _, ok := want[s.Name]; ok {
				filtered = append(filtered, s)
			}
		}
		sections = filtered
	}

	etag := inventoryETag(sections)
	w.Header().Set("ETag", etag)
	if ifNoneMatchHits(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"sections": sections, "total": len(sections),
	})
}

// inventoryETag 计算返回节的实体标签：节按名字排序后拼接 (name,hash)，
// SHA-256 取前 16 个十六进制字符。
// 排序是为了确定性——ListByAgent 的返回顺序依赖存储层，顺序一变
// 内容没变也算变了，ETag 就失去意义。带引号符合 RFC 7232 的 ETag 形态。
func inventoryETag(sections []domain.HostInventorySection) string {
	parts := make([]string, 0, len(sections))
	for _, s := range sections {
		parts = append(parts, s.Name+"\x00"+s.Hash)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

// ifNoneMatchHits 判断 If-None-Match 是否命中当前 ETag。
// 宽松匹配：容忍 W/ 前缀、引号有无与多值（逗号分隔）——浏览器与
// 各类 HTTP 客户端对 ETag 的回显格式并不完全一致，从严会漏 304。
func ifNoneMatchHits(header, etag string) bool {
	if header == "" {
		return false
	}
	cur := strings.Trim(etag, `"`)
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" {
			return true // 资源存在即命中（GET 场景下我们刚查出来，必然存在）
		}
		part = strings.TrimPrefix(part, "W/")
		if strings.Trim(part, `"`) == cur {
			return true
		}
	}
	return false
}
