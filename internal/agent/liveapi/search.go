//go:build windows
// +build windows

package liveapi

// search.go：/fs/search —— 目录限深搜索（契约 §11.1，狩猎场景）。
//
// 性能纪律：quick 检查（Open 验 MZ / 枚举流）只对"模式命中的条目"做——
// 全树逐文件 Open 在 C:\Windows 规模（30 万+条目）下不可接受；walk 本体
// 只做 ReadDir + 名称匹配，成本与条目数线性。
//
// junction 环防护：不进入 reparse 目录（与 v1 "junction 不可进入"口径一致），
// 否则 C:\Documents and Settings 这类循环 junction 会让 depth 限制形同虚设。

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	searchMaxDepth     = 4
	searchDefaultDepth = 2
	searchMaxLimit     = 200
	searchDefaultLimit = 100
)

// searchBudget 包级变量：30s 预算（契约），可注入是为了单测能在毫秒级
// 验证 truncated 分支，不必真等 30s。测试外不得改写。
var searchBudget = 30 * time.Second

// quickInfo 是条目的快速指纹（契约 quick 四布尔）。
type quickInfo struct {
	PE     bool `json:"pe"`
	ADS    bool `json:"ads"`
	Hidden bool `json:"hidden"`
	System bool `json:"system"`
}

// searchHit 在 Entry 之上补定位信息与 quick：
//   - path = 相对搜索根的完整相对路径（含文件名）；
//   - dir  = 相对搜索根的目录（"." 表示根层）——前端拼完整路径打开
//     抽屉用，depth≥2 的子目录命中没有它无法定位（前端联调补充契约）。
type searchHit struct {
	Entry
	RelPath string    `json:"path"`
	Dir     string    `json:"dir"`
	Quick   quickInfo `json:"quick"`
}

func (s *server) handleFSSearch(w http.ResponseWriter, r *http.Request) {
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pattern := r.URL.Query().Get("pattern")
	if pattern == "" {
		// 空 pattern = 全树枚举，成本模型完全不同——明确拒绝而不是当 "*"
		httpx.WriteError(w, r, apperr.Invalid("pattern 参数必填"))
		return
	}
	depth := queryInt(r, "depth", searchDefaultDepth, 1, searchMaxDepth)
	limit := queryInt(r, "limit", searchDefaultLimit, 1, searchMaxLimit)

	e, err := s.d.FS.Stat(path)
	if err != nil {
		writeFSErr(w, r, err)
		return
	}
	if !e.IsDir {
		httpx.WriteError(w, r, apperr.Invalid("搜索起点必须是目录"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), searchBudget)
	defer cancel()

	needle := strings.ToLower(pattern)
	hits := make([]searchHit, 0, limit)
	truncated := false

	// walk 顺序 = os.ReadDir 的文件名序（确定序保证 limit 截断结果可复现）
	var walk func(dir, rel string, level int)
	walk = func(dir, rel string, level int) {
		if ctx.Err() != nil {
			truncated = true
			return
		}
		if len(hits) >= limit {
			// limit 到达后立即停止整棵树的遍历（在入口判，避免继续
			// 深入子目录白耗 IO）；不计入 truncated——limit 是调用方
			// 要的上限，truncated 语义只归预算超时（契约口径）
			return
		}
		if level > depth {
			return
		}
		entries, err := s.d.FS.List(dir)
		if err != nil {
			// 单目录不可读（权限/瞬态）跳过：狩猎宁可少一块也不整体失败
			return
		}
		for _, en := range entries {
			if ctx.Err() != nil {
				truncated = true
				return
			}
			childRel := en.Name
			if rel != "" {
				childRel = rel + `\` + en.Name
			}
			if matchWildcard(needle, strings.ToLower(en.Name)) {
				hits = append(hits, s.buildHit(filepath.Join(dir, en.Name), en, childRel))
				if len(hits) >= limit {
					return
				}
			}
			if en.IsDir && !en.Reparse {
				walk(filepath.Join(dir, en.Name), childRel, level+1)
			}
		}
	}
	walk(path, "", 1)

	sortSearchHits(hits)
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"path":      path,
		"pattern":   pattern,
		"entries":   hits,
		"truncated": truncated,
	})
}

// buildHit 对命中的条目做 quick 检查。目录不验 MZ/ADS（无意义），
// hidden/system 直接取 List 时已拿到的属性，零额外成本。
func (s *server) buildHit(full string, en Entry, rel string) searchHit {
	q := quickInfo{Hidden: en.Hidden, System: en.System}
	if !en.IsDir {
		if rc, _, err := s.d.FS.Open(full); err == nil {
			var magic [2]byte
			_, _ = io.ReadFull(rc, magic[:])
			q.PE = magic[0] == 'M' && magic[1] == 'Z'
			_ = rc.Close()
		}
		if streams, err := winapi.EnumerateStreams(full); err == nil && len(streams) > 0 {
			q.ADS = true
		}
	}
	// filepath.Dir 对根层条目返回 "."，与前端契约口径一致
	return searchHit{Entry: en, RelPath: rel, Dir: filepath.Dir(rel), Quick: q}
}

// sortSearchHits 排序口径同 fs（目录优先 + casefold 升序），但比较键用
// 相对路径——搜索结果跨目录，纯名称排序会让同名文件交错难读。
func sortSearchHits(hits []searchHit) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].IsDir != hits[j].IsDir {
			return hits[i].IsDir
		}
		a, b := strings.ToLower(hits[i].RelPath), strings.ToLower(hits[j].RelPath)
		if a != b {
			return a < b
		}
		return hits[i].RelPath < hits[j].RelPath
	})
}

// matchWildcard 自实现 `*`/`?` 匹配（casefold 由调用方完成）。
// 为什么不用 path.Match：它的 `?`/`*` 匹配 rune 且带 `\\` 转义语义
// （Windows Separator），文件名含反斜杠时行为反直觉；经典双指针回溯
// 对本场景（pattern 短、目标为文件名）更可控。`?` 按字节匹配，含中文的
// 文件名配 `?` 会退化为多字节——可接受（模式的主要形态是 `*.exe`）。
func matchWildcard(pattern, s string) bool {
	pi, si := 0, 0
	star, ss := -1, 0
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			pi++
			si++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			pi++
			ss = si
			continue
		}
		if star >= 0 {
			// 回溯：让最近的 `*` 多吞一个字符
			pi = star + 1
			ss++
			si = ss
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
