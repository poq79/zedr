// 本文件 NEUTRAL：fs* 四端点双平台编译。平台差异收敛为三个钩子：
//   - validateFSPath（路径校验，Windows 要求盘符卷名 / Linux 要求绝对路径
//     防穿越——这是 LiveFS 移植的历史雷区，规则分治见 platform_*.go）；
//   - fileSignature（/fs/hash 的签名块，Linux 无 Authenticode 语义）；
//   - fsPathKey（collect 去重键的大小写口径）。
package liveapi

// fs.go：/fs、/fs/stat、/fs/read、/fs/hash 四个端点（契约 §5.2）。
// 路径校验 helper 为四端点共用，规则逐条对齐 docs/LIVE-TUNNEL.md §5.2。

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// signatureInfo 是文件签名验证的中性投影（/fs/hash 的 authenticode 块与
// procinfo 模块未签名计数的共用钩子返回值）。Windows 由 Authenticode
// 校验填充；Linux 无 Authenticode 语义，State 恒为 "unsupported"（诚实
// 表达"本平台不做签名判定"，绝不冒充 unsigned）。
type signatureInfo struct {
	State  string
	Signer string
	Signed bool
}

// parseCursor 解析 v1 游标：`o<十进制offset>`；空串 = 从头。
// 前缀 o 预留给未来 v2 的其他游标形态（如名称续传位）。
func parseCursor(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	if len(raw) < 2 || raw[0] != 'o' {
		return 0, apperr.Invalid("cursor 格式错误")
	}
	n, err := strconv.Atoi(raw[1:])
	if err != nil || n < 0 {
		return 0, apperr.Invalid("cursor 格式错误")
	}
	return n, nil
}

// sortEntries 目录优先 + 名称 casefold 升序（契约 §5.2）。
// casefold 相同时按原始名二次排序：翻页按顺序切片，排序必须全序稳定，
// 否则两次请求间同 casefold 名（A.txt/a.txt）会重/漏。
func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].IsDir != es[j].IsDir {
			return es[i].IsDir
		}
		a, b := strings.ToLower(es[i].Name), strings.ToLower(es[j].Name)
		if a != b {
			return a < b
		}
		return es[i].Name < es[j].Name
	})
}

// writeFSErr 把 FSys 哨兵错误映射为规范 HTTP 错误。
func writeFSErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotExist):
		httpx.WriteError(w, r, apperr.NotFound("路径"))
	case errors.Is(err, ErrNotDir):
		httpx.WriteError(w, r, apperr.Invalid("目标不是目录"))
	case errors.Is(err, ErrIsDir):
		httpx.WriteError(w, r, apperr.Invalid("目标是目录，拒绝该操作"))
	case errors.Is(err, ErrPermission):
		httpx.WriteError(w, r, apperr.Forbidden("访问被操作系统拒绝"))
	default:
		httpx.WriteError(w, r, apperr.Internal(err))
	}
}

func (s *server) handleFSList(w http.ResponseWriter, r *http.Request) {
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	offset, err := parseCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limit := queryInt(r, "limit", fsListDefault, 1, fsListMax)

	entries, err := s.d.FS.List(path)
	if err != nil {
		writeFSErr(w, r, err)
		return
	}
	sortEntries(entries)

	// 游标分页：offset 越界（翻页瞬间目录被并发删空）按"空页 + 无下一页"
	// 处理而非报错——目录内容变化是常态，报错会让前端反复弹错
	next := ""
	switch {
	case offset >= len(entries):
		entries = []Entry{}
	default:
		end := offset + limit
		if end >= len(entries) {
			end = len(entries)
		} else {
			next = "o" + strconv.Itoa(end)
		}
		entries = entries[offset:end]
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"path":        path,
		"entries":     entries,
		"next_cursor": next,
	})
}

func (s *server) handleFSStat(w http.ResponseWriter, r *http.Request) {
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := s.d.FS.Stat(path)
	if err != nil && !errors.Is(err, ErrNotExist) {
		writeFSErr(w, r, err)
		return
	}
	// 不存在是正常调查结论（200 exists:false）而非 404——
	// "这个文件还在不在"本身就是问题的一部分
	exists := err == nil && e.Name != ""
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"path":       path,
		"exists":     exists,
		"size":       e.Size,
		"is_dir":     e.IsDir,
		"hidden":     e.Hidden,
		"system":     e.System,
		"readonly":   e.Readonly,
		"reparse":    e.Reparse,
		"mtime_unix": e.MtimeUnix,
	})
}

func (s *server) handleFSRead(w http.ResponseWriter, r *http.Request) {
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	offset := queryInt64(r, "offset", 0, math.MaxInt64)
	limit := queryInt64(r, "limit", fsReadDefault, fsReadMax)

	rc, size, err := s.d.FS.Open(path)
	if err != nil {
		writeFSErr(w, r, err) // 目录在 Open 处被拒绝（ErrIsDir → 400）
		return
	}
	defer rc.Close()

	// 越界判定：空文件是唯一例外——offset==size==0 表示"读空"，是合法请求
	if offset >= size && !(offset == 0 && size == 0) {
		httpx.WriteError(w, r, apperr.Invalid("偏移超出文件大小"))
		return
	}

	// 定位：FSys.Open 只保证 io.ReadCloser；可 Seek 则 O(1) 跳转，
	// 否则丢弃式跳过。两种方式都不把整个文件读进内存。
	body := io.Reader(rc)
	if sk, ok := rc.(io.Seeker); ok {
		if _, err := sk.Seek(offset, io.SeekStart); err != nil {
			httpx.WriteError(w, r, apperr.Internal(err))
			return
		}
	} else if offset > 0 {
		if _, err := io.CopyN(io.Discard, rc, offset); err != nil {
			httpx.WriteError(w, r, apperr.Internal(err))
			return
		}
	}

	// 嗅探窗口：最多 512B 且不超过 limit；借出的字节随后原样写回响应，
	// 不为嗅探多读一个字节
	sniff := make([]byte, sniffLen)
	if int64(len(sniff)) > limit {
		sniff = sniff[:limit]
	}
	n, _ := io.ReadFull(body, sniff) // EOF/UnexpectedEOF 都按"读到了多少算多少"
	sniff = sniff[:n]

	ct := http.DetectContentType(sniff)
	// DetectContentType 对文本类本就返回 "text/plain; charset=utf-8"，
	// 只在缺失 charset 时补，避免拼出双 charset
	if strings.HasPrefix(ct, "text/") && !strings.Contains(ct, "charset=") {
		ct += "; charset=utf-8"
	}

	remaining := limit - int64(n)
	send := size - offset - int64(n)
	if remaining < send {
		send = remaining
	}
	if send < 0 {
		send = 0
	}

	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("X-ZEDR-File-Size", strconv.FormatInt(size, 10))
	// 截断口径按 offset+limit 与 size 比（契约字面）：limit 覆盖越过 EOF 时
	// 必然已读到结尾，与实发字节数一致
	if offset+limit < size {
		h.Set("X-ZEDR-Truncated", "1")
	} else {
		h.Set("X-ZEDR-Truncated", "0")
	}
	h.Set("Content-Length", strconv.FormatInt(int64(n)+send, 10))

	w.WriteHeader(http.StatusOK)
	if n > 0 {
		if _, err := w.Write(sniff); err != nil {
			return
		}
	}
	_, _ = io.Copy(w, io.LimitReader(body, send))
}

// authenticodeInfo 是 /fs/hash 的签名块，字段名对齐契约 §5.2。
// issuer 目前映射不出来（signature.go 的 SignatureResult 只解出签名主体），
// 如实留空，不伪造。
type authenticodeInfo struct {
	State   string `json:"state"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

func (s *server) handleFSHash(w http.ResponseWriter, r *http.Request) {
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := s.d.FS.Stat(path)
	if err != nil {
		writeFSErr(w, r, err) // 不存在 → 404
		return
	}
	if e.IsDir {
		httpx.WriteError(w, r, apperr.Invalid("目录无法计算哈希"))
		return
	}
	if e.Size > hashMaxBytes {
		httpx.WriteError(w, r, apperr.Invalid("文件超过 2GB，拒绝哈希"))
		return
	}
	rc, size, err := s.d.FS.Open(path)
	if err != nil {
		writeFSErr(w, r, err)
		return
	}
	defer rc.Close()
	// 与 Stat 双检：Stat 与 Open 之间文件可能被换成大文件
	if size > hashMaxBytes {
		httpx.WriteError(w, r, apperr.Invalid("文件超过 2GB，拒绝哈希"))
		return
	}

	digest := sha256.New()
	// 256KB 定长缓冲流式哈希：命中 2GB 上限的文件内存占用也只有一层缓冲
	buf := make([]byte, hashBufSize)
	hashed, err := io.CopyBuffer(digest, rc, buf)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}

	sig := fileSignature(path)
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"path":   path,
		"sha256": hex.EncodeToString(digest.Sum(nil)),
		"size":   hashed,
		"authenticode": authenticodeInfo{
			State:   sig.State,
			Subject: sig.Signer,
		},
	})
}
