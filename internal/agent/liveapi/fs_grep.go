package liveapi

// fs_grep.go：/fs/grep —— 单文件内容正则查找（AI 调查的"内容定位不搬内容"）。
//
// 设计口径：
//   - 定位：fs/read 是 512KB 原文流（暴露面大，对 AI 关闭），fs/grep 只回传
//     命中行片段——有界（每行 ≤240 字符、命中 ≤max）、脱敏面小，且正是调查
//     要的形态。这就是"内容查找不搬内容"。
//   - 为什么单文件、不递归：文件名发现归 /fs/search（通配符 + 限深目录树），
//     内容定位归 /fs/grep（单文件 + 正则），职责分离。递归内容 grep 要对
//     全树逐文件 Open+扫描，CPU 成本与误用面（对 C:\ 全盘来一发）都不可控，
//     留 P2 再评估。
//   - 为什么 RE2（Go regexp）：线性时间匹配、无回溯爆炸。pattern 是调用方
//     （可能是 AI 生成）的任意输入，ReDoS 在引擎层面天然不存在，不需要再
//     自造一层模式白名单/复杂度审计；Compile 失败直接 400 带原因。
//   - 不做文件大小准入：预算本身就封顶扫描面（见下），10GB 文件也只扫
//     2MB，无需按 size 拒绝。
//
// 资源上限（扫描面恒有界）：
//   - 单行保留缓冲 1MB：超长行超出部分只消费不保留，绝不让一行日志撑爆
//     内存（代价：1MB 之后的行尾不参与匹配，诚实取舍并写进注释）；
//   - 扫描预算 2MB 或 15s（grepMaxScanBytes / grepBudget 包级变量，注入
//     仅为单测，先例同 searchBudget；测试外不得改写）。字节预算逐块/逐行
//     查（纯整数比较，零成本），时间预算每 64KB 或每 1000 行查一次
//     （time.Now 有成本，按节流窗查）；触顶 truncated=true，已收集命中
//     仍然有效；
//   - 命中数到 max 即停扫描：省 CPU。matched 因此不承诺全文件总数，不做
//     matched_total，诚实输出已收集数；每行至多一条命中（grep -n 口径）。
//
// 二进制拒绝：首 512B 含 NUL → 200 + is_binary（不报错）。"这是二进制"
// 本身就是调查结论，调用方据此转 /analyze（PE 分析）或 /fs/hash（比对）。
// UTF-16 文本因含 NUL 同样落到此分支——与 grep/ripgrep 行为一致。
//
// 行扫描为什么用 bufio.Reader.ReadSlice 而不是 bufio.Scanner：Scanner 撞上
// 超长行返回 ErrTooLong 后不可续扫，且已消费字节数无从得知（offset 字段会
// 失真）；ReadSlice 的 ErrBufferFull 天然可续（行没完就继续消费），每个字节
// 的消费量精确可见——超长行"截断继续扫 + 偏移精确"只有它能直接表达。
//
// 行尾换行（含 CRLF 的 \r）在匹配前剥离：Windows 文件 CRLF 是常态，保留它
// 会让 `xxx$` 类锚点静默失配；offset / scanned_bytes 口径不受影响（换行
// 字节照常计入扫描量）。
//
// 接线（归主线会话）：liveapi.go New() 中
//
//	mux.HandleFunc("GET /fs/grep", s.handleFSGrep)
//
// 本文件只提供 handler 与测试，不改 liveapi.go。

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/redact"
)

const (
	grepMaxPatternLen = 200      // pattern 长度上限（字符）
	grepDefaultMax    = 50       // 命中上限默认值
	grepMaxMax        = 50       // 命中上限钳制峰值
	grepMaxLineBytes  = 1 << 20  // 单行保留缓冲上限 1MB，超出只消费不保留
	grepLineOutRunes  = 240      // 命中行回传最大字符数（按 rune 裁，不腰斩多字节）
	grepCheckBytes    = 64 << 10 // 时间预算检查节流窗（字节）
	grepCheckLines    = 1000     // 时间预算检查节流窗（行数）
)

// 预算硬顶：包级变量是为了单测注入（先例同 searchBudget）；测试外不得改写。
var (
	grepBudget = 15 * time.Second
	// grepMaxScanBytes 扫描字节预算：检查粒度是"块/行"，实际最多超出一个
	// ReadSlice 块（32KB），对 2MB 量级可忽略
	grepMaxScanBytes int64 = 2 << 20
)

// grepHit 是单条命中（契约字段）：line_no 1 基；line 前后 trim 且 ≤240 字符；
// line_truncated 标记输出被裁（240 字符裁剪或 1MB 行缓冲裁剪）；offset 是
// 该行起始字节偏移（含此前全部换行字节，从文件 0 开始）。
type grepHit struct {
	LineNo        int    `json:"line_no"`
	Line          string `json:"line"`
	LineTruncated bool   `json:"line_truncated"`
	Offset        int64  `json:"offset"`
}

func (s *server) handleFSGrep(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pattern := r.URL.Query().Get("pattern")
	if pattern == "" {
		// 空 pattern = 整文件逐行回传，成本模型完全不同——明确拒绝（同
		// /fs/search 对空 pattern 的口径）
		httpx.WriteError(w, r, apperr.Invalid("pattern 参数必填"))
		return
	}
	if utf8.RuneCountInString(pattern) > grepMaxPatternLen {
		httpx.WriteError(w, r, apperr.Invalid("pattern 超长（≤200 字符）"))
		return
	}
	// ci（case insensitive）：缺省/非法值一律 false，与 queryInt 的宽松口径
	// 一致——bool 参数不值得一个 400 分支
	expr := pattern
	if ci, perr := strconv.ParseBool(r.URL.Query().Get("ci")); perr == nil && ci {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		// 带原因返回：调用方（含 AI）需要知道哪个 token 非法才能自行修正
		httpx.WriteError(w, r, apperr.Invalid("pattern 不是合法的正则表达式: %s", err.Error()))
		return
	}
	maxHits := queryInt(r, "max", grepDefaultMax, 1, grepMaxMax)

	e, err := s.d.FS.Stat(path)
	if err != nil {
		writeFSErr(w, r, err) // 不存在 → 404，与 /fs/read 同语义
		return
	}
	if e.IsDir {
		httpx.WriteError(w, r, apperr.Invalid("目录无法 grep 内容，文件名发现用 /fs/search"))
		return
	}
	rc, _, err := s.d.FS.Open(path)
	if err != nil {
		writeFSErr(w, r, err) // Stat 与 Open 之间被删除/换权限的窗口
		return
	}
	defer rc.Close()

	// 二进制嗅探：首 512B 含 NUL 即判二进制（grep 的经典判法）。借出的字节
	// 随后回灌扫描流，不为嗅探多读一个字节（同 /fs/read 惯例）。
	sniff := make([]byte, sniffLen)
	sn, _ := io.ReadFull(rc, sniff)
	sniff = sniff[:sn]
	if bytes.IndexByte(sniff, 0) >= 0 {
		// 拒绝本身是调查结论：200 而非 4xx，note 指路替代端点
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"path":          path,
			"pattern":       pattern,
			"matched":       0,
			"items":         []any{},
			"scanned_bytes": sn,
			"elapsed_ms":    time.Since(start).Milliseconds(),
			"truncated":     false,
			"is_binary":     true,
			"note":          "二进制文件不支持 grep，用 /analyze 做 PE 分析或 /fs/hash 比对",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), grepBudget)
	defer cancel()
	hits, scanned, truncated := scanGrep(io.MultiReader(bytes.NewReader(sniff), rc), ctx, re, maxHits, path)

	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"path":          path,
		"pattern":       pattern,
		"matched":       len(hits),
		"items":         hits,
		"scanned_bytes": scanned,
		"elapsed_ms":    time.Since(start).Milliseconds(),
		"truncated":     truncated,
	})
}

// scanGrep 流式逐行扫描：返回（命中、已消费字节、是否预算截断）。
// 语义要点：max 命中即停（truncated 保持 false——上限是调用方要的，与
// /fs/search 口径一致）；预算触顶把当行已保留的前缀照常参与匹配后停止，
// truncated=true 表示"结果可能不完整"；读错误（非 EOF）降级为 truncated
// 而非 500——grep 是线索生成器，半途结果与预算触顶对外语义一致，且已
// 读到的命中不应陪葬。
func scanGrep(src io.Reader, ctx context.Context, re *regexp.Regexp, maxHits int, path string) ([]grepHit, int64, bool) {
	br := bufio.NewReaderSize(src, 32<<10)

	hits := make([]grepHit, 0, 8)
	var (
		pos        int64 // 已消费字节（含换行与被丢弃的超长行尾部）
		lineNo     int
		truncated  bool
		sinceLines int   // 时间预算节流窗计数（行）
		sinceBytes int64 // 时间预算节流窗计数（字节）
	)

	for {
		lineStart := pos
		var (
			cur       []byte // 当前行保留内容（≤ grepMaxLineBytes）
			cut       bool   // 1MB 行缓冲是否发生裁剪
			lineBytes int64  // 当前行已消费字节（含换行）——行存在性判据
			eof       bool
			stop      bool
		)
		for {
			chunk, err := br.ReadSlice('\n')
			n := int64(len(chunk))
			pos += n
			lineBytes += n
			sinceBytes += n
			if n > 0 {
				// 1MB 保留上限：超出部分只消费不保留（防单行日志撑爆内存）
				if room := grepMaxLineBytes - int64(len(cur)); room > 0 {
					if room >= n {
						cur = append(cur, chunk...)
					} else {
						cur = append(cur, chunk[:room]...)
						cut = true
					}
				} else {
					cut = true
				}
			}
			if err == nil {
				break // 行完整（含换行符）
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				// 行还没完：字节预算逐块查——超长行可能上 GB，不能等行结束
				if pos >= grepMaxScanBytes {
					truncated, stop = true, true
					break
				}
				if sinceBytes >= grepCheckBytes {
					sinceBytes = 0
					if ctx.Err() != nil {
						truncated, stop = true, true
						break
					}
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				eof = true
				break
			}
			// 读错误（非 EOF）：按截断返回，已保留内容照常匹配
			slog.Warn("grep_read_error", "path", redact.Path(path), "err", err.Error())
			truncated, stop = true, true
			break
		}

		// 行存在性 = 至少消费过 1 字节：空文件/以 \n 收尾的文件末尾不会
		// 造出幽灵行（`^`/`.*` 类模式匹配空串，幽灵行会凭空多出命中）
		if lineBytes > 0 {
			lineNo++
			cur = stripEOL(cur)
			if re.Match(cur) {
				hits = append(hits, buildGrepHit(lineNo, cur, cut, lineStart))
				if len(hits) >= maxHits {
					// 到 max 即停：后续内容不再消费，matched 不承诺全文件总数
					break
				}
			}
		}
		if stop || eof {
			break
		}
		// 行边界预算检查：字节预算逐行查（整数比较）；时间预算按节流窗查
		if pos >= grepMaxScanBytes {
			truncated = true
			break
		}
		sinceLines++
		if sinceLines >= grepCheckLines || sinceBytes >= grepCheckBytes {
			sinceLines, sinceBytes = 0, 0
			if ctx.Err() != nil {
				truncated = true
				break
			}
		}
	}
	return hits, pos, truncated
}

// stripEOL 去掉行尾换行（先 \n 后 \r，CRLF 一次剥净；行尾 \r 一并剥离——
// 单个 \r 作行分隔的老 Mac 文件不在此口径内，与 grep 行为一致）。
func stripEOL(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if n := len(b); n > 0 && b[n-1] == '\r' {
		b = b[:n-1]
	}
	return b
}

// buildGrepHit 把命中行裁成回传形态：前后 trim、≤240 字符（按 rune 裁，
// 不腰斩多字节字符——中文日志是常态）。len≤240 字节时 rune 数必 ≤240，
// 跳过 rune 计数（1MB 行的主流出口路径）。
func buildGrepHit(lineNo int, cur []byte, cut bool, offset int64) grepHit {
	out := strings.TrimSpace(string(cur))
	hit := grepHit{LineNo: lineNo, Line: out, LineTruncated: cut, Offset: offset}
	if len(out) > grepLineOutRunes && utf8.RuneCountInString(out) > grepLineOutRunes {
		hit.Line = string([]rune(out)[:grepLineOutRunes])
		hit.LineTruncated = true
	}
	return hit
}
