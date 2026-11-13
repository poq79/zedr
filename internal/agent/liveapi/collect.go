//go:build windows
// +build windows

package liveapi

// collect.go：GET /collect —— 文件取证打包（zip 流式回传）。
//
// 为什么存在：/fs/read 有 512KB 上限（交互式预览口径），调查取证需要把
// 完整文件（样本、脚本、日志）原样取走并带完整性证据。本端点把一批文件
// 打进一个 zip 流式回传，条目名带 4 位序号防同名碰撞，manifest 记录每个
// 条目的 sha256 与全部失败项。
//
// 三个设计决定（读代码前先看）：
//  1. 为什么是 GET：服务端代理 liveForward 对隧道内请求硬编码 GET
//     （internal/server/api/live.go：http.NewRequestWithContext(..., http.MethodGet,
//     "http://tunnel/"+rest+"?"+RawQuery, ...)），端点要进其预算表就必须是
//     GET；多值参数 p= 经 RawQuery 原样透传不会丢。
//  2. 为什么全程不落盘：zip 直接写 HTTP 响应，探针磁盘不出现任何临时
//     文件——取证对象常含隐私与恶意样本，临时文件既是泄露面又需要清理，
//     还会破坏取证链的干净性。
//  3. 为什么 manifest 是唯一事实源：zip 流式写出没有事务性——
//     archive/zip 的 Writer 对文件条目恒用 data descriptor（flag 0x8），
//     条目收尾时按"实际写入的字节"计算 CRC32/大小写入。这意味着中途
//     失败的条目在 zip 里是**结构合法的部分内容**（解压工具不会报 CRC
//     错，只会拿到截断的数据），比"CRC 错误条目"更隐蔽——只有 manifest
//     的 errors 清单能告诉调查者这个条目不可信。errors 条目一律
//     sha256=null：部分内容的哈希不是文件的哈希，绝不冒充完整性证据。

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	// collectMaxPaths 单次请求最多打包的文件数（去重后；取证是人工发起
	// 的低频动作，16 个足够一次调查使用，同时钳住单请求的 IO 时间）。
	collectMaxPaths = 16

	// manifestName zip 内清单条目名（固定约定，服务端/前端按此解包）。
	manifestName = "__zedr_manifest.json"

	// collectCopyBuf 流式复制缓冲：单层 256KB，内存占用与文件大小无关
	// （与 /fs/hash 的 hashBufSize 同口径）。
	collectCopyBuf = 256 << 10
)

// 预算三项做成包级变量（模式同 search.go 的 searchBudget）：单测注入
// 极小值即可在毫秒级验证截断分支，不必造 64MB/128MB 真文件；测试外不得改写。
var (
	collectFileMaxBytes  int64 = 64 << 20  // 单文件上限（/fs/read 512KB 的取证级放宽）
	collectTotalMaxBytes int64 = 128 << 20 // 总字节预算（原始字节口径，非压缩后）
	collectSoftDeadline        = 110 * time.Second
	// 110s 软预算 vs 服务端代理 120s：留 10s 给 manifest 与 central
	// directory 收尾，让代理超时前总能收到一个合法完整的 zip。
)

// collectManifestFile 是 manifest.files 的一条：成功采集的文件与完整性证据。
type collectManifestFile struct {
	Path    string `json:"path"`     // 请求路径（Clean 后）
	ZipName string `json:"zip_name"` // zip 内条目名（NNNN_basename）
	Size    int64  `json:"size"`     // 实际写入字节数
	SHA256  string `json:"sha256"`   // 内容哈希（hex）
}

// collectManifestError 是 manifest.errors 的一条：每个未被成功采集的请求
// 路径在这里有且只有一条记录——manifest 是事实源。
type collectManifestError struct {
	Path   string  `json:"path"`
	Error  string  `json:"error"`  // 机器可读原因（取值见 statErrReason 与流内分支）
	SHA256 *string `json:"sha256"` // 恒 null：失败条目没有可信的完整性证据
}

// collectManifest zip 内清单条目（__zedr_manifest.json）。
type collectManifest struct {
	AgentVersion string                 `json:"agent_version"`
	CollectedAt  int64                  `json:"collected_at"` // unix 秒
	Files        []collectManifestFile  `json:"files"`
	Errors       []collectManifestError `json:"errors"`
	Truncated    bool                   `json:"truncated"` // 因预算/期限截断为 true（单文件读失败不算截断）
}

// statErrReason 把 FSys 错误归类成 manifest 的机器可读原因。保留底层错误
// 原文：manifest 面向调查者，诊断信息比统一文案更有价值（且不经过 5xx
// 脱敏层——这是取证产物，访问者本就是获授权的分析人员）。
func statErrReason(err error) string {
	switch {
	case errors.Is(err, ErrNotExist):
		return "not_found"
	case errors.Is(err, ErrPermission):
		return "permission_denied"
	default:
		return "stat_failed: " + err.Error()
	}
}

// handleCollect 处理 GET /collect?p=路径1&p=路径2...。
// 契约：任一路径非法 → 400（调用方 bug，从严不部分放行）；全部不可采集
// → 404/400 带逐项原因；部分可采集 → 200 zip 流 + errors 清单。
func (s *server) handleCollect(w http.ResponseWriter, r *http.Request) {
	deadline := time.Now().Add(collectSoftDeadline)

	// ---- 阶段一：参数校验。先全部校验建计划、再开流——一旦开始写响应
	//      就没有回头路，非法参数绝不能等到流里才发现 ----
	raws := r.URL.Query()["p"]
	if len(raws) == 0 {
		httpx.WriteError(w, r, apperr.Invalid("p 参数必填（可重复，每个为一个绝对路径）"))
		return
	}
	// 去重按 Clean 后路径 casefold（Windows 路径大小写不敏感），保序取首个。
	seen := make(map[string]bool, len(raws))
	paths := make([]string, 0, len(raws))
	for _, raw := range raws {
		clean, err := validateFSPath(raw)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		key := strings.ToLower(clean)
		if seen[key] {
			continue
		}
		seen[key] = true
		paths = append(paths, clean)
	}
	if len(paths) > collectMaxPaths {
		httpx.WriteError(w, r, apperr.Invalid("最多 %d 个路径（去重后实得 %d）", collectMaxPaths, len(paths)))
		return
	}

	// ---- 阶段二：计划。全部 Stat，存在/目录/单文件上限/总预算一次判定完 ----
	errs := make([]collectManifestError, 0, len(paths))
	files := make([]collectManifestFile, 0, len(paths))
	type planItem struct {
		path  string
		size  int64
		mtime time.Time
	}
	plan := make([]planItem, 0, len(paths))
	allocated := int64(0)
	budgetBlown := false
	for _, p := range paths {
		// 先 Stat 再判预算：预算已放不下时，后面的路径仍要如实分类
		// （不存在就记 not_found，不能把别人的锅记成 budget_exceeded）
		e, err := s.d.FS.Stat(p)
		if err != nil {
			errs = append(errs, collectManifestError{Path: p, Error: statErrReason(err)})
			continue
		}
		if e.IsDir {
			errs = append(errs, collectManifestError{Path: p, Error: "is_directory"})
			continue
		}
		if e.Size > collectFileMaxBytes {
			errs = append(errs, collectManifestError{Path: p, Error: "too_large"})
			continue
		}
		if budgetBlown || allocated+e.Size > collectTotalMaxBytes {
			// 总预算装不下：停止加新文件（含更小的后续文件——按序保真，
			// 不做跳大取小的挑拣，行为可预期才可审计）
			budgetBlown = true
			errs = append(errs, collectManifestError{Path: p, Error: "budget_exceeded"})
			continue
		}
		allocated += e.Size
		plan = append(plan, planItem{path: p, size: e.Size, mtime: time.Unix(e.MtimeUnix, 0)})
	}

	// 全部不可采集：不开流（空 zip 对调查者毫无价值），逐项给出原因。
	// 全是不存在 → 404；混有目录/超限/权限 → 400（语义上是请求本身错了）。
	if len(plan) == 0 {
		allNotFound := true
		detail := make([]string, 0, len(errs))
		for _, e := range errs {
			if e.Error != "not_found" {
				allNotFound = false
			}
			detail = append(detail, e.Path+" ("+e.Error+")")
		}
		msg := "没有可采集的文件: " + strings.Join(detail, ", ")
		if allNotFound {
			httpx.WriteError(w, r, &apperr.Error{
				Code:    apperr.CodeNotFound,
				Message: msg,
				Status:  http.StatusNotFound,
			})
			return
		}
		httpx.WriteError(w, r, apperr.Invalid("%s", msg))
		return
	}

	// ---- 阶段三：开流。头必须在第一个字节前发；截断状态在流中才可能
	//      最终确定，头部只能给计划时点可预见的值——流中发现的意外
	//      （文件变大、I/O 失败）只在 manifest 里体现，两者以 manifest 为准 ----
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	// 计划条目数：正常路径与最终成功数一致；I/O 中途失败时 manifest 更准
	h.Set("X-ZEDR-Collect-Files", strconv.Itoa(len(plan)))
	if budgetBlown || time.Now().After(deadline) {
		h.Set("X-ZEDR-Truncated", "1")
	} else {
		h.Set("X-ZEDR-Truncated", "0")
	}
	w.WriteHeader(http.StatusOK)

	zw := zip.NewWriter(w)
	var total int64 // 已写入 zip 的原始字节（预算口径，非压缩后）
	truncated := budgetBlown
	entrySeq := 0 // 条目序号：含中途失败条目，保证 zip 内名字唯一

	for i, it := range plan {
		// 文件边界检查 deadline（文件内部不检查：单文件天然受总预算
		// 约束，且 io 层的 deadline 语义在隧道流上不可靠）
		if time.Now().After(deadline) {
			truncated = true
			for _, rest := range plan[i:] {
				errs = append(errs, collectManifestError{Path: rest.path, Error: "deadline_exceeded"})
			}
			break
		}
		remaining := collectTotalMaxBytes - total
		// 实际进度超出 Stat 口径（文件在 Stat 与 Open 之间变大）的兜底：
		// 放不下的文件不开新条目（0 字节的部分条目只会制造噪音）
		if remaining <= 0 || it.size > remaining {
			truncated = true
			for _, rest := range plan[i:] {
				errs = append(errs, collectManifestError{Path: rest.path, Error: "budget_exceeded"})
			}
			break
		}

		rc, _, err := s.d.FS.Open(it.path)
		if err != nil {
			// Stat 说存在但 Open 失败（TOCTOU：被删/权限收紧）——文件从未
			// 进 zip，记原因后继续其余文件，不让单点失败放大成整包失败
			errs = append(errs, collectManifestError{Path: it.path, Error: "open_failed: " + err.Error()})
			continue
		}

		// 条目名带 4 位序号：不同目录的同名文件（a\log.txt、b\log.txt）
		// 解包时都会落在同一层，序号是唯一防碰撞手段
		entrySeq++
		fh := &zip.FileHeader{
			Name:     fmt.Sprintf("%04d_%s", entrySeq, filepath.Base(it.path)),
			Method:   zip.Deflate,
			Modified: it.mtime,
		}
		ew, err := zw.CreateHeader(fh)
		if err != nil {
			// 写响应失败（客户端断开）——流已坏，manifest 也写不出去
			_ = rc.Close()
			return
		}
		hasher := sha256.New()
		// 限流复制：最多 remaining 字节进条目，tee 一路喂 sha256。
		// 复制结束后从原始 reader 多探 1 字节区分"恰好读完"与"被预算截断"。
		n, copyErr := io.CopyBuffer(ew,
			io.TeeReader(io.LimitReader(rc, remaining), hasher),
			make([]byte, collectCopyBuf))
		total += n
		if copyErr == nil {
			var probe [1]byte
			m, _ := rc.Read(probe[:])
			_ = rc.Close()
			if m > 0 {
				// 流中触顶：本条目只写进 remaining 字节，zip 收尾时按已写
				// 部分计算 CRC/大小——结构合法的部分条目（见文件头注释 3），
				// sha256=null 绝不冒充完整性。剩余计划文件全部停止。
				truncated = true
				errs = append(errs, collectManifestError{Path: it.path, Error: "budget_exceeded mid-stream"})
				for _, rest := range plan[i+1:] {
					errs = append(errs, collectManifestError{Path: rest.path, Error: "budget_exceeded"})
				}
				break
			}
			files = append(files, collectManifestFile{
				Path:    it.path,
				ZipName: fh.Name,
				Size:    n,
				SHA256:  hex.EncodeToString(hasher.Sum(nil)),
			})
			continue
		}
		_ = rc.Close()
		// 读/写中途失败：条目已成部分内容。区分客户端断开（响应已死，
		// manifest 无处可写，直接退出）与真读失败（记 errors 继续下一个；
		// 写侧失败而 ctx 还活着时，下轮 CreateHeader 会再次失败并退出）
		if r.Context().Err() != nil {
			return
		}
		errs = append(errs, collectManifestError{Path: it.path, Error: "read_failed mid-stream"})
	}

	// ---- 收尾：manifest 最后一个条目。无论上面怎么截断，走到这里都
	//      必须产出合法完整的 zip（central directory 由 Close 补齐，
	//      绝不许半途断流）——manifest 是事实源，它必须在场 ----
	manifest := collectManifest{
		AgentVersion: s.d.Version,
		CollectedAt:  time.Now().Unix(),
		Files:        files,
		Errors:       errs,
		Truncated:    truncated,
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		// 字段全是字符串/数字/布尔，实际不可达；宁可给空清单也不给坏 zip
		mb = []byte("{}")
	}
	mw, err := zw.CreateHeader(&zip.FileHeader{
		Name:     manifestName,
		Method:   zip.Deflate,
		Modified: time.Now(),
	})
	if err == nil {
		// 写失败只可能因响应已坏，无恢复动作
		_, _ = mw.Write(mb)
	}
	if err := zw.Close(); err != nil {
		// central directory 写失败 = 响应传输已坏；头部已发出，只能留痕
		slog.Warn("liveapi_collect_zip_close_failed", "error", err.Error())
	}
}
