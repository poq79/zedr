package uplink

// 离线告警的磁盘 spool。
//
// 为什么需要它：内存队列只能扛"网络短暂抖动"，探针重启（升级/崩溃/
// 服务重启）会连同未送达告警一起消失。主机侧检测的价值在于事后可追溯，
// 丢一条告警就可能丢掉整条攻击链的起点。
//
// 设计取舍：
//   - 追加式 NDJSON 分段（每段最多 500 条或 4MB），写路径只 append 不 fsync：
//     告警不是金融交易，掉电丢最后几条可接受，换来的是检测主循环零阻塞；
//   - 段是删除单位：超限时整段淘汰最旧的，最多多丢半段（<=500 条）；
//   - 发送成功才删段，失败保留，语义是 at-least-once；服务端按 fingerprint
//     去重，重复投递不会产生重复告警；
//   - 发送前先轮转活跃段，保证正在发送的段不再被写入，避免"边读边删"
//     丢掉并发新到的告警。
//
// 磁盘异常（无权限/满盘）时 enqueue 返回错误，由调用方降级回内存队列，
// 不能因为 spool 坏了就阻断检测。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"zedr/internal/model"
)

const (
	spoolSegmentMaxRecords = 500
	spoolSegmentMaxBytes   = 4 << 20
	// 单条告警超过 512KB 视为异常（正常证据包远小于此），落盘只会
	// 拖垮批量上报；服务端单次请求上限 1MiB，也不允许这种记录。
	spoolRecordMaxBytes = 512 << 10
	// 发送批次上限：条数与字节双约束，避免 200 条大证据包撞上 1MiB 体积上限。
	spoolBatchMaxRecords = 200
	spoolBatchMaxBytes   = 700 << 10
)

type spoolSeg struct {
	path  string
	count int
	bytes int64
}

type spool struct {
	dir        string
	maxRecords int
	// segMaxRecords 是单段记录上限：取 min(500, maxRecords/4)，
	// 保证超限淘汰时"整段丢弃"的粒度不会超过总容量的约 1/4。
	segMaxRecords int

	mu       sync.Mutex
	segs     []spoolSeg // 已封存段，按文件名升序（最旧在前）
	total    int        // 所有段 + 活跃段的记录数
	bytes    int64
	dropped  int64
	nextSeq  uint64
	active   *os.File
	activePath string
	activeN  int
	activeB  int64
	flushing bool
	closed   bool
}

// openSpool 打开（或创建）spool 目录并恢复已有段。
func openSpool(dir string, maxRecords int) (*spool, error) {
	if maxRecords <= 0 {
		return nil, fmt.Errorf("spool 容量必须为正数")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建磁盘队列目录失败: %w", err)
	}
	s := &spool{dir: dir, maxRecords: maxRecords}
	s.segMaxRecords = maxRecords / 4
	if s.segMaxRecords < 1 {
		s.segMaxRecords = 1
	}
	if s.segMaxRecords > spoolSegmentMaxRecords {
		s.segMaxRecords = spoolSegmentMaxRecords
	}
	s.loadDropped()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取磁盘队列失败: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "alerts-") || !strings.HasSuffix(name, ".ndjson") {
			continue
		}
		if seq, ok := parseSegmentSeq(name); ok && seq >= s.nextSeq {
			s.nextSeq = seq + 1
		}
		path := filepath.Join(dir, name)
		n, size, err := scanSegment(path)
		if err != nil {
			_ = os.Remove(path) // 读不了/格式坏：不能让一个坏段永久堵住队列
			continue
		}
		if n == 0 {
			_ = os.Remove(path)
			continue
		}
		s.segs = append(s.segs, spoolSeg{path: path, count: n, bytes: size})
		s.total += n
		s.bytes += size
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].path < s.segs[j].path })

	// 启动时若历史段超额（例如调小了 HG_AGENT_OFFLINE_QUEUE），
	// 按最旧优先淘汰。单个段最多 500 条，误差有界。
	for s.total > s.maxRecords && len(s.segs) > 1 {
		s.dropOldestLocked()
	}
	return s, nil
}

func parseSegmentSeq(name string) (uint64, bool) {
	base := strings.TrimSuffix(strings.TrimPrefix(name, "alerts-"), ".ndjson")
	n, err := strconv.ParseUint(base, 10, 64)
	return n, err == nil
}

// scanSegment 统计一个段的有效记录数与字节数。
func scanSegment(path string) (count int, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), spoolRecordMaxBytes*2)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		count++
		size += int64(len(line)) + 1
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	return count, size, nil
}

// enqueue 追加一条告警。返回错误表示磁盘不可用，调用方应降级。
func (s *spool) enqueue(env model.AlertEnvelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	line := append(raw, '\n')
	if len(line) > spoolRecordMaxBytes {
		// 记录异常大：丢弃并计数，避免一条脏数据拖垮整个队列。
		s.mu.Lock()
		s.dropped++
		s.saveDroppedLocked()
		s.mu.Unlock()
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("磁盘队列已关闭")
	}
	if s.active == nil || s.activeN >= s.segMaxRecords ||
		s.activeB+int64(len(line)) > spoolSegmentMaxBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := s.active.Write(line); err != nil {
		return err
	}
	s.activeN++
	s.activeB += int64(len(line))
	s.total++
	s.bytes += int64(len(line))

	for s.total > s.maxRecords && len(s.segs) > 0 {
		s.dropOldestLocked()
	}
	return nil
}

// rotateLocked 封存当前活跃段并起一个新的。调用方必须持锁。
func (s *spool) rotateLocked() error {
	if err := s.sealActiveLocked(); err != nil {
		return err
	}
	return s.newActiveLocked()
}

// sealActiveLocked 关闭并登记当前活跃段，不创建新文件。
// flush 只需要"封存"，新段等真有告警时再懒创建——否则每轮 flush
// 都会留下一个空文件句柄，既占句柄也妨碍测试/卸载清理。
func (s *spool) sealActiveLocked() error {
	if s.active == nil {
		return nil
	}
	if err := s.active.Close(); err != nil {
		return err
	}
	if s.activeN > 0 {
		s.segs = append(s.segs, spoolSeg{
			path: s.activePath, count: s.activeN, bytes: s.activeB,
		})
	} else {
		_ = os.Remove(s.activePath)
	}
	s.active, s.activePath, s.activeN, s.activeB = nil, "", 0, 0
	return nil
}

func (s *spool) newActiveLocked() error {
	name := fmt.Sprintf("alerts-%016d.ndjson", s.nextSeq)
	s.nextSeq++
	path := filepath.Join(s.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.active, s.activePath = f, path
	return nil
}

// dropOldestLocked 删除最旧的一个已封存段。调用方必须持锁。
func (s *spool) dropOldestLocked() {
	seg := s.segs[0]
	s.segs = s.segs[1:]
	s.total -= seg.count
	s.bytes -= seg.bytes
	s.dropped += int64(seg.count)
	_ = os.Remove(seg.path)
	s.saveDroppedLocked()
}

func (s *spool) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

func (s *spool) droppedCount() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// flush 按最旧优先发送已封存段。send 成功才删段。
//
// 返回已成功发送的条数。失败时保留当前段，下次重发该段（at-least-once）。
func (s *spool) flush(ctx context.Context, send func(context.Context, []model.AlertEnvelope) error) (int, error) {
	s.mu.Lock()
	if s.flushing {
		s.mu.Unlock()
		return 0, nil
	}
	if s.total == 0 {
		s.mu.Unlock()
		return 0, nil
	}
	// 封存活跃段：本次发送的所有段都是不可变文件。
	if s.active != nil {
		if err := s.sealActiveLocked(); err != nil {
			s.mu.Unlock()
			return 0, err
		}
	}
	snapshot := append([]spoolSeg(nil), s.segs...)
	s.flushing = true
	s.mu.Unlock()

	sent := 0
	var flushErr error
	for _, seg := range snapshot {
		lines, err := readSegmentLines(seg.path)
		if err != nil {
			// 坏段/被外部删除：移出队列，不能堵住后面的告警。
			s.removeSegment(seg)
			continue
		}
		n, err := sendSegment(ctx, lines, send)
		sent += n
		if err != nil {
			flushErr = err
			break
		}
		s.removeSegment(seg)
	}

	s.mu.Lock()
	s.flushing = false
	s.mu.Unlock()
	return sent, flushErr
}

func readSegmentLines(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), spoolRecordMaxBytes*2)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(bytes.TrimSpace(line)) > 0 {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func sendSegment(ctx context.Context, lines [][]byte, send func(context.Context, []model.AlertEnvelope) error) (int, error) {
	sent := 0
	var batch []model.AlertEnvelope
	batchBytes := 0

	flushBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := send(ctx, batch); err != nil {
			return err
		}
		sent += len(batch)
		batch = nil
		batchBytes = 0
		return nil
	}

	for _, line := range lines {
		var env model.AlertEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			continue // 单行损坏只跳过该行
		}
		if len(batch) >= spoolBatchMaxRecords || batchBytes+len(line) > spoolBatchMaxBytes {
			if err := flushBatch(); err != nil {
				return sent, err
			}
		}
		batch = append(batch, env)
		batchBytes += len(line)
	}
	if err := flushBatch(); err != nil {
		return sent, err
	}
	return sent, nil
}

func (s *spool) removeSegment(seg spoolSeg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.segs {
		if s.segs[i].path == seg.path {
			s.segs = append(s.segs[:i], s.segs[i+1:]...)
			break
		}
	}
	s.total -= seg.count
	s.bytes -= seg.bytes
	if s.total < 0 {
		s.total = 0
	}
	if s.bytes < 0 {
		s.bytes = 0
	}
	_ = os.Remove(seg.path)
}

// close 关闭活跃文件（测试/退出时使用；正常运行由进程退出兜底）。
func (s *spool) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.active != nil {
		_ = s.active.Close()
		s.active = nil
	}
}

// ---------------------------------------------------------------- 丢弃计数持久化

func (s *spool) statsPath() string { return filepath.Join(s.dir, "stats.json") }

func (s *spool) loadDropped() {
	raw, err := os.ReadFile(s.statsPath())
	if err != nil {
		return
	}
	var st struct {
		Dropped int64 `json:"dropped"`
	}
	if json.Unmarshal(raw, &st) == nil && st.Dropped > 0 {
		s.dropped = st.Dropped
	}
}

func (s *spool) saveDroppedLocked() {
	raw, err := json.Marshal(struct {
		Dropped int64 `json:"dropped"`
	}{Dropped: s.dropped})
	if err != nil {
		return
	}
	// temp+rename：崩溃时不留下半个 JSON（与隔离清单同纪律）
	tmp := s.statsPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, s.statsPath())
	}
}
