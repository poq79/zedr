package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hostguard/internal/model"
)

// makeSample 写一个临时文件并返回其 SHA256，供 IOC 命中测试使用。
func makeSample(t *testing.T, content string) (path, hash string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写测试样本失败: %v", err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

// hasSignal 判断结果中是否含指定信号 ID。
func hasSignal(res *Result, id string) bool {
	for _, s := range res.Evidence.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}

// TestIOCHashHit 验证服务端下发的 IOC 哈希命中：
// 单凭命中即达恶意阈值，证据带 S-IOC 信号，分量可对账。
func TestIOCHashHit(t *testing.T) {
	e := newTestEngine(t)
	path, hash := makeSample(t, "hostguard-ioc-test-payload")

	e.SetIOCs(map[string]string{hash: "演练样本 A（测试）"})

	res := e.Analyze(Input{Proc: ProcessInfo{PID: 100, PPID: 4, Name: "sample.exe", Path: path}})
	if res == nil {
		t.Fatal("IOC 命中应产生判定结果")
	}
	if res.Verdict != model.VerdictMalicious {
		t.Fatalf("IOC 命中应判恶意（总分 %d），实际 %s", res.Score, res.Verdict)
	}
	if !hasSignal(res, "S-IOC") {
		t.Fatalf("应产生 S-IOC 信号，实际信号: %s", signalIDs(res.Evidence.Signals))
	}
	// 加成必须折进 StaticScore（保证"分量之和 = 总分"可对账），
	// 路径信誉的加分随环境浮动，这里只断言不小于加成本身。
	if res.Evidence.StaticScore < iocHashBonus {
		t.Fatalf("StaticScore 应含 IOC 加成（≥%d），实际 %.0f", iocHashBonus, res.Evidence.StaticScore)
	}
}

// TestIOCCleanFile 无命中文件不受 IOC 表影响（不产生 S-IOC）；
// 清空 IOC 表（服务端明确清库）后原命中也不再触发。
func TestIOCCleanFile(t *testing.T) {
	e := newTestEngine(t)
	path, hash := makeSample(t, "hostguard-clean-file")
	e.SetIOCs(map[string]string{strings.Repeat("ab", 32): "无关条目"})

	res := e.Analyze(Input{Proc: ProcessInfo{PID: 101, Name: "clean.exe", Path: path}})
	if res == nil {
		t.Fatal("应产生判定结果")
	}
	if hasSignal(res, "S-IOC") {
		t.Fatal("未命中 IOC 的文件不应产生 S-IOC 信号")
	}

	// 清空 IOC 库后，之前的命中条目不再触发
	e.SetIOCs(map[string]string{hash: "演练样本"})
	if res := e.Analyze(Input{Proc: ProcessInfo{PID: 102, Name: "clean.exe", Path: path}}); !hasSignal(res, "S-IOC") {
		t.Fatal("清空前命中应有效")
	}
	e.SetIOCs(nil)
	if e.IOCCount() != 0 {
		t.Fatalf("清空后 IOC 数应为 0，实际 %d", e.IOCCount())
	}
	if res := e.Analyze(Input{Proc: ProcessInfo{PID: 103, Name: "clean.exe", Path: path}}); hasSignal(res, "S-IOC") {
		t.Fatal("清空 IOC 库后不应再命中")
	}
}
