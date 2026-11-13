//go:build windows
// +build windows

package winapi

// regnotify_test.go：RegWatch 的真实通知验证。
//
// 全部用例走真实注册表（HKCU 临时键 + 真实 RegNotifyChangeKeyValue），
// 不做 mock——阻塞通知、事件触发、关句柄取消、THREAD_AGNOSTIC 降级
// 这些行为只有真机才能验证。测试进程为管理员时 HKCU 就是普通用户
// hive，写权限天然具备。

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// testHive 是测试用的根 hive：HKCU。测试以管理员跑，HKCU 即当前用户。
const testHive = syscall.Handle(windows.HKEY_CURRENT_USER)

var procRegDeleteTreeW = modAdvapi32.NewProc("RegDeleteTreeW")

// deleteTestTree 递归删除测试键。x/sys 未导出 RegDeleteTree，这里按
// 包内 LazyProc 惯例声明；LazyProc.Call 的 err 恒非 nil（残留 LastErr），
// 判错只能看返回码——本仓库实锤，见 AGENTS.md §5.1 同类先例。
func deleteTestTree(root windows.Handle, path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	ret, _, _ := procRegDeleteTreeW.Call(uintptr(root), uintptr(unsafe.Pointer(p)))
	if ret != 0 {
		return fmt.Errorf("RegDeleteTreeW(%s) errno=%d", path, ret)
	}
	return nil
}

// newTestRegPath 生成本测试专用的一次性根路径并注册清理。
func newTestRegPath(t *testing.T) string {
	t.Helper()
	p := `Software\zedr-regwatch-test-` + t.Name()
	t.Cleanup(func() {
		// Close 已在测试函数的 defer 里执行完，此时不应再有持有句柄；
		// 删除失败只记录（可能是历史残留键本就不存在），不让清理失败
		// 掩盖真正的断言结果。
		if err := deleteTestTree(windows.HKEY_CURRENT_USER, p); err != nil {
			t.Logf("清理临时键失败 %s: %v", p, err)
		}
	})
	return p
}

func createTestKey(t *testing.T, path string) {
	t.Helper()
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("创建测试键失败 %s: %v", path, err)
	}
	k.Close()
}

func writeTestValue(t *testing.T, path, name, val string) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("打开测试键失败 %s: %v", path, err)
	}
	defer k.Close()
	if err := k.SetStringValue(name, val); err != nil {
		t.Fatalf("写测试值失败 %s\\%s: %v", path, name, err)
	}
}

func testRegLogger() *slog.Logger {
	// 输出到 stderr：挂载/重试的 Debug 日志是定位偶发漏报的唯一线索，
	// 仅在 -v 时由 go test 透传显示。
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// waitArmedMargin 等到守护发起首次挂载并留出宽限。挂载回执点只是
// "即将发起注册"（注册本身立即完成），宽限覆盖调度与 syscall 进入延迟。
func waitArmedMargin(t *testing.T, w *RegWatch, display string) {
	t.Helper()
	if !w.waitGuardArmed(display, 2*time.Second) {
		t.Fatalf("守护未在 2s 内完成首次挂载: %s", display)
	}
	time.Sleep(150 * time.Millisecond)
}

// writeAndExpectFire 写值并等待变更回调。首次写值存在被启动竞态吞掉的
// 可能（挂载回执与内核注册之间是本 API 的固有间隙），1s 内无响应时
// 补写一次——补写本身就是合法变更，任何一次触发都证明通知链路工作。
func writeAndExpectFire(t *testing.T, fires <-chan string, path, disp string) {
	t.Helper()
	writeTestValue(t, path, "zedr-probe", "1")
	select {
	case p := <-fires:
		if p != disp {
			t.Fatalf("回调路径不符: got %q want %q", p, disp)
		}
		return
	case <-time.After(time.Second):
	}
	writeTestValue(t, path, "zedr-probe", "2")
	select {
	case p := <-fires:
		if p != disp {
			t.Fatalf("回调路径不符: got %q want %q", p, disp)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("补写后仍未收到变更通知")
	}
}

// 核心验收：真实写入一个值，2s 内收到 onChange；Close 后守护 goroutine
// 全部退出。
func TestRegWatchRealNotificationAndClose(t *testing.T) {
	root := newTestRegPath(t)
	leaf := root + `\leaf`
	createTestKey(t, leaf)

	fires := make(chan string, 16)
	w, err := StartRegWatch([]RegWatchKey{{Hive: testHive, Path: leaf}},
		func(p string) { fires <- p }, testRegLogger())
	if err != nil {
		t.Fatalf("StartRegWatch 失败: %v", err)
	}
	defer w.Close()

	disp := displayPath(RegWatchKey{Hive: testHive, Path: leaf})
	waitArmedMargin(t, w, disp)

	writeAndExpectFire(t, fires, leaf, disp)

	// Close 幂等性顺带覆盖
	w.Close()
	w.Close()
	if !w.waitExited(3 * time.Second) {
		t.Fatal("Close 后守护 goroutine 未在 3s 内退出")
	}
}

// Subtree 语义：父键 Subtree=true 时，写"子键的值"（父键自身不动）也要触发。
func TestRegWatchSubtreeChildChangeFiresParent(t *testing.T) {
	root := newTestRegPath(t)
	parent := root + `\tree`
	child := parent + `\child`
	createTestKey(t, child)

	fires := make(chan string, 16)
	w, err := StartRegWatch([]RegWatchKey{{Hive: testHive, Path: parent, Subtree: true}},
		func(p string) { fires <- p }, testRegLogger())
	if err != nil {
		t.Fatalf("StartRegWatch 失败: %v", err)
	}
	defer w.Close()

	disp := displayPath(RegWatchKey{Hive: testHive, Path: parent})
	waitArmedMargin(t, w, disp)

	writeAndExpectFire(t, fires, child, disp)
}

// 非 Subtree 语义的反向验证：子键的值变更不应触发父键。
// 子键必须先于挂载创建——新建"直接子键"是父键自己的 NAME 事件，
// 非子树监听本来就会收到，不能拿它当反例。
func TestRegWatchNonSubtreeIgnoresChildValues(t *testing.T) {
	root := newTestRegPath(t)
	parent := root + `\nsub`
	child := parent + `\child`
	createTestKey(t, child)

	fires := make(chan string, 16)
	w, err := StartRegWatch([]RegWatchKey{{Hive: testHive, Path: parent}},
		func(p string) { fires <- p }, testRegLogger())
	if err != nil {
		t.Fatalf("StartRegWatch 失败: %v", err)
	}
	defer w.Close()

	waitArmedMargin(t, w, displayPath(RegWatchKey{Hive: testHive, Path: parent}))

	writeTestValue(t, child, "zedr-probe", "x")
	select {
	case p := <-fires:
		t.Fatalf("非子树监听收到了子键值变更: %s", p)
	case <-time.After(1500 * time.Millisecond):
	}
}

// 打不开的键（HKEY_USERS 下捏造路径，模拟用户 hive 未加载）不阻塞
// 其他键注册与触发；Close 能把退避重试中的坏键守护一并收掉。
func TestRegWatchBrokenKeyDoesNotBlockOthers(t *testing.T) {
	root := newTestRegPath(t)
	leaf := root + `\leaf`
	createTestKey(t, leaf)

	fires := make(chan string, 16)
	w, err := StartRegWatch([]RegWatchKey{
		{Hive: syscall.Handle(windows.HKEY_USERS),
			Path: `S-1-5-21-0-0-0-999999\Software\Microsoft\Windows\CurrentVersion\Run`},
		{Hive: testHive, Path: leaf},
	}, func(p string) { fires <- p }, testRegLogger())
	if err != nil {
		t.Fatalf("存在打不开的键不应导致整体失败: %v", err)
	}
	defer w.Close()

	disp := displayPath(RegWatchKey{Hive: testHive, Path: leaf})
	waitArmedMargin(t, w, disp)

	writeAndExpectFire(t, fires, leaf, disp)

	w.Close()
	// 坏键守护此刻处于首次 5s 退避睡眠中，Close 必须立即唤醒并退出，
	// 不能等退避自然到期——waitExited 的 3s 预算验证的就是这一点。
	if !w.waitExited(3 * time.Second) {
		t.Fatal("Close 后守护 goroutine 未在 3s 内退出（含退避中的坏键守护）")
	}
}

// 全部键都打不开：返回错误且不返回 RegWatch（调用方无从 Close，
// 也不应泄漏任何 goroutine）。
func TestRegWatchAllKeysBrokenReturnsError(t *testing.T) {
	w, err := StartRegWatch([]RegWatchKey{
		{Hive: syscall.Handle(windows.HKEY_USERS),
			Path: `S-1-5-21-0-0-0-999999\Software\Microsoft\Windows\CurrentVersion\Run`},
	}, func(string) {}, testRegLogger())
	if err == nil {
		if w != nil {
			w.Close()
		}
		t.Fatal("全部键打不开时应返回错误")
	}
	if w != nil {
		t.Fatal("失败时不应返回非 nil 的 RegWatch")
	}
	if !strings.Contains(err.Error(), "1 个") {
		// 检查错误信息里带上了键计数与首错，便于排障
		t.Logf("错误信息（人工核对）: %v", err)
	}
}

// 同键 1s 合并：合并窗口内的连续写入只应产生一次回调（安装器风暴形态）。
// 窗口内的通知要么被合并丢弃、要么落在重挂间隙里——两者都不应二次回调。
func TestRegWatchMergesSameKeyBurst(t *testing.T) {
	root := newTestRegPath(t)
	leaf := root + `\leaf`
	createTestKey(t, leaf)

	fires := make(chan string, 16)
	w, err := StartRegWatch([]RegWatchKey{{Hive: testHive, Path: leaf}},
		func(p string) { fires <- p }, testRegLogger())
	if err != nil {
		t.Fatalf("StartRegWatch 失败: %v", err)
	}
	defer w.Close()

	disp := displayPath(RegWatchKey{Hive: testHive, Path: leaf})
	waitArmedMargin(t, w, disp)

	// 首火用稳健路径拿到（含补写），保证 lastFire 已就位
	writeAndExpectFire(t, fires, leaf, disp)

	writeTestValue(t, leaf, "zedr-probe", "3")
	time.Sleep(100 * time.Millisecond)
	writeTestValue(t, leaf, "zedr-probe", "4")
	select {
	case p := <-fires:
		t.Fatalf("1s 合并窗口内的重复通知未合并: %s", p)
	case <-time.After(1300 * time.Millisecond):
	}
}

// 默认键集：形状校验（固定键齐全、IFEO 子树、无 _Classes、数量在
// 线程预算内）+ 真机启动/停止一轮。
func TestRegWatchDefaultKeysShapeAndLifecycle(t *testing.T) {
	keys := DefaultRegWatchKeys()
	// 下限：6 个固定键 + 至少 1 个用户 hive 的 Run/RunOnce（成对入集，
	// 不因键不存在而剔除）
	if len(keys) < 7 {
		t.Fatalf("默认键集过少: %d（应为 6 固定 + 2×已加载用户）", len(keys))
	}
	// 上限防"过滤器失效把系统 hive 也收进来"：本机（单交互用户）实测
	// 恰好 8 个；多用户终端服务器会更高，但 CI/本机口径下不该超过 12。
	if len(keys) > 12 {
		t.Fatalf("默认键集超出线程预算: %d", len(keys))
	}
	haveIFEO := false
	for _, k := range keys {
		if k.Path == "" {
			t.Fatal("存在空路径键")
		}
		if strings.Contains(strings.ToLower(k.Path), "_classes") {
			t.Fatalf("用户 hive 枚举混入 _Classes 条目: %s", k.Path)
		}
		if strings.Contains(k.Path, "Image File Execution Options") {
			if !k.Subtree {
				t.Fatal("IFEO 根键必须是 Subtree 监听")
			}
			haveIFEO = true
		}
	}
	if !haveIFEO {
		t.Fatal("键集缺少 IFEO 根键")
	}

	w, err := StartRegWatch(keys, func(string) {}, testRegLogger())
	if err != nil {
		t.Fatalf("默认键集真机启动失败: %v", err)
	}
	w.Close()
	if !w.waitExited(3 * time.Second) {
		t.Fatal("默认键集 Close 后守护未退出")
	}
}
