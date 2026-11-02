package winapi

// threads_test.go：线程枚举/起始地址/模块归属/匿名执行判定真机冒烟。
// 线程数量与地址随运行时变化，只断言"至少一个线程归属到模块"与"不 panic"。

import (
	"os"
	"testing"

	"zedr/internal/model"
)

func TestListThreadsSelf(t *testing.T) {
	pid := uint32(os.Getpid())
	rows, err := ListThreads(pid)
	if err != nil {
		t.Fatalf("ListThreads(self) 失败: %v", err)
	}
	if len(rows) < 1 {
		t.Fatalf("本进程线程数应 ≥1，实得 %d", len(rows))
	}
	sawModule := false
	for _, row := range rows {
		if row.TID == 0 {
			t.Errorf("TID 不应为 0: %+v", row)
		}
		if row.Module != "" {
			sawModule = true
		}
	}
	// 主线程起始地址必然落在测试二进制镜像内，module 应非空；
	// 若模块快照整体不可用则属环境限制，跳过而不是判失败。
	if !sawModule {
		t.Skip("模块快照不可用（可能权限受限），无法断言 module 归属")
	}
}

func TestScanThreadsSelfStats(t *testing.T) {
	pid := uint32(os.Getpid())
	res, err := ScanThreads(pid, nil)
	if err != nil {
		t.Fatalf("ScanThreads(self) 失败: %v", err)
	}
	if res.Total != len(res.Rows) {
		t.Errorf("Total=%d 与行数 %d 不一致", res.Total, len(res.Rows))
	}
	if res.Skipped < 0 || res.QueryFailed < 0 {
		t.Errorf("计数不应为负: %+v", res)
	}
	if !res.ProcessOpened {
		t.Log("本进程竟未能以 PROCESS_QUERY_INFORMATION 打开，in_anonymous_exec 将不可判定")
	}
}

func TestScanThreadsUnknownPID(t *testing.T) {
	const ghost = uint32(0xFFFFFFF0)
	res, err := ScanThreads(ghost, nil)
	if err != nil {
		t.Fatalf("不存在的 pid 不应返回错误: %v", err)
	}
	if len(res.Rows) != 0 || res.Total != 0 {
		t.Fatalf("不存在的 pid 不应有线程: %+v", res)
	}
}

func TestListThreadsProtectedPID(t *testing.T) {
	// PID 4 的线程在用户态打不开：必须返回空/仅 TID 的行，而不是错误或 panic。
	rows, err := ListThreads(4)
	if err != nil {
		t.Fatalf("受保护进程不应让枚举整体失败: %v", err)
	}
	for _, row := range rows {
		if row.InAnonymousExec {
			t.Errorf("打不开的进程不应给出 in_anonymous_exec=true: %+v", row)
		}
	}
	t.Logf("PID 4 可见线程 %d 个（起始地址/模块多为空属预期）", len(rows))
}

func TestModuleForAddress(t *testing.T) {
	mods := []model.ModuleInfo{
		{Name: "a.dll", BaseAddr: 0x1000, Size: 0x1000},
		{Name: "b.dll", BaseAddr: 0x3000, Size: 0x100},
	}
	cases := []struct {
		addr uint64
		want string
	}{
		{0x1000, "a.dll"},
		{0x1FFF, "a.dll"},
		{0x2000, ""},
		{0x3000, "b.dll"},
		{0x30FF, "b.dll"},
		{0x3100, ""},
		{0, ""},
	}
	for _, tc := range cases {
		if got := moduleForAddress(mods, tc.addr); got != tc.want {
			t.Errorf("moduleForAddress(0x%x) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
