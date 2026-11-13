//go:build windows
// +build windows

package winapi

// netstat.go：带归属 PID 的 TCP/UDP 连接表枚举（liveapi /netstat 的数据源）。
//
// 为什么带 PID：现有数据模型里网络证据（model.NetConn）只有五元组，没有
// 归属进程——"这条外联是谁发的"只能靠时间窗对齐去猜，网络告警与进程证据
// 之间始终隔着一层。本表在同一时刻原子地拿到"连接 + PID"，供 liveapi
// /netstat 富化出 proc_name/proc_path，补上网络→进程的关联缺口。
//
// 实现说明：与 network.go / inventory_windows.go 同一套"两次调用"模式
// （先探长度再取表，缓冲多留 1KB 规避两次调用之间表增长导致的截断）。
// DLL 绑定与常量（procGetExtendedTcpTable/procGetExtendedUdpTable/afInet/
// tcpTableOwnerPIDAll/udpTableOwnerPID/tcp6Row/stateName/ntohs/uint32ToIP）
// 直接复用同包既有声明，本文件不重复定义。

import (
	"fmt"
	"net"
	"unsafe"

	"zedr/internal/agent/nettypes"
)

// NetRow 是一条带归属 PID 的连接行（nettypes 单一事实源）；JSON 字段名
// 即 liveapi /netstat 线协议。Linux 侧由 /proc/net/tcp 投影同形状。
type NetRow = nettypes.NetRow

// GetNetstat 一次拉取全系统 TCP（v4+v6）与 UDP（v4+v6）端点表。
//
// 容错口径与 TCPConnections 一致：IPv4 TCP 是主数据集，失败即整体失败；
// v6 与 UDP 拿不到时降级返回已有行（调查场景 TCP v4 外联是主线索，
// 不因次要表失败丢掉主证据）。
func GetNetstat() ([]NetRow, error) {
	rows, err := netstatTCP(afInet, "tcp")
	if err != nil {
		return nil, err
	}
	if v6, err := netstatTCP(afInet6, "tcp6"); err == nil {
		rows = append(rows, v6...)
	}
	if u4, err := netstatUDP(afInet, "udp"); err == nil {
		rows = append(rows, u4...)
	}
	if u6, err := netstatUDP(afInet6, "udp6"); err == nil {
		rows = append(rows, u6...)
	}
	return rows, nil
}

// netstatTCP 读一种地址族的 MIB_TCP*_ROW_OWNER_PID 表
// （TableClass = TCP_TABLE_OWNER_PID_ALL，含 LISTEN/ESTABLISHED 等全部状态）。
func netstatTCP(family uint32, proto string) ([]NetRow, error) {
	rowSize := 24 // MIB_TCPROW_OWNER_PID：6 个 DWORD
	if family == afInet6 {
		rowSize = 56 // MIB_TCP6ROW_OWNER_PID，布局见 network.go 的 tcp6Row
	}

	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(family), tcpTableOwnerPIDAll, 0)
	if ret != 0 && size == 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable 获取长度失败: family=%d ret=%d", family, ret)
	}

	buf := make([]byte, size+1024)
	ret, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable 失败: family=%d ret=%d", family, ret)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	if count == 0 {
		return nil, nil
	}
	if int(4+int(count)*rowSize) > len(buf) {
		return nil, fmt.Errorf("TCP 表长度异常: family=%d count=%d", family, count)
	}
	base := unsafe.Pointer(&buf[0])

	out := make([]NetRow, 0, count)
	for i := 0; i < int(count); i++ {
		if family == afInet6 {
			row := (*tcp6Row)(unsafe.Add(base, 4+i*rowSize))
			out = append(out, NetRow{
				Proto:      proto,
				LocalIP:    net.IP(row.LocalAddr[:]).String(),
				LocalPort:  ntohs(row.LocalPort),
				RemoteIP:   net.IP(row.RemoteAddr[:]).String(),
				RemotePort: ntohs(row.RemotePort),
				State:      stateName(row.State),
				PID:        row.OwningPID,
			})
			continue
		}
		// MIB_TCPROW_OWNER_PID: DwState/DwLocalAddr/DwLocalPort/DwRemoteAddr/DwRemotePort/DwOwningPid
		row := (*[6]uint32)(unsafe.Add(base, 4+i*rowSize))
		out = append(out, NetRow{
			Proto:      proto,
			LocalIP:    uint32ToIP(row[1]),
			LocalPort:  ntohs(row[2]),
			RemoteIP:   uint32ToIP(row[3]),
			RemotePort: ntohs(row[4]),
			State:      stateName(row[0]),
			PID:        row[5],
		})
	}
	return out, nil
}

// netstatUDP 读一种地址族的 MIB_UDP*_ROW_OWNER_PID 表
// （TableClass = UDP_TABLE_OWNER_PID）。UDP 无连接语义，每行只有本端端点：
// 远端恒为 0.0.0.0:0（v6 为 ::），State 恒空串。
func netstatUDP(family uint32, proto string) ([]NetRow, error) {
	// v4 行 12 字节（Addr4/Port/PID），v6 行 28 字节（Addr16/ScopeId/Port/PID），
	// 布局与 inventory_windows.go 的 udpTable 完全一致，端口同样复用 ntohs
	rowSize, portOff, pidOff := 12, 4, 8
	if family == afInet6 {
		rowSize, portOff, pidOff = 28, 20, 24
	}

	var size uint32
	ret, _, _ := procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(family), udpTableOwnerPID, 0)
	if ret != 0 && size == 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable 获取长度失败: family=%d ret=%d", family, ret)
	}

	buf := make([]byte, size+1024)
	ret, _, _ = procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, uintptr(family), udpTableOwnerPID, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable 失败: family=%d ret=%d", family, ret)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	if count == 0 {
		return nil, nil
	}
	if int(4+int(count)*rowSize) > len(buf) {
		return nil, fmt.Errorf("UDP 表长度异常: family=%d count=%d", family, count)
	}
	base := unsafe.Pointer(&buf[0])

	out := make([]NetRow, 0, count)
	for i := 0; i < int(count); i++ {
		row := unsafe.Add(base, 4+i*rowSize)
		nr := NetRow{
			Proto:     proto,
			LocalPort: ntohs(*(*uint32)(unsafe.Add(row, portOff))),
			PID:       *(*uint32)(unsafe.Add(row, pidOff)),
		}
		if family == afInet6 {
			nr.LocalIP = net.IP((*(*[16]byte)(row))[:]).String()
			nr.RemoteIP = "::"
		} else {
			nr.LocalIP = uint32ToIP(*(*uint32)(row))
			nr.RemoteIP = "0.0.0.0"
		}
		out = append(out, nr)
	}
	return out, nil
}
