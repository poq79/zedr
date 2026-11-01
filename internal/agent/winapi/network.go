package winapi

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet         = 2
	afInet6        = 23
	tcpTableOwnerPIDAll = 5

	tcpStateEstablished = 5
)

// TCPConn 是一条 TCP 连接（含归属 PID）。
type TCPConn struct {
	Proto      string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	State      string
	PID        uint32
}

// tcpStateNames 把 MIB_TCP_STATE 映射成可读文本。
var tcpStateNames = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
	6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
	10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

// TCPConnections 一次性拉取全系统 TCP 连接表，返回 pid → 连接列表。
//
// 用单次 API 调用获取所有进程的连接，避免"每进程一次"造成 N 次系统调用。
func TCPConnections() (map[uint32][]TCPConn, error) {
	out := make(map[uint32][]TCPConn, 256)

	if err := collectTCP4(out); err != nil {
		return out, err
	}
	// IPv6 失败不影响 IPv4 结果
	_ = collectTCP6(out)
	return out, nil
}

func collectTCP4(out map[uint32][]TCPConn) error {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		afInet, tcpTableOwnerPIDAll, 0)
	if ret != 0 && size == 0 {
		return fmt.Errorf("GetExtendedTcpTable 获取长度失败: %d", ret)
	}

	buf := make([]byte, size+1024)
	ret, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return fmt.Errorf("GetExtendedTcpTable(IPv4) 失败: %d", ret)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	if count == 0 {
		return nil
	}
	// MIB_TCPROW_OWNER_PID = 6 * DWORD；首 4 字节是条目数
	const rowSize = 24
	base := unsafe.Pointer(&buf[0])
	if int(4+int(count)*rowSize) > len(buf) {
		return fmt.Errorf("TCP 表长度异常")
	}

	for i := 0; i < int(count); i++ {
		row := (*[6]uint32)(unsafe.Add(base, 4+i*rowSize))
		pid := row[5]
		if pid == 0 {
			continue
		}
		out[pid] = append(out[pid], TCPConn{
			Proto:      "TCP",
			LocalIP:    uint32ToIP(row[1]),
			LocalPort:  ntohs(row[2]),
			RemoteIP:   uint32ToIP(row[3]),
			RemotePort: ntohs(row[4]),
			State:      stateName(row[0]),
			PID:        pid,
		})
	}
	return nil
}

// MIB_TCP6ROW_OWNER_PID:
//   UCHAR localAddr[16]; DWORD dwLocalScopeId; DWORD dwLocalPort;
//   UCHAR remoteAddr[16]; DWORD dwRemoteScopeId; DWORD dwRemotePort;
//   DWORD dwState; DWORD dwOwningPid;
type tcp6Row struct {
	LocalAddr      [16]byte
	LocalScopeID   uint32
	LocalPort      uint32
	RemoteAddr     [16]byte
	RemoteScopeID  uint32
	RemotePort     uint32
	State          uint32
	OwningPID      uint32
}

func collectTCP6(out map[uint32][]TCPConn) error {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		afInet6, tcpTableOwnerPIDAll, 0)
	if ret != 0 && size == 0 {
		return fmt.Errorf("IPv6 表长度失败")
	}

	buf := make([]byte, size+1024)
	ret, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, afInet6, tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return fmt.Errorf("IPv6 表查询失败: %d", ret)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	const rowSize = 56
	base := unsafe.Pointer(&buf[0])
	if int(4+int(count)*rowSize) > len(buf) {
		return fmt.Errorf("IPv6 表长度异常")
	}

	for i := 0; i < int(count); i++ {
		row := (*tcp6Row)(unsafe.Add(base, 4+i*rowSize))
		if row.OwningPID == 0 {
			continue
		}
		out[row.OwningPID] = append(out[row.OwningPID], TCPConn{
			Proto:      "TCP6",
			LocalIP:    net.IP(row.LocalAddr[:]).String(),
			LocalPort:  ntohs(row.LocalPort),
			RemoteIP:   net.IP(row.RemoteAddr[:]).String(),
			RemotePort: ntohs(row.RemotePort),
			State:      stateName(row.State),
			PID:        row.OwningPID,
		})
	}
	return nil
}

func stateName(s uint32) string {
	if n, ok := tcpStateNames[s]; ok {
		return n
	}
	return fmt.Sprintf("STATE_%d", s)
}

// uint32ToIP 把 MIB 中以网络序存储的 DWORD 还原成点分十进制。
func uint32ToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// ntohs 把以网络序存放在低 16 位的端口转换为主机序。
func ntohs(v uint32) uint16 {
	lo := uint16(v & 0xFFFF)
	return lo<<8 | lo>>8
}

// ---------------------------------------------------------------- 内网判定

var (
	privateOnce sync.Once
	privateNets []*net.IPNet
)

// IsPublicRemote 判断远端地址是否为公网（用于"隐藏窗口 + 公网外联"这类组合判定）。
func IsPublicRemote(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	privateOnce.Do(func() {
		for _, cidr := range []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
			"127.0.0.0/8", "fc00::/7", "fe80::/10",
		} {
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				privateNets = append(privateNets, n)
			}
		}
	})
	for _, n := range privateNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
