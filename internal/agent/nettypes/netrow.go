package nettypes

// NetRow 是 netstat 展示行（liveapi /netstat 端点的输出形状）：
// Windows 由 GetExtendedTcpTable 投影，Linux 由 /proc/net/tcp + inode→PID
// 映射投影，服务端零分叉。
type NetRow struct {
	Proto      string `json:"proto"`
	LocalIP    string `json:"local_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint16 `json:"remote_port"`
	State      string `json:"state"`
	PID        uint32 `json:"pid"`
}
