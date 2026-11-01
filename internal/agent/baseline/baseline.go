// Package baseline 维护"父子链基线"，为检测体系提供第 4 层（血缘图）信号。
//
// 思路来自 Elastic ProblemChild 与华为"可信进程树"：正常环境里
// "谁拉起谁"是高度稳定的。若某个父进程历史上从不产生某类子进程，
// 这种"罕见的父子组合"本身就是强信号——即便命令行和哈希都干净。
package baseline

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Model 是父子链频次模型。
type Model struct {
	// Pairs[parent][child] = 观测次数
	Pairs map[string]map[string]int `json:"pairs"`
	// ParentTotal[parent] = 该父进程产生过的子进程总数
	ParentTotal map[string]int `json:"parent_total"`
	// Total = 全局观测总数
	Total int64 `json:"total"`
	// ChildrenSeen[child] = 该子进程出现过的不同父进程数
	ChildrenSeen map[string]map[string]struct{} `json:"-"`
	// UpdatedAt 最后更新时间
	UpdatedAt time.Time `json:"updated_at"`

	path string
}

// 冷启动阈值：观测样本少于此数时，对"罕见组合"整体降权。
// 实测：300 样本时线上仍有大量合法进程拿到 7~9 分底噪，提高到 1500 后显著收敛。
const warmupObservations = 1500

// hubFanout：父进程子进程种类数超过该值即为"高扇出父进程"
// （svchost / services / explorer 这类什么都能拉起）。
// 对它们，"没见过的父子组合"几乎没有判别力，必须降权，否则噪声爆炸。
const hubFanout = 15

// Load 从磁盘加载基线；文件不存在时返回空模型。
func Load(path string) *Model {
	m := &Model{
		path:       path,
		Pairs:      make(map[string]map[string]int),
		ParentTotal: make(map[string]int),
		ChildrenSeen: make(map[string]map[string]struct{}),
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	if err := json.Unmarshal(raw, m); err != nil {
		return m
	}
	if m.Pairs == nil {
		m.Pairs = make(map[string]map[string]int)
	}
	if m.ParentTotal == nil {
		m.ParentTotal = make(map[string]int)
	}
	// 重建反查索引
	for parent, children := range m.Pairs {
		for child := range children {
			if m.ChildrenSeen[child] == nil {
				m.ChildrenSeen[child] = make(map[string]struct{})
			}
			m.ChildrenSeen[child][parent] = struct{}{}
		}
	}
	m.path = path
	return m
}

// Learn 记录一次父子关系观测。
func (m *Model) Learn(parent, child string) {
	if parent == "" || child == "" {
		return
	}
	parent = strings.ToLower(parent)
	child = strings.ToLower(child)

	if m.Pairs[parent] == nil {
		m.Pairs[parent] = make(map[string]int)
	}
	m.Pairs[parent][child]++
	m.ParentTotal[parent]++
	m.Total++

	if m.ChildrenSeen[child] == nil {
		m.ChildrenSeen[child] = make(map[string]struct{})
	}
	m.ChildrenSeen[child][parent] = struct{}{}
	m.UpdatedAt = time.Now()
}

// Len 返回观测总量，用于判断是否已走出冷启动。
func (m *Model) Len() int64 { return m.Total }

// Score 计算血缘异常分（0-30）并给出可解释说明。
func (m *Model) Score(parent, child string, ancestors []string, parentAlive bool, pid uint32) (float64, []string) {
	parent = strings.ToLower(parent)
	child = strings.ToLower(child)

	var score float64
	var notes []string

	// 冷启动缩放：样本不足时整体降权，避免初始误报
	confidence := math.Min(1, float64(m.Total)/float64(warmupObservations))

	// 1) 罕见父子组合
	if parent != "" {
		total := m.ParentTotal[parent]
		fanout := len(m.Pairs[parent]) // 该父进程产生过的子进程种类数

		// 高扇出父进程（svchost/explorer 等）什么都能拉起，组合本身没有判别力
		hubFactor := 1.0
		if fanout >= hubFanout {
			hubFactor = 0.25
		} else if fanout >= 8 {
			hubFactor = 0.6
		}

		if total >= 10 {
			seen := m.Pairs[parent][child]
			if seen == 0 {
				rare := 4 + 1.6*math.Log2(float64(total))
				if rare > 10 {
					rare = 10
				}
				add := rare * confidence * hubFactor
				if add >= 1 {
					score += add
					notes = append(notes,
						"血缘异常：该父进程历史子进程均为其它程序，此前从未拉起过此进程")
				}
			} else if seen <= 2 && total >= 30 && fanout < 8 {
				score += 3 * confidence
				notes = append(notes, "血缘稀有：该父子组合在基线中极少出现")
			}
		} else if total == 0 && fanout == 0 {
			add := 6 * confidence
			if add >= 1 {
				score += add
				notes = append(notes, "基线未知：该父进程此前未出现过子进程")
			}
		}
	}

	// 2) 祖先链过长（进程注入器 / 脚本层层嵌套的典型特征）
	if len(ancestors) >= 7 {
		score += 4
		notes = append(notes, "调用链异常深：祖先链长度 "+itoa(len(ancestors)))
	}

	// 3) 孤儿进程：父进程已退出，常见于"父进程拉起子进程后自杀"的规避手法
	if !parentAlive && pid > 100 && !isSystemParent(parent) {
		score += 3
		notes = append(notes, "孤儿进程：父进程已退出，无法还原完整启动链")
	}

	// 4) 攻击链组合：文档程序与命令解释器同时出现在祖先链中
	if hasAny(ancestors, officeApps) && hasAny(ancestors, shells) {
		score += 8
		notes = append(notes, "攻击链特征：文档程序 → 命令解释器的完整调用链")
	}

	// 5) 稀有子进程：全局只有极少数父进程会产生它
	if len(m.ChildrenSeen[child]) == 1 && m.Total > 500 && !isCommonChild(child) {
		score += 2
	}

	if score > 30 {
		score = 30
	}
	score = math.Round(score*10) / 10
	return score, notes
}

// Save 持久化基线。
func (m *Model) Save() error {
	if m.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o750); err != nil {
		return err
	}
	m.UpdatedAt = time.Now()
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// ---------------------------------------------------------------- helpers

var (
	officeApps = []string{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "visio.exe"}
	shells     = []string{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
	commonChild = []string{
		"svchost.exe", "conhost.exe", "runtimebroker.exe", "dllhost.exe", "taskhostw.exe",
		"searchindexer.exe", "backgroundtaskhost.exe", "ctfmon.exe", "msedgewebview2.exe",
		"werfault.exe", "audiodg.exe", "sihost.exe", "explorer.exe", "notepad.exe",
	}
)

func hasAny(list []string, want []string) bool {
	for _, a := range list {
		for _, w := range want {
			if strings.EqualFold(a, w) {
				return true
			}
		}
	}
	return false
}

func isCommonChild(s string) bool {
	for _, c := range commonChild {
		if s == c {
			return true
		}
	}
	return false
}

func isSystemParent(s string) bool {
	switch s {
	case "system", "smss.exe", "wininit.exe", "winlogon.exe", "services.exe", "csrss.exe", "lsass.exe", "":
		return true
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
