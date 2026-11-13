//go:build windows
// +build windows

// 计划任务定义（Task Scheduler 2.0 XML）的富解析，供资产盘点使用。
//
// 为什么单独一个文件：persist.go 里已有一个 parseTaskXML，但它只服务
// 持久化基线的三个布尔信号（开机/登录/定时）与命令行，并且刻意"零值退化"。
// 资产盘点需要的是完整视图（作者/启用状态/权限级别/全部触发器/全部动作），
// 且要求"坏文件能报错、调用方可跳过并计数"——两者关切不同，硬合并会让
// 基线侧多出它不需要的失败面。因此这里提供独立的富解析，供 inventory 使用。
//
// 编码事实（真机实测 2026-11-02）：%SystemRoot%\System32\Tasks 下的任务
// 定义文件没有扩展名，且文件头为 UTF-16LE BOM（FF FE），XML 声明里写着
// encoding="UTF-16"。所以：
//   - 枚举按"全部普通文件"处理，不按扩展名过滤；
//   - 读取后必须按 BOM/魔数转成 UTF-8，否则 encoding/xml 只会看到 NUL 字节；
//   - 转码后 XML 声明仍写 UTF-16，必须给 Decoder 一个直通的 CharsetReader，
//     否则标准库会以 "declared but CharsetReader is nil" 拒绝解析。
//
// 不引新依赖：UTF-16 用标准库 unicode/utf16 + encoding/binary 自行解码。
package winapi

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// taskXMLMaxSize 是单个任务定义文件的读取上限。
//
// 正常任务文件只有几 KB（含 EventTrigger 订阅串的也很少超过 100KB）；
// 设上限是为了防止被替换成超大文件时把一次盘点拖成秒级 IO。超限直接
// 返回 error，调用方按"坏文件"跳过——宁可少一个任务的富字段，不拖垮整节。
const taskXMLMaxSize = 1 << 20

// taskXMLEnumBudget 是整轮枚举的总预算（含遍历与解析）。
//
// 与资产盘点"单节 <50ms 常态"的纪律相比，5s 是兜底而非目标：真机上
// 数百个任务通常几十毫秒完成；留出量级余量是为了兼容磁盘抖动/杀软
// 扫描驻留导致的偶发慢速，同时保证 inventory 轮询不会被单节卡死。
const taskXMLEnumBudget = 5 * time.Second

// TaskXMLInfo 是一个计划任务定义文件里对资产/研判有价值的字段。
//
// 时间字段刻意不输出：任务 XML 的时间带本地时区语义、格式不一，
// 转成字符串既容易误导又需要额外解析成本，本轮不做。
type TaskXMLInfo struct {
	Author   string        `json:"author"`    // RegistrationInfo/Author，缺失为空串
	Enabled  bool          `json:"enabled"`   // Settings/Enabled，缺失按任务计划程序默认 true
	RunLevel string        `json:"run_level"` // Principals/Principal/RunLevel：LeastPrivilege/HighestAvailable
	Triggers []TaskTrigger `json:"triggers"`
	Actions  []TaskAction  `json:"actions"`
}

// TaskTrigger 是一个触发器的类型与启用状态。
//
// Type 取元素名去掉 "Trigger" 后缀，覆盖 schema 里的
// Boot/Logon/Time/Daily/Weekly/Monthly/MonthlyDOW/Calendar/
// SessionStateChange/Registration/Idle/Event。
type TaskTrigger struct {
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

// TaskAction 是一个动作的执行体。
//
// 只收 Exec（命令+参数）与 ComHandler（ClassId 记为 command）：
// ShowMessage/Email 之类对入侵检测几乎没有判别力，忽略可减少噪音。
type TaskAction struct {
	Command   string `json:"command"`
	Arguments string `json:"arguments"`
}

// TaskDef 是一个任务文件的枚举结果。
//
// Err 非空表示该文件读取/解析失败；调用方应保留条目（说明"这里有个文件"）
// 但不要使用 Info——单个坏文件不中断整轮枚举。
type TaskDef struct {
	Name string       // 与既有 tasks 采集口径一致：'\' + 相对路径（去扩展名，反斜杠）
	Path string       // 绝对路径，便于排障
	Info *TaskXMLInfo // 解析成功时的富字段；失败为 nil
	Err  error        // 读取/解析失败原因；成功为 nil
}

// taskXMLDoc 是 Task Scheduler 2.0 schema 的裁剪视图。
// 只声明需要的元素：完整 schema 有几十个与安全无关的调优项，
// 全量建模只会放大维护面与解析失败的可能性。
type taskXMLDoc struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		Principal struct {
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Triggers struct {
		// ,any 保留文档顺序：同一任务可能有多类触发器，
		// 输出顺序稳定才能让资产快照 hash 在内容不变时不抖动。
		Any []taskXMLTrigger `xml:",any"`
	} `xml:"Triggers"`
	Settings struct {
		Enabled *bool `xml:"Enabled"`
	} `xml:"Settings"`
	Actions struct {
		Any []taskXMLAction `xml:",any"`
	} `xml:"Actions"`
}

type taskXMLTrigger struct {
	XMLName xml.Name
	Enabled *bool `xml:"Enabled"`
}

type taskXMLAction struct {
	XMLName   xml.Name
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
	ClassID   string `xml:"ClassId"`
}

// ParseTaskXML 读取并解析一个任务定义文件。
//
// 任何读取/解码/XML 结构错误都返回 error，由调用方决定跳过（资产盘点
// 不允许一个坏文件拖垮整节）。Author/Arguments 等文本统一 TrimSpace：
// 任务编辑器常写入缩进换行，原样透出会让前端展示与 hash 都不稳定。
func ParseTaskXML(path string) (*TaskXMLInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("任务文件不可读: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("不是普通文件: %s", path)
	}
	if st.Size() > taskXMLMaxSize {
		return nil, fmt.Errorf("任务文件超过 %d 字节上限", taskXMLMaxSize)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取任务文件失败: %w", err)
	}

	utf8Body, err := taskXMLToUTF8(raw)
	if err != nil {
		return nil, err
	}

	dec := xml.NewDecoder(bytes.NewReader(utf8Body))
	// 任务文件声明 encoding="UTF-16"，但内容已在上一步转成 UTF-8。
	// 直通返回即可：这是"我们已经转过了"的显式声明，不是忽略编码。
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	var doc taskXMLDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("任务 XML 解析失败: %w", err)
	}

	info := &TaskXMLInfo{
		Author:   strings.TrimSpace(doc.RegistrationInfo.Author),
		Enabled:  true, // schema 默认：Settings/Enabled 缺省即启用
		RunLevel: strings.TrimSpace(doc.Principals.Principal.RunLevel),
		// 初始化为空切片而非 nil：JSON 输出 [] 而不是 null，
		// 资产差量协议按 JSON 文本算 hash，null/[] 来回切换会造成假变更。
		Triggers: make([]TaskTrigger, 0, len(doc.Triggers.Any)),
		Actions:  make([]TaskAction, 0, len(doc.Actions.Any)),
	}
	if doc.Settings.Enabled != nil {
		info.Enabled = *doc.Settings.Enabled
	}

	for _, t := range doc.Triggers.Any {
		typ := strings.TrimSuffix(t.XMLName.Local, "Trigger")
		if typ == "" {
			// 元素名就叫 Trigger（不合 schema）时保留原名，避免输出空类型
			typ = t.XMLName.Local
		}
		enabled := true // 触发器自身的 Enabled 缺省即启用
		if t.Enabled != nil {
			enabled = *t.Enabled
		}
		info.Triggers = append(info.Triggers, TaskTrigger{Type: typ, Enabled: enabled})
	}

	for _, a := range doc.Actions.Any {
		switch a.XMLName.Local {
		case "Exec":
			info.Actions = append(info.Actions, TaskAction{
				Command:   strings.TrimSpace(a.Command),
				Arguments: strings.TrimSpace(a.Arguments),
			})
		case "ComHandler":
			// COM 处理器没有命令行，把 ClassId 当作"执行体"记录：
			// 前端至少能看到 {GUID}，否则这一行动作信息完全缺失。
			info.Actions = append(info.Actions, TaskAction{
				Command: strings.TrimSpace(a.ClassID),
			})
		}
	}
	return info, nil
}

// EnumerateTaskXML 递归枚举 root 下的全部任务定义文件并逐个解析。
//
// 命名口径与持久化基线/资产盘点现有 tasks 节保持一致：Name = '\' +
// 相对路径（截掉扩展名、分隔符统一为反斜杠），这样调用方可以直接用
// 现有 TaskInfo.Path 做 map join，不需要再做字符串归一化。
//
// 容错语义：坏文件保留在结果里（Err 非空）但不中断；超过总预算时
// 提前返回已收集部分（不报错——调用方拿到的是"至少这些"）。
func EnumerateTaskXML(root string) ([]TaskDef, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("任务目录不可读: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("任务目录不是目录: %s", root)
	}

	deadline := time.Now().Add(taskXMLEnumBudget)
	out := make([]TaskDef, 0, 256)
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// 根目录本身不可读要上抛（调用方据此判断整节不可用）；
			// 子目录权限不足（极少见）跳过即可，同 persist 侧口径。
			if path == root {
				return err
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fs.SkipAll // 预算耗尽：带着已收集结果返回
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // 符号链接/设备文件不跟随，防止异常挂载拖慢枚举
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		name := `\` + strings.ReplaceAll(
			strings.TrimSuffix(rel, filepath.Ext(rel)), string(filepath.Separator), `\`)

		info, perr := ParseTaskXML(path)
		out = append(out, TaskDef{Name: name, Path: path, Info: info, Err: perr})
		return nil
	})
	if walkErr != nil {
		return out, walkErr
	}
	return out, nil
}

// taskXMLToUTF8 按 BOM/魔数把任务文件内容转成 UTF-8。
//
// 判定顺序即注释里的优先级：带 BOM 的 UTF-16/UTF-8 最可靠；无 BOM 时
// 用"<"与 NUL 的交替模式识别 UTF-16（真机上也确实存在无 BOM 的变体）；
// 其余一律按 UTF-8 原样交给 XML 解析器，让它自己报错。
func taskXMLToUTF8(raw []byte) ([]byte, error) {
	switch {
	case len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE:
		return decodeUTF16(raw[2:], binary.LittleEndian), nil
	case len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF:
		return decodeUTF16(raw[2:], binary.BigEndian), nil
	case len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF:
		return raw[3:], nil
	case len(raw) >= 2 && raw[0] == '<' && raw[1] == 0:
		return decodeUTF16(raw, binary.LittleEndian), nil
	case len(raw) >= 2 && raw[0] == 0 && raw[1] == '<':
		return decodeUTF16(raw, binary.BigEndian), nil
	}
	return raw, nil
}

// decodeUTF16 把 UTF-16 字节流转成 UTF-8。
//
// 奇数尾字节直接丢弃（半字符无法解释，丢弃比 panic 更符合"坏文件容忍"）；
// utf16.Decode 会正确处理代理对，BMP 外的字符不会变成乱码。
func decodeUTF16(b []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, order.Uint16(b[i:i+2]))
	}
	runes := utf16.Decode(units)
	buf := make([]byte, 0, len(runes))
	for _, r := range runes {
		buf = append(buf, string(r)...)
	}
	return buf
}
