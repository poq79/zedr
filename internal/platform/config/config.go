// Package config 提供环境变量驱动的集中配置加载。
//
// 原则：
//   1. 所有配置只来自环境变量（可叠加 .env 文件，方便本地开发）；
//   2. 启动时集中校验，缺失或非法立即失败（fail fast），不带病运行；
//   3. 校验错误一次性汇总返回，避免改一个报一个。
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Loader 收集所有字段的读取与校验错误。
type Loader struct {
	problems []string
}

// Env 读取环境变量（缺失返回 def）。
func (l *Loader) Env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

// Required 读取必填环境变量，缺失则记录问题。
func (l *Loader) Required(key string) string {
	v, ok := os.LookupEnv(key)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		l.problems = append(l.problems, fmt.Sprintf("%s 为必填项但未设置", key))
		return ""
	}
	return v
}

// Duration 读取 duration，非法时回退默认值并记录问题。
func (l *Loader) Duration(key string, def time.Duration) time.Duration {
	raw := l.Env(key, "")
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		l.problems = append(l.problems, fmt.Sprintf("%s=%q 不是合法的 duration（例如 15m、2s、168h）", key, raw))
		return def
	}
	if d <= 0 {
		l.problems = append(l.problems, fmt.Sprintf("%s 必须为正数", key))
		return def
	}
	return d
}

// DurationZeroOK 同 Duration，但允许显式配置为 0（表示"关闭该特性"）。
func (l *Loader) DurationZeroOK(key string, def time.Duration) time.Duration {
	raw := l.Env(key, "")
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		l.problems = append(l.problems, fmt.Sprintf("%s=%q 不是合法的 duration（例如 15m、2s、0s）", key, raw))
		return def
	}
	if d < 0 {
		l.problems = append(l.problems, fmt.Sprintf("%s 不能为负数", key))
		return def
	}
	return d
}

// Int 读取整数。
func (l *Loader) Int(key string, def int) int {
	raw := l.Env(key, "")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		l.problems = append(l.problems, fmt.Sprintf("%s=%q 不是合法整数", key, raw))
		return def
	}
	return n
}

// Float 读取浮点。
func (l *Loader) Float(key string, def float64) float64 {
	raw := l.Env(key, "")
	if raw == "" {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		l.problems = append(l.problems, fmt.Sprintf("%s=%q 不是合法浮点数", key, raw))
		return def
	}
	return f
}

// Bool 读取布尔。
func (l *Loader) Bool(key string, def bool) bool {
	raw := strings.ToLower(l.Env(key, ""))
	if raw == "" {
		return def
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	l.problems = append(l.problems, fmt.Sprintf("%s=%q 不是合法布尔值(true/false)", key, raw))
	return def
}

// CSV 读取逗号分隔列表。
func (l *Loader) CSV(key string, def []string) []string {
	raw := l.Env(key, "")
	if raw == "" {
		return def
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Check 自定义校验；cond 为 false 时记录 msg。
func (l *Loader) Check(cond bool, msg string) {
	if !cond {
		l.problems = append(l.problems, msg)
	}
}

// Err 汇总返回所有校验问题。
func (l *Loader) Err() error {
	if len(l.problems) == 0 {
		return nil
	}
	return fmt.Errorf("配置校验失败:\n  - %s", strings.Join(l.problems, "\n  - "))
}

// SecurityWarning 返回非致命但需提醒的配置风险。
func (l *Loader) SecurityWarning(cond bool, msg string) {
	if !cond {
		l.problems = append(l.problems, "安全风险: "+msg)
	}
}

// LoadDotEnv 从当前目录向上查找 .env 并注入进程环境（不覆盖已存在的真实环境变量）。
// 找不到文件不算错误，方便容器/服务场景直接用系统环境变量。
// LoadDotEnv 查找并加载 .env。
//
// 查找顺序刻意先看"可执行文件所在目录"，再看"当前工作目录"：
// 作为 Windows 服务运行时，工作目录是 C://Windows//System32，
// 只按 cwd 向上找永远是找不到配置的——而这会导致所有 HG_* 变量静默失效，
// 服务用一个完全默认的配置跑起来，排查起来极其隐蔽。
func LoadDotEnv() (string, error) {
	if exe, err := os.Executable(); err == nil {
		if p, err := findDotEnv(filepath.Dir(exe)); p != "" || err != nil {
			if p != "" {
				return p, injectDotEnv(p)
			}
			return "", err
		}
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	p, err := findDotEnv(dir)
	if p == "" || err != nil {
		return p, err
	}
	return p, injectDotEnv(p)
}

// findDotEnv 从 start 开始向上最多 5 层查找 .env。
func findDotEnv(start string) (string, error) {
	dir := start
	for i := 0; i < 5; i++ {
		p := filepath.Join(dir, ".env")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", nil
}

func injectDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// 去掉成对引号
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		// 行尾注释（仅当值未被引号包裹且存在 " #"）
		if i := strings.Index(val, " #"); i > 0 && !strings.Contains(val, "\"") {
			val = strings.TrimSpace(val[:i])
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return sc.Err()
}
