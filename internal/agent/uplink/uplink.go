// Package uplink 负责探针与服务端之间的所有网络通信。
//
// 设计要点：
//   - 凭证落地在数据目录（0600），重启后无需重新注册；
//   - 告警采用"本地有界队列 + 批量上报"，断网时不阻塞检测主循环；
//   - 队列满时丢弃最旧告警并计数，绝不无限占用内存；
//   - 所有请求带超时，单次失败不影响整体链路。
package uplink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"zedr/internal/model"
	"zedr/internal/platform/redact"
	"zedr/internal/platform/rulehash"
)

// Credentials 是注册后持久化的凭证。
type Credentials struct {
	AgentID   string `json:"agent_id"`
	Secret    string `json:"agent_secret"`
	Server    string `json:"server_url"`
	MachineID string `json:"machine_id"`
}

// Client 是服务端 API 客户端。
type Client struct {
	baseURL     string
	enrollToken string
	dataDir     string
	http        *http.Client

	mu       sync.Mutex
	creds    *Credentials
	queue    []model.AlertEnvelope
	maxQueue int
	dropped  int64

	// fails 是批次重试的连败计数，键为批次的重试身份（spool 段路径 /
	// 内存内容指纹，拆分子批派生子键）。连败 ≥2 次触发对半拆分——
	// 只记内存：重启归零后重新数两次即可，不值得持久化。
	fails map[string]int

	// spool 是磁盘持久队列（离线/重启不丢告警）。为 nil 时退回内存队列：
	// 数据目录不可写等异常不能阻断检测主链路。
	spool *spool

	lastRuleETag string
	// ruleSignKey 非空时强制校验规则包签名（HG_AGENT_RULE_SIGN_KEY）
	ruleSignKey []byte
	// lastRuleVersion 用于版本单调性检查，防止规则包被回滚到更宽松的历史版本
	lastRuleVersion int

	lastIOCEtag    string
	lastIOCVersion int

	// lastUpgradeETag 是自升级清单的 ETag（状态归 uplink/upgrade.go 使用），
	// 与规则/IOC 同一套协商语义：清单未变时不重复解析与验签。
	lastUpgradeETag string
}

// SetRuleSignKey 设置规则包验签密钥。空值表示不校验（仅记录告警日志）。
func (c *Client) SetRuleSignKey(key []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ruleSignKey = key
}

// SetTLSRootCAs 配置私有 CA 信任池（企业内部 CA 签发服务端证书、系统根池
// 不认的场景）。nil = 回到系统根池。必须在首网请求前调用（构造后立即
// 调用是唯一合法时机）：会整体替换两个客户端的 Transport。
// 升级下载走独立的 upgradeHTTP 客户端（10min 超时），必须一并覆盖，
// 否则"上报走 TLS、下载走明文/系统根"的分裂会被用来绕过证书校验。
func (c *Client) SetTLSRootCAs(pool *x509.CertPool) {
	tlsCfg := func() *tls.Config {
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	c.mu.Lock()
	tr := c.http.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg()
	c.http.Transport = tr
	c.mu.Unlock()
	upg := upgradeHTTP.Transport.(*http.Transport).Clone()
	upg.TLSClientConfig = tlsCfg()
	upgradeHTTP.Transport = upg
}

// New 创建客户端。
func New(baseURL, enrollToken, dataDir string, maxQueue int) *Client {
	if maxQueue <= 0 {
		maxQueue = 5000
	}
	c := &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		enrollToken: enrollToken,
		dataDir:     dataDir,
		http: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		queue:    make([]model.AlertEnvelope, 0, 256),
		maxQueue: maxQueue,
		fails:    make(map[string]int),
	}
	// 磁盘 spool 是主队列；创建失败（目录不可写/无权限）时保持 nil，
	// Enqueue 自动落到上面的内存队列——降级要无声但可观测（QueueMode）。
	if dataDir != "" {
		if sp, err := openSpool(filepath.Join(dataDir, "spool"), maxQueue); err == nil {
			c.spool = sp
		}
	}
	return c
}

// QueueMode 返回当前告警队列形态：disk（持久）或 memory（降级）。
func (c *Client) QueueMode() string {
	if c.spool != nil {
		return "disk"
	}
	return "memory"
}

// LoadCredentials 从数据目录读取已保存的凭证。
func (c *Client) LoadCredentials() bool {
	path := filepath.Join(c.dataDir, "agent.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var creds Credentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		return false
	}
	if creds.AgentID == "" || creds.Secret == "" {
		return false
	}
	c.mu.Lock()
	c.creds = &creds
	c.mu.Unlock()
	return true
}

// Enrolled 返回是否已注册。
func (c *Client) Enrolled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creds != nil
}

// AgentID 返回当前终端 ID。
func (c *Client) AgentID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds == nil {
		return ""
	}
	return c.creds.AgentID
}

// Enroll 调用注册接口并持久化凭证。
func (c *Client) Enroll(ctx context.Context, req model.EnrollRequest) (*model.EnrollResponse, error) {
	req.EnrollToken = c.enrollToken
	var resp model.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/agents/enroll", req, &resp, false); err != nil {
		return nil, err
	}
	if resp.AgentID == "" || resp.AgentSecret == "" {
		return nil, errors.New("服务端返回的注册凭证为空")
	}

	creds := &Credentials{
		AgentID:   resp.AgentID,
		Secret:    resp.AgentSecret,
		Server:    c.baseURL,
		MachineID: req.MachineID,
	}
	if err := c.saveCredentials(creds); err != nil {
		return nil, fmt.Errorf("保存终端凭证失败: %w", err)
	}
	c.mu.Lock()
	c.creds = creds
	c.mu.Unlock()
	return &resp, nil
}

func (c *Client) saveCredentials(creds *Credentials) error {
	if err := os.MkdirAll(c.dataDir, 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(c.dataDir, "agent.json")
	return os.WriteFile(path, raw, 0o600)
}

// Heartbeat 上报心跳并取回待执行指令。
func (c *Client) Heartbeat(ctx context.Context, req model.HeartbeatRequest) (*model.HeartbeatResponse, error) {
	var resp model.HeartbeatResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/agent/heartbeat", req, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Enqueue 把告警放入本地队列（非阻塞）。
func (c *Client) Enqueue(env model.AlertEnvelope) {
	// 统一出口脱敏：命令行可能带安装参数里的密码/令牌，
	// 一旦入队就等于会被写进服务端数据库、管理台页面与导出文件。
	sanitize(&env)

	// 优先落盘：进程重启后仍能补发。写失败（盘满/权限）才降级内存，
	// 降级本身不阻塞检测——但队列上限仍然生效，绝不无限占内存。
	if c.spool != nil {
		if err := c.spool.enqueue(env); err == nil {
			return
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) >= c.maxQueue {
		// 丢弃最旧的一条，保留最近的告警
		c.queue = c.queue[1:]
		c.dropped++
	}
	c.queue = append(c.queue, env)
}

// sanitize 对告警内容做脱敏与截断。
//
// 放在入队这个唯一出口，而不是各个检测层：告警来源会越来越多
// （进程检测、持久化变更、后续的文件/网络行为），分散处理必然漏。
func sanitize(env *model.AlertEnvelope) {
	env.CmdLine = redact.CmdLine(env.CmdLine)
	env.ImagePath = redact.Path(env.ImagePath)
	env.Summary = redact.Text(env.Summary)
	env.Title = redact.Text(env.Title)

	env.Evidence.Process.CmdLine = redact.CmdLine(env.Evidence.Process.CmdLine)
	env.Evidence.Process.Path = redact.Path(env.Evidence.Process.Path)
	for i := range env.Evidence.Ancestry {
		env.Evidence.Ancestry[i].Path = redact.Path(env.Evidence.Ancestry[i].Path)
		env.Evidence.Ancestry[i].Cmd = redact.CmdLine(env.Evidence.Ancestry[i].Cmd)
	}
	for i := range env.Evidence.Signals {
		env.Evidence.Signals[i].Note = redact.CmdLine(env.Evidence.Signals[i].Note)
	}
	for i := range env.Evidence.Notes {
		env.Evidence.Notes[i] = redact.Text(env.Evidence.Notes[i])
	}
}

// Pending 返回队列长度（磁盘 + 内存降级两部分）。
func (c *Client) Pending() int {
	n := 0
	if c.spool != nil {
		n += c.spool.len()
	}
	c.mu.Lock()
	n += len(c.queue)
	c.mu.Unlock()
	return n
}

// Dropped 返回因队列溢出/记录异常丢弃的告警数（跨重启累计）。
func (c *Client) Dropped() int64 {
	n := int64(0)
	if c.spool != nil {
		n += c.spool.droppedCount()
	}
	c.mu.Lock()
	n += c.dropped
	c.mu.Unlock()
	return n
}

// RuleVersion 返回最近一次成功应用的规则包版本。
//
// 为什么由 uplink 暴露而不是让 app 自己记：版本号是在 FetchRules
// 校验/接受之后才更新的，只有这里知道"终端实际在用哪一版"。
// 心跳必须上报真值——此前硬编码 0，服务端看到的终端规则版本永远是
// 假的，规则灰度/回滚在运营面上完全不可见。
func (c *Client) RuleVersion() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRuleVersion
}

// IOCVersion 返回最近一次成功应用的 IOC 包版本（语义同 RuleVersion）。
func (c *Client) IOCVersion() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastIOCVersion
}

// Flush 批量上报队列中的告警。
//
// 先发磁盘段（更旧），再发内存降级队列；磁盘段发送成功才删除。
func (c *Client) Flush(ctx context.Context) (int, error) {
	sent := 0
	if c.spool != nil {
		n, err := c.spool.flush(ctx, c.sendBatchWithPolicy)
		sent += n
		if err != nil {
			return sent, err
		}
	}
	n, err := c.flushMemory(ctx)
	return sent + n, err
}

// sendChunk 发送一个批次。抽出来给磁盘/内存两条路径共用，
// 保证批次语义（200 条、服务端去重）只有一处。
func (c *Client) sendChunk(ctx context.Context, chunk []model.AlertEnvelope) error {
	var resp model.AlertBatchResponse
	return c.do(ctx, http.MethodPost, "/api/v1/agent/alerts",
		model.AlertBatchRequest{Alerts: chunk}, &resp, true)
}

// flushMemory 发送内存降级队列。
func (c *Client) flushMemory(ctx context.Context) (int, error) {
	c.mu.Lock()
	if len(c.queue) == 0 {
		c.mu.Unlock()
		return 0, nil
	}
	batch := c.queue
	c.queue = nil
	c.mu.Unlock()

	// 服务端单批上限 500，这里按 200 分批，降低单次失败的影响面
	sent := 0
	for len(batch) > 0 {
		n := len(batch)
		if n > 200 {
			n = 200
		}
		chunk := batch[:n]
		rej, err := c.sendBatchWithPolicy(ctx, memKey(chunk), chunk)
		if len(rej) > 0 {
			// 被服务端明确拒收的单条：重试只会得到同样的 4xx，
			// 丢弃并计数（唯一允许的丢弃出口，与 spool 同口径）
			c.mu.Lock()
			c.dropped += int64(len(rej))
			c.mu.Unlock()
		}
		if err != nil {
			// 上报失败：把未送达部分放回队列头部，等待下一轮重试。
			// 已送达的子批随整批重发，服务端按 fingerprint 去重兜底。
			keep := make([]model.AlertEnvelope, 0, len(chunk))
			rejected := make(map[int]bool, len(rej))
			for _, i := range rej {
				rejected[i] = true
			}
			for i, e := range chunk {
				if !rejected[i] {
					keep = append(keep, e)
				}
			}
			c.mu.Lock()
			c.queue = append(keep, c.queue...)
			if len(c.queue) > c.maxQueue {
				over := len(c.queue) - c.maxQueue
				c.queue = c.queue[over:]
				c.dropped += int64(over)
			}
			c.mu.Unlock()
			return sent, err
		}
		batch = batch[n:]
		sent += n - len(rej)
	}
	return sent, nil
}

// ---------------------------------------------------------------- 批次重试策略

// 连败拆分 + 抖动退避的参数。基础退避 500ms 起步、指数翻倍封顶 8s：
// 服务端重启窗口（几十秒量级）内靠 5s flush 周期兜底，这里只约束
// 同一轮 flush 内的拆分重试节奏，不再拉长。基础值做成变量仅为测试
// 可以把退避调到毫秒级。
var (
	retryBaseDelay = 500 * time.Millisecond
	retryMaxDelay  = 8 * time.Second
)

// fails 键空间上限：每个失败批最多派生 log2(200)+1 个子键，正常用量
// 远达不到；超限整体重置，代价只是连败从头数。
const retryFailsCap = 4096

// sendBatchWithPolicy 发送一个批次，执行重试策略（磁盘 spool 与内存队列共用）：
//
//  1. 连败拆分：同一批连续失败 ≥2 次（跨 flush 轮次按 key 计数）→ 批内
//     对半拆分再试（200→100→50…），把"一批太大永远过不去"（服务端曾因
//     大批查重慢而 20s 超时 500）变成逐步收敛；首次失败整批留给下一轮，
//     不因一次网络抖动就把批打碎。
//  2. 抖动退避：每次拆分重试前退避 500ms*2^(连败-2)（±30% 抖动），
//     避免服务端重启后众多探针的重试同步齐拍。
//  3. 参数错误短路：400/422 说明请求内容本身非法，原样重试无意义——
//     直接对半拆分定位坏记录；拆到单条仍被拒的记录以下标返回，由调用方
//     单独处置（spool 段内清除 / 内存队列丢弃计数），不再阻塞队列。
//
// 除"单条且服务端明确拒收（400/422）"外绝不丢弃：其余失败一律保留，
// 语义仍是 at-least-once，重复投递由服务端按 fingerprint 去重兜底。
// rejected 返回批内被永久拒收记录的下标（相对 batch）。
func (c *Client) sendBatchWithPolicy(ctx context.Context, key string, batch []model.AlertEnvelope) ([]int, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	err := c.sendChunk(ctx, batch)
	if err == nil {
		c.clearBatchFails(key)
		return nil, nil
	}
	if len(batch) == 1 {
		if isParamRejection(err) {
			// 服务端明确拒收且无兄弟记录可收敛：单独标记交还调用方
			return []int{0}, nil
		}
		return nil, err // 瞬时失败：保留待下一轮
	}
	if !isParamRejection(err) {
		streak := c.markBatchFail(key)
		if streak < 2 {
			return nil, err
		}
		if !sleepBackoff(ctx, backoffDelay(streak)) {
			return nil, err // flush 预算耗尽/停机：剩余部分留给下一轮
		}
	}
	// 对半拆分（400/422 时免退避——参数错误快速失败，二分定位坏记录）。
	// 子键派生自父键：拆分后的连败按子批自身计数。
	half := len(batch) / 2
	rej, err2 := c.sendBatchWithPolicy(ctx, key+"\x00a", batch[:half])
	if err2 != nil {
		return rej, err2
	}
	rej2, err3 := c.sendBatchWithPolicy(ctx, key+"\x00b", batch[half:])
	for _, i := range rej2 {
		rej = append(rej, half+i)
	}
	return rej, err3
}

func (c *Client) markBatchFail(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.fails) >= retryFailsCap {
		c.fails = make(map[string]int)
	}
	c.fails[key]++
	return c.fails[key]
}

func (c *Client) clearBatchFails(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.fails, key)
}

// backoffDelay 拆分重试的指数退避：连败第 n 轮退 500ms*2^(n-2)，封顶 8s。
func backoffDelay(streak int) time.Duration {
	shift := streak - 2
	if shift > 4 {
		shift = 4
	}
	if shift < 0 {
		shift = 0
	}
	d := retryBaseDelay << uint(shift)
	if d <= 0 || d > retryMaxDelay {
		d = retryMaxDelay
	}
	return jitter30(d)
}

// jitter30 给退避加 ±30% 抖动：重启风暴后众多探针的重试时刻不再齐拍，
// 把同步重试洪峰摊成平滑到达。
func jitter30(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	span := d * 3 / 10
	return d - span + time.Duration(rand.Int64N(int64(2*span)+1))
}

// sleepBackoff 等待退避；ctx 取消（flush 预算耗尽/停机）返回 false。
func sleepBackoff(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// memKey 内存批次的重试键：内容指纹（条数 + 首尾 fingerprint）。
// 失败批在下一轮重放时内容不变（新告警只追加队尾），键稳定才能跨轮计连败。
func memKey(chunk []model.AlertEnvelope) string {
	return fmt.Sprintf("m:%d:%s:%s", len(chunk),
		chunk[0].Fingerprint, chunk[len(chunk)-1].Fingerprint)
}

// statusError 携带 HTTP 状态码的错误：重试策略据此区分"请求本身非法
// （400/422，重试无意义）"与"服务端/网络瞬时故障（值得重试）"。
type statusError struct {
	status int
	msg    string
}

func (e *statusError) Error() string { return e.msg }

// isParamRejection 判定服务端是否明确拒收了请求内容。保守起见只认
// 400/422 类参数错误：401/403 可能因重新注册恢复，429 是限流要退避
// 重试，413 等连败拆分后自愈——这些都不跳过。
func isParamRejection(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.status == http.StatusBadRequest || se.status == http.StatusUnprocessableEntity
	}
	return false
}

// FetchRules 拉取规则整包；服务端版本未变时返回 notModified=true。
func (c *Client) FetchRules(ctx context.Context) (*model.RuleBundle, bool, error) {
	c.mu.Lock()
	etag := c.lastRuleETag
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/agent/rules", nil)
	if err != nil {
		return nil, false, err
	}
	c.decorate(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, decodeError(res.StatusCode, body)
	}
	var wrap struct {
		Data model.RuleBundle `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, false, fmt.Errorf("规则包解析失败: %w", err)
	}

	c.mu.Lock()
	key := c.ruleSignKey
	localVer := c.lastRuleVersion
	c.mu.Unlock()

	// 完整性校验：配置了密钥就强制验签，验不过直接拒绝应用。
	// 这一层防的是"下发链路被篡改后悄悄关掉检测"。
	if len(key) > 0 {
		if err := rulehash.Verify(&wrap.Data, key); err != nil {
			return nil, false, fmt.Errorf("规则包校验失败，已拒绝应用: %w", err)
		}
	}

	// 版本单调：拒绝比本地更旧的规则包（重放旧版宽松规则是常见绕过手法）
	if localVer > 0 && wrap.Data.Version < localVer {
		return nil, false, fmt.Errorf("规则包版本回退（本地 %d，收到 %d），已拒绝",
			localVer, wrap.Data.Version)
	}

	c.mu.Lock()
	c.lastRuleETag = res.Header.Get("ETag")
	c.lastRuleVersion = wrap.Data.Version
	c.mu.Unlock()
	return &wrap.Data, false, nil
}

// FetchIOCs 拉取威胁指标整包；服务端版本未变时返回 notModified=true。
// 校验逻辑与 FetchRules 同源：签名 + 版本单调，防篡改与防回滚。
func (c *Client) FetchIOCs(ctx context.Context) (*model.IOCBundle, bool, error) {
	c.mu.Lock()
	etag := c.lastIOCEtag
	key := c.ruleSignKey
	localVer := c.lastIOCVersion
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/agent/iocs", nil)
	if err != nil {
		return nil, false, err
	}
	c.decorate(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, decodeError(res.StatusCode, body)
	}
	var wrap struct {
		Data model.IOCBundle `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, false, fmt.Errorf("IOC 包解析失败: %w", err)
	}

	// 哈希表进入检测引擎前必须过签名：篡改 IOC 可以把恶意样本洗白
	// （删条目）或制造误报风暴（塞垃圾条目），与改规则同级。
	if len(key) > 0 {
		if err := rulehash.VerifyIOCBundle(&wrap.Data, key); err != nil {
			return nil, false, fmt.Errorf("IOC 包校验失败，已拒绝应用: %w", err)
		}
	}
	if localVer > 0 && wrap.Data.Version < localVer {
		return nil, false, fmt.Errorf("IOC 包版本回退（本地 %d，收到 %d），已拒绝",
			localVer, wrap.Data.Version)
	}

	c.mu.Lock()
	c.lastIOCEtag = res.Header.Get("ETag")
	c.lastIOCVersion = wrap.Data.Version
	c.mu.Unlock()
	return &wrap.Data, false, nil
}

// ReportCommandResults 回传指令执行结果。
func (c *Client) ReportCommandResults(ctx context.Context, results []model.CommandResult) error {
	if len(results) == 0 {
		return nil
	}
	var out any
	return c.do(ctx, http.MethodPost, "/api/v1/agent/commands/result",
		map[string]any{"results": results}, &out, true)
}

// PostInventory 上报资产清单差量节，返回服务端确认应用的节名。
//
// sections 为空直接返回：调用方（inventory.Manager）保证差量语义，
// 空批次不该产生网络往返。20s 超时由 http.Client 全局兜底，
// 调用方传 context 控制更细的取消。
func (c *Client) PostInventory(ctx context.Context, sections []model.InventorySection) ([]string, error) {
	if len(sections) == 0 {
		return nil, nil
	}
	var resp model.InventoryAck
	if err := c.do(ctx, http.MethodPost, "/api/v1/agent/inventory",
		model.InventoryReport{Sections: sections}, &resp, true); err != nil {
		return nil, err
	}
	return resp.Applied, nil
}

// ---------------------------------------------------------------- 内部

func (c *Client) decorate(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.mu.Lock()
	creds := c.creds
	c.mu.Unlock()
	if creds != nil {
		req.Header.Set("X-Agent-Id", creds.AgentID)
		req.Header.Set("Authorization", "Bearer "+creds.Secret)
	}
}

func (c *Client) do(ctx context.Context, method, path string, in any, out any, needAuth bool) error {
	if needAuth && !c.Enrolled() {
		return errors.New("终端尚未注册")
	}

	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.decorate(req)

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("请求 %s 失败: %w", path, err)
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return decodeError(res.StatusCode, respBody)
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}

	// 服务端成功响应统一为 {"data": ...}
	var wrap struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respBody, &wrap); err == nil && len(wrap.Data) > 0 {
		return json.Unmarshal(wrap.Data, out)
	}
	return json.Unmarshal(respBody, out)
}

func decodeError(status int, body []byte) error {
	var eb model.ErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Error.Code != "" {
		return &statusError{status: status, msg: fmt.Sprintf("%s (HTTP %d, %s)", eb.Error.Message, status, eb.Error.Code)}
	}
	return &statusError{status: status, msg: fmt.Sprintf("服务端返回 HTTP %d", status)}
}

// TunnelCreds 返回隧道拨号用的凭证快照（供 tunnel.Options.Creds 使用）。
//
// 为什么返回快照而不是暴露 creds 指针：隧道循环是独立的长生命周期
// goroutine，若直接持有指针，重注册（Enroll 覆盖 creds）会与其读取
// 形成数据竞争；在锁内完成拷贝则天然安全。
func (c *Client) TunnelCreds() (agentID, secret string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds == nil {
		return "", "", false
	}
	return c.creds.AgentID, c.creds.Secret, true
}
