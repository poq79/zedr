package api

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"hostguard/internal/server/auth"
)

// ticketStore 为 SSE 提供一次性短时效票据。
//
// 为什么需要它：EventSource 无法自定义 Authorization 头，而按安全规范
// 绝不能把访问令牌放进 URL（会进入访问日志与代理日志）。折中方案是
// 用一个 60 秒有效、单次可用的随机票据，权级等同于发起者本人的只读会话。
type ticketStore struct {
	mu  sync.Mutex
	m   map[string]streamTicket
	ttl time.Duration
}

type streamTicket struct {
	principal *auth.Principal
	exp       time.Time
}

func newTicketStore(ttl time.Duration) *ticketStore {
	return &ticketStore{m: make(map[string]streamTicket), ttl: ttl}
}

func (t *ticketStore) issue(p *auth.Principal) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])

	t.mu.Lock()
	defer t.mu.Unlock()
	// 顺带清理过期票据，避免内存无界增长
	now := time.Now()
	if len(t.m) > 1000 {
		for k, v := range t.m {
			if now.After(v.exp) {
				delete(t.m, k)
			}
		}
	}
	t.m[id] = streamTicket{principal: p, exp: now.Add(t.ttl)}
	return id
}

func (t *ticketStore) consume(id string) (*auth.Principal, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[id]
	if !ok {
		return nil, false
	}
	delete(t.m, id) // 单次使用
	if time.Now().After(v.exp) {
		return nil, false
	}
	return v.principal, true
}
