package service

import (
	"context"
	"encoding/json"
	"time"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/server/domain"
)

// InventorySection 是探针上报的一节资产清单（接收结构）。
// 共享线协议的正式定义在 internal/model（由探针侧任务维护），本层先独立
// 定义同形结构，避免阻塞并行开发；字段与契约保持一致：name/hash/payload。
type InventorySection struct {
	Name    string `json:"name"`
	Hash    string `json:"hash"`
	Payload string `json:"payload"`
}

// inventorySectionNames 是允许上报的节名白名单（与探针侧并行任务约定的
// 共享契约，不得增删）。节名是管理台展示与查询的一部分，必须收敛：
// 开放命名会让一个失控的探针版本把清单表变成垃圾场。
var inventorySectionNames = map[string]struct{}{
	"system":    {},
	"adapters":  {},
	"listeners": {},
	"services":  {},
	"tasks":     {},
	"startup":   {},
	"agent":     {},
}

const (
	// inventoryMaxSections 单次上报节数上限。白名单本身 7 节，上限给 10 节
	// 只留容错余量，防止探针 bug 无限刷行。
	inventoryMaxSections = 10
	// inventoryMaxPayload 单节 payload 上限（512KB）。services 一节在极端
	// 主机上也就几十 KB，512KB 已是 10 倍余量；再大基本可判定探针实现坏了。
	inventoryMaxPayload = 512 << 10
)

// SaveInventory 保存探针上报的资产清单节，返回全部合法节的节名（applied）。
//
// 幂等语义：hash（payload 的 SHA-256 十六进制摘要）与库中相同则跳过写入
// 但仍计入 applied——探针按心跳周期重发全量清单是常态，内容不变就不该
// 产生写放大；管理台也不需要感知"这次上报有没有真的写库"。
// 任一节非法则整体拒绝（400）：部分应用部分拒绝会让探针状态与库内状态难对账。
func (s *AgentService) SaveInventory(ctx context.Context, agentID string, sections []InventorySection) ([]string, error) {
	a, err := s.repos.Agents.ByID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("终端")
	}
	if len(sections) > inventoryMaxSections {
		return nil, apperr.Invalid("单次上报不能超过 %d 节", inventoryMaxSections)
	}

	// 现库 hash 索引：内容没变的节跳过写入
	existing, err := s.repos.Inventory.ListByAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}
	curHash := make(map[string]string, len(existing))
	for _, sec := range existing {
		curHash[sec.Name] = sec.Hash
	}

	applied := make([]string, 0, len(sections))
	unchanged := 0
	now := time.Now()
	for _, sec := range sections {
		if _, ok := inventorySectionNames[sec.Name]; !ok {
			return nil, apperr.Invalid("非法的清单节名: %s", sec.Name)
		}
		if len(sec.Payload) > inventoryMaxPayload {
			return nil, apperr.Invalid("清单节 %s 的 payload 超过 %dKB 上限", sec.Name, inventoryMaxPayload>>10)
		}
		// payload 是不透明 JSON：只校验合法性，不解析内容（JSON 进 JSON 出）
		if !json.Valid([]byte(sec.Payload)) {
			return nil, apperr.Invalid("清单节 %s 的 payload 不是合法 JSON", sec.Name)
		}
		// hash 必须与内容一致：这是探针自证的完整性，也是去重的依据
		if got := sha256Hex(sec.Payload); got != sec.Hash {
			return nil, apperr.Invalid("清单节 %s 的 hash 与内容不匹配", sec.Name)
		}
		applied = append(applied, sec.Name)
		if curHash[sec.Name] == sec.Hash {
			unchanged++
			continue
		}
		if err := s.repos.Inventory.Upsert(ctx, agentID, domain.HostInventorySection{
			Name:      sec.Name,
			Hash:      sec.Hash,
			Payload:   sec.Payload,
			UpdatedAt: now,
		}); err != nil {
			return nil, err
		}
	}

	s.log.InfoContext(ctx, "inventory_saved", "agent_id", agentID,
		"applied", len(applied), "written", len(applied)-unchanged, "unchanged", unchanged)
	return applied, nil
}

// GetInventory 返回主机资产清单（管理台查询）。
func (s *AgentService) GetInventory(ctx context.Context, agentID string) ([]domain.HostInventorySection, error) {
	a, err := s.repos.Agents.ByID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("终端")
	}
	return s.repos.Inventory.ListByAgent(ctx, agentID)
}
