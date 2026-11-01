package service

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"zedr/internal/ai"
	"zedr/internal/ai/eval"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
)

// AI 质量评测执行器。
//
// 两种模式（docs/AI.md §8）：
//   - heuristic：注入/引用/审批等**结构护栏**的契约自检，零 token 成本，
//     用独立引擎跑（不污染生产统计），适合每次改动后回归；
//   - llm：用**当前生产配置**（同槽位/同提示词/同技能包）在独立引擎实例上
//     跑完整质量评测，消耗真实 token（约 44 样本 × 1.5-2k tokens）。
//
// 独立引擎的意义：评测结论必须能代表生产行为，但评测流量不能改写
// 生产侧的 triaged/tokens/budget 统计——两组需求靠"同配置、异实例"同时满足。

//go:embed evaldata/*.json
var evalFixtures embed.FS

// 评测结果存 settings（覆盖式，只保留最近一次——评测是快照不是流水）。
const aiEvalLastRunKey = "ai_eval_last_run"

// loadEvalSamples 读取并校验全部夹具。
func loadEvalSamples() ([]eval.Sample, error) {
	var all []eval.Sample
	for _, name := range []string{"evaldata/triage.json", "evaldata/injection.json"} {
		raw, err := evalFixtures.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("读取评测夹具 %s 失败: %w", name, err)
		}
		var part []eval.Sample
		if err := json.Unmarshal(raw, &part); err != nil {
			return nil, fmt.Errorf("解析评测夹具 %s 失败: %w", name, err)
		}
		all = append(all, part...)
	}
	if err := eval.ValidateSamples(all); err != nil {
		return nil, fmt.Errorf("评测夹具校验失败: %w", err)
	}
	return all, nil
}

// RunEval 执行一次评测并返回结果（同步；heuristic 秒级，llm 分钟级）。
func (s *AIService) RunEval(ctx context.Context, mode string) (*eval.RunResult, error) {
	if mode != "heuristic" && mode != "llm" {
		return nil, apperr.Invalid("mode 只能是 heuristic 或 llm")
	}
	samples, err := loadEvalSamples()
	if err != nil {
		return nil, apperr.Internal(err)
	}

	var eng *ai.Engine
	workers := 8
	switch mode {
	case "heuristic":
		// 独立启发式引擎：评测"降级路径"的结构契约，零 token
		eng = ai.NewEngine(ai.Config{Provider: "none"}, s.log)
	case "llm":
		cfg, prompts, skills, err := s.assembleEngineConfig(ctx)
		if err != nil {
			return nil, err
		}
		if len(cfg.Slots) == 0 {
			return nil, apperr.Invalid("未配置模型服务，无法运行 LLM 质量评测；请先在「模型接入」完成配置")
		}
		eng = ai.NewEngine(cfg, s.log)
		eng.ApplyConfig(cfg, prompts, skills) // 与生产同提示词/技能包
		workers = 3                           // 控制并发，避免触发服务商限流
	}

	started := time.Now()
	results := make([]eval.Result, len(samples))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range samples {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s := samples[i]
			res := eng.Triage(ctx, s.Input(idgen.URLSafe(6)))
			results[i] = eval.FromTriage(&s, res, nil)
		}(i)
	}
	wg.Wait()

	rr := eval.Score(mode, started, samples, results)

	// 持久化最近一次结果（覆盖式）；失败不影响本次返回
	if raw, err := json.Marshal(rr); err == nil {
		_ = s.repos.AIConfig.SetSetting(ctx, aiEvalLastRunKey, string(raw))
	}
	if s.log != nil {
		s.log.InfoContext(ctx, "ai_eval_done", "mode", mode, "total", rr.Metrics.Total,
			"accuracy", rr.Metrics.Accuracy, "passed", rr.Passed, "violations", len(rr.Violations))
	}
	return rr, nil
}

// LastEval 返回最近一次评测结果；从未运行过时返回 (nil, nil)。
func (s *AIService) LastEval(ctx context.Context) (*eval.RunResult, error) {
	raw, ok, err := s.repos.AIConfig.GetSetting(ctx, aiEvalLastRunKey)
	if err != nil || !ok || raw == "" {
		return nil, err
	}
	var rr eval.RunResult
	if err := json.Unmarshal([]byte(raw), &rr); err != nil {
		return nil, nil // 历史格式损坏按"没有记录"处理
	}
	return &rr, nil
}

// EvalSampleInfo 是夹具规模的展示信息。
func EvalSampleInfo() (triage, injection int) {
	samples, err := loadEvalSamples()
	if err != nil {
		return 0, 0
	}
	for _, s := range samples {
		if s.Suite == "injection" {
			injection++
		} else {
			triage++
		}
	}
	return triage, injection
}
