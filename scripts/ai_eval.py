# -*- coding: utf-8 -*-
"""AI 研判质量评测门禁脚本（纯标准库，无第三方依赖）。

用法（仓库根目录）：
    python scripts/ai_eval.py --mode heuristic    # 结构护栏自检，零 token，CI 默认
    python scripts/ai_eval.py --mode llm          # 当前生产配置的真实质量评测（消耗 token）
    python scripts/ai_eval.py --last              # 只打印最近一次结果

行为：登录管理台 → POST /api/v1/ai/eval/run → 打印 Markdown 报告 →
按服务端门禁结论设置退出码（0 通过 / 1 未通过 / 2 调用失败）。

评测口径（docs/AI.md §8）：
- 结论一致率、恶意召回、误报率(FPR)、漏检率(FNR) 分开统计——accuracy 会掩盖方向；
- 注入拦截率/翻转数/审批合规/可溯源率 是结构护栏，任何模式都不打折；
- 合成夹具验证"引擎行为是否符合设计契约"，真实世界质量靠分析师反馈集积累。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(ROOT, ".env")


def read_env_password() -> str:
    """从 .env 读管理员密码（只读 HG_SERVER_BOOTSTRAP_PASSWORD 一行）。"""
    if not os.path.exists(ENV_PATH):
        return ""
    for line in open(ENV_PATH, encoding="utf-8", errors="ignore"):
        if line.startswith("HG_SERVER_BOOTSTRAP_PASSWORD="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        # 本机/内网直连：显式绕代理，否则会话代理会静默 502
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.token = ""

    def call(self, method: str, path: str, body=None, timeout: int = 600):
        req = urllib.request.Request(self.base + path, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        data = json.dumps(body).encode() if body is not None else None
        try:
            with self.opener.open(req, data=data, timeout=timeout) as r:
                out = json.loads(r.read().decode())
                # 全站契约：外层 {data:} 包装
                return out.get("data", out) if isinstance(out, dict) else out
        except urllib.error.HTTPError as e:
            payload = e.read().decode()
            raise SystemExit(f"[ai_eval] {method} {path} -> HTTP {e.status}: {payload[:400]}")
        except urllib.error.URLError as e:
            raise SystemExit(f"[ai_eval] 无法连接 {self.base}: {e}")

    def login(self, user: str, password: str):
        res = self.call("POST", "/api/v1/auth/login", {"username": user, "password": password})
        self.token = res.get("access_token", "")
        if not self.token:
            raise SystemExit("[ai_eval] 登录失败：未取得访问令牌")


def pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def print_report(rr: dict):
    m = rr.get("metrics", {})
    print(f"\n## AI 评测结果（mode={rr.get('mode')} / engine={rr.get('engine')} / "
          f"suite={rr.get('suite')}）\n")
    print(f"- 通过门禁: **{'是' if rr.get('passed') else '否'}**")
    print(f"- 时间: {rr.get('started_at')} · 耗时 {rr.get('duration_ms')}ms · 样本 {m.get('total')}")
    print()
    print("| 指标 | 值 | 说明 |")
    print("|---|---|---|")
    rows = [
        ("结论一致率", pct(m.get("accuracy", 0)), "verdict 精确匹配预期"),
        ("恶意召回", pct(m.get("malicious_recall", 0)), "预期恶意 → 判恶意"),
        ("误报率 FPR", pct(m.get("fp_rate", 0)), "预期无害 → 判恶意（方向：多扰民）"),
        ("漏检率 FNR", pct(m.get("fn_rate", 0)), "预期恶意 → 判无害（方向：真风险）"),
        ("可疑未降级", pct(m.get("suspicious_not_benign", 0)), "预期可疑 → 未被判无害"),
        ("可溯源率", pct(m.get("grounded_rate", 0)), "非 benign 样本的理由全部有有效引用"),
        ("无引用理由占比", pct(m.get("uncited_ratio", 0)), "引用契约违规率（越低越好）"),
        ("注入拦截率", pct(m.get("injection_intercepted", 0)), "注入载荷被隔离的比例"),
        ("注入翻转数", str(m.get("injection_flips", 0)), "注入样本被判无害（必须 0）"),
        ("扫描误拦（对照）", str(m.get("scanner_false_pos", 0)), "正常文本被误判注入"),
        ("审批违规", str(m.get("approval_violations", 0)), "处置建议未强制人工确认（必须 0）"),
        ("降级样本", str(m.get("degraded", 0)), "走了启发式而非模型（LLM 模式必须 0）"),
        ("平均/P95 延迟", f"{m.get('avg_latency_ms', 0):.0f}/{m.get('p95_latency_ms', 0):.0f} ms", ""),
    ]
    for name, val, desc in rows:
        print(f"| {name} | {val} | {desc} |")
    if rr.get("violations"):
        print("\n**门禁违规：**\n")
        for v in rr["violations"]:
            print(f"- {v}")
    failures = rr.get("failures") or []
    if failures:
        print(f"\n**失败样本（{len(failures)}）：**\n")
        print("| 样本 | 预期 | 实际 | 原因 |")
        print("|---|---|---|---|")
        for f in failures[:30]:
            print(f"| {f.get('id')} | {f.get('expected')} | {f.get('actual')} | {f.get('why')} |")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="AI 研判质量评测门禁")
    ap.add_argument("--mode", choices=["heuristic", "llm"], default="heuristic")
    ap.add_argument("--last", action="store_true", help="不运行评测，只打印最近一次结果")
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="")
    args = ap.parse_args()

    cli = Client(args.base_url)
    cli.login(args.user, args.password or read_env_password())

    if args.last:
        rr = cli.call("GET", "/api/v1/ai/eval/last")
        if not rr:
            print("[ai_eval] 还没有任何评测记录，先运行一次 --mode heuristic")
            return 1
        print_report(rr)
        return 0 if rr.get("passed") else 1

    import time
    t0 = time.time()
    rr = cli.call("POST", "/api/v1/ai/eval/run", {"mode": args.mode})
    print(f"[ai_eval] 评测完成（客户端往返 {time.time() - t0:.1f}s）")
    print_report(rr)
    return 0 if rr.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
