#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从探针本地接口或探针日志读取告警并打印摘要。

用法：
  python scripts/show_alerts.py                 # 读本地 API
  python scripts/show_alerts.py --log FILE      # 直接从日志解析
  python scripts/show_alerts.py --server        # 读总控服务端（需先登录）
"""
import json
import os
import sys
import urllib.request

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

AGENT = "http://127.0.0.1:8843"
SERVER = "http://127.0.0.1:8080"


def fetch(url: str):
    with _OPENER.open(url, timeout=5) as r:
        return json.load(r)


def from_log(path: str):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"alert_raised"' not in line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            rows.append({
                "severity": d.get("severity", "?"),
                "verdict": d.get("verdict", "?"),
                "score": d.get("score", 0),
                "process_name": d.get("process", "?"),
                "title": d.get("title", ""),
                "rule_ids": d.get("rules", []),
            })
    return rows


def main() -> int:
    if "--log" in sys.argv:
        path = sys.argv[sys.argv.index("--log") + 1]
        rows = from_log(path)
    else:
        try:
            data = fetch(AGENT + "/api/local/alerts?limit=100")
            rows = data.get("data", {}).get("items", [])
        except Exception as e:
            print("读取探针接口失败:", e)
            return 1

    if not rows:
        print("(暂无告警)")
        return 0

    print("%-9s %-11s %-4s %-24s %s" % ("SEVERITY", "VERDICT", "SCORE", "PROCESS", "TITLE"))
    print("-" * 96)
    for a in rows:
        print("%-9s %-11s %-4s %-24s %s" % (
            a.get("severity", ""),
            a.get("verdict", ""),
            a.get("score", 0),
            str(a.get("process_name", ""))[:24],
            a.get("title", ""),
        ))
    print("\n共 %d 条" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
