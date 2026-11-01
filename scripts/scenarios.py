#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HostGuard 检测能力评估套件

安全边界：不下载任何外部文件，所有"攻击样本"均由本机自造：
  - 二进制改名：复制我方 hgdiag.exe，内容完全无害
  - 可疑命令行：只用 echo 打印，再用 ping 回环保活，绝不执行真实危险命令
  - EICAR：行业标准测试串，本身不含可执行代码

判定口径：直接读该进程在引擎里的 **评分与判定**，而不是只看"有没有新增告警"。
这样才能区分三种完全不同的情况：
  检出并告警 / 检出但被降噪抑制（warmup、duplicate） / 根本没判出来（漏检）

用法：
  python scripts/scenarios.py            跑攻击场景矩阵
  python scripts/scenarios.py fp         误报面分析
  python scripts/scenarios.py perf       探针资源占用
  python scripts/scenarios.py load       服务端接入吞吐压测
  python scripts/scenarios.py all        全部
"""
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import urllib.request

# 会话环境可能配置了系统 HTTP 代理，访问 127.0.0.1 必须显式绕过
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
AGENT = "http://127.0.0.1:8843"
SERVER = "http://127.0.0.1:8080"
WORK = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Temp", "hg-scenarios")
HGD_IAG = os.path.join(BIN, "hgdiag.exe")

# 文件类样本的路径标记（用于与系统同名进程区分）
WORK_MARK = "hg-scenarios"

MALICIOUS_AT = 70
SUSPICIOUS_AT = 38

# 探针本地 API 的访问令牌（v0.9 起强制校验，见 internal/agent/localapi/auth.go）
def _local_token():
    p = os.path.join(os.environ.get("LOCALAPPDATA", ""), "HostGuard", "local.token")
    try:
        with open(p, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""

LOCAL_TOKEN = _local_token()

report = {"scenarios": [], "falsepositives": [], "perf": {}, "load": {}}


# ----------------------------------------------------------------- 基础工具
def http_get(url, timeout=8):
    h = {"X-HG-Token": LOCAL_TOKEN} if LOCAL_TOKEN else {}
    req = urllib.request.Request(url, headers=h)
    with _OPENER.open(req, timeout=timeout) as r:
        return json.load(r)


def http_post(url, payload, headers=None, timeout=10):
    data = json.dumps(payload).encode()
    h = {"Content-Type": "application/json"}
    if LOCAL_TOKEN:
        h["X-HG-Token"] = LOCAL_TOKEN
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with _OPENER.open(req, timeout=timeout) as r:
        body = r.read()
        return r.status, (json.loads(body) if body else None)


def processes():
    try:
        return http_get(AGENT + "/api/local/processes?limit=600")["data"]["items"]
    except Exception:
        return []


def alerts():
    try:
        return http_get(AGENT + "/api/local/alerts?limit=200")["data"]["items"]
    except Exception:
        return []


def copy_as(name):
    dst = os.path.join(WORK, name)
    shutil.copy2(HGD_IAG, dst)
    return dst


def spawn(path, *args):
    return subprocess.Popen([path, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=0x00000008)


def spawn_cmd(cmdline):
    return subprocess.Popen(["cmd", "/c", cmdline], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, creationflags=0x00000008)


def payload(text, seconds=12):
    """含特征串但无实际危害：只 echo，靠 ping 回环保活以跨越采集周期。"""
    return f'echo {text} & ping -n {max(3, seconds)} 127.0.0.1 >nul'


def _deep_sample():
    deep = os.path.join(WORK, "a", "b", "c", "d", "e", "f")
    os.makedirs(deep, exist_ok=True)
    dst = os.path.join(deep, "helper.exe")
    shutil.copy2(HGD_IAG, dst)
    return dst


def _eicar():
    e1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    e2 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    path = os.path.join(WORK, "eicar_test.com")
    with open(path, "w", encoding="ascii") as f:
        f.write(e1 + e2)
    try:
        subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=0x00000008)
    except Exception:
        pass  # Windows 不支持 .com 执行，属预期


# ----------------------------------------------------------------- 场景定义
SCENARIOS = [
    dict(id="S01", name="伪装系统进程（temp 下的 svchost.exe）",
         run=lambda: spawn(copy_as("svchost.exe"), "-hold", "20s"),
         probe=("svchost.exe", "", WORK_MARK), expect=["HG-016"]),

    dict(id="S02", name="改名扫描器（temp 下的 nmap.exe）",
         run=lambda: spawn(copy_as("nmap.exe"), "-hold", "20s"),
         probe=("nmap.exe", "", WORK_MARK), expect=["N-009", "HG-019"]),

    dict(id="S03", name="Office→shell 父子链（winword.exe 拉起 cmd.exe）",
         run=lambda: spawn(copy_as("winword.exe"), "-hold", "20s",
                           "-spawn", "cmd.exe /c ping -n 9 127.0.0.1"),
         probe=("winword.exe", "", WORK_MARK), expect=["HG-001"]),

    dict(id="S04", name="PowerShell 编码命令（弱信号单独出现）",
         run=lambda: spawn_cmd(payload("-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")),
         probe=("cmd.exe", "-enc SQBFAFgA"), expect=["K-001", "K-002"]),

    dict(id="S05", name="删除卷影副本（勒索前置）",
         run=lambda: spawn_cmd(payload("vssadmin delete shadows /all /quiet")),
         probe=("cmd.exe", "delete shadows"), expect=["K-014", "HG-009"]),

    dict(id="S06", name="清空事件日志（反取证）",
         run=lambda: spawn_cmd(payload("wevtutil cl system")),
         probe=("cmd.exe", "wevtutil cl"), expect=["K-022", "HG-034"]),

    dict(id="S07", name="计划任务持久化",
         run=lambda: spawn_cmd(payload("schtasks /create /tn upd /tr calc")),
         probe=("cmd.exe", "schtasks /create"), expect=["K-024", "HG-013"]),

    dict(id="S08", name="服务创建指向可写目录（echo 模拟）",
         run=lambda: spawn_cmd(payload(r"sc create upd binpath= C:\Temp\upd.exe")),
         probe=("cmd.exe", "sc create"), expect=["HG-014", "K-025"]),

    dict(id="S09", name="注册表 Run 持久化（echo 模拟）",
         run=lambda: spawn_cmd(payload(r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x")),
         probe=("cmd.exe", "CurrentVersion"), expect=["HG-023", "K-027"]),

    dict(id="S10", name="挖矿命令行",
         run=lambda: spawn_cmd(payload("miner --url stratum+tcp://pool.example:3333")),
         probe=("cmd.exe", "stratum+tcp"), expect=["K-028", "HG-022"]),

    dict(id="S11", name="AMSI 绕过载荷",
         run=lambda: spawn_cmd(payload("bypass amsiutils amsi.dll")),
         probe=("cmd.exe", "amsiutils"), expect=["K-037"]),

    dict(id="S12", name="深层目录无签名程序",
         run=lambda: spawn(_deep_sample(), "-hold", "20s"),
         probe=("helper.exe", "", WORK_MARK), expect=["HG-021", "HG-031"]),

    dict(id="S13", name="EICAR 标准测试样本（静态哈希层）",
         run=lambda: _eicar(), probe=("eicar_test.com", ""), expect=["S-HASH"]),

    dict(id="S14", name="极短命进程（验证轮询采集盲区）",
         run=lambda: subprocess.run(["cmd", "/c", "echo short-lived"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
         probe=None, expect=[]),
]


def locate(probe):
    """在探针视图里定位目标进程。

    probe = (进程名, 命令行标记, 路径标记)
    路径标记用于把"我们造的那一份"与系统里同名的真实进程区分开
    （例如本机有 10 个 svchost.exe）。
    """
    if not probe:
        return None
    name, marker = probe[0], probe[1]
    path_hint = probe[2] if len(probe) > 2 else ""
    best = None
    for r in processes():
        if (r.get("name") or "").lower() != name.lower():
            continue
        if marker and marker.lower() not in (r.get("cmdline") or "").lower():
            continue
        if path_hint and path_hint.lower() not in (r.get("path") or "").lower():
            continue
        if best is None or (r.get("score") or 0) > (best.get("score") or 0):
            best = r
    return best


def run_scenarios():
    print("=" * 100)
    print("攻击场景矩阵（全部为本地自造样本，零外部下载）")
    print("=" * 100)

    os.makedirs(WORK, exist_ok=True)
    if not processes():
        print("!! 探针本地接口不可用，请先启动 secagent.exe")
        return []

    results = []
    for sc in SCENARIOS:
        print(f"\n[{sc['id']}] {sc['name']}")
        before = {a["id"] for a in alerts()}
        try:
            sc["run"]()
        except Exception as e:
            print("    执行异常:", e)

        row = None
        for _ in range(10):
            time.sleep(2)
            row = locate(sc["probe"])
            if row and (row.get("score") or 0) > 0:
                break

        new_alerts = [a for a in alerts() if a["id"] not in before]

        if sc["probe"] is None:
            state, score, suppressed, title = "未观测（预期漏检）", 0, "", ""
        elif row is None:
            state, score, suppressed, title = "未采集到该进程", 0, "", ""
        else:
            score = row.get("score") or 0
            suppressed = row.get("suppressed") or ""
            title = row.get("title") or ""
            if score >= MALICIOUS_AT:
                state = "检出·恶意"
            elif score >= SUSPICIOUS_AT:
                state = "检出·可疑"
            elif suppressed == "whitelist":
                state = "白名单豁免"
            else:
                state = "漏检"

        print(f"    引擎判定: {state}  score={score}  suppressed={suppressed or '-'}")
        if title:
            print(f"    理由: {title}")
        if new_alerts:
            print(f"    新增告警 {len(new_alerts)} 条: {[a['process_name'] for a in new_alerts][:5]}")

        results.append(dict(sc_id=sc["id"], name=sc["name"], state=state, score=score,
                            suppressed=suppressed, title=title, expect=sc["expect"],
                            new_alerts=len(new_alerts)))
        time.sleep(4)

    print("\n" + "=" * 100)
    print("%-4s %-42s %-16s %-6s %s" % ("ID", "场景", "引擎判定", "分值", "说明"))
    print("-" * 100)
    for r in results:
        print("%-4s %-42s %-16s %-6s %s" % (r["sc_id"], r["name"][:40], r["state"], r["score"],
                                            r["suppressed"] or "-"))

    det = sum(1 for r in results if r["state"].startswith("检出"))
    print(f"\n合计：检出 {det}/{len(results)}（被降噪抑制会标注 duplicate/warmup，但判定仍成立）")

    report["scenarios"] = results
    return results


# ----------------------------------------------------------------- 误报面
def run_fp():
    print("\n" + "=" * 100)
    print("误报面分析：当前全部进程的评分分布")
    print("=" * 100)
    rows = processes()
    if not rows:
        print("探针不可用")
        return []

    scored = [r for r in rows if (r.get("score") or 0) > 0]
    scored.sort(key=lambda r: -(r.get("score") or 0))

    print("进程总数=%d，评分 0 的=%d，评分>0 的=%d" % (len(rows), len(rows) - len(scored), len(scored)))
    print("\n%-6s %-26s %-16s %s" % ("分值", "进程", "抑制原因", "路径"))
    print("-" * 100)
    for r in scored[:40]:
        print("%-6d %-26s %-16s %s" % (r["score"], (r.get("name") or "")[:24],
                                       (r.get("suppressed") or "-"), (r.get("path") or "")[:46]))

    report["falsepositives"] = scored[:40]
    return scored


# ----------------------------------------------------------------- 性能
def run_perf(seconds=30):
    print("\n" + "=" * 100)
    print(f"探针资源占用采样（{seconds}s）")
    print("=" * 100)
    cpu, mem, lat = [], [], []
    base = None
    end = time.time() + seconds
    while time.time() < end:
        try:
            d = http_get(AGENT + "/api/local/status")["data"]
            base = base or d
            cpu.append(d.get("cpu_percent") or 0)
            mem.append(d.get("mem_mb") or 0)
            lat.append((d.get("stats") or {}).get("avg_latency_ms") or 0)
        except Exception:
            pass
        time.sleep(2)

    def agg(xs):
        return (round(statistics.mean(xs), 2), round(max(xs), 2)) if xs else (0, 0)

    c, c_max = agg(cpu)
    m, m_max = agg(mem)
    l, l_max = agg(lat)
    print(f"CPU     平均 {c}%   峰值 {c_max}%")
    print(f"内存    平均 {m} MB  峰值 {m_max} MB")
    print(f"检测耗时 平均 {l} ms  峰值 {l_max} ms")
    if base:
        st = base.get("stats") or {}
        print(f"\n监控进程 {base.get('proc_count')}  规则 {base.get('rule_count')}  "
              f"基线样本 {base.get('baseline_size')}")
        print(f"累计扫描 {st.get('scanned')}  告警 {st.get('fired')}  "
              f"抑制 {st.get('suppressed')}  白名单 {st.get('whitelisted')}")

    report["perf"] = dict(cpu_avg=c, cpu_max=c_max, mem_avg=m, mem_max=m_max,
                          latency_avg=l, latency_max=l_max,
                          proc_count=(base or {}).get("proc_count"),
                          baseline=(base or {}).get("baseline_size"),
                          stats=(base or {}).get("stats"))


# ----------------------------------------------------------------- 接入压测
def run_load(batches=20, per_batch=100):
    print("\n" + "=" * 100)
    print(f"服务端接入压测：{batches} 批 × {per_batch} 条 = {batches * per_batch} 条")
    print("=" * 100)

    token = os.environ.get("HG_AGENT_ENROLL_TOKEN", "dev-enroll-token-change-me")
    try:
        _, res = http_post(SERVER + "/api/v1/agents/enroll", {
            "enroll_token": token, "machine_id": "LOADTEST-0001", "hostname": "LOADTEST-HOST",
            "os_version": "test", "arch": "amd64", "username": "load", "version": "test",
        })
    except Exception as e:
        print("注册压测终端失败:", e)
        return
    agent = res["data"]
    headers = {"X-Agent-Id": agent["agent_id"], "Authorization": "Bearer " + agent["agent_secret"]}

    lat, ok = [], 0
    t0 = time.time()
    for b in range(batches):
        batch = [{
            "fingerprint": "load-%d-%d" % (b, i), "title": "压测告警 %d-%d" % (b, i),
            "summary": "性能测试", "verdict": "suspicious", "severity": "medium", "score": 45,
            "pid": 1000 + i, "ppid": 4, "process_name": "loadtest.exe",
            "image_path": r"C:\Temp\loadtest.exe", "cmdline": "loadtest.exe --bench",
            "proc_user": "LOAD", "hash_sha256": "0" * 64, "signed": False,
            "rule_ids": ["HG-021"], "mitre": ["T1036"],
            "evidence": {"process": {"name": "loadtest.exe", "pid": 1000 + i}},
            "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        } for i in range(per_batch)]
        s = time.time()
        try:
            http_post(SERVER + "/api/v1/agent/alerts", {"alerts": batch}, headers, timeout=40)
            ok += per_batch
        except Exception as e:
            print("  批次 %d 失败: %s" % (b, e))
        lat.append((time.time() - s) * 1000)

    elapsed = time.time() - t0
    print(f"成功写入 {ok} 条，总耗时 {elapsed:.2f}s，吞吐 {ok / elapsed:.0f} 条/秒")
    print(f"批次延迟 平均 {statistics.mean(lat):.1f}ms  最大 {max(lat):.1f}ms")

    report["load"] = dict(total=ok, elapsed=round(elapsed, 2),
                          tps=round(ok / elapsed) if elapsed else 0,
                          latency_avg_ms=round(statistics.mean(lat), 1),
                          latency_max_ms=round(max(lat), 1))


def cleanup():
    shutil.rmtree(WORK, ignore_errors=True)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "scenarios"
    # "matrix" 是 "scenarios" 的别名——口头语都管这步叫场景矩阵，
    # 传 matrix 却被静默当 no-op 跳过（报告照样写出但 scenarios 为空）
    # 属于最阴险的工具坑，这里显式收编。
    if mode == "matrix":
        mode = "scenarios"
    if mode not in ("scenarios", "fp", "perf", "load", "all"):
        print("未知模式 %r，可用：scenarios(默认) | fp | perf | load | all" % mode)
        sys.exit(2)
    try:
        if mode in ("scenarios", "all"):
            run_scenarios()
        if mode in ("fp", "all"):
            run_fp()
        if mode in ("perf", "all"):
            run_perf()
        if mode in ("load", "all"):
            run_load()
    finally:
        cleanup()
        out = os.path.join(ROOT, ".smoke", "scenario-report.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("\n报告已写入 %s" % out)


if __name__ == "__main__":
    main()
