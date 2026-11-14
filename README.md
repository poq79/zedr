# Z-EDR

**A detection-first, user-mode EDR for Windows hosts — with an AI-native investigation console.**

[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%20Server%202016%2B-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows-server)
[![Version](https://img.shields.io/badge/version-0.9.14-informational)](#)

**English** | [中文](README.zh-CN.md)

Z-EDR records process, file-drop, persistence, network and event-log telemetry on
Windows endpoints, scores it with a five-layer detection pipeline mapped to
MITRE ATT&CK, clusters alerts into incidents, and gives analysts an investigation
console with AI triage, live forensics and human-approved response actions.

It runs **entirely in user mode** — no kernel driver, no hooking, no process
injection, and no inline blocking. Z-EDR is an *EDR* (detect & respond), not an
*EPP* (prevent & block). Uninstalling leaves no trace.

---

## The console

<p align="center">
  <img src="assets/console-overview.png" alt="Z-EDR console — duty briefing, alert trend, severity distribution, ATT&CK hits" width="100%">
</p>
<p align="center"><sub>Duty briefing (deterministic aggregation, zero model calls) · alert trend & severity distribution · host / rule / ATT&CK rankings</sub></p>

<p align="center">
  <img src="assets/console-alert-detail.png" alt="Alert evidence chain — score composition, command line, matched signals, lineage" width="49%">
  <img src="assets/console-attack-matrix.png" alt="ATT&CK matrix — hit counts vs rule coverage" width="49%">
</p>
<p align="center"><sub>Every alert carries an explainable evidence chain — left · ATT&CK coverage matrix (hits vs. static coverage) — right</sub></p>

<p align="center">
  <img src="assets/console-incidents.png" alt="Incidents — alerts clustered into attack chains with status machine" width="49%">
  <img src="assets/console-rules.png" alt="Rules center — 44 built-in rules, severity / score / ATT&CK / shadow mode" width="49%">
</p>
<p align="center"><sub>Alerts clustered into incident chains with a disposition state machine — left · rules center with shadow mode &amp; one-click promotion — right</sub></p>

<p align="center">
  <img src="assets/console-hosts.png" alt="Host fleet — online state, CPU, memory, pending alerts, heartbeat" width="49%">
  <img src="assets/console-host-onboard.png" alt="Onboard host — deploy bundle, enrollment token, one-line install" width="49%">
</p>
<p align="center"><sub>Fleet view with per-agent resource footprint — left · three-step onboarding (bundle + token + one command) — right</sub></p>

<p align="center">
  <img src="assets/console-host-detail.png" alt="Host detail — 13 investigation tabs, live agent stats" width="49%">
  <img src="assets/console-ai-platform.png" alt="AI platform — provider, task slots, budget, eval gate" width="49%">
</p>
<p align="center"><sub>Host detail: services / tasks / autoruns / live files / recon / baseline / accounts / changes — left · AI platform: one provider, per-task slots, budget & cache hot-reload — right</sub></p>

<p align="center">
  <img src="assets/console-alerts.png" alt="Alert center — severity filters, scores, disposition" width="49%">
  <img src="assets/console-hunt.png" alt="AI hunting — natural language to a safe, reviewable DSL" width="49%">
</p>
<p align="center"><sub>Alert center with severity / verdict / status filters — left · natural-language hunting compiled to a safe DSL (the model never sees SQL) — right</sub></p>

<p align="center">
  <img src="assets/console-login.png" alt="Login — split screen with the five-layer pipeline story" width="75%">
</p>
<p align="center"><sub>Console entry: the login page doubles as a tour of the five-layer detection pipeline</sub></p>

## Highlights

- **Five-layer detection** — static fingerprints, keyword matching, Sigma-style
  JSON DSL behavioral rules (server-delivered, hot-reloadable), parent-child
  lineage baselining, and score fusion. Every alert carries an explainable
  evidence chain.
- **Broad behavioral telemetry** — file-drop monitoring, USN Journal catch-up
  for drops that happened while the agent was stopped, persistence monitoring
  with baseline-on-first-run, registry autorun watch, network behavior detectors
  (port scan / sweeps / lateral fan-out), ransomware canaries + delete/rename
  rate defense, Windows event-log ingestion, and host inventory change events.
- **Attack-chain correlation** — an EQL-style on-endpoint state machine links
  individual signals into chains (drop→execute→C2, persistence→run,
  injection→outbound), each stage referencing the alert that fed it.
- **AI-native investigation** — grounded AI triage (every claim cites evidence,
  prompt-injection hardened, deterministic fallback without a model), natural-
  language hunting compiled to a safe DSL, agentic alert investigation, cross-
  alert incident narratives, an in-console AI assistant, and a critical-alert
  duty queue — all routed through one configurable AI platform with per-task
  model slots, prompt overrides, budgets and an eval gate (44 synthetic
  fixtures with a deterministic scorer).
- **Live forensics** — outbound-only yamux tunnel (zero inbound listening),
  30 read-only investigation endpoints (processes, connections, files, registry,
  event logs, tasks, services, drivers, logon sessions, ARP/route/DNS cache,
  USN, PE analysis, evidence zip collection), surfaced in the console and to
  MCP clients.
- **Fleet operations** — enrollment + three-step onboarding, signed rule / IOC /
  intel packs (HMAC, dual v1/v2 signatures for mixed fleets), a rules center
  with shadow mode (observe → count → promote), ATT&CK coverage matrix,
  incident state machine with MTTA, IM/email notifications, daily backups,
  Prometheus metrics, offline-sensor alerting, and signed agent self-upgrade.
- **Human-approved response** — `terminate` and file `quarantine`/`restore`
  behind server + agent switches, **off by default**, every action audited.
  Detection drills (five controlled self-tests) are also double-switched and
  off by default.
- **Low, measured footprint** — 0.68% CPU / 24.7 MB RSS on the reference host
  (~250 processes, 2 s scan interval, adaptive backoff when idle); single-
  process detection ≈25 ms; server ingest ≈871 alerts/s sustained.

## Design principles

1. **Detection, not prevention.** No inline blocking or filesystem filters —
   Z-EDR works after the fact: record, detect, investigate, respond.
2. **User mode, low intrusion.** Only documented user-mode APIs. Nothing is
   patched or injected; uninstalling leaves no trace.
3. **Response is opt-in.** Nothing is killed or quarantined without explicit
   configuration and human approval.
4. **Honest limits.** Polling-based collection has a TOCTOU window for
   short-lived processes, and there is no tamper protection. Measured detection
   results are published as-is, including misses — see [Testing](#testing) and
   the known-limitations list.

## Architecture

<p align="center">
  <img src="assets/architecture.svg" alt="Z-EDR architecture: user-mode agent with five-layer pipeline, control server, analysts & integrations" width="100%">
</p>

| Component | Binary | Role |
|---|---|---|
| Server | `zedr-server.exe` | REST API, SQLite, embedded web console, JWT/RBAC, signed rule/IOC/intel delivery, AI orchestration, MCP tools |
| Agent | `zedr-agent.exe` | Collection + detection + attack-chain engine + uplink; installable as a Windows service |
| Desktop panel | `zedr-ui.exe` | WebView2 window for local status & hygiene views (falls back to browser) |
| Diagnostics | `zedr-diag.exe` | Collector self-check (`-compare`, `-persist`, `-usn`, `-hold`, `-spawn`, `-chaintest`, `-netburst`, `-memtestout`) |

## Detection model

| Layer | What | Typical signal |
|---|---|---|
| L1 | Static fingerprint | known-bad SHA256, Authenticode (incl. catalog), path reputation |
| L2 | Keyword | Aho-Corasick multi-pattern scan of command lines |
| L3 | Behavioral rules | Sigma-style JSON DSL rules, server-delivered & hot-reloadable |
| L4 | Lineage graph | parent-child frequency baselines, rare pairs, orphan processes |
| L5 | Fusion | thresholds (≥70 malicious / ≥38 suspicious), allowlist, dedup, warm-up silence |

Beyond the pipeline, dedicated detector families emit their own alert IDs:
`CHAIN-*` (attack chains), `NW-001..005` (network behavior), `FILE-CANARY` /
`FILE-RANSOM` (ransomware defense), `EVT-*` (event log), `INV-*` (inventory
drift), `SEN-OFFLINE` (sensor loss). Detection **drills** let one host rehearse
five controlled self-tests end-to-end (process chain, port scan, service event,
registry run, canary touch) — self-made samples only, double-switched, off by
default.

## Quick start

**Requirements:** Windows 10 / Server 2016+ (x64), Go 1.22+ (1.27 tested), no CGO.

```bash
git clone https://github.com/poq79/zedr.git && cd zedr
go mod download
bash scripts/build.sh            # or: go build -o bin/zedr-server.exe ./cmd/server
cp .env.example .env             # set HG_SERVER_JWT_SECRET + HG_SERVER_ENROLL_TOKEN
./bin/zedr-server.exe            # first run prints the bootstrap admin password once
./bin/zedr-agent.exe             # point it at the server via HG_AGENT_SERVER_URL
```

Console: `http://127.0.0.1:8080` · local panel: `http://127.0.0.1:8843` (loopback only).

**Desktop panel**: launch `bin\zedr-ui.exe` for a native frameless window
(custom titlebar, system-tray notifier, close-to-tray). It auto-connects to
the local agent and starts it if it is not running. The UI process does
nothing in the background — closing the window frees its memory while the
tray notifier and the agent service keep protecting.

Beyond detection, the local panel ships read-only hygiene views: installed
software (with hidden-uninstaller flags), Autoruns-style startup audit
(signature / file-missing flags), security posture & patch checks
(green/yellow/red with reasons), network exposure (listeners → process,
hosts, proxy), and browser extension review — evidence and guidance only,
no one-click "fixing".

Install the agent as a Windows service (auto failure-recovery configured):

```powershell
.\bin\zedr-agent.exe -install     # start + auto-start on boot
.\bin\zedr-agent.exe -uninstall   # stop + remove
```

**Deploy to a second machine** — the console's *Hosts → Onboard host* page closes
the loop: download the deploy bundle (agent + tray + install scripts), copy the
enrollment parameters, and run one command on the target:

```powershell
.\install-agent.ps1 -Url http://<server>:8080 -Token <enroll-token> [-Tags a,b] [-WithUI]
```

The script is idempotent (rerun = reinstall), exits with stable codes (0 enrolled
/ 2 privileges / 4 arguments), and fleets verify via `-status -json` (`online`).

All configuration is environment variables (`HG_*`), validated at startup — see
[`.env.example`](.env.example) for every option with comments.

## Safety defaults

| Capability | Default | Switch |
|---|---|---|
| Process terminate | **off** | `HG_SERVER_KILL_ENABLED` + `HG_AGENT_KILL_ENABLED` |
| File quarantine / restore | **off** | `HG_SERVER_QUARANTINE_ENABLED` + `HG_AGENT_QUARANTINE_ENABLED` |
| Live file-content read | **off** | `HG_SERVER_LIVEQUERY_FILEREAD` |
| Live queries (read-only) | on | `HG_SERVER_LIVEQUERY_ENABLED` |
| Evidence zip collection | **off** | `HG_SERVER_LIVEQUERY_COLLECT` |
| Detection drills | **off** | `HG_SERVER_DRILL_ENABLED` + `HG_AGENT_DRILL_ENABLED` |
| Agent self-upgrade | **off** | see `.env.example` |

Response actions are audited, RBAC-gated, and never automatic.

## Interfaces

- **Agent API** (API key): enroll, heartbeat, alert ingest, rule fetch, command result, tunnel upgrade.
- **Console API** (JWT): dashboard, alerts, incidents, hosts, inventory, commands, live queries, ATT&CK matrix, IOCs/intel, rules, allowlist, audit, users, SSE stream.
- **MCP tools** (Bearer token, read-only): alert/incident/intel queries plus
  `host_live` — real-time on-endpoint forensics. Every tool call is audited;
  the AI assistant in the console shares the same toolset.
- **Public**: `/health`, `/ready`, `/metrics` (Prometheus text format).

The full endpoint table and RBAC matrix live in the repository's internal docs.

## Testing

```bash
go vet ./...                          # static analysis — must be clean
go test ./...                         # unit + integration (temp SQLite)
bash scripts/simulate_detection.sh    # controlled end-to-end run (self-made samples only)
python scripts/scenarios.py all       # detection matrix / false positives / perf / load
```

Samples are limited to self-built binaries, constructed command lines and the
EICAR string — no external executables are ever downloaded.

**Measured results, published as-is** (see the test report in the repo history
for the full methodology):

- Detection matrix: 17 scripted scenarios — **13 detected cleanly**; 2 are
  known weak-signal calibration items and 2 are environment/design blind
  spots (documented, not hidden).
- Steady-state false positives: **0** on the long-running reference host
  (worst round across all campaigns: 1/256).
- Attack chains: 3 of 4 chain rules verified end-to-end; the fourth (brute
  force → success) needs a real brute-force wave that cannot be safely
  fabricated.
- AI eval gate: 44 synthetic fixtures (26 triage + 18 prompt-injection) with
  a deterministic scorer; the first baseline run was fully green
  (agreement / recall / injection blocking).

## Known limitations

- Collection is user-mode polling (default 2 s, adaptive). Processes shorter
  than one interval can be missed (TOCTOU); file-drop monitoring partially
  compensates, and USN catch-up recovers drops during agent downtime. An ETW
  consumer implementation exists behind a build tag but is **not** enabled — it
  failed validation on Windows Server 2022.
- USN records carry only the leaf file name, so catch-up feeds the same
  base-name fallback used when path resolution is incomplete. Deletion records
  are ignored by design.
- Alert delivery is at-least-once: a crash after the server accepted a batch but
  before the spool segment was deleted can replay that batch; server-side
  fingerprint dedup absorbs the common case.
- No kernel-level blocking or tamper protection by design.
- Authenticode verification uses local caches; no online revocation checks.
- IOC/intel libraries are manually maintained and signed for delivery; no
  automatic intelligence feeds yet.
- **Linux agent (experimental)**: a Linux build (`GOOS=linux`) shares the
  detection engine, procfs collection, netwatch, attack-chain, ransom canaries
  and persistence baselines (cron/systemd/ssh profiles) with the Windows agent.
  It is cross-compile and unit-test validated only — **not yet validated on
  real Linux hardware**; response commands, memory scanning, event-log
  ingestion and ETW are Windows-only.

## Contributing

Issues and pull requests are welcome. Please run `go vet ./...` and
`go test ./...` before opening a PR, and keep changes focused.

**Enable the local secret scanner** (recommended once per clone, zero dependencies):

```bash
bash scripts/install-hooks.sh
```

The pre-commit hook blocks commits that contain private keys, common token
formats (AWS/GitHub/Slack/Google), `.env`-style files, or non-placeholder
credential assignments. Bypass for a single commit with `git commit --no-verify`
(discouraged — if a real secret was committed, rotate it; cleaning history does
not make it safe).

## License

A license is being selected before the first public release — see `LICENSE`
once added. Until then, all rights reserved.
