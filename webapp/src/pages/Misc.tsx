import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowUpCircle, Copy, Download, Eye, EyeOff, KeyRound, Monitor, Plus, RefreshCw, ShieldCheck, Sparkles } from 'lucide-react';
import { api } from '../lib/api';
import type { Host, AllowEntry, AuditRow, User as UserRow, Role, IntegrityReport, Incident, Burst, UpgradeAvail, FleetStatus, FleetEntry } from '../lib/types';
import { SEV_LABEL, relTime, fmtTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Input, Select, SkeletonRows } from '../components/ui/basics';
import { Drawer, useToast, useConfirm } from '../components/ui/overlays';
import { useError } from '../lib/hooks';
import { cn, cmpVersion } from '../lib/utils';

/* ================= 主机终端 ================= */
/* 主机详情已升级为整页 /hosts/:id（见 HostDetail.tsx） */

/** 接入引导配置（GET /api/v1/deploy/enroll-config，adminOnly）。 */
interface EnrollConfig { enroll_token: string; deploy_enabled: boolean; deploy_version: string }

/** 复制到剪贴板：管理台常经 http://局域网IP 访问（非安全上下文），
    navigator.clipboard 不存在，必须留 execCommand 兜底。 */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard) { await navigator.clipboard.writeText(text); return true; }
  } catch { /* 落到 execCommand */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch { return false; }
}

/** 接入新主机抽屉：下载部署包 → 展示接入参数 → 生成一条命令。
    面向"在另一台机器装探针"的运维人员，零外部文档闭环。 */
function DeployDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [cfg, setCfg] = useState<EnrollConfig | null>(null);
  const [cfgErr, setCfgErr] = useState<string | null>(null);
  const [serverUrl, setServerUrl] = useState(() => window.location.origin);
  const [showToken, setShowToken] = useState(false);
  const [withUI, setWithUI] = useState(false);
  const [tags, setTags] = useState('');
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (!open || cfg || cfgErr) return;
    api.get<EnrollConfig>('/api/v1/deploy/enroll-config')
      .then(setCfg)
      .catch((e) => setCfgErr((e as Error).message));
  }, [open, cfg, cfgErr]);

  const token = cfg?.enroll_token || '';
  const command = [
    '.\\install-agent.ps1',
    `-Url ${serverUrl.trim() || 'http://<总控地址>:8080'}`,
    token ? `-Token ${showToken ? token : '<令牌>'}` : '-Token <注册令牌>',
    tags.trim() ? `-Tags ${tags.trim()}` : '',
    withUI ? '-WithUI' : '',
  ].filter(Boolean).join(' ');

  const doCopy = async (text: string, what: string) => {
    const ok = await copyText(text);
    toast(ok ? `已复制${what}` : '复制失败，请手动选择复制', ok ? undefined : 'err');
  };

  const doDownload = async () => {
    setDownloading(true);
    try {
      const blob = await api.download('/api/v1/deploy/agent-package');
      const name = cfg?.deploy_version ? `zedr-deploy-v${cfg.deploy_version}.zip` : 'zedr-deploy.zip';
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      URL.revokeObjectURL(a.href);
      toast('部署包已开始下载');
    } catch (e) {
      toast((e as Error).message, 'err');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <Drawer open={open} onClose={onClose} width={720}
      title="接入新主机"
      sub={<>在目标 Windows 机器上以管理员完成以下三步；装完约 30 秒内出现在主机列表。</>}>
      {/* 仅打开时渲染内容：Drawer 为动画常驻 DOM，children 常驻会出现在
          无障碍树里，且配置未加载时第一步会闪出误导性的"未配置"占位 */}
      {open && <div className="space-y-5">
        {/* 第一步：下载部署包 */}
        <section className="rounded-lg border border-border p-4">
          <h3 className="m-0 flex items-center gap-2 text-[13.5px] font-semibold">第一步 · 下载部署包</h3>
          <p className="mt-1.5 text-xs text-faint">
            包内含探针、桌面托盘与官方安装/卸载脚本；响应头 X-ZEDR-Package-SHA256 可用于完整性核对。
          </p>
          <div className="mt-2.5">
            {cfg?.deploy_enabled ? (
              <Button size="sm" variant="primary" disabled={downloading} onClick={doDownload}>
                <Download size={13} /> 下载部署包{cfg.deploy_version ? `（v${cfg.deploy_version}）` : ''}
              </Button>
            ) : (
              <p className="m-0 text-xs text-medium">
                部署包未配置：在服务端 <code className="font-mono">bash scripts/build.sh</code> 产出
                <code className="mx-1 rounded bg-brand-soft px-1 font-mono">bin/zedr-deploy-v*.zip</code>
                后，把 <code className="font-mono">HG_SERVER_DEPLOY_PACKAGE</code> 指向它并重启。
                也可手工拷贝 bin/zedr-agent.exe 到目标机后按下述参数安装。
              </p>
            )}
          </div>
        </section>

        {/* 第二步：接入参数 */}
        <section className="rounded-lg border border-border p-4">
          <h3 className="m-0 flex items-center gap-2 text-[13.5px] font-semibold">第二步 · 接入参数</h3>
          {cfgErr ? (
            <p className="mt-2 mb-0 text-xs text-medium">{cfgErr}（接入参数仅管理员可见；也可从服务端 .env 的 HG_SERVER_ENROLL_TOKEN 获取）</p>
          ) : !cfg ? (
            <p className="mt-2 mb-0 text-xs text-faint">读取接入配置…</p>
          ) : (
            <div className="mt-3 space-y-3">
              <label className="block">
                <span className="mb-1 block text-[11.5px] text-faint">服务端地址（必须是目标机器可达的地址——本页地址栏不一定通）</span>
                <Input value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} className="w-full font-mono" />
              </label>
              <div>
                <span className="mb-1 block text-[11.5px] text-faint">注册令牌（预共享，仅管理员可见）</span>
                <div className="flex items-center gap-2">
                  <code className="min-w-0 flex-1 truncate rounded border border-border bg-[var(--code-bg)] px-2.5 py-1.5 font-mono text-[12px]">
                    {token ? (showToken ? token : '•'.repeat(Math.min(24, token.length))) : '（未配置 HG_SERVER_ENROLL_TOKEN）'}
                  </code>
                  <Button size="sm" variant="ghost" onClick={() => setShowToken((v) => !v)} title={showToken ? '隐藏' : '显示'}>
                    {showToken ? <EyeOff size={13} /> : <Eye size={13} />}
                  </Button>
                  <Button size="sm" variant="ghost" disabled={!token} onClick={() => doCopy(token, '令牌')} title="复制令牌">
                    <Copy size={13} />
                  </Button>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <span className="mb-1 block text-[11.5px] text-faint">主机标签（可选，逗号分隔）</span>
                  <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="office,finance" className="w-full" />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11.5px] text-faint">桌面托盘</span>
                  <button type="button" onClick={() => setWithUI((v) => !v)}
                    className={cn('flex h-[34px] w-full items-center gap-2 rounded-md border px-2.5 text-[12.5px] transition-colors',
                      withUI ? 'border-primary bg-brand-soft text-primary' : 'border-border text-faint hover:bg-secondary')}>
                    <span className={cn('inline-block h-3.5 w-3.5 shrink-0 rounded-sm border', withUI ? 'border-primary bg-primary' : 'border-border-strong')} />
                    同时安装托盘自启（-WithUI）
                  </button>
                </label>
              </div>
            </div>
          )}
        </section>

        {/* 第三步：一条命令 */}
        <section className="rounded-lg border border-border p-4">
          <h3 className="m-0 flex items-center gap-2 text-[13.5px] font-semibold">第三步 · 在目标机器上执行</h3>
          <p className="mt-1.5 text-xs text-faint">管理员 PowerShell，进入部署包解压目录；脚本幂等，重复执行等于重装。</p>
          <div className="relative mt-2">
            <pre className="m-0 rounded-lg border border-border bg-[var(--code-bg)] p-3 pr-10 font-mono text-[11.5px] leading-[1.6] break-all whitespace-pre-wrap">{command}</pre>
            <Button size="icon" variant="ghost" className="!absolute top-1.5 right-1.5" title="复制命令" onClick={() => doCopy(command, '命令')}>
              <Copy size={13} />
            </Button>
          </div>
          <p className="mt-2.5 mb-0 text-xs text-faint">
            卸载：<code className="font-mono">.\uninstall-agent.ps1</code>（默认保留数据目录，取证优先；<code className="font-mono">-Purge</code> 连数据一起删）。
            脚本判断在线：<code className="font-mono">zedr-agent.exe -status -json</code> 的 <code className="font-mono">online</code> 字段。
          </p>
        </section>
      </div>}
    </Drawer>
  );
}

/* ================= 探针批量升级（2026-11-19） =================
   服务端波次编排（语义与判定口径在 service/upgrade.go：版本翻转=成功，
   波内失败率过半自动暂停）；本抽屉只做发起确认、进度投影与 abort/resume
   两个动作，不复制任何判定逻辑。 */

const FLEET_ENTRY_LABEL: Record<string, string> = {
  pending: '在途', success: '成功', already_latest: '已是最新', failed: '失败',
  timed_out: '超时', skipped_offline: '离线跳过', skipped_linux: 'Linux 跳过',
  skipped_newer: '版本更新',
};
const FLEET_ENTRY_TONE: Record<string, string> = {
  pending: 'medium', success: 'resolved', already_latest: 'info', failed: 'critical',
  timed_out: 'high', skipped_offline: 'neutral', skipped_linux: 'neutral', skipped_newer: 'neutral',
};
/** 发起时就已分流、不占波次的三类主机（报告里单独列出） */
const PRE_START_STATUSES = ['already_latest', 'skipped_linux', 'skipped_newer'];

function UpgradeDrawer({ open, onClose, hosts, avail }: {
  open: boolean; onClose: () => void; hosts: Host[]; avail: UpgradeAvail | null;
}) {
  const toast = useToast();
  const confirm = useConfirm();
  const [status, setStatus] = useState<FleetStatus | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);

  /* 打开即拉当前批次：进行中/暂停的批次直接进进度视图——服务重启丢进度的
     诚实边界在这里体现为"批次没了、发起视图重新可用" */
  useEffect(() => {
    if (!open) return;
    setLoaded(false);
    api.get<FleetStatus | null>('/api/v1/upgrade/fleet')
      .then(setStatus)
      .catch(() => setStatus(null))
      .finally(() => setLoaded(true));
  }, [open]);

  const active = !!status && (status.state === 'running' || status.state === 'paused');
  /* 活跃批次 5s 轮询；终态停止 */
  useEffect(() => {
    if (!open || !active) return;
    const t = setInterval(() => {
      api.get<FleetStatus | null>('/api/v1/upgrade/fleet').then((s) => { if (s) setStatus(s); }).catch(() => {});
    }, 5000);
    return () => clearInterval(t);
  }, [open, active]);

  const start = async () => {
    if (!avail) return;
    const ok = await confirm({
      title: `批量升级全部终端到 v${avail.version}？`,
      message: `共 ${hosts.length} 台终端参与。服务端按波次分批推进（默认每波 10 台在线主机），任一波失败率过半会自动暂停等人工放行。升级会让探针退出重启（服务模式数秒拉起新版本）；已是目标版本 / Linux / 离线终端自动跳过并在报告注明。`,
      okText: '发起升级',
    });
    if (!ok) return;
    setBusy(true);
    try {
      setStatus(await api.post<FleetStatus>('/api/v1/upgrade/fleet', {}));
      toast('批量升级已发起，按波次推进');
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  const act = async (path: 'abort' | 'resume') => {
    const isAbort = path === 'abort';
    const ok = await confirm({
      title: isAbort ? '中止升级批次？' : '恢复升级批次？',
      danger: isAbort,
      okText: isAbort ? '中止' : '恢复',
      message: isAbort
        ? '已下发未执行的指令不会召回（探针拿到会照常执行），批次进度冻结在这里。'
        : '从冻结处继续推进后续波次。',
    });
    if (!ok) return;
    setBusy(true);
    try { setStatus(await api.post<FleetStatus>(`/api/v1/upgrade/fleet/${path}`, {})); }
    catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  const entryRow = (e: FleetEntry) => (
    <div key={e.agent_id} className="flex items-center gap-2 py-1 text-[12.5px]">
      <Badge tone={FLEET_ENTRY_TONE[e.status] || 'neutral'}>{FLEET_ENTRY_LABEL[e.status] || e.status}</Badge>
      <span className="font-mono text-xs text-muted-foreground">{e.agent_id}</span>
      {e.detail && <span className="min-w-0 flex-1 truncate text-[11.5px] text-faint" title={e.detail}>{e.detail}</span>}
    </div>
  );

  return (
    <Drawer open={open} onClose={onClose} title="批量升级探针"
      sub={`目标版本 v${avail?.version || '?'} · 波次推进，失败率过半自动暂停`} width={720}>
      {!loaded ? (
        <SkeletonRows rows={4} />
      ) : active && status ? (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={status.state === 'paused' ? 'medium' : 'info'}>
              {status.state === 'paused' ? '已暂停（等待人工放行）' : '推进中'}
            </Badge>
            <span className="text-xs text-faint">目标 v{status.target_version} · {status.created_by} 发起于 {fmtTime(status.created_at)}</span>
            <div className="flex-1" />
            {status.state === 'paused' && (
              <Button size="sm" onClick={() => act('resume')} disabled={busy}>恢复推进</Button>
            )}
            <Button size="sm" variant="ghost" onClick={() => act('abort')} disabled={busy}>中止批次</Button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(status.summary).filter(([, n]) => n > 0).map(([k, n]) => (
              <Badge key={k} tone={FLEET_ENTRY_TONE[k] || 'neutral'}>
                {FLEET_ENTRY_LABEL[k] || k} {n}
              </Badge>
            ))}
            {status.queue_remain > 0 && <Badge tone="neutral">排队中 {status.queue_remain}</Badge>}
          </div>
          {status.waves.length === 0 ? (
            <p className="m-0 text-xs text-faint">尚未开波：等待终端上线，或收尾判定中。</p>
          ) : status.waves.map((w) => (
            <Card key={w.index} className="px-3.5 py-3">
              <CardTitle className="mb-1.5 text-[13px]">第 {w.index} 波 · {w.hosts.length} 台</CardTitle>
              {w.hosts.map(entryRow)}
            </Card>
          ))}
          {Object.values(status.hosts).some((e) => PRE_START_STATUSES.includes(e.status)) && (
            <Card className="px-3.5 py-3">
              <CardTitle className="mb-1.5 text-[13px]">发起时已分流（不占波次）</CardTitle>
              {Object.values(status.hosts).filter((e) => PRE_START_STATUSES.includes(e.status)).map(entryRow)}
            </Card>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <p className="m-0 text-[13px] leading-relaxed text-muted-foreground">
            把全部终端升级到服务端配置的版本 <b className="text-foreground">v{avail?.version || '-'}</b>
            （{(Number(avail?.size || 0) / 1048576).toFixed(1)} MB）。
            服务端按<b className="text-foreground">波次</b>分批推进：每波只向在线主机下发升级指令，这一波全部落定（版本翻转或回执）才开下一波；任一波失败率过半自动暂停，冻结现场等人工放行——把"可能出问题"的爆炸半径限制在一小批终端里。
          </p>
          <ul className="m-0 list-none space-y-1.5 p-0 text-[12.5px] text-faint">
            <li>· 已是目标版本 / 版本更新 / Linux 探针 / 离线终端自动跳过并在报告注明；</li>
            <li>· 升级让探针进程退出重启：服务模式由 SCM 数秒拉起新版本，前台模式需手动重启；</li>
            <li>· 批次进度在服务端内存：服务重启丢进度（已下发指令照常执行），指令历史可查。</li>
          </ul>
          <div>
            <Button variant="primary" onClick={start} disabled={busy || hosts.length === 0}>
              <ArrowUpCircle size={14} /> 对 {hosts.length} 台终端发起升级
            </Button>
          </div>
        </div>
      )}
    </Drawer>
  );
}

export function HostsPage({ user }: { user: UserRow }) {
  const err = useError();
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [deployOpen, setDeployOpen] = useState(false);
  const [upgradeOpen, setUpgradeOpen] = useState(false);
  /* 服务端升级物料元信息：enabled=false 时升级入口（按钮/徽章）整体隐藏 */
  const [avail, setAvail] = useState<UpgradeAvail | null>(null);

  const load = useCallback(async () => {
    try { setHosts((await api.get<{ items: Host[] }>('/api/v1/hosts')).items || []); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    api.get<UpgradeAvail>('/api/v1/upgrade/available').then(setAvail).catch(() => setAvail(null));
  }, []);
  if (err.rendered) return err.rendered;

  const canUpgrade = !!avail?.enabled && (hosts || []).some(
    (h) => !!h.version && cmpVersion(h.version, avail.version) < 0);

  return (
    <div>
      <DeployDrawer open={deployOpen} onClose={() => setDeployOpen(false)} />
      <UpgradeDrawer open={upgradeOpen} onClose={() => setUpgradeOpen(false)} hosts={hosts || []} avail={avail} />
      {!hosts ? <Card className="px-2 pb-2"><SkeletonRows rows={5} /></Card> : !hosts.length ? (
        <Card><EmptyState tone="info" icon={<Monitor size={20} />} title="还没有终端注册"
          action={<Button size="sm" variant="primary" onClick={() => setDeployOpen(true)}><Plus size={13} /> 接入新主机</Button>}
          sub={<>在目标机器上运行部署包里的 <b>install-agent.ps1</b>（「接入新主机」可下载包并生成命令），<br />或手工启动 <b>zedr-agent.exe</b> 并配置 <code className="rounded bg-brand-soft px-1 font-mono text-[11px] text-primary">HG_AGENT_SERVER_URL</code> 与 <code className="rounded bg-brand-soft px-1 font-mono text-[11px] text-primary">HG_AGENT_ENROLL_TOKEN</code>。<br />终端注册后约 30 秒内会出现在这里。</>} /></Card>
      ) : (
        <>
          <div className="mb-3 flex items-center gap-2.5">
            <span className="text-xs text-faint">共 {hosts.length} 台终端 · 默认每 30 秒心跳一次</span>
            <div className="flex-1" />
            {user.role === 'admin' && canUpgrade && (
              <Button size="sm" onClick={() => setUpgradeOpen(true)}>
                <ArrowUpCircle size={13} /> 批量升级
              </Button>
            )}
            <Button size="sm" variant="primary" onClick={() => setDeployOpen(true)}><Plus size={13} /> 接入新主机</Button>
          </div>
          <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['状态', '主机', '系统', '运行账号', '进程数', 'CPU', '内存', '待处置', '最后心跳'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.id} onClick={() => navigate(`/hosts/${h.id}`)}
                  className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5">
                    <Badge tone={h.status}>{h.status === 'online' ? '在线' : '离线'}</Badge>
                    {(h.clock_skew_ms || 0) > 10000 && (
                      <div className="mt-1"><Badge tone="medium" title="终端与服务端时钟偏移超过 10 秒">时钟偏移 {Math.round(h.clock_skew_ms! / 1000)}s</Badge></div>
                    )}
                  </td>
                  <td className="px-3.5 py-2.5"><b>{h.hostname}</b><div className="font-mono text-xs text-faint">{h.id}</div></td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">
                    {h.os_version || '-'}<br />{h.arch || ''} · v{h.version || '-'}
                    {avail?.enabled && h.version && cmpVersion(h.version, avail.version) < 0 && (
                      <div className="mt-1"><Badge tone="info" title={`服务端有 v${avail.version} 可升级`}>可升级</Badge></div>
                    )}
                  </td>
                  <td className="px-3.5 py-2.5 font-mono text-xs">{h.username || '-'}</td>
                  <td className="px-3.5 py-2.5 tabular-nums">{h.proc_count || 0}</td>
                  <td className="px-3.5 py-2.5 tabular-nums">{(h.cpu_percent || 0).toFixed(1)}%</td>
                  <td className="px-3.5 py-2.5 tabular-nums">{(h.mem_mb || 0).toFixed(0)} MB</td>
                  <td className="px-3.5 py-2.5">{h.open_alerts ? <Badge tone="critical">{h.open_alerts}</Badge> : <span className="text-faint">0</span>}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint" title={fmtTime(h.last_seen_at)}>{relTime(h.last_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 px-3.5 text-xs text-faint">点击任意一行进入主机详情整页：系统概要 · 网络适配器 · 监听端口 · 服务 · 计划任务 · 自启动 · 处置指令 · 指令历史。终端默认每 30 秒心跳一次。</p>
          </Card>
        </>
      )}
    </div>
  );
}


/* ================= 白名单（例外与降噪） =================
   检测规则页已升级为「规则中心」整页（pages/RulesCenter.tsx）；
   白名单是它的姊妹能力：规则管"什么该响"，这里管"什么确认安全"。 */

/** 五种加白类型：类型语义直接写进选项与提示——加白最大的风险是
    条目太宽把真攻击也洗白了，提示里把"怎么写才窄"讲清楚。 */
const ALLOW_TYPES: { value: string; label: string; hint: string; placeholder: string }[] = [
  { value: 'hash', label: '文件哈希 SHA256', hint: '单个文件的精确匹配，最窄最安全。适用于"这个文件确认安全"。', placeholder: '64 位十六进制 SHA256，如 7f3a91c0…' },
  { value: 'path', label: '路径', hint: '镜像路径匹配：指向文件为精确匹配，以 \\ 结尾则匹配整个目录。目录越深越窄越安全。', placeholder: 'C:\\Tools\\procmon.exe 或 C:\\Tools\\Sysinternals\\' },
  { value: 'signer', label: '签名主体', hint: '按可信签名者匹配——一条加白覆盖该厂商全部签名文件，适合标准化软件资产。', placeholder: '签名主体名，如 Contoso Ltd' },
  { value: 'pair', label: '父子进程对', hint: '格式 parent.exe>child.exe：只放行特定启动组合，比整条命令行加白窄得多。', placeholder: 'deployment-agent.exe>cmd.exe' },
  { value: 'cmdline', label: '命令行片段', hint: '包含匹配（不区分大小写）。务必写得尽量窄——命令行是最容易被攻击者复用的维度。', placeholder: '如 --backup-mode' },
];

export function AllowlistPage({ user }: { user: { role: Role } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const canWrite = user.role !== 'viewer';
  const isAdmin = user.role === 'admin';
  const [items, setItems] = useState<AllowEntry[] | null>(null);
  const [form, setForm] = useState({ type: 'hash', value: '', note: '' });
  const typeMeta = ALLOW_TYPES.find((t) => t.value === form.type) || ALLOW_TYPES[0];

  const load = useCallback(async () => {
    try { setItems((await api.get<{ items: AllowEntry[] }>('/api/v1/allowlist')).items || []); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const add = async () => {
    if (!form.value.trim()) return toast('请填写加白内容', 'warn');
    try {
      await api.post('/api/v1/allowlist', { type: form.type, value: form.value.trim(), note: form.note.trim() });
      toast('已加入白名单（匹配的历史未处置告警已一并回收）');
      setForm({ type: form.type, value: '', note: '' });
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const remove = async (e: AllowEntry) => {
    const ok = await confirm({
      title: '删除该白名单项？',
      message: '删除后相关检测会重新生效，该对象若仍有可疑行为会再次告警。',
      danger: true, okText: '删除',
    });
    if (!ok) return;
    try {
      await api.del(`/api/v1/allowlist/${encodeURIComponent(e.id)}`);
      toast('已删除');
      load();
    } catch (ex) { toast((ex as Error).message, 'err'); }
  };

  /* 导出/导入（adminOnly）：白名单是误报治理资产，重建环境时
     "导出→导入"直通，格式与导出文件对称 */
  const exportList = async () => {
    try {
      const blob = await api.download('/api/v1/allowlist/export');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'zedr-allowlist.json'; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const importList = async (file: File) => {
    let entries: { type: string; value: string; note?: string }[] = [];
    try {
      const data = JSON.parse(await file.text());
      if (Array.isArray(data?.entries)) entries = data.entries;
      else if (Array.isArray(data?.items)) entries = data.items;
      else if (Array.isArray(data)) entries = data;
    } catch {
      return toast('文件不是合法 JSON（应使用本页导出的格式）', 'err');
    }
    if (!entries.length) return toast('文件里没有可导入的条目', 'warn');
    try {
      const res = await api.post<{ added: number; skipped: number; failed: number }>('/api/v1/allowlist/import', { entries });
      toast(`导入完成：新增 ${res.added} · 已存在跳过 ${res.skipped} · 失败 ${res.failed}`);
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  return (
    <div className="space-y-3.5">
      {canWrite && (
        <Card className="p-4">
          <CardTitle className="mb-3">新增白名单</CardTitle>
          <div className="grid items-end gap-2.5 sm:grid-cols-[170px_1fr_1fr_auto]">
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">类型</span>
              <Select value={form.type} onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))} className="w-full">
                {ALLOW_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </Select>
            </label>
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">内容</span>
              <Input value={form.value} onChange={(e) => setForm((f) => ({ ...f, value: e.target.value }))} className="w-full font-mono text-xs" placeholder={typeMeta.placeholder} />
            </label>
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">备注</span>
              <Input value={form.note} onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))} className="w-full" placeholder="为什么加白（会进入审计）" />
            </label>
            <Button variant="primary" onClick={add}><Plus size={13} /> 添加</Button>
          </div>
          <div className="mt-2.5 text-[11.5px] text-faint">{typeMeta.hint}</div>
        </Card>
      )}

      {!items ? <Card className="px-2 pb-2"><SkeletonRows rows={4} /></Card> : !items.length ? (
        <Card><EmptyState icon={<ShieldCheck size={20} />} title="白名单为空"
          sub="加白名单能让确认安全的对象不再告警。可在告警详情里一键添加，或在这里手动新增。" /></Card>
      ) : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <div className="mb-2 flex items-center px-3.5">
            <span className="text-[11px] tracking-[.06em] uppercase text-faint">共 {items.length} 条 · 加白即回收历史未处置告警</span>
            <div className="flex-1" />
            {isAdmin && (
              <label className="cursor-pointer">
                <input type="file" accept="application/json" className="hidden"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) importList(f); e.target.value = ''; }} />
                <Button size="sm" variant="ghost">导入</Button>
              </label>
            )}
            {isAdmin && <Button size="sm" variant="ghost" onClick={exportList}>导出</Button>}
          </div>
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['类型', '内容', '备注', '添加人', '时间', '操作'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5">
                    <Badge tone="info">{ALLOW_TYPES.find((t) => t.value === e.type)?.label || e.type}</Badge>
                  </td>
                  <td className="max-w-[420px] px-3.5 py-2.5 font-mono text-xs break-all">{e.value}</td>
                  <td className="px-3.5 py-2.5 text-xs">{e.note || <span className="text-faint">-</span>}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{e.created_by || '-'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{e.created_at ? relTime(e.created_at) : '-'}</td>
                  <td className="px-3.5 py-2.5">{canWrite && <Button size="sm" variant="ghost" onClick={() => remove(e)}>删除</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

/* ================= 审计日志 ================= */

/* 审计动作语义化：原始 action 串保留在 title 里可查，界面给中文与色彩 */
const AUDIT_LABEL: Record<string, string> = {
  'alert.status': '告警处置', 'alert.bulk_status': '批量处置', 'alert.triage': 'AI 研判',
  'ai.hunt': 'AI 狩猎', 'host.delete': '删除主机', 'host.command': '下发指令',
  'ioc.add': '添加 IOC', 'ioc.delete': '删除 IOC',
  'rule.upsert': '规则变更', 'rule.toggle': '规则启停', 'rule.mode': '规则模式切换', 'rule.delete': '删除规则',
  'allowlist.add': '添加白名单', 'allowlist.delete': '删除白名单',
  'auth.login': '登录', 'auth.logout': '退出登录', 'auth.change_password': '修改密码',
  'user.create': '创建账号',
};
const auditTone = (a: string): string =>
  /delete|terminate/.test(a) ? 'critical' : /command|status|bulk/.test(a) ? 'info' : /add|upsert/.test(a) ? 'ok' : 'neutral';

export function AuditPage() {
  const err = useError();
  const [rows, setRows] = useState<AuditRow[] | null>(null);

  useEffect(() => {
    api.get<{ items: AuditRow[] }>('/api/v1/audit?limit=300')
      .then((r) => setRows(r.items || []))
      .catch(err.capture);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (err.rendered) return err.rendered;

  return !rows ? <Card className="px-2 pb-2"><SkeletonRows rows={8} /></Card> : !rows.length ? (
    <Card><EmptyState icon={<ShieldCheck size={20} />} title="暂无审计记录"
      sub="登录、处置、规则变更等关键操作都会留痕在这里，方便回溯与合规检查。" /></Card>
  ) : (
    <Card className="overflow-x-auto px-2 py-3.5">
      <table className="w-full text-[13px]">
        <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
          {['时间', '操作人', '动作', '目标', '详情', '来源 IP'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
        </tr></thead>
        <tbody>
          {rows.map((l) => (
            <tr key={l.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
              <td className="px-3.5 py-2.5 text-xs text-faint">{fmtTime((l as AuditRow & { created_at: string }).created_at)}</td>
              <td className="px-3.5 py-2.5 text-xs">{(l as AuditRow & { username?: string }).username || '-'}</td>
              <td className="px-3.5 py-2.5">
                <Badge tone={auditTone(l.action)} title={l.action}>{AUDIT_LABEL[l.action] || l.action}</Badge>
              </td>
              <td className="px-3.5 py-2.5 font-mono text-xs break-all text-faint" title={(l as AuditRow & { target?: string }).target}>{(l as AuditRow & { target?: string }).target || '-'}</td>
              <td className="px-3.5 py-2.5 text-xs">{l.detail || '-'}</td>
              <td className="px-3.5 py-2.5 font-mono text-xs text-faint">{(l as AuditRow & { ip?: string }).ip || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

/* ================= 账号管理 ================= */

type UserAcc = UserRow & { display_name?: string; disabled?: boolean; last_login_at?: string; created_at?: string };

export function UsersPage({ self, onPasswordChanged }: { self: { username: string }; onPasswordChanged?: () => void }) {
  const err = useError();
  const toast = useToast();
  const [users, setUsers] = useState<UserAcc[] | null>(null);
  const [form, setForm] = useState({ username: '', display_name: '', password: '', role: 'viewer' });
  const [pw, setPw] = useState({ old: '', neu: '' });

  const load = useCallback(async () => {
    try { setUsers(((await api.get<{ items: UserRow[] }>('/api/v1/users')).items || []) as UserAcc[]); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const add = async () => {
    try {
      await api.post('/api/v1/users', { ...form, username: form.username.trim() });
      toast('账号已创建');
      setForm({ username: '', display_name: '', password: '', role: 'viewer' });
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const changePw = async () => {
    if (pw.neu.length < 8) return toast('新密码至少 8 位', 'warn');
    try {
      await api.post('/api/v1/auth/change-password', { old_password: pw.old, new_password: pw.neu });
      toast('密码已修改，下次登录使用新密码');
      setPw({ old: '', neu: '' });
      onPasswordChanged?.();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  return (
    <div className="space-y-3.5">
      <Card className="p-4">
        <CardTitle className="mb-3">新建账号</CardTitle>
        <div className="grid items-end gap-2.5 lg:grid-cols-[1fr_1fr_1fr_140px_auto]">
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">用户名</span><Input value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">显示名</span><Input value={form.display_name} onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">初始密码（≥8 位）</span><Input type="password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">角色</span>
            <Select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))} className="w-full">
              <option value="viewer">只读</option><option value="analyst">分析师</option><option value="admin">管理员</option>
            </Select>
          </label>
          <Button variant="primary" onClick={add}>创建</Button>
        </div>
      </Card>

      <Card className="p-4">
        <CardTitle className="mb-3">修改我的密码（{self.username}）</CardTitle>
        <div className="grid items-end gap-2.5 sm:grid-cols-[1fr_1fr_auto]">
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">当前密码</span><Input type="password" value={pw.old} onChange={(e) => setPw((p) => ({ ...p, old: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">新密码（≥8 位）</span><Input type="password" value={pw.neu} onChange={(e) => setPw((p) => ({ ...p, neu: e.target.value }))} className="w-full" /></label>
          <Button onClick={changePw}><KeyRound size={13} /> 修改密码</Button>
        </div>
      </Card>

      {!users ? <Card className="px-2 pb-2"><SkeletonRows rows={3} /></Card> : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['用户名', '显示名', '角色', '状态', '最近登录', '创建时间'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5 font-mono text-xs">{u.username}</td>
                  <td className="px-3.5 py-2.5">{u.display_name || '-'}</td>
                  <td className="px-3.5 py-2.5"><Badge tone="info">{u.role}</Badge></td>
                  <td className="px-3.5 py-2.5">{u.disabled ? <Badge tone="offline">禁用</Badge> : <Badge tone="online">正常</Badge>}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{u.last_login_at ? fmtTime(u.last_login_at) : '从未登录'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{fmtTime(u.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

/* ================= 事件（攻击链聚类） ================= */

const INCIDENT_STATUS_LABEL: Record<string, string> = {
  open: '待调查', investigating: '调查中', contained: '已遏制', resolved: '已解决',
};
const INCIDENT_STATUS_TONE: Record<string, string> = {
  open: 'critical', investigating: 'medium', contained: 'info', resolved: 'resolved',
};

/* ---- 事件级 AI 检测：攻击链叙事的数据契约（对应 /api/v1/incidents/{id}/narrative） ---- */
interface NarrativePhase {
  name: string; tactic: string; tactic_id: string;
  alerts: string[]; description: string;
}
interface NarrativeAction { type: string; target: string; detail: string; requires_approval: boolean }
interface IncidentNarrative {
  summary: string; risk_score: number;
  phases: NarrativePhase[]; missing_phases?: string[]; coverage?: string[];
  actions?: NarrativeAction[];
  grounded: boolean; uncited: number; untrusted_ignored: number;
  model: string; engine: string; latency_ms: number;
  degraded: boolean; degraded_reason?: string;
}
interface IncidentNarrativeView {
  incident_id: string; hostname: string; alert_total: number;
  narrative: IncidentNarrative; generated_at: string;
}

export function IncidentsPage({ user }: { user?: { role: Role } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const navigate = useNavigate();
  const [data, setData] = useState<{ items: Incident[]; bursts: Burst[] } | null>(null);
  const [tick, setTick] = useState(0);
  const [status, setStatus] = useState('');
  const [busyId, setBusyId] = useState('');
  const [narr, setNarr] = useState<IncidentNarrativeView | null>(null);
  const [narrOpen, setNarrOpen] = useState(false);
  const [narrBusy, setNarrBusy] = useState('');
  const canWrite = !user || user.role !== 'viewer';

  useEffect(() => {
    const qs = new URLSearchParams({ limit: '100' });
    if (status) qs.set('status', status);
    api.get<{ items: Incident[]; bursts?: Burst[] }>(`/api/v1/incidents?${qs.toString()}`)
      .then((r) => setData({ items: r.items || [], bursts: r.bursts || [] }))
      .catch(err.capture);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, status]);

  if (err.rendered) return err.rendered;
  if (!data) return <Card className="p-4"><SkeletonRows rows={5} /></Card>;

  const { items, bursts } = data;

  /* 状态机只允许前进：open → investigating → contained → resolved（contained 可直接 resolved） */
  const NEXT: Record<string, Array<{ to: Incident['status']; label: string; danger?: boolean; note: string }>> = {
    open: [
      { to: 'investigating', label: '开始调查', note: '事件进入调查阶段' },
      { to: 'contained', label: '已遏制', note: '威胁已遏制' },
      { to: 'resolved', label: '直接解决', note: '事件已解决' },
    ],
    investigating: [
      { to: 'contained', label: '已遏制', note: '威胁已遏制' },
      { to: 'resolved', label: '解决', note: '事件已解决' },
    ],
    contained: [
      { to: 'resolved', label: '解决', note: '事件已解决' },
    ],
  };

  const transition = async (it: Incident, to: Incident['status'], label: string, note: string) => {
    const ok = await confirm({
      title: `${label}：「${it.title}」？`,
      message: `状态 ${it.status} → ${to}。\n状态机只允许前进、不可回退（避免 SLA 计时失真）。`,
      okText: label, danger: to === 'resolved',
    });
    if (!ok) return;
    setBusyId(it.id);
    try {
      await api.post(`/api/v1/incidents/${encodeURIComponent(it.id)}/status`, { status: to, note });
      toast(`事件已更新为「${INCIDENT_STATUS_LABEL[to]}」`);
      setTick((t) => t + 1);
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusyId(''); }
  };

  /* AI 攻击链：有缓存直接开；没有则确认后生成（可能触发模型调用）。 */
  const openNarrative = async (it: Incident) => {
    setNarrBusy(it.id);
    try {
      const cached = await api.get<IncidentNarrativeView | null>(`/api/v1/incidents/${encodeURIComponent(it.id)}/narrative`);
      setNarrBusy('');
      if (cached) { setNarr(cached); setNarrOpen(true); return; }
      const ok = await confirm({
        title: '生成 AI 攻击链叙事？',
        message: '将把本事件的多条告警按时间线重建为攻击链（阶段 / 风险 / 缺失环节）。配置模型时会调用一次模型并消耗 token；未配置时由确定性引擎完成。',
        okText: '生成',
      });
      if (!ok) return;
      setNarrBusy(it.id);
      const v = await api.post<IncidentNarrativeView>(`/api/v1/incidents/${encodeURIComponent(it.id)}/narrate`, {});
      setNarr(v); setNarrOpen(true);
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setNarrBusy(''); }
  };

  return (
    <div>
      {bursts.length > 0 && (
        <Card className="mb-3 border-l-3 border-l-crit p-4" style={{ background: 'linear-gradient(90deg, var(--destructive-soft), transparent)' }}>
          <div className="flex flex-wrap items-center gap-2.5">
            <Badge tone="critical" className="text-xs">⚠ 跨主机爆发 ×{bursts.length}</Badge>
            <span className="text-[13px]">同一份载荷在多台主机同时出现——横向移动 / 蠕虫式投递信号，优先处置：</span>
          </div>
          {bursts.map((b, i) => (
            <div key={i} className="mt-2.5 rounded-lg bg-secondary px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2.5">
                <b className="font-mono text-xs">{b.hash.slice(0, 16)}…</b>
                <Badge tone="high">{b.host_count} 台主机</Badge>
                <Badge tone="info">{b.alert_count} 条告警</Badge>
                <Badge tone={b.peak_severity === 'critical' ? 'critical' : 'medium'}>{b.peak_severity}</Badge>
                <span className="text-xs text-faint">{b.hosts.join(' · ')}</span>
              </div>
              <div className="mt-1 text-xs text-faint">{b.title_sample || ''}</div>
            </div>
          ))}
        </Card>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-2.5">
        <span className="text-xs text-faint">同主机 · 相邻间隔 ≤30 分钟的告警聚类为事件 · 状态机只前进</span>
        <div className="flex-1" />
        <Select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">全部状态</option>
          {Object.entries(INCIDENT_STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        <Button size="sm" onClick={() => setTick((t) => t + 1)}><RefreshCw size={13} /> 刷新</Button>
      </div>

      {!items.length ? (
        <Card><EmptyState icon={<ShieldCheck size={20} />} title="当前没有事件"
          sub="这是好事——说明各终端都在安静运行，没有形成攻击链的行为序列。事件会在多条相关告警出现时自动聚类并持久化。" /></Card>
      ) : items.map((it) => {
        const durSec = Math.max(0, (new Date(it.last_seen).getTime() - new Date(it.first_seen).getTime()) / 1000);
        const dur = durSec >= 3600 ? `${Math.round(durSec / 3600)} 小时` : durSec >= 60 ? `${Math.round(durSec / 60)} 分钟` : '<1 分钟';
        const nexts = canWrite ? (NEXT[it.status] || []) : [];
        return (
          <Card key={it.id} className={cn('mb-3 p-4', `border-l-3 ${it.peak_severity === 'critical' ? 'border-l-crit' : it.peak_severity === 'high' ? 'border-l-destructive' : it.peak_severity === 'medium' ? 'border-l-warn' : 'border-l-border'}`)}>
            <div className="flex flex-wrap items-center gap-3">
              <Badge tone={it.peak_severity} className="px-3 py-1 text-[13px]">{SEV_LABEL[it.peak_severity] || it.peak_severity}</Badge>
              <div className="min-w-[220px] flex-1">
                <div className="flex flex-wrap items-center gap-1.5 font-semibold">
                  {it.title}
                  <Badge tone="info">{it.alert_count} 条告警</Badge>
                  {it.open_count > 0 ? <Badge tone="medium">待处置 {it.open_count}</Badge> : <Badge tone="resolved">告警全部处置</Badge>}
                  <Badge tone={INCIDENT_STATUS_TONE[it.status] || 'neutral'} title="事件处置状态">{INCIDENT_STATUS_LABEL[it.status] || it.status}</Badge>
                </div>
                <div className="mt-1 text-xs text-faint">
                  {it.hostname} · {fmtTime(it.first_seen)} → {fmtTime(it.last_seen)} · 持续 {dur} · 峰值分 <b className="font-mono">{it.max_score}</b>
                </div>
              </div>
              <Button size="sm" variant="ghost" onClick={() => navigate(`/alerts?q=${encodeURIComponent(it.hostname)}`)}>该主机告警</Button>
              <Button size="sm" disabled={narrBusy === it.id} onClick={() => openNarrative(it)}>
                <Sparkles size={12} /> {narrBusy === it.id ? '重建中…' : 'AI 攻击链'}
              </Button>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {(it.processes || []).slice(0, 6).map((p, i) => <Badge key={`p${i}`} tone="neutral" title="进程">{p}</Badge>)}
              {(it.rule_ids || []).slice(0, 4).map((r, i) => <Badge key={`r${i}`} tone="neutral" title="规则" >{r}</Badge>)}
              {(it.mitre || []).slice(0, 6).map((m, i) => <Badge key={`m${i}`} tone="info">{m}</Badge>)}
            </div>
            {it.note && <div className="mt-2 text-xs text-faint">备注：{it.note}</div>}
            {nexts.length > 0 && (
              <div className="mt-2.5 flex flex-wrap items-center gap-1.5 border-t border-border-soft pt-2.5">
                <span className="mr-1 text-[11px] text-ghost">推进状态：</span>
                {nexts.map((n) => (
                  <Button key={n.to} size="sm" variant={n.to === 'resolved' ? 'ghost' : 'default'}
                    disabled={busyId === it.id}
                    onClick={() => transition(it, n.to, n.label, n.note)}>{n.label}</Button>
                ))}
              </div>
            )}
          </Card>
        );
      })}

      {/* AI 攻击链叙事抽屉（事件级检测 L6） */}
      <Drawer open={narrOpen} onClose={() => setNarrOpen(false)} width={720}
        title="AI 攻击链叙事"
        sub={narr ? `${narr.hostname} · ${narr.alert_total} 条告警 · ${narr.narrative.engine === 'llm' ? 'LLM 引擎' : '确定性重建'}` : ''}
        foot={narr && (
          <>
            <Button variant="ghost" onClick={() => setNarrOpen(false)}>关闭</Button>
            <Button variant="primary" disabled={narrBusy === narr.incident_id}
              onClick={() => { const it = items.find((x) => x.id === narr.incident_id); if (it) { setNarrOpen(false); setTimeout(() => openNarrative(it), 120); } }}>
              <RefreshCw size={12} /> 重新生成
            </Button>
          </>
        )}>
        {narr && (
          <div>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Badge tone={narr.narrative.risk_score >= 70 ? 'critical' : narr.narrative.risk_score >= 40 ? 'high' : 'medium'}>
                风险 {narr.narrative.risk_score}
              </Badge>
              {narr.narrative.grounded
                ? <Badge tone="online">阶段全部可溯源</Badge>
                : <Badge tone="medium">{narr.narrative.uncited} 个阶段无引用</Badge>}
              {narr.narrative.untrusted_ignored > 0 && <Badge tone="high">注入已隔离 ×{narr.narrative.untrusted_ignored}</Badge>}
              {narr.narrative.degraded && <Badge tone="medium">降级：{narr.narrative.degraded_reason || '确定性重建'}</Badge>}
              <span className="text-[11px] text-faint">{narr.narrative.model || 'heuristic'} · {narr.narrative.latency_ms}ms · {relTime(narr.generated_at)}</span>
            </div>
            <p className="mb-4 text-[13px] leading-[1.8] text-foreground">{narr.narrative.summary}</p>

            <CardTitle className="mb-2">攻击链阶段（按 ATT&CK 战术顺序）</CardTitle>
            <div className="mb-4 grid gap-2">
              {narr.narrative.phases.map((p, i) => (
                <div key={`${p.tactic_id}-${i}`} className="rounded-lg border border-border-soft bg-secondary/40 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="grid h-5 w-5 place-items-center rounded-full bg-primary text-[10px] font-bold text-primary-foreground">{i + 1}</span>
                    <b className="text-[12.5px] text-foreground">{p.name}</b>
                    <Badge tone="info">{p.tactic}{p.tactic_id ? ` · ${p.tactic_id}` : ''}</Badge>
                    <Badge tone="neutral">{p.alerts.length} 条告警</Badge>
                  </div>
                  <p className="mt-1.5 text-[12px] leading-[1.7] text-muted-foreground">{p.description}</p>
                  {!!p.alerts.length && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {p.alerts.slice(0, 8).map((id) => (
                        <span key={id} className="rounded border border-border-soft px-1.5 py-0.5 font-mono text-[10.5px] text-ghost" title="证据告警 ID">{id}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {!!narr.narrative.missing_phases?.length && (
              <div className="mb-3 text-[12px] text-faint">
                未观测到：{narr.narrative.missing_phases.join('、')}（可能已发生但未被检出，或尚未发生）
              </div>
            )}

            {!!narr.narrative.actions?.length && (
              <div>
                <CardTitle className="mb-2">建议动作（全部需人工确认）</CardTitle>
                <div className="grid gap-1.5">
                  {narr.narrative.actions.map((a, i) => (
                    <div key={i} className="flex flex-wrap items-center gap-2 text-[12px]">
                      <Badge tone="medium">{a.type}</Badge>
                      <span className="font-mono text-[11.5px]">{a.target}</span>
                      <span className="text-muted-foreground">{a.detail}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}

/* ================= 运营周报 ================= */

interface WeeklyReport {
  alerts_week?: number; resolved_week?: number; fp_rate?: number;
  mttr_min?: number; hosts_active?: number;
  fp_ranking?: { rule_id: string; fp_rate: number; false_pos: number; handled: number; tune_candidate?: boolean }[];
  [k: string]: unknown;
}

export function ReportPage() {
  const err = useError();
  const [rep, setRep] = useState<WeeklyReport | null>(null);
  const [ig, setIg] = useState<IntegrityReport | null>(null);

  useEffect(() => {
    api.get<WeeklyReport>('/api/v1/report/weekly').then(setRep).catch(err.capture);
    api.get<IntegrityReport>('/api/v1/integrity').then(setIg).catch(() => setIg(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (err.rendered) return err.rendered;
  if (!rep) return <Card className="p-4"><SkeletonRows rows={6} /></Card>;

  return (
    <div className="space-y-3.5">
      <Card className="p-0">
        {/* 与概览 KPI 同构：单面板 + 发丝线分隔 + mono 读数 */}
        <div className="grid grid-cols-2 divide-border-soft md:grid-cols-4 md:divide-x">
          {([
            ['本周新增告警', rep.alerts_week, '过去 7 天'],
            ['本周已处置', rep.resolved_week, '含确认/解决/误报'],
            ['综合误报率', rep.fp_rate != null ? `${(rep.fp_rate * 100).toFixed(1)}%` : null, '已处置样本中的误报占比'],
            ['平均处置时长', rep.mttr_min != null ? `${Math.round(rep.mttr_min)} 分钟` : null, '创建 → 处置'],
          ] as [string, string | number | null, string][]).map(([label, v, sub]) => (
            <div key={label} className="px-4 py-3.5">
              <div className="text-[11px] tracking-[.5px] text-faint">{label}</div>
              <div className="anim-digit mt-1.5 font-mono text-[26px] leading-none font-semibold tabular-nums">{v ?? '—'}</div>
              <div className="mt-1.5 text-[11.5px] text-faint">{sub}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-4">
        <CardTitle className="mb-3">误报率最高的规则（需 ≥5 次处置）</CardTitle>
        {(rep.fp_ranking || []).length ? (
          <>
            {rep.fp_ranking!.map((r) => (
              <div key={r.rule_id} className="mb-2 flex items-center gap-2.5">
                <span className="w-[90px] font-mono text-xs">{r.rule_id}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border-soft">
                  <i className={cn('block h-full rounded-full', r.fp_rate > 0.5 ? 'bg-destructive' : 'bg-warn')} style={{ width: `${Math.round(r.fp_rate * 100)}%` }} />
                </div>
                <span className="w-28 text-xs text-faint">{r.false_pos}/{r.handled} 误报</span>
                <b className={cn('w-12 text-right', r.fp_rate > 0.5 ? 'text-destructive' : 'text-warn')}>{Math.round(r.fp_rate * 100)}%</b>
                {r.tune_candidate && <Badge tone="medium" title="已处置 ≥5 条且误报率 ≥80%：建议核对该规则的匹配条件与阈值，或为已确认的良性场景配置白名单">调优候选</Badge>}
              </div>
            ))}
            <div className="mt-2.5 text-xs text-faint">高误报规则建议核对命中样本后加白，或在规则页调整分值。</div>
          </>
        ) : <div className="px-2 py-6 text-center text-[13px] text-faint">处置样本不足，暂无排名</div>}
      </Card>

      {ig && (
        <Card className="p-4">
          <CardTitle className="mb-3">告警完整性链（日志防篡改校验）</CardTitle>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Badge tone="resolved">完好 {ig.ok} 天</Badge>
            {ig.purged > 0 && <Badge tone="neutral">已按策略清理 {ig.purged} 天</Badge>}
            {ig.tampered > 0 && <Badge tone="critical">校验异常 {ig.tampered} 天</Badge>}
            <div className="flex-1" />
            <span className="text-[11.5px] text-faint">
              {ig.tampered === 0 ? '全链校验通过：告警记录未被篡改，可作为合规证据导出。' : '存在校验异常日期——请立即核对数据库访问记录。'}
            </span>
          </div>
          <div className="flex flex-wrap gap-1">
            {ig.days.map((d) => (
              <span key={d.day} title={`${d.day} · ${d.status === 'ok' ? '完好' : d.status === 'purged' ? '已清理' : '校验异常'}`}
                className={cn('h-4 w-4 rounded-[3px] border',
                  d.status === 'ok' && 'border-ok/30 bg-ok-soft',
                  d.status === 'purged' && 'border-border bg-secondary',
                  d.status === 'tampered' && 'border-crit/50 bg-crit-soft')} />
            ))}
          </div>
          <p className="mt-2.5 text-xs text-faint">每个方块代表一天：<span className="text-ok">绿=哈希链完好</span>，灰=按保留策略清理，<span className="text-crit">红=校验异常</span>。</p>
        </Card>
      )}

      <p className="text-xs text-faint">本报表按当前数据实时生成，可在浏览器中打印为 PDF 存档或发送给管理层。</p>
    </div>
  );
}
