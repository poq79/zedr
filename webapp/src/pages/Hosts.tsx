// HostsPage（Misc.tsx 拆分生成，2026-11-22 god file 治理）。
import { useCallback, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { EyeOff, Copy, Eye, Download, Monitor, Plus, ArrowUpCircle } from 'lucide-react';
import { api } from '../lib/api';
import { Host, FleetEntry, UpgradeAvail, FleetStatus, UserRow } from '../lib/types';
import { relTime, fmtTime } from '../lib/format';
import { useError } from '../lib/hooks';
import { cn, cmpVersion } from '../lib/utils';
import { Button, Input, SkeletonRows, Card, Badge, CardTitle, EmptyState } from '../components/ui/basics';
import { Drawer, useToast, useConfirm } from '../components/ui/overlays';

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
                    {h.isolated && (
                      <div className="mt-1"><Badge tone="critical" title="主机网络隔离生效中：业务网络已被切断，仅保留管理通道">已隔离</Badge></div>
                    )}
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
