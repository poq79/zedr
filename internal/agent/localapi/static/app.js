/* Z-EDR 桌面端（本机防护）· 前端应用 */
'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const SEV = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
const VERDICT = { malicious: '恶意', suspicious: '可疑', safe: '安全' };
const LAYER = { static: '静态', keyword: '关键词', rule: '规则', lineage: '血缘', behavior: '行为' };

let procs = [];
let alerts = [];
let status = null;
let timer = null;

/* 页面级空状态：图标 + 结论 + 引导（与管理台同款） */
function emptyState(icon, title, sub, tone = '') {
  return `<div class="empty-state">
    <div class="e-ico ${tone}">${icon}</div>
    <div class="e-title">${title}</div>
    <div class="e-sub">${sub}</div>
  </div>`;
}
const EMPTY_ICONS = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 5-5"/></svg>',
  search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
};

/* toast 图标（内联 SVG，语义色由 CSS 控制） */
const TOAST_ICONS = {
  ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  err: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/></svg>',
};

function toast(msg, kind = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<span class="t-ico">${TOAST_ICONS[kind] || TOAST_ICONS.ok}</span><span>${esc(msg)}</span>`;
  $('#toasts').appendChild(el);
  setTimeout(() => el.classList.add('out'), 2800);
  setTimeout(() => el.remove(), 3250);
}

/* Promise 化确认对话框（替代原生 confirm）：Enter 确认 / Esc 取消 */
function hgConfirm({ title = '确认操作', message = '', danger = false, okText = '确认', cancelText = '取消' } = {}) {
  return new Promise((resolve) => {
    const mask = document.createElement('div');
    mask.className = 'confirm-mask';
    mask.innerHTML = `
      <div class="confirm ${danger ? 'danger' : ''}" role="alertdialog" aria-modal="true" aria-label="${esc(title)}">
        <div class="c-title"><span class="c-ico">${TOAST_ICONS[danger ? 'err' : 'warn']}</span>${esc(title)}</div>
        <div class="c-msg">${message}</div>
        <div class="c-actions">
          <button class="btn" data-act="cancel">${esc(cancelText)}</button>
          <button class="btn ${danger ? 'danger' : 'primary'}" data-act="ok">${esc(okText)}</button>
        </div>
      </div>`;
    const cleanup = () => { mask.remove(); document.removeEventListener('keydown', onKey); };
    const onKey = (e) => {
      if (e.key === 'Escape') { cleanup(); resolve(false); }
      else if (e.key === 'Enter') { e.preventDefault(); cleanup(); resolve(true); }
    };
    mask.addEventListener('click', (e) => {
      if (e.target === mask) { cleanup(); resolve(false); return; }
      const act = e.target.closest('[data-act]');
      if (act) { cleanup(); resolve(act.dataset.act === 'ok'); }
    });
    document.addEventListener('keydown', onKey);
    document.body.appendChild(mask);
    mask.querySelector('[data-act="ok"]').focus();
  });
}

function rel(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d)) return '-';
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}

function fullTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d)) return '-';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ---- 本地接口访问令牌 ----
// 桌面宿主会把令牌放在首屏 URL 里传进来；这里立刻存起来并从地址栏抹掉，
// 避免留在浏览器历史记录、书签或截图里。
const TOKEN_KEY = 'hg_local_token';

function bootstrapToken() {
  const params = new URLSearchParams(location.search);
  const fromURL = params.get('token');
  if (fromURL) {
    localStorage.setItem(TOKEN_KEY, fromURL);
    params.delete('token');
    const q = params.toString();
    history.replaceState(null, '', location.pathname + (q ? '?' + q : ''));
    return fromURL;
  }
  return localStorage.getItem(TOKEN_KEY) || '';
}

let LOCAL_TOKEN = bootstrapToken();

async function api(path, opts = {}) {
  const headers = { Accept: 'application/json' };
  if (opts.body) headers['Content-Type'] = 'application/json';
  if (LOCAL_TOKEN) headers['X-HG-Token'] = LOCAL_TOKEN;

  let res;
  try {
    res = await fetch(path, {
      method: opts.method || 'GET',
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
  } catch (e) {
    throw new Error('无法连接本地探针服务，请确认探针进程正在运行');
  }

  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);

  if (res.status === 401) {
    promptForToken();
    throw new Error('需要访问令牌');
  }
  if (!res.ok) {
    // 错误体可能是 { error: { message } } 或 { error: "字符串" }
    const e = data && data.error;
    const msg = (e && e.message) || (typeof e === 'string' ? e : '') || `请求失败 (${res.status})`;
    throw new Error(msg);
  }
  return data && Object.prototype.hasOwnProperty.call(data, 'data') ? data.data : data;
}

// promptForToken 在缺少令牌时提供一次性输入入口。
// 浏览器直接访问时需要；桌面宿主会自动带上，不会走到这里。
function promptForToken() {
  if (document.getElementById('tokenGate')) return;
  const box = document.createElement('div');
  box.id = 'tokenGate';
  box.style.cssText = 'position:fixed;inset:0;background:rgba(8,12,20,.92);display:flex;align-items:center;justify-content:center;z-index:9999';
  box.innerHTML = `
    <div style="max-width:460px;padding:28px;border-radius:14px;background:#111a26;border:1px solid #22303f;color:#dbe6f2;font-size:14px;line-height:1.7">
      <div style="font-size:16px;font-weight:600;margin-bottom:10px">需要访问令牌</div>
      <div style="color:#8ba0b6;margin-bottom:14px">
        本地接口已启用访问控制，防止网页/其它程序调用。令牌由探针自动生成，位于数据目录的
        <code style="color:#5eead4">local.token</code> 文件。
      </div>
      <input id="tokenInput" placeholder="粘贴令牌" style="width:100%;padding:9px 11px;border-radius:8px;border:1px solid #22303f;background:#0b1220;color:#dbe6f2;margin-bottom:12px;box-sizing:border-box" />
      <button id="tokenSave" style="padding:9px 18px;border-radius:8px;border:0;background:#2563eb;color:#fff;cursor:pointer">保存并重新加载</button>
    </div>`;
  document.body.appendChild(box);
  document.getElementById('tokenSave').addEventListener('click', () => {
    const v = document.getElementById('tokenInput').value.trim();
    if (!v) return;
    localStorage.setItem(TOKEN_KEY, v);
    LOCAL_TOKEN = v;
    location.reload();
  });
  document.getElementById('tokenInput').focus();
}

/* ------------------------------------------------------------ 渲染 */

function renderCards(s) {
  const critCount = alerts.filter((a) => a.severity === 'critical').length;
  const susCount = alerts.filter((a) => a.verdict === 'suspicious').length;
  const stat = s.stats || {};

  const cards = [
    {
      cls: s.online ? 'ok' : (s.enrolled ? 'warn' : ''),
      label: '防护状态',
      value: s.warmup ? '基线学习中' : (s.online ? '运行中' : (s.enrolled ? '离线' : '仅本地')),
      sub: s.warmup
        ? `静默至 ${fullTime(s.warmup_until)}（仅上报恶意级）`
        : (s.enrolled ? `已注册 · ${s.agent_id}` : '未配置总控服务端'),
    },
    {
      cls: critCount > 0 ? 'crit' : '',
      label: '严重告警',
      value: String(critCount),
      sub: `可疑 ${susCount} · 本地共 ${alerts.length} 条`,
    },
    {
      cls: '',
      label: '监控进程',
      value: String(s.proc_count || 0),
      sub: `规则 ${s.rule_count || 0} 条 · 基线 ${s.baseline_size || 0} 样本`,
    },
    {
      cls: (s.cpu_percent || 0) > 5 ? 'warn' : 'ok',
      label: '资源占用',
      value: `${(s.cpu_percent || 0).toFixed(1)}%`,
      sub: `${(s.mem_mb || 0).toFixed(0)} MB · 平均检测 ${stat.avg_latency_ms || 0} ms`,
    },
    {
      cls: s.file_watch ? 'ok' : 'warn',
      label: '落地监控',
      value: s.file_watch ? `${s.watched_dirs} 个目录` : '未启用',
      sub: s.file_watch
        ? `已捕获 ${s.drop_events || 0} 次文件落地`
        : '落地即执行关联不可用',
    },
    {
      cls: '',
      label: '自启动基线',
      value: String(s.persist_count || 0),
      sub: '对比新增/改写，变更才告警',
    },
  ];

  $('#cards').innerHTML = cards.map((c) => `
    <div class="card ${c.cls}">
      <div class="label">${esc(c.label)}</div>
      <div class="value">${esc(c.value)}</div>
      <div class="sub">${esc(c.sub)}</div>
    </div>`).join('');
}

function renderAlerts() {
  const box = $('#alertList');
  if (!alerts.length) {
    box.innerHTML = emptyState(EMPTY_ICONS.shield,
      '暂无告警',
      '探针正在持续监控进程创建事件。有可疑行为时，告警会实时出现在这里。');
    $('#alertMeta').textContent = '';
    return;
  }
  $('#alertMeta').textContent = `共 ${alerts.length} 条 · 检测 ${status ? status.stats.scanned : 0} 次`;
  box.innerHTML = alerts.slice(0, 60).map((a) => `
    <div class="alert-row sev-${esc(a.severity)}" data-id="${esc(a.id)}">
      <span class="badge ${esc(a.severity)}">${esc(SEV[a.severity] || a.severity)}</span>
      <span class="main-col">
        <div class="t">${esc(a.title)}</div>
        <div class="d">${esc(a.process_name)} · ${esc(a.image_path || '-')}</div>
      </span>
      <span class="when">${rel(a.occurred_at)}</span>
    </div>`).join('');

  $$('#alertList .alert-row').forEach((row) => {
    row.addEventListener('click', () => openAlert(row.dataset.id));
  });
}

// 渲染"接近阈值"观察列表：评分未达告警线、但已经有信号的进程。
// 这段信息对调参和误报分析很有价值——能看出"差一点就报警"的到底是什么。
function renderWatchlist() {
  const box = $('#watchList');
  if (!box) return;
  const watch = procs
    .filter((p) => (p.score || 0) >= 20 && (p.score || 0) < 38)
    .sort((a, b) => (b.score || 0) - (a.score || 0))
    .slice(0, 12);

  if (!watch.length) {
    box.innerHTML = emptyState(EMPTY_ICONS.check, '没有进程接近告警线（评分 20–37）',
      '这是好事——说明当前环境没有擦边行为。');
    return;
  }
  $('#watchMeta').textContent = `评分 20–37，未达告警线 · 共 ${watch.length} 个`;

  box.innerHTML = watch.map((p) => `
    <div class="alert-row" style="cursor:default">
      <span class="badge medium">${p.score || 0}</span>
      <span class="main-col">
        <div class="t">${esc(p.name)}</div>
        <div class="d">${esc(p.title || '—')} · ${esc(p.path || '')}</div>
      </span>
      <button class="btn sm" data-allow-path="${esc(p.path || '')}" data-allow-name="${esc(p.name)}">信任此路径</button>
    </div>`).join('');

  $$('[data-allow-path]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const path = btn.dataset.allowPath;
      if (!path) return toast('该进程没有可用的镜像路径', 'err');
      if (!(await hgConfirm({
        title: '信任该路径？',
        message: `该路径下的程序不再告警：<br /><code>${esc(path)}</code>`,
        danger: true, okText: '信任此路径',
      }))) return;
      try {
        await api('/api/local/allowlist', {
          method: 'POST',
          body: { type: 'path', value: path, note: `观察列表加白：${btn.dataset.allowName}` },
        });
        toast('已加入本地白名单');
        refresh();
      } catch (e) { toast(e.message, 'err'); }
    });
  });
}

function renderProcs() {
  const q = $('#procFilter').value.trim().toLowerCase();
  const sortBy = $('#procSort').value;

  let list = procs.filter((p) => {
    if (!q) return true;
    return (p.name || '').toLowerCase().includes(q) || (p.path || '').toLowerCase().includes(q);
  });

  if (sortBy === 'name') list = list.slice().sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  else if (sortBy === 'pid') list = list.slice().sort((a, b) => a.pid - b.pid);

  const body = $('#procBody');
  if (!list.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">没有匹配的进程——试试更短的关键词，或按名称排序浏览全部</td></tr>`;
    return;
  }

  body.innerHTML = list.slice(0, 300).map((p) => {
    const cls = p.score >= 60 ? 's2' : p.score >= 30 ? 's1' : 's0';
    return `<tr>
      <td><span class="score ${cls}">${p.score || 0}</span></td>
      <td class="mono muted">${p.pid}</td>
      <td>
        <div>${esc(p.name)}</div>
        ${p.title ? `<div class="small muted">${esc(p.title)}</div>` : ''}
      </td>
      <td>
        <div class="path">${esc(p.path || '-')}</div>
        ${p.cmdline ? `<div class="cmd">${esc(p.cmdline.length > 180 ? p.cmdline.slice(0, 180) + '…' : p.cmdline)}</div>` : ''}
      </td>
      <td class="small muted">${esc(p.user || '-')}</td>
      <td class="small">${p.conn_count || 0}</td>
    </tr>`;
  }).join('');
}

function renderAllow(entries) {
  const box = $('#allowList');
  if (!entries.length) {
    box.innerHTML = emptyState(EMPTY_ICONS.check, '本地白名单为空',
      '加白后，确认安全的文件或路径不再告警。可在告警详情里一键添加。');
    $('#allowMeta').textContent = '';
    return;
  }
  $('#allowMeta').textContent = `共 ${entries.length} 条`;
  box.innerHTML = entries.map((e) => `
    <div class="alert-row" style="cursor:default">
      <span class="badge type">${esc(e.type)}</span>
      <span class="main-col">
        <div class="mono" style="word-break:break-all">${esc(e.value)}</div>
        <div class="d">${esc(e.note || '无备注')}</div>
      </span>
      <button class="btn sm danger" data-del-type="${esc(e.type)}" data-del-value="${esc(e.value)}">移除</button>
    </div>`).join('');

  $$('[data-del-type]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const type = btn.dataset.delType;
      const value = btn.dataset.delValue;
      if (!(await hgConfirm({
        title: '移除该白名单？',
        message: '移除后相关检测会重新生效。',
        danger: true, okText: '移除',
      }))) return;
      try {
        await api(`/api/local/allowlist?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`, { method: 'DELETE' });
        toast('已移除');
        refresh();
      } catch (e) { toast(e.message, 'err'); }
    });
  });
}

/* ------------------------------------------------------------ 告警详情 */

async function openAlert(id) {
  $('#mask').classList.add('show');
  $('#drawer').classList.add('show');
  $('#dTitle').textContent = '加载中…';
  $('#dBody').innerHTML = '';
  $('#dFoot').innerHTML = '';

  let a;
  try { a = await api(`/api/local/alerts/${encodeURIComponent(id)}`); }
  catch (e) { $('#dBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }

  const ev = a.evidence || {};
  const p = ev.process || {};

  $('#dTitle').textContent = a.title;
  $('#dSub').innerHTML = `<span class="badge ${esc(a.severity)}">${esc(SEV[a.severity] || a.severity)}</span>
    <span class="badge ${esc(a.verdict)}">${esc(VERDICT[a.verdict] || a.verdict)}</span>
    <span class="muted small">${fullTime(a.occurred_at)}${a.sent ? ' · 已上报' : ' · 待上报'}</span>`;

  const kv = (k, v, mono) => `<dt>${esc(k)}</dt><dd class="${mono ? 'mono' : ''}">${esc(v || '-')}</dd>`;

  const total = Math.max(1, (ev.static_score || 0) + (ev.keyword_score || 0) + (ev.rule_score || 0) + (ev.lineage_score || 0));
  const parts = [
    ['静态', ev.static_score || 0, '#3d8bfd'],
    ['关键词', ev.keyword_score || 0, '#22d3ee'],
    ['规则', ev.rule_score || 0, '#a78bfa'],
    ['血缘', ev.lineage_score || 0, '#fbbf24'],
  ];

  const signals = (ev.signals || []).map((s) => `
    <div class="sig">
      <span class="layer">${esc(LAYER[s.layer] || s.layer)}</span>
      <span style="flex:1;min-width:0">
        <b>${esc(s.name)}</b>
        ${s.note ? `<div class="small muted" style="margin-top:2px">${esc(s.note)}</div>` : ''}
      </span>
      <span class="pts">+${s.score}</span>
    </div>`).join('') || '<div class="empty small">无独立信号</div>';

  const ancestry = (ev.ancestry || []).map((n, i) => `
    <div style="padding-left:${i * 14}px">
      <span class="muted">${i === 0 ? '●' : '└─'}</span>
      <b>${esc(n.name)}</b> <span class="muted">PID ${n.pid}</span>
      ${n.path ? `<div class="muted small" style="padding-left:20px;word-break:break-all">${esc(n.path)}</div>` : ''}
    </div>`).join('') || '<div class="empty small">无祖先记录</div>';

  const net = (ev.network || []).map((c) => `
    <tr><td class="mono">${esc(c.proto)}</td><td class="mono">${esc(c.local_ip)}:${c.local_port}</td>
    <td class="mono">${esc(c.remote_ip)}:${c.remote_port}</td><td class="small muted">${esc(c.state)}</td></tr>`).join('');

  $('#dBody').innerHTML = `
    <section class="blk">
      <h4>置信分构成</h4>
      <div class="bar">${parts.map(([, v, c]) => `<i style="width:${(v / total) * 100}%;background:${c}"></i>`).join('')}</div>
      <div class="legend">
        ${parts.map(([n, v, c]) => `<span><i style="background:${c}"></i>${n} ${v.toFixed(0)}</span>`).join('')}
        <span style="margin-left:auto;color:var(--text)">综合 <b>${a.score}</b> / 100</span>
      </div>
    </section>

    <section class="blk">
      <h4>结论</h4>
      <div class="small" style="line-height:1.8">${esc(a.summary || '-')}</div>
      ${(ev.notes || []).length ? `<ul class="small muted" style="margin:8px 0 0;padding-left:18px;line-height:1.8">
        ${ev.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
    </section>

    <section class="blk">
      <h4>进程</h4>
      <dl class="kv">
        ${kv('进程名', p.name || a.process_name, true)}
        ${kv('PID / PPID', `${p.pid || a.pid} / ${p.ppid || a.ppid}`, true)}
        ${kv('镜像路径', p.path || a.image_path, true)}
        ${kv('运行账号', p.user || a.user)}
        ${kv('SHA256', p.hash_sha256 || a.hash_sha256, true)}
        ${kv('数字签名', p.signature_ok ? '校验通过' : p.signed ? '存在但不可信' : '无签名')}
        ${kv('签名主体', p.signer || a.signer)}
        ${kv('高权限', p.elevated ? '是' : '否')}
        ${kv('启动时间', fullTime(p.start_time))}
      </dl>
      ${(p.cmdline || a.cmdline) ? `<pre class="code" style="margin-top:10px">${esc(p.cmdline || a.cmdline)}</pre>` : ''}
    </section>

    <section class="blk"><h4>命中信号</h4>${signals}</section>
    <section class="blk"><h4>血缘链</h4><div class="tree">${ancestry}</div></section>
    ${net ? `<section class="blk"><h4>网络连接</h4><table>
      <thead><tr><th>协议</th><th>本地</th><th>远端</th><th>状态</th></tr></thead>
      <tbody>${net}</tbody></table></section>` : ''}
  `;

  const canAllow = !!(a.hash_sha256 || p.hash_sha256);
  $('#dFoot').innerHTML = canAllow
    ? `<button class="btn primary" id="allowHash">信任此文件（按哈希加白）</button>
       <button class="btn" id="allowPath">信任此路径</button>
       <span class="small muted" style="align-self:center">加白后该对象在本机不再告警</span>`
    : `<button class="btn" id="allowPath">信任此路径</button>`;

  const ah = $('#allowHash');
  if (ah) {
    ah.addEventListener('click', async () => {
      const hash = a.hash_sha256 || p.hash_sha256;
      if (!(await hgConfirm({
        title: '信任该文件？',
        message: `按哈希加白：<br /><code>${esc(hash)}</code><br />加白后该文件在本机不再告警，请确认这是可信程序。`,
        danger: true, okText: '仍要信任',
      }))) return;
      try {
        await api('/api/local/allowlist', { method: 'POST', body: { type: 'hash', value: hash, note: `来自告警：${a.title}` } });
        toast('已加入本地白名单');
        closeDrawer();
        refresh();
      } catch (e) { toast(e.message, 'err'); }
    });
  }
  const ap = $('#allowPath');
  if (ap) {
    ap.addEventListener('click', async () => {
      const path = a.image_path || p.path;
      if (!path) return toast('缺少镜像路径', 'err');
      if (!(await hgConfirm({
        title: '信任该路径下的程序？',
        message: `<code>${esc(path)}</code><br />路径下任意程序都不会再告警，请确认范围可接受。`,
        danger: true, okText: '仍要信任',
      }))) return;
      try {
        await api('/api/local/allowlist', { method: 'POST', body: { type: 'path', value: path, note: `来自告警：${a.title}` } });
        toast('已加入本地白名单');
        closeDrawer();
        refresh();
      } catch (e) { toast(e.message, 'err'); }
    });
  }
}

function closeDrawer() {
  $('#mask').classList.remove('show');
  $('#drawer').classList.remove('show');
}

/* ------------------------------------------------------------ 刷新 */

async function refresh() {
  try {
    const [s, pl, al, aw] = await Promise.all([
      api('/api/local/status'),
      api('/api/local/processes?limit=600'),
      api('/api/local/alerts?limit=200'),
      api('/api/local/allowlist'),
    ]);
    status = s;
    procs = pl.items || [];
    alerts = al.items || [];

    $('#connState').className = 'conn ' + (s.online ? 'on' : 'off');
    $('#connText').textContent = s.online ? '已连接总控' : (s.enrolled ? '总控离线' : '仅本地模式');
    $('#hostLine').textContent = `${s.hostname} · ${s.os_version}`;

    renderCards(s);
    renderAlerts();
    renderWatchlist();
    renderProcs();
    renderAllow(aw.items || []);
  } catch (e) {
    $('#connText').textContent = '探针未响应';
    $('#connState').className = 'conn off';
  }
}

function boot() {
  $('#rescanBtn').addEventListener('click', async () => {
    try {
      await api('/api/local/rescan', { method: 'POST' });
      toast('已触发全量重扫');
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#procFilter').addEventListener('input', renderProcs);
  $('#procSort').addEventListener('change', renderProcs);
  $('#dClose').addEventListener('click', closeDrawer);
  $('#mask').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });

  refresh();
  timer = setInterval(refresh, 3000);
}

document.addEventListener('DOMContentLoaded', boot);
