/* =========================================================================
 * HostGuard 总控管理后台 · 前端应用
 *
 * 设计要点：
 *  1. 访问令牌只存在内存变量中（绝不写 localStorage / sessionStorage）；
 *     刷新令牌由服务端写入 HttpOnly Cookie，前端不可读。
 *  2. 401 自动刷新一次并重放原请求；刷新失败则回到登录页。
 *  3. 5xx 对幂等请求（GET）自动重试最多 3 次，4xx 一律不重试。
 *  4. 服务端错误码统一映射为可读中文文案。
 * ========================================================================= */
'use strict';

/* ------------------------------------------------------------------ 基础工具 */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const esc = (s) =>
  String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
const STATUS_LABEL = { open: '待处置', acknowledged: '已确认', resolved: '已解决', false_positive: '误报' };
const VERDICT_LABEL = { malicious: '恶意', suspicious: '可疑', safe: '安全' };
const LAYER_LABEL = { static: '静态指纹', keyword: '关键词', rule: '行为规则', lineage: '血缘图', behavior: '行为' };

function badge(cls, text) {
  return `<span class="badge ${esc(cls)}">${esc(text)}</span>`;
}
function sevBadge(s) { return badge(s, SEV_LABEL[s] || s); }
function statusBadge(s) { return badge(s, STATUS_LABEL[s] || s); }
function verdictBadge(v) { return badge(v, VERDICT_LABEL[v] || v); }

function fmtTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d)) return '-';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function relTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d)) return '-';
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}
function fmtBytes(n) {
  if (!n || n < 1024) return `${n || 0} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function toast(msg, kind = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, 3200);
  setTimeout(() => el.remove(), 3600);
}

/* ------------------------------------------------------------------ API 客户端 */
class ApiError extends Error {
  constructor(code, message, status, requestId) {
    super(message);
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

const CODE_TEXT = {
  invalid_argument: '提交的内容不合法',
  unauthenticated: '登录状态已失效，请重新登录',
  forbidden: '当前角色无权执行该操作',
  not_found: '目标对象不存在',
  conflict: '操作冲突，请刷新后重试',
  too_many_requests: '操作过于频繁，请稍后再试',
  unavailable: '服务暂不可用，请稍后重试',
  internal_error: '服务内部错误，请稍后重试或联系管理员',
};

const api = {
  token: null,
  tokenExp: 0,
  refreshing: null,

  /** 带鉴权、错误映射、401 刷新与 5xx 重试的请求封装 */
  async request(path, opts = {}) {
    const method = opts.method || 'GET';
    const maxAttempts = method === 'GET' ? 4 : 1; // GET: 首次 + 最多重试 3 次
    let attempt = 0;

    while (true) {
      let res;
      const headers = { Accept: 'application/json' };
      if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
      if (this.token) headers.Authorization = `Bearer ${this.token}`;

      try {
        res = await fetch(path, {
          method,
          headers,
          credentials: 'same-origin',
          body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        });
      } catch (e) {
        // 网络层失败：给出离线提示，不无限重试
        if (attempt < maxAttempts - 1) { attempt++; await sleep(400 * attempt); continue; }
        throw new ApiError('offline', '无法连接服务端，请检查网络或服务进程是否运行', 0);
      }

      // 会话过期 → 尝试刷新一次，成功则重放
      if (res.status === 401 && !opts._retried && !path.startsWith('/api/v1/auth/')) {
        const ok = await this.tryRefresh();
        if (ok) return this.request(path, Object.assign({}, opts, { _retried: true }));
        throw new ApiError('unauthenticated', CODE_TEXT.unauthenticated, 401);
      }

      if (res.status >= 500 && attempt < maxAttempts - 1) {
        attempt++;
        await sleep(300 * attempt);
        continue;
      }

      if (res.status === 204) return null;

      let payload = null;
      try { payload = await res.json(); } catch (_) { /* 非 JSON 响应 */ }

      if (!res.ok) {
        const e = (payload && payload.error) || {};
        const msg = e.message || CODE_TEXT[e.code] || `请求失败（HTTP ${res.status}）`;
        throw new ApiError(e.code || 'unknown', msg, res.status, e.request_id);
      }
      // 服务端成功响应统一包在 { data: ... } 里
      return payload && Object.prototype.hasOwnProperty.call(payload, 'data') ? payload.data : payload;
    }
  },

  get(p) { return this.request(p); },
  post(p, body) { return this.request(p, { method: 'POST', body }); },
  del(p) { return this.request(p, { method: 'DELETE' }); },

  /** 用 HttpOnly Cookie 里的刷新令牌换取新的访问令牌（并发调用会合并） */
  async tryRefresh() {
    if (this.refreshing) return this.refreshing;
    this.refreshing = (async () => {
      try {
        const res = await fetch('/api/v1/auth/refresh', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        });
        if (!res.ok) return false;
        const payload = await res.json();
        const data = payload && payload.data;
        if (!data || !data.access_token) return false;
        this.token = data.access_token;
        this.tokenExp = Date.parse(data.expires_at) || 0;
        return true;
      } catch (_) {
        return false;
      } finally {
        this.refreshing = null;
      }
    })();
    return this.refreshing;
  },
};

/* ------------------------------------------------------------------ 全局状态 */
const state = {
  user: null,
  route: 'overview',
  alerts: {
    page: 1, pageSize: 20, total: 0, items: [],
    filters: { status: '', severity: '', verdict: '', q: '' },
    selected: new Set(),   // 批量处置用
    focus: -1,             // 键盘焦点行索引
  },
  hosts: [],
  rules: [],
  allowlist: [],
  audit: [],
  users: [],
  live: false,
  sse: null,
  unread: 0,
};

/* ------------------------------------------------------------------ 路由定义 */
const ROUTES = [
  { key: 'overview', label: '概览', icon: '▤', title: '概览', roles: null },
  { key: 'alerts', label: '告警中心', icon: '⚠', title: '告警中心', roles: null },
  { key: 'incidents', label: '事件', icon: '⛓', title: '事件（攻击链聚类）', roles: null },
  { key: 'hosts', label: '主机终端', icon: '◫', title: '主机终端', roles: null },
  { key: 'rules', label: '检测规则', icon: '⌗', title: '检测规则', roles: null },
  { key: 'allowlist', label: '白名单', icon: '✓', title: '白名单与降噪', roles: null },
  { key: 'audit', label: '审计日志', icon: '≡', title: '审计日志', roles: null },
  { key: 'users', label: '账号管理', icon: '◉', title: '账号管理', roles: ['admin'] },
];

function buildNav() {
  const nav = $('#nav');
  nav.innerHTML = ROUTES.filter((r) => !r.roles || r.roles.includes(state.user.role))
    .map((r) => `<button class="nav-item" data-route="${r.key}">
        <span class="ico">${r.icon}</span>${r.label}
        ${r.key === 'alerts' ? '<span class="nav-badge" id="navAlerts" style="display:none">0</span>' : ''}
      </button>`)
    .join('');
  $$('.nav-item[data-route]', nav).forEach((el) => {
    el.addEventListener('click', () => { location.hash = '#/' + el.dataset.route; });
  });
}

function setActiveNav() {
  $$('.nav-item[data-route]').forEach((el) => {
    el.classList.toggle('active', el.dataset.route === state.route);
  });
  const def = ROUTES.find((r) => r.key === state.route);
  $('#pageTitle').textContent = def ? def.title : '概览';
}

/* ------------------------------------------------------------------ 图表（纯 SVG） */
function timelineChart(points) {
  if (!points || !points.length) return '<div class="empty">暂无数据</div>';
  const W = 680, H = 150, padL = 34, padB = 20, padT = 8;
  const innerW = W - padL - 8;
  const innerH = H - padB - padT;
  const max = Math.max(1, ...points.map((p) => p.total));
  const bw = innerW / points.length;

  let bars = '';
  points.forEach((p, i) => {
    const h = (p.total / max) * innerH;
    const critH = p.total > 0 ? (p.critical / p.total) * h : 0;
    const x = padL + i * bw + Math.max(1, bw * 0.16);
    const w = Math.max(1, bw * 0.68);
    const y = padT + innerH - h;
    bars += `<rect x="${x}" y="${y}" width="${w}" height="${Math.max(0, h - critH)}" rx="2" fill="#3d8bfd" opacity="0.75"></rect>`;
    if (critH > 0) {
      bars += `<rect x="${x}" y="${padT + innerH - critH}" width="${w}" height="${critH}" rx="2" fill="#fb7185"></rect>`;
    }
  });

  // Y 轴刻度
  let grid = '';
  for (let i = 0; i <= 3; i++) {
    const v = Math.round((max / 3) * i);
    const y = padT + innerH - (i / 3) * innerH;
    grid += `<line x1="${padL}" y1="${y}" x2="${W - 8}" y2="${y}" stroke="#1f2b45" stroke-width="1"></line>`;
    grid += `<text x="${padL - 6}" y="${y + 3.5}" font-size="9" fill="#6b7c99" text-anchor="end">${v}</text>`;
  }

  // X 轴标签（最多 6 个）
  let labels = '';
  const step = Math.max(1, Math.ceil(points.length / 6));
  points.forEach((p, i) => {
    if (i % step !== 0) return;
    const d = new Date(p.bucket);
    const hh = String(d.getHours()).padStart(2, '0');
    const x = padL + i * bw + bw / 2;
    labels += `<text x="${x}" y="${H - 5}" font-size="9" fill="#6b7c99" text-anchor="middle">${hh}:00</text>`;
  });

  return `<div class="chart-wrap"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" height="150">${grid}${bars}${labels}</svg></div>
    <div class="legend"><span><i style="background:#3d8bfd"></i>普通告警</span><span><i style="background:#fb7185"></i>严重告警</span></div>`;
}

function severityDonut(dist) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const colors = { critical: '#fb7185', high: '#f87171', medium: '#fbbf24', low: '#64748b', info: '#475569' };
  const total = order.reduce((a, k) => a + (dist[k] || 0), 0);
  if (!total) return '<div class="empty">暂无数据</div>';

  const R = 46, C = 2 * Math.PI * R;
  let offset = 0, arcs = '';
  order.forEach((k) => {
    const v = dist[k] || 0;
    if (!v) return;
    const len = (v / total) * C;
    arcs += `<circle cx="60" cy="60" r="${R}" fill="none" stroke="${colors[k]}" stroke-width="14"
      stroke-dasharray="${len - 2} ${C - len + 2}" stroke-dashoffset="${-offset}"
      transform="rotate(-90 60 60)" stroke-linecap="butt"></circle>`;
    offset += len;
  });

  const rows = order
    .filter((k) => (dist[k] || 0) > 0)
    .map((k) => `<div style="display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:6px">
        <i style="width:8px;height:8px;border-radius:2px;background:${colors[k]};display:inline-block"></i>
        <span style="color:var(--text-dim);flex:1">${SEV_LABEL[k]}</span>
        <b style="font-variant-numeric:tabular-nums">${dist[k]}</b>
      </div>`)
    .join('');

  return `<div style="display:flex;gap:18px;align-items:center">
      <svg viewBox="0 0 120 120" width="120" height="120" style="flex:0 0 120px">
        <circle cx="60" cy="60" r="${R}" fill="none" stroke="#1a2438" stroke-width="14"></circle>
        ${arcs}
        <text x="60" y="58" text-anchor="middle" font-size="20" font-weight="700" fill="#e6edf7">${total}</text>
        <text x="60" y="74" text-anchor="middle" font-size="9" fill="#6b7c99">总告警</text>
      </svg>
      <div style="flex:1">${rows}</div>
    </div>`;
}

function barList(items, valueKey, labelKey) {
  if (!items || !items.length) return '<div class="empty">暂无数据</div>';
  const max = Math.max(1, ...items.map((i) => i[valueKey] || 0));
  return items.map((i) => `<div class="bar-row">
      <span class="name" title="${esc(i[labelKey])}">${esc(i[labelKey])}</span>
      <span class="track"><i style="width:${Math.max(2, ((i[valueKey] || 0) / max) * 100)}%"></i></span>
      <span class="num">${i[valueKey] || 0}</span>
    </div>`).join('');
}

/* ------------------------------------------------------------------ 视图：概览 */
async function viewOverview() {
  const c = $('#content');
  c.innerHTML = '<div class="empty"><span class="spin"></span> 加载中…</div>';
  let d;
  try { d = await api.get('/api/v1/dashboard'); } catch (e) { return renderError(e); }

  const hostRate = d.total_hosts ? Math.round((d.online_hosts / d.total_hosts) * 100) : 0;
  c.innerHTML = `
    <div class="grid grid-4" style="margin-bottom:14px">
      <div class="card kpi ${hostRate < 60 ? 'warn' : 'ok'}">
        <div class="label">受管主机</div>
        <div class="value">${d.online_hosts}<span class="muted" style="font-size:15px">/${d.total_hosts}</span></div>
        <div class="sub">在线率 ${hostRate}%</div>
      </div>
      <div class="card kpi"><div class="label">近 24 小时告警</div><div class="value">${d.alerts_24h}</div><div class="sub">全部告警 ${d.open_alerts + (d.alerts_24h || 0)} 条量级</div></div>
      <div class="card kpi warn"><div class="label">待处置告警</div><div class="value">${d.open_alerts}</div><div class="sub">需人工确认</div></div>
      <div class="card kpi crit"><div class="label">严重且待处置</div><div class="value">${d.critical_open}</div><div class="sub">恶意判定 ${d.malicious_count} · 误报 ${d.false_positive}</div></div>
    </div>

    <div class="grid" style="grid-template-columns: 2fr 1fr; margin-bottom:14px">
      <div class="card"><h3 class="card-title">告警时间趋势（24h / 每小时）</h3>${timelineChart(d.timeline)}</div>
      <div class="card"><h3 class="card-title">严重度分布</h3>${severityDonut(d.severity_dist || {})}
        <div class="small muted" style="margin-top:14px">平均置信分 <b style="color:var(--text)">${(d.avg_score || 0).toFixed(1)}</b></div>
      </div>
    </div>

    <div class="grid" style="grid-template-columns:1fr 1fr 1fr">
      <div class="card"><h3 class="card-title">主机告警排行</h3>${barList(d.top_hosts, 'count', 'hostname')}</div>
      <div class="card"><h3 class="card-title">规则命中排行</h3>${barList(d.top_rules, 'count', 'name')}</div>
      <div class="card"><h3 class="card-title">MITRE ATT&amp;CK 命中</h3>${barList(d.top_mitre, 'count', 'tech')}</div>
    </div>
  `;
}

/* ------------------------------------------------------------------ 视图：告警 */
async function viewAlerts() {
  const c = $('#content');
  const f = state.alerts.filters;
  c.innerHTML = `
    <div class="toolbar">
      <input type="search" id="fQ" placeholder="搜索进程名 / 路径 / 命令行 / 主机" value="${esc(f.q)}" />
      <select id="fStatus">
        <option value="">全部状态</option>
        ${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}" ${f.status === k ? 'selected' : ''}>${v}</option>`).join('')}
      </select>
      <select id="fSeverity">
        <option value="">全部严重度</option>
        ${Object.entries(SEV_LABEL).map(([k, v]) => `<option value="${k}" ${f.severity === k ? 'selected' : ''}>${v}</option>`).join('')}
      </select>
      <select id="fVerdict">
        <option value="">全部结论</option>
        ${Object.entries(VERDICT_LABEL).map(([k, v]) => `<option value="${k}" ${f.verdict === k ? 'selected' : ''}>${v}</option>`).join('')}
      </select>
      <div class="spacer"></div>
      <button class="btn sm primary" id="fApply">应用筛选</button>
      <button class="btn sm ghost" id="fReset">重置</button>
      <button class="btn sm ghost" id="fExport" title="按当前筛选导出 CSV（含审计）">导出 CSV</button>
      <button class="btn sm ghost" id="fSaveView" title="把当前筛选条件存为本机视图">保存视图</button>
      <button class="btn sm ghost" id="helpKeys" title="查看键盘快捷键">?</button>
    </div>
    <div class="toolbar" id="savedViews" style="margin-top:-4px"></div>
    <div class="toolbar" style="margin-top:-6px">
      <input type="search" id="aiHunt" placeholder="用一句话检索，例如：最近24小时未签名的高分告警"
             style="flex:1;min-width:280px" />
      <button class="btn sm" id="aiHuntBtn">AI 检索</button>
      <button class="btn sm ghost" id="aiHuntClear" style="display:none">清除结果</button>
    </div>
    <div id="aiHuntResult"></div>
    <div class="card" style="padding:14px 8px 8px">
      <div id="alertTable"><div class="empty"><span class="spin"></span> 加载中…</div></div>
      <div class="pager" id="alertPager"></div>
    </div>
  `;

  $('#fApply').addEventListener('click', () => {
    f.q = $('#fQ').value.trim();
    f.status = $('#fStatus').value;
    f.severity = $('#fSeverity').value;
    f.verdict = $('#fVerdict').value;
    state.alerts.page = 1;
    loadAlertTable();
  });
  bindAIHunt();
  renderSavedViews();
  const sv = $('#fSaveView');
  if (sv) sv.addEventListener('click', saveCurrentView);
  const ex = $('#fExport');
  if (ex) ex.addEventListener('click', exportCSV);
  const hk = $('#helpKeys');
  if (hk) hk.addEventListener('click', showShortcuts);

  $('#fReset').addEventListener('click', () => {
    state.alerts.filters = { status: '', severity: '', verdict: '', q: '' };
    state.alerts.page = 1;
    viewAlerts();
  });
  $('#fQ').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#fApply').click(); });

  loadAlertTable();
}

async function loadAlertTable() {
  const f = state.alerts.filters;
  const qs = new URLSearchParams();
  qs.set('page', state.alerts.page);
  qs.set('page_size', state.alerts.pageSize);
  if (f.status) qs.set('status', f.status);
  if (f.severity) qs.set('severity', f.severity);
  if (f.verdict) qs.set('verdict', f.verdict);
  if (f.q) qs.set('q', f.q);

  const box = $('#alertTable');
  if (!box) return;
  let res;
  try { res = await api.get('/api/v1/alerts?' + qs.toString()); }
  catch (e) { box.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }

  state.alerts.items = res.items || [];
  state.alerts.total = res.total || 0;

  if (!state.alerts.items.length) {
    box.innerHTML = '<div class="empty">没有符合条件的告警。试试放宽筛选条件。</div>';
  } else {
    box.innerHTML = `<table>
      <thead><tr>
        <th style="width:36px"><input type="checkbox" id="selAll" title="全选当前页 (a)" /></th>
        <th style="width:64px">严重度</th><th>告警</th><th style="width:150px">主机</th>
        <th style="width:200px">进程</th><th style="width:64px">分值</th>
        <th style="width:88px">状态</th><th style="width:96px">时间</th>
      </tr></thead>
      <tbody>${state.alerts.items.map((a, i) => `
        <tr class="clickable ${state.alerts.selected.has(a.id) ? 'selected' : ''} ${state.alerts.focus === i ? 'focused' : ''}" data-id="${esc(a.id)}" data-idx="${i}">
          <td><input type="checkbox" class="rowSel" data-id="${esc(a.id)}" ${state.alerts.selected.has(a.id) ? 'checked' : ''} /></td>
          <td>${sevBadge(a.severity)}</td>
          <td>
            <div style="font-weight:500">${esc(a.title)}</div>
            <div class="small muted" style="margin-top:3px">${esc((a.rule_ids || []).join(' · ') || '-')}</div>
          </td>
          <td>${esc(a.hostname)}${a.duplicate ? `<span class="small muted"> ×${a.duplicate + 1}</span>` : ''}</td>
          <td class="mono">${esc(a.process_name)}<span class="small muted"> :${a.pid}</span></td>
          <td><b style="color:${a.score >= 70 ? 'var(--crit)' : a.score >= 40 ? 'var(--warn)' : 'var(--text-dim)'}">${a.score}</b></td>
          <td>${statusBadge(a.status)}</td>
          <td class="small muted" title="${esc(fmtTime(a.created_at))}">${relTime(a.created_at)}</td>
        </tr>`).join('')}
      </tbody></table>`;
    $$('#alertTable tr[data-id]').forEach((tr) => {
      tr.addEventListener('click', (e) => {
        if (e.target && e.target.classList.contains('rowSel')) return;
        openAlert(tr.dataset.id);
      });
    });
    $$('#alertTable .rowSel').forEach((cb) => {
      cb.addEventListener('change', () => {
        if (cb.checked) state.alerts.selected.add(cb.dataset.id);
        else state.alerts.selected.delete(cb.dataset.id);
        const tr = cb.closest('tr');
        if (tr) tr.classList.toggle('selected', cb.checked);
        syncBulkbar();
      });
    });
    const selAll = $('#selAll');
    if (selAll) {
      const items = state.alerts.items || [];
      selAll.checked = items.length > 0 && items.every((a) => state.alerts.selected.has(a.id));
      selAll.addEventListener('change', () => toggleSelectAll(selAll.checked));
    }
  }
  box.dataset.loaded = '1';
  bindSortable();
  syncBulkbar();

  const pages = Math.max(1, Math.ceil(state.alerts.total / state.alerts.pageSize));
  $('#alertPager').innerHTML = `
    <span>共 ${state.alerts.total} 条 · 第 ${state.alerts.page}/${pages} 页</span>
    <button class="btn sm" id="prevPage" ${state.alerts.page <= 1 ? 'disabled' : ''}>上一页</button>
    <button class="btn sm" id="nextPage" ${state.alerts.page >= pages ? 'disabled' : ''}>下一页</button>`;
  const prev = $('#prevPage'), next = $('#nextPage');
  if (prev) prev.addEventListener('click', () => { state.alerts.page--; clearSelection(); loadAlertTable(); });
  if (next) next.addEventListener('click', () => { state.alerts.page++; clearSelection(); loadAlertTable(); });
}

/* ------------------------------------------------------------------ 告警详情抽屉 */
async function openAlert(id) {
  const mask = $('#drawerMask'), drawer = $('#drawer');
  mask.classList.add('show');
  drawer.classList.add('show');
  $('#drawerTitle').textContent = '加载中…';
  $('#drawerSub').textContent = '';
  $('#drawerBody').innerHTML = '<div class="empty"><span class="spin"></span></div>';
  $('#drawerFoot').innerHTML = '';

  let a;
  try { a = await api.get('/api/v1/alerts/' + encodeURIComponent(id)); }
  catch (e) {
    $('#drawerBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`;
    return;
  }
  renderAlertDetail(a);
}

function closeDrawer() {
  $('#drawerMask').classList.remove('show');
  $('#drawer').classList.remove('show');
}

function scoreBar(ev, a) {
  const parts = [
    ['静态指纹', ev.static_score || 0, '#3d8bfd'],
    ['关键词', ev.keyword_score || 0, '#22d3ee'],
    ['行为规则', ev.rule_score || 0, '#a78bfa'],
    ['血缘图', ev.lineage_score || 0, '#fbbf24'],
  ];
  const total = Math.max(1, parts.reduce((s, p) => s + p[1], 0));
  return `<div class="scorebar">${parts.map(([, v, col]) =>
    `<i style="width:${(v / total) * 100}%;background:${col}" title="${v.toFixed(1)}"></i>`).join('')}</div>
    <div class="legend">${parts.map(([n, v, col]) =>
      `<span><i style="background:${col}"></i>${n} ${v.toFixed(1)}</span>`).join('')}
      <span style="margin-left:auto;color:var(--text)">综合置信分 <b>${a.score}</b> / 100</span></div>`;
}

function renderAlertDetail(a) {
  const ev = a.evidence || {};
  const p = ev.process || {};

  $('#drawerTitle').textContent = a.title;
  $('#drawerSub').innerHTML = `${sevBadge(a.severity)} ${verdictBadge(a.verdict)} ${statusBadge(a.status)}
    &nbsp;·&nbsp; ${esc(a.hostname)} &nbsp;·&nbsp; ${esc(fmtTime(a.created_at))}
    ${a.duplicate ? `&nbsp;·&nbsp; 重复 ${a.duplicate} 次已折叠` : ''}`;

  const kv = (k, v, mono) => `<dt>${k}</dt><dd class="${mono ? 'mono' : ''}">${esc(v || '-')}</dd>`;

  const signals = (ev.signals || []).map((s) => `
    <div class="signal">
      <span class="layer">${esc(LAYER_LABEL[s.layer] || s.layer)}</span>
      <span style="flex:1;min-width:0">
        <b>${esc(s.name)}</b>${s.note ? `<div class="small muted" style="margin-top:3px">${esc(s.note)}</div>` : ''}
        ${s.mitre ? `<span class="badge info" style="margin-top:6px">${esc(s.mitre)}</span>` : ''}
      </span>
      <span class="pts">+${s.score}</span>
    </div>`).join('') || '<div class="empty small">无独立信号</div>';

  const ruleHits = (ev.rule_hits || []).map((r) => `
    <div class="signal">
      <span class="layer">${esc(r.rule_id)}</span>
      <span style="flex:1;min-width:0">
        <b>${esc(r.name)}</b>
        ${(r.matched || []).length ? `<div class="small muted" style="margin-top:3px;font-family:var(--mono)">${esc(r.matched.join('；'))}</div>` : ''}
        ${(r.mitre || []).map((m) => `<span class="badge info" style="margin-top:6px">${esc(m)}</span>`).join(' ')}
      </span>
      <span class="pts">+${r.score}</span>
    </div>`).join('') || '<div class="empty small">未命中原生规则</div>';

  const ancestry = (ev.ancestry || []).map((n, i) => `
    <div class="node" style="padding-left:${i * 16}px">
      <span class="arrow">${i === 0 ? '●' : '└─'}</span>
      <span class="name">${esc(n.name)}</span>
      <span class="pid">PID ${n.pid} ← PPID ${n.ppid}</span>
      ${n.path ? `<span class="pid" style="opacity:.6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(n.path)}</span>` : ''}
    </div>`).join('') || '<div class="empty small">无祖先链记录</div>';

  const net = (ev.network || []).map((n) => `
    <tr><td class="mono">${esc(n.proto)}</td><td class="mono">${esc(n.local_ip)}:${n.local_port}</td>
    <td class="mono">${esc(n.remote_ip)}:${n.remote_port}</td><td class="small muted">${esc(n.state)}</td></tr>`).join('');

  const mods = (ev.modules || []).slice(0, 30).map((m) => `
    <tr><td class="mono">${esc(m.name)}</td><td class="mono small muted" style="word-break:break-all">${esc(m.path)}</td></tr>`).join('');

  $('#drawerBody').innerHTML = `
    <section class="block">
      <h3>检测结论</h3>
      <div class="card" style="padding:14px">
        ${scoreBar(ev, a)}
        ${(ev.notes || []).length ? `<ul class="small muted" style="margin:12px 0 0;padding-left:18px;line-height:1.8">
          ${ev.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
      </div>
    </section>

    <section class="block">
      <h3>进程信息</h3>
      <div class="card" style="padding:14px">
        <dl class="kv">
          ${kv('进程名', p.name || a.process_name, true)}
          ${kv('PID / PPID', `${p.pid || a.pid} / ${p.ppid || a.ppid}`, true)}
          ${kv('镜像路径', p.path || a.image_path, true)}
          ${kv('命令行', p.cmdline || a.cmdline, true)}
          ${kv('运行账号', p.user || a.proc_user, true)}
          ${kv('会话 ID', String(p.session_id ?? '-'), true)}
          ${kv('高权限', p.elevated ? '是（管理员完整性）' : '否')}
          ${kv('SHA256', p.hash_sha256 || a.hash_sha256 || '-', true)}
          ${kv('文件大小', fmtBytes(p.file_size))}
          ${kv('数字签名', p.signature_ok ? '校验通过' : p.signed ? '存在但不通过' : '无签名')}
          ${kv('签名主体', p.signer || a.signer || '-')}
          ${kv('启动时间', fmtTime(p.start_time))}
        </dl>
      </div>
    </section>

    ${a.cmdline || p.cmdline ? `<section class="block"><h3>命令行原文</h3>
      <pre class="code">${esc(p.cmdline || a.cmdline)}</pre></section>` : ''}

    ${aiPanelHTML(a)}

    <section class="block">
      <h3>命中信号（${(ev.signals || []).length}）</h3>
      ${signals}
    </section>

    <section class="block">
      <h3>行为规则（${(ev.rule_hits || []).length}）</h3>
      ${ruleHits}
    </section>

    <section class="block">
      <h3>进程血缘链</h3>
      <div class="card" style="padding:14px"><div class="tree">${ancestry}</div></div>
    </section>

    <section class="block">
      <h3>同主机事件时间线</h3>
      <div class="card" style="padding:16px 14px 4px">
        <div id="hostTimeline"><div class="empty small"><span class="spin"></span> 加载中…</div></div>
      </div>
    </section>

    ${net ? `<section class="block"><h3>网络连接</h3>
      <div class="card" style="padding:6px 12px 10px"><table>
        <thead><tr><th>协议</th><th>本地</th><th>远端</th><th>状态</th></tr></thead>
        <tbody>${net}</tbody></table></div></section>` : ''}

    ${mods ? `<section class="block"><h3>加载模块（最多 30 条）</h3>
      <div class="card" style="padding:6px 12px 10px"><table>
        <thead><tr><th style="width:200px">模块</th><th>路径</th></tr></thead>
        <tbody>${mods}</tbody></table></div></section>` : ''}

    <section class="block">
      <h3>处置记录</h3>
      <div class="card" style="padding:14px"><dl class="kv">
        ${kv('当前状态', STATUS_LABEL[a.status] || a.status)}
        ${kv('处置人', a.handled_by)}
        ${kv('处置时间', fmtTime(a.handled_at))}
        ${kv('备注', a.note)}
      </dl></div>
    </section>
  `;

  // 底栏：处置操作 + 加白
  const canWrite = state.user.role === 'admin' || state.user.role === 'analyst';
  const actions = [
    ['acknowledged', '标记已确认', ''],
    ['resolved', '标记已解决', 'primary'],
    ['false_positive', '标记误报', ''],
    ['open', '重新打开', 'ghost'],
  ];
  bindAITriage(a);
  loadHostTimeline(a);

  $('#drawerFoot').innerHTML = canWrite
    ? `${actions.map(([st, label, cls]) =>
        `<button class="btn sm ${cls}" data-status="${st}">${label}</button>`).join('')}
       <div class="spacer" style="flex:1"></div>
       <button class="btn sm" id="addFalsePositiveWhite">加入白名单</button>`
    : '<span class="small muted">当前角色为只读，无法处置告警</span>';

  if (canWrite) {
    $$('#drawerFoot [data-status]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const note = (a.status === btn.dataset.status) ? '' : prompt('处置备注（可选）') || '';
        try {
          await api.post(`/api/v1/alerts/${encodeURIComponent(a.id)}/status`, { status: btn.dataset.status, note });
          toast('已更新处置状态');
          closeDrawer();
          if (state.route === 'alerts') loadAlertTable();
          if (state.route === 'overview') viewOverview();
        } catch (e) { toast(e.message, 'err'); }
      });
    });
    const wb = $('#addFalsePositiveWhite');
    if (wb) wb.addEventListener('click', () => quickAllowlist(a));
  }
}

async function quickAllowlist(a) {
  const value = a.hash_sha256;
  if (!value) return toast('该告警没有文件哈希，无法按哈希加白', 'warn');
  if (!confirm(`将文件哈希加入白名单？\n\n${value}\n\n加白后该文件在本机与服务端都不再告警，请确认这是可信程序。`)) return;
  try {
    await api.post('/api/v1/allowlist', {
      type: 'hash', value, note: `来自告警 ${a.id}（${a.process_name}）`,
    });
    toast('已加入白名单');
  } catch (e) { toast(e.message, 'err'); }
}

/* ------------------------------------------------------------------ 视图：主机 */
async function viewHosts() {
  const c = $('#content');
  c.innerHTML = '<div class="empty"><span class="spin"></span> 加载中…</div>';
  let res;
  try { res = await api.get('/api/v1/hosts'); } catch (e) { return renderError(e); }
  state.hosts = res.items || [];

  if (!state.hosts.length) {
    c.innerHTML = `<div class="card"><div class="empty">
      还没有终端注册。<br /><br />
      <span class="small">在目标机器上启动 <b>secagent.exe</b>，并配置正确的
      <code>HG_AGENT_SERVER_URL</code> 与 <code>HG_AGENT_ENROLL_TOKEN</code>。</span>
    </div></div>`;
    return;
  }

  c.innerHTML = `<div class="card" style="padding:14px 8px 8px"><table>
    <thead><tr>
      <th style="width:110px">状态</th><th>主机</th><th>系统</th><th>运行账号</th>
      <th style="width:90px">进程数</th><th style="width:100px">CPU</th><th style="width:90px">内存</th>
      <th style="width:80px">待处置</th><th style="width:110px">最后心跳</th>
    </tr></thead>
    <tbody>${state.hosts.map((h) => `
      <tr>
        <td>${badge(h.status, h.status === 'online' ? '在线' : '离线')}</td>
        <td><b>${esc(h.hostname)}</b><div class="small muted mono">${esc(h.id)}</div></td>
        <td class="small muted">${esc(h.os_version || '-')}<br />${esc(h.arch || '')} · v${esc(h.version || '-')}</td>
        <td class="mono small">${esc(h.username || '-')}</td>
        <td>${h.proc_count || 0}</td>
        <td>${(h.cpu_percent || 0).toFixed(1)}%</td>
        <td>${(h.mem_mb || 0).toFixed(0)} MB</td>
        <td>${h.open_alerts ? badge('critical', h.open_alerts) : '<span class="muted">0</span>'}</td>
        <td class="small muted" title="${esc(fmtTime(h.last_seen_at))}">${relTime(h.last_seen_at)}</td>
      </tr>`).join('')}
    </tbody></table></div>
    <p class="small muted" style="margin-top:12px">
      提示：终端默认每 ${30} 秒上报一次心跳，超过 3 分钟无心跳会被标记为离线。
    </p>`;
}

/* ------------------------------------------------------------------ 视图：规则 */
async function viewRules() {
  const c = $('#content');
  c.innerHTML = '<div class="empty"><span class="spin"></span> 加载中…</div>';
  let res;
  try { res = await api.get('/api/v1/rules'); } catch (e) { return renderError(e); }
  state.rules = res.items || [];
  const canWrite = state.user.role !== 'viewer';

  c.innerHTML = `
    <div class="toolbar">
      <span class="small muted">共 ${state.rules.length} 条规则 · 内置规则可禁用但不可删除</span>
      <div class="spacer"></div>
      ${canWrite ? '<button class="btn sm primary" id="newRule">新建规则</button>' : ''}
    </div>
    <div class="card" style="padding:14px 8px 8px"><table>
      <thead><tr>
        <th style="width:90px">规则 ID</th><th>名称</th><th style="width:78px">严重度</th>
        <th style="width:60px">分值</th><th style="width:140px">ATT&amp;CK</th>
        <th style="width:90px">来源</th><th style="width:70px">状态</th><th style="width:80px">操作</th>
      </tr></thead>
      <tbody>${state.rules.map((r) => `
        <tr>
          <td class="mono">${esc(r.id)}</td>
          <td><div style="font-weight:500">${esc(r.name)}</div>
              <div class="small muted" style="margin-top:3px;max-width:520px">${esc(r.description)}</div></td>
          <td>${sevBadge(r.severity)}</td>
          <td><b>${r.score}</b></td>
          <td class="small mono muted">${esc((r.mitre || []).join(', ') || '-')}</td>
          <td class="small muted">${r.builtin ? '内置' : '自定义'}</td>
          <td>${r.enabled ? badge('resolved', '启用') : badge('info', '禁用')}</td>
          <td>
            ${canWrite ? `<button class="btn sm ghost" data-toggle="${esc(r.id)}" data-enabled="${r.enabled ? '1' : '0'}">${r.enabled ? '禁用' : '启用'}</button>` : '-'}
          </td>
        </tr>`).join('')}
      </tbody></table></div>
    ${canWrite ? `
    <div class="card" id="ruleEditor" style="margin-top:14px;display:none">
      <h3 class="card-title">新建 / 更新规则</h3>
      <div class="grid grid-2">
        <label class="field"><span>规则 ID（留空自动生成）</span><input id="rId" style="width:100%" placeholder="HG-C-xxxx" /></label>
        <label class="field"><span>名称</span><input id="rName" style="width:100%" placeholder="例如：可疑的登录脚本执行" /></label>
      </div>
      <div class="grid grid-3">
        <label class="field"><span>严重度</span>
          <select id="rSeverity" style="width:100%">
            ${Object.entries(SEV_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}
          </select></label>
        <label class="field"><span>分值（1-100）</span><input id="rScore" type="number" value="30" min="1" max="100" style="width:100%" /></label>
        <label class="field"><span>ATT&amp;CK（逗号分隔）</span><input id="rMitre" style="width:100%" placeholder="T1059.001" /></label>
      </div>
      <label class="field"><span>规则定义（JSON：all / any / none）</span>
        <textarea id="rDef" rows="10" style="width:100%">{
  "all": [
    { "field": "process.name", "op": "in", "value": ["powershell.exe"] }
  ],
  "any": [
    { "field": "process.cmdline", "op": "icontains", "value": "invoke-" }
  ]
}</textarea></label>
      <div style="display:flex;gap:8px">
        <button class="btn primary" id="saveRule">保存并下发</button>
        <button class="btn ghost" id="cancelRule">取消</button>
      </div>
    </div>` : ''}
  `;

  if (!canWrite) return;

  $$('[data-toggle]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const enabled = btn.dataset.enabled === '1';
      try {
        await api.post(`/api/v1/rules/${encodeURIComponent(btn.dataset.toggle)}/toggle`, { enabled: !enabled });
        toast(enabled ? '已禁用该规则' : '已启用该规则');
        viewRules();
      } catch (e) { toast(e.message, 'err'); }
    });
  });

  const editor = $('#ruleEditor');
  $('#newRule').addEventListener('click', () => {
    editor.style.display = editor.style.display === 'none' ? 'block' : 'none';
  });
  $('#cancelRule').addEventListener('click', () => { editor.style.display = 'none'; });
  $('#saveRule').addEventListener('click', async () => {
    const def = $('#rDef').value.trim();
    try { JSON.parse(def); } catch (e) { return toast('规则定义不是合法 JSON', 'err'); }
    try {
      await api.post('/api/v1/rules', {
        id: $('#rId').value.trim(),
        name: $('#rName').value.trim(),
        description: '自定义规则',
        severity: $('#rSeverity').value,
        score: parseInt($('#rScore').value, 10) || 30,
        mitre: $('#rMitre').value.split(',').map((s) => s.trim()).filter(Boolean),
        enabled: true,
        definition: def,
      });
      toast('规则已保存，将在终端下次拉取时生效');
      viewRules();
    } catch (e) { toast(e.message, 'err'); }
  });
}

/* ------------------------------------------------------------------ 视图：白名单 */
async function viewAllowlist() {
  const c = $('#content');
  c.innerHTML = '<div class="empty"><span class="spin"></span> 加载中…</div>';
  let res;
  try { res = await api.get('/api/v1/allowlist'); } catch (e) { return renderError(e); }
  state.allowlist = res.items || [];
  const canWrite = state.user.role !== 'viewer';

  const TYPE_HINT = {
    hash: '文件 SHA256，64 位十六进制',
    path: '镜像完整路径（小写，支持包含匹配）',
    signer: '数字签名主体名称',
    pair: '父子进程对，如 winword.exe>powershell.exe',
    cmdline: '命令行包含的固定片段',
  };

  c.innerHTML = `
    <div class="card" style="margin-bottom:14px">
      <h3 class="card-title">降噪说明</h3>
      <p class="small muted" style="margin:0;line-height:1.8">
        白名单是五级降噪流水线的第一级：命中白名单的进程不会进入检测引擎，从源头消除噪声。
        加白务必谨慎——它会让该对象永久免检。误报处置完成后建议同步加白，形成闭环。<br />
        加白时会自动把 <b>已经触发过、且与之匹配的未处置告警</b> 标记为误报（加白回收），
        避免历史告警继续堆在队列里。
      </p>
    </div>

    ${canWrite ? `<div class="card" style="margin-bottom:14px">
      <h3 class="card-title">新增白名单</h3>
      <div class="grid" style="grid-template-columns:150px 2fr 1fr auto;align-items:end;gap:10px">
        <label class="field" style="margin:0"><span>类型</span>
          <select id="aType" style="width:100%">
            ${Object.keys(TYPE_HINT).map((k) => `<option value="${k}">${k}</option>`).join('')}
          </select></label>
        <label class="field" style="margin:0"><span>取值</span><input id="aValue" style="width:100%" placeholder="按类型填写" /></label>
        <label class="field" style="margin:0"><span>备注</span><input id="aNote" style="width:100%" placeholder="为什么可信" /></label>
        <button class="btn primary" id="aAdd" style="height:36px">添加</button>
      </div>
      <p class="small muted" id="aHint" style="margin:10px 0 0">${esc(TYPE_HINT.hash)}</p>
    </div>` : ''}

    <div class="card" style="padding:14px 8px 8px">
      ${state.allowlist.length ? `<table>
        <thead><tr><th style="width:90px">类型</th><th>取值</th><th style="width:200px">备注</th>
        <th style="width:90px">创建人</th><th style="width:70px">命中</th><th style="width:100px">时间</th><th style="width:60px"></th></tr></thead>
        <tbody>${state.allowlist.map((e) => `
          <tr>
            <td>${badge('open', e.type)}</td>
            <td class="mono small" style="word-break:break-all">${esc(e.value)}</td>
            <td class="small muted">${esc(e.note || '-')}</td>
            <td class="small">${esc(e.created_by || '-')}</td>
            <td>${e.hits || 0}</td>
            <td class="small muted">${relTime(e.created_at)}</td>
            <td>${canWrite ? `<button class="btn sm danger" data-del="${esc(e.id)}">删除</button>` : ''}</td>
          </tr>`).join('')}
        </tbody></table>` : '<div class="empty">白名单为空</div>'}
    </div>`;

  if (!canWrite) return;

  const typeSel = $('#aType');
  typeSel.addEventListener('change', () => { $('#aHint').textContent = TYPE_HINT[typeSel.value] || ''; });
  $('#aAdd').addEventListener('click', async () => {
    const type = typeSel.value;
    const value = $('#aValue').value.trim();
    if (!value) return toast('取值不能为空', 'err');
    try {
      await api.post('/api/v1/allowlist', { type, value, note: $('#aNote').value.trim() });
      toast('已添加白名单');
      viewAllowlist();
    } catch (e) { toast(e.message, 'err'); }
  });
  $$('[data-del]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('确认删除该白名单项？删除后相关检测会重新生效。')) return;
      try { await api.del('/api/v1/allowlist/' + encodeURIComponent(btn.dataset.del)); toast('已删除'); viewAllowlist(); }
      catch (e) { toast(e.message, 'err'); }
    });
  });
}

/* ------------------------------------------------------------------ 视图：审计 */
async function viewAudit() {
  const c = $('#content');
  c.innerHTML = '<div class="empty"><span class="spin"></span> 加载中…</div>';
  let res;
  try { res = await api.get('/api/v1/audit?limit=300'); } catch (e) { return renderError(e); }
  state.audit = res.items || [];

  c.innerHTML = `<div class="card" style="padding:14px 8px 8px">
    ${state.audit.length ? `<table>
      <thead><tr><th style="width:130px">时间</th><th style="width:110px">操作人</th>
      <th style="width:150px">动作</th><th style="width:180px">目标</th><th>详情</th><th style="width:120px">来源 IP</th></tr></thead>
      <tbody>${state.audit.map((l) => `
        <tr>
          <td class="small muted">${fmtTime(l.created_at)}</td>
          <td class="small">${esc(l.username || '-')}</td>
          <td class="mono small">${esc(l.action)}</td>
          <td class="mono small muted" style="word-break:break-all">${esc(l.target || '-')}</td>
          <td class="small">${esc(l.detail || '-')}</td>
          <td class="mono small muted">${esc(l.ip || '-')}</td>
        </tr>`).join('')}
      </tbody></table>` : '<div class="empty">暂无审计记录</div>'}
  </div>`;
}

/* ------------------------------------------------------------------ 视图：账号 */
async function viewUsers() {
  const c = $('#content');
  c.innerHTML = '<div class="empty"><span class="spin"></span> 加载中…</div>';
  let res;
  try { res = await api.get('/api/v1/users'); } catch (e) { return renderError(e); }
  state.users = res.items || [];

  c.innerHTML = `
    <div class="card" style="margin-bottom:14px">
      <h3 class="card-title">新建账号</h3>
      <div class="grid" style="grid-template-columns:1fr 1fr 1fr 150px auto;align-items:end;gap:10px">
        <label class="field" style="margin:0"><span>用户名</span><input id="uName" style="width:100%" /></label>
        <label class="field" style="margin:0"><span>显示名</span><input id="uDisplay" style="width:100%" /></label>
        <label class="field" style="margin:0"><span>初始密码（≥8 位）</span><input id="uPass" type="password" style="width:100%" /></label>
        <label class="field" style="margin:0"><span>角色</span>
          <select id="uRole" style="width:100%">
            <option value="viewer">只读</option>
            <option value="analyst">分析师</option>
            <option value="admin">管理员</option>
          </select></label>
        <button class="btn primary" id="uAdd" style="height:36px">创建</button>
      </div>
    </div>
    <div class="card" style="padding:14px 8px 8px"><table>
      <thead><tr><th style="width:150px">用户名</th><th>显示名</th><th style="width:100px">角色</th>
      <th style="width:90px">状态</th><th style="width:160px">最近登录</th><th style="width:160px">创建时间</th></tr></thead>
      <tbody>${state.users.map((u) => `
        <tr>
          <td class="mono">${esc(u.username)}</td>
          <td>${esc(u.display_name || '-')}</td>
          <td>${badge('open', u.role)}</td>
          <td>${u.disabled ? badge('offline', '禁用') : badge('online', '正常')}</td>
          <td class="small muted">${u.last_login_at ? fmtTime(u.last_login_at) : '从未登录'}</td>
          <td class="small muted">${fmtTime(u.created_at)}</td>
        </tr>`).join('')}
      </tbody></table></div>`;

  $('#uAdd').addEventListener('click', async () => {
    try {
      await api.post('/api/v1/users', {
        username: $('#uName').value.trim(),
        display_name: $('#uDisplay').value.trim(),
        password: $('#uPass').value,
        role: $('#uRole').value,
      });
      toast('账号已创建');
      viewUsers();
    } catch (e) { toast(e.message, 'err'); }
  });
}

/* ------------------------------------------------------------------ 实时通道 */
async function connectStream() {
  if (state.sse) { state.sse.close(); state.sse = null; }
  let ticket;
  try {
    const res = await api.post('/api/v1/stream/ticket', {});
    ticket = res.ticket;
  } catch (_) {
    setLive(false);
    return;
  }
  const es = new EventSource('/api/v1/stream/alerts?ticket=' + encodeURIComponent(ticket));
  state.sse = es;

  es.addEventListener('ready', () => setLive(true));
  es.addEventListener('alert', (ev) => {
    try {
      const a = JSON.parse(ev.data);
      state.unread++;
      updateUnreadBadge();
      const nav = document.getElementById('navAlerts');
      if (nav) { nav.style.display = 'inline-block'; nav.textContent = state.unread > 99 ? '99+' : state.unread; }
      if (state.route === 'overview') viewOverview();
      else if (state.route === 'alerts' && state.alerts.page === 1) loadAlertTable();
      if (a.severity === 'critical' || a.severity === 'high') {
        toast(`新告警：${a.hostname} · ${a.title}`, 'warn');
      }
    } catch (_) { /* 忽略坏帧 */ }
  });
  es.onerror = () => {
    setLive(false);
    // EventSource 自带重连；票是一次性的，因此这里主动重建连接
    es.close();
    state.sse = null;
    setTimeout(() => { if (state.user) connectStream(); }, 5000);
  };
}

function setLive(on) {
  state.live = on;
  const el = $('#liveIndicator');
  if (!el) return;
  el.classList.toggle('off', !on);
  $('#liveText').textContent = on ? '实时通道已连接' : '实时通道重连中…';
}

function updateUnreadBadge() {
  const nav = document.getElementById('navAlerts');
  if (!nav) return;
  if (state.unread > 0) {
    nav.style.display = 'inline-block';
    nav.textContent = state.unread > 99 ? '99+' : state.unread;
  } else {
    nav.style.display = 'none';
  }
}

/* ------------------------------------------------------------------ 框架 */
function renderError(e) {
  $('#content').innerHTML = `<div class="card"><div class="empty">
    ${esc(e.message)}${e.requestId ? `<div class="small muted" style="margin-top:8px">请求 ID：${esc(e.requestId)}</div>` : ''}
    <div style="margin-top:14px"><button class="btn sm" onclick="location.reload()">重新加载</button></div>
  </div></div>`;
}

async function renderRoute() {
  const hash = location.hash.replace(/^#\/?/, '') || 'overview';
  const route = ROUTES.find((r) => r.key === hash) ? hash : 'overview';
  if (ROUTES.find((r) => r.key === route).roles && !ROUTES.find((r) => r.key === route).roles.includes(state.user.role)) {
    location.hash = '#/overview';
    return;
  }
  state.route = route;
  setActiveNav();
  if (route === 'alerts') state.unread = 0;
  updateUnreadBadge();

  switch (route) {
    case 'overview': return viewOverview();
    case 'alerts': return viewAlerts();
    case 'incidents': return viewIncidents();
    case 'hosts': return viewHosts();
    case 'rules': return viewRules();
    case 'allowlist': return viewAllowlist();
    case 'audit': return viewAudit();
    case 'users': return viewUsers();
    default: return viewOverview();
  }
}

function showLogin(msg) {
  $('#app').style.display = 'none';
  $('#loginWrap').style.display = 'grid';
  const err = $('#loginErr');
  if (msg) { err.textContent = msg; err.classList.add('show'); }
  else { err.classList.remove('show'); }
  if (state.sse) { state.sse.close(); state.sse = null; }
}

function showApp() {
  $('#loginWrap').style.display = 'none';
  $('#app').style.display = 'flex';
  $('#userName').textContent = state.user.username;
  const roleText = { admin: '管理员', analyst: '分析师', viewer: '只读' }[state.user.role] || state.user.role;
  $('#userRole').textContent = roleText;
  $('#avatar').textContent = (state.user.username || 'U').slice(0, 1).toUpperCase();
  buildNav();
  renderRoute();
  connectStream();
}

async function boot() {
  // 恢复上次的密度选择：值班习惯应当跨会话保留
  if (localStorage.getItem('hg_dense') === '1') document.body.classList.add('dense');
  installKeyboard();

  // 登录表单
  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#loginBtn');
    btn.disabled = true;
    btn.textContent = '登录中…';
    try {
      const res = await api.request('/api/v1/auth/login', {
        method: 'POST',
        body: { username: $('#loginUser').value.trim(), password: $('#loginPass').value },
      });
      api.token = res.access_token;
      api.tokenExp = Date.parse(res.expires_at) || 0;
      state.user = res.user;
      $('#loginPass').value = '';
      showApp();
      toast('登录成功');
    } catch (err) {
      const el = $('#loginErr');
      el.textContent = err.message;
      el.classList.add('show');
    } finally {
      btn.disabled = false;
      btn.textContent = '登录';
    }
  });

  $('#logoutBtn').addEventListener('click', async () => {
    try { await api.request('/api/v1/auth/logout', { method: 'POST', body: {} }); } catch (_) {}
    api.token = null;
    state.user = null;
    showLogin('已退出登录');
  });

  $('#refreshBtn').addEventListener('click', () => renderRoute());
  $('#drawerClose').addEventListener('click', closeDrawer);
  $('#drawerMask').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
  window.addEventListener('hashchange', () => { if (state.user) renderRoute(); });

  // 尝试用 HttpOnly Cookie 恢复会话（刷新页面后无需重新登录）
  try {
    const ok = await api.tryRefresh();
    if (ok) {
      const me = await api.get('/api/v1/me');
      state.user = { id: me.id, username: me.username, role: me.role, display_name: me.username };
      showApp();
      return;
    }
  } catch (_) { /* 落到登录页 */ }
  showLogin();
}

document.addEventListener('DOMContentLoaded', boot);

/* ------------------------------------------------------------------ AI 研判 */

let AI_STATS = null;

function aiPanelHTML(a) {
  return `
  <section class="block">
    <h3 style="display:flex;align-items:center;gap:10px">
      AI 研判
      <span id="aiEngineBadge" class="badge info" style="font-weight:400">…</span>
      <button class="btn sm" id="aiTriageBtn" style="margin-left:auto">开始分析</button>
    </h3>
    <div class="card" style="padding:14px">
      <div id="aiBody" class="small muted">
        结合该告警的完整证据链做判断：给出结论、置信度、逐条可核对的理由，以及处置建议。
        <br />所有结论都会标注所依据的证据编号，可以逐条回到下方"命中信号"核对。
      </div>
    </div>
  </section>`;
}

async function loadAIStats() {
  try { AI_STATS = await api.get('/api/v1/ai/stats'); } catch (_) { AI_STATS = null; }
  const el = $('#aiEngineBadge');
  if (!el || !AI_STATS) return;
  const st = AI_STATS.stats || {};
  el.textContent = AI_STATS.enabled
    ? `模型 ${st.model || ''}`
    : '确定性引擎';
  el.className = 'badge ' + (AI_STATS.enabled ? 'ok' : 'info');
  el.title = AI_STATS.enabled
    ? `已接入大模型；本小时 token 用量 ${st.budget_used || 0}/${st.budget_cap || 0}`
    : '未配置外部模型，使用内置确定性分析（结论同样带证据引用）';
}

function bindAITriage(a) {
  loadAIStats();
  const btn = $('#aiTriageBtn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = '分析中…';
    const body = $('#aiBody');
    body.innerHTML = '<span class="spin"></span> 正在分析证据链…';
    try {
      const r = await api.post(`/api/v1/alerts/${encodeURIComponent(a.id)}/triage`, {});
      body.innerHTML = renderTriage(r);
    } catch (e) {
      body.innerHTML = `<span style="color:var(--crit)">分析失败：${esc(e.message)}</span>`;
    } finally {
      btn.disabled = false;
      btn.textContent = '重新分析';
    }
  });
}

const TRIAGE_VERDICT = {
  malicious: ['恶意', 'crit'],
  suspicious: ['可疑', 'warn'],
  benign: ['无害', 'ok'],
  inconclusive: ['证据不足', 'info'],
};

function renderTriage(r) {
  const [vLabel, vCls] = TRIAGE_VERDICT[r.verdict] || ['未知', 'info'];
  const conf = Math.round((r.confidence || 0) * 100);

  // 引擎与质量标注：让分析师一眼看出"这份结论是怎么来的、可不可信"
  const meta = [];
  meta.push(`<span class="badge ${r.engine === 'llm' ? 'ok' : 'info'}">${r.engine === 'llm' ? '大模型' : '确定性引擎'}</span>`);
  if (r.model) meta.push(`<span class="badge info">${esc(r.model)}</span>`);
  meta.push(`<span class="badge ${r.grounded ? 'ok' : 'warn'}">${r.grounded ? '结论全部可溯源' : `${r.uncited} 条结论无引用`}</span>`);
  if (r.degraded) meta.push(`<span class="badge warn" title="${esc(r.degraded_reason || '')}">已降级</span>`);
  if (r.untrusted_ignored > 0) {
    meta.push(`<span class="badge crit" title="命令行/路径中包含试图操纵分析模型的指令，已隔离">拦截 ${r.untrusted_ignored} 处注入</span>`);
  }
  meta.push(`<span class="muted small">${r.latency_ms || 0} ms</span>`);

  const reasons = (r.reasoning || []).map((x) => {
    const cites = (x.citations || []).map((c) => `<span class="badge info" style="font-family:var(--mono)">${esc(c)}</span>`).join(' ');
    const isGuard = (x.text || '').startsWith('【护栏】');
    return `<div class="signal" style="${isGuard ? 'background:rgba(239,68,68,.08);border-left:3px solid var(--crit)' : ''}">
      <span style="flex:1;min-width:0">${esc(x.text)}</span>
      <span style="white-space:nowrap">${cites || '<span class="badge warn">无引用</span>'}</span>
    </div>`;
  }).join('') || '<div class="empty small">无</div>';

  const actions = (r.actions || []).map((x) => `
    <div class="signal">
      <span class="layer">${esc(x.type)}</span>
      <span style="flex:1;min-width:0">
        <b>${esc(x.target || '')}</b>
        <div class="small muted" style="margin-top:3px">${esc(x.detail || '')}</div>
      </span>
      ${x.requires_approval ? '<span class="badge warn">需人工确认</span>' : '<span class="badge info">可自助</span>'}
    </div>`).join('') || '<div class="empty small">无建议动作</div>';

  const chain = (r.attack_chain || []).length
    ? `<div style="margin-top:12px"><div class="small muted" style="margin-bottom:6px">推测攻击链</div>
       <div class="tree">${r.attack_chain.map((c, i) => `<div>${i + 1}. ${esc(c)}</div>`).join('')}</div></div>`
    : '';

  return `
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <span class="badge ${vCls}" style="font-size:14px;padding:4px 12px">${vLabel}</span>
      <span class="small muted">置信度 <b style="color:var(--text)">${conf}%</b></span>
      ${meta.join(' ')}
    </div>
    ${r.narrative ? `<div style="margin-bottom:14px;line-height:1.8">${esc(r.narrative)}</div>` : ''}
    <div class="small muted" style="margin:10px 0 6px">判断依据（括号内为引用的证据编号）</div>
    ${reasons}
    <div class="small muted" style="margin:14px 0 6px">建议处置</div>
    ${actions}
    ${chain}
  `;
}

/* ------------------------------------------------------------------ 自然语言检索 */

function bindAIHunt() {
  const btn = $('#aiHuntBtn'), input = $('#aiHunt'), clear = $('#aiHuntClear');
  if (!btn || !input) return;

  // 回车即检索
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') runAIHunt(); });
  btn.addEventListener('click', runAIHunt);
  if (clear) clear.addEventListener('click', () => {
    $('#aiHuntResult').innerHTML = '';
    clear.style.display = 'none';
    loadAlertTable();
  });
}

const FIELD_LABEL = {
  process_name: '进程名', image_path: '路径', cmdline: '命令行',
  hash_sha256: 'SHA256', verdict: '结论', severity: '严重度',
  score: '分值', signed: '签名', proc_user: '账号',
  hostname: '主机', rule_ids: '规则', status: '状态',
};

async function runAIHunt() {
  const input = $('#aiHunt');
  const q = (input.value || '').trim();
  if (!q) return;

  const box = $('#aiHuntResult');
  const btn = $('#aiHuntBtn');
  btn.disabled = true; btn.textContent = '解析中…';
  box.innerHTML = '<div class="card" style="padding:14px"><span class="spin"></span> 正在理解查询…</div>';

  let r;
  try { r = await api.post('/api/v1/ai/hunt', { query: q }); }
  catch (e) {
    box.innerHTML = `<div class="card" style="padding:14px;color:var(--crit)">${esc(e.message)}</div>`;
    btn.disabled = false; btn.textContent = 'AI 检索';
    return;
  } finally {
    btn.disabled = false; btn.textContent = 'AI 检索';
  }

  const query = r.query || {};
  const conds = (query.filters || []).map((f) =>
    `<span class="badge info">${esc(FIELD_LABEL[f.field] || f.field)} ${esc(f.op)} ${esc(f.value || (f.values || []).join(','))}</span>`
  ).join(' ') || '<span class="muted small">无条件（仅时间窗口）</span>';

  const rows = (r.alerts || []).map((a) => `
    <tr class="clickable" data-hunt-id="${esc(a.id)}">
      <td>${sevBadge(a.severity)}</td>
      <td><div style="font-weight:500">${esc(a.title)}</div></td>
      <td>${esc(a.hostname)}</td>
      <td class="mono">${esc(a.process_name)}</td>
      <td><b style="color:${a.score >= 70 ? 'var(--crit)' : a.score >= 40 ? 'var(--warn)' : 'var(--text-dim)'}">${a.score}</b></td>
      <td>${statusBadge(a.status)}</td>
      <td class="small muted">${relTime(a.created_at)}</td>
    </tr>`).join('') || '<tr><td colspan="7" class="empty">没有匹配的告警</td></tr>';

  box.innerHTML = `
    <div class="card" style="padding:14px;margin-bottom:12px">
      <div class="small muted" style="margin-bottom:8px">引擎理解的查询意图</div>
      <div style="margin-bottom:10px">${esc(query.explain || q)}</div>
      <div class="small muted" style="margin-bottom:6px">解析出的条件</div>
      <div style="margin-bottom:10px;display:flex;flex-wrap:wrap;gap:6px">${conds}</div>
      <div class="small muted">
        时间窗口 ${Math.round((query.since_sec || 86400) / 3600)} 小时 ·
        命中 <b style="color:var(--text)">${r.total || 0}</b> 条 · 显示前 ${(r.alerts || []).length} 条
      </div>
    </div>
    <div class="card" style="padding:6px 12px 10px">
      <table>
        <thead><tr>
          <th style="width:64px">严重度</th><th>告警</th><th style="width:150px">主机</th>
          <th style="width:180px">进程</th><th style="width:64px">分值</th>
          <th style="width:88px">状态</th><th style="width:96px">时间</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;

  const clear = $('#aiHuntClear');
  if (clear) clear.style.display = '';
  $$('#aiHuntResult tr[data-hunt-id]').forEach((tr) => {
    tr.addEventListener('click', () => openAlert(tr.dataset.huntId));
  });
}

/* ==================================================================
   运营效率层：批量处置 / 键盘导航 / 保存视图 / 同主机时间线
   ------------------------------------------------------------------
   设计依据（业界控制台的共同做法）：
   - 分析师的时间瓶颈不是"看"，而是"重复操作"。批量与快捷键直接压缩这部分；
   - 队列要能被保存和恢复：从调查返回时不能丢失筛选条件与位置；
   - 从告警到动作的路径必须短：误报加白应当一次点击完成，并自动回收同指纹历史告警。
   ================================================================== */

/* ---------------- 批量操作条 ---------------- */
function syncBulkbar() {
  let bar = document.getElementById('bulkbar');
  const n = state.alerts.selected.size;
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'bulkbar';
    bar.className = 'bulkbar';
    document.body.appendChild(bar);
  }
  if (n === 0) { bar.classList.remove('show'); return; }

  bar.innerHTML = `
    <span class="count">已选 ${n} 条</span>
    <button class="btn sm" data-bulk="resolved">标记已处理</button>
    <button class="btn sm" data-bulk="false_positive">标记误报</button>
    <button class="btn sm ghost" data-bulk="acknowledged">确认</button>
    <button class="btn sm ghost" id="bulkClear">取消选择 <span class="kbd">Esc</span></button>`;

  bar.querySelectorAll('[data-bulk]').forEach((b) => {
    b.addEventListener('click', () => bulkSetStatus(b.dataset.bulk));
  });
  const c = bar.querySelector('#bulkClear');
  if (c) c.addEventListener('click', () => { clearSelection(); });
  bar.classList.add('show');
}

function clearSelection() {
  state.alerts.selected.clear();
  state.alerts.focus = -1;
  $$('#alertTable .rowSel').forEach((cb) => { cb.checked = false; });
  $$('#alertTable tr[data-id]').forEach((tr) => tr.classList.remove('selected', 'focused'));
  const selAll = $('#selAll');
  if (selAll) selAll.checked = false;
  syncBulkbar();
}

function toggleSelectAll(checked) {
  const items = state.alerts.items || [];
  if (checked) items.forEach((a) => state.alerts.selected.add(a.id));
  else state.alerts.selected.clear();
  $$('#alertTable .rowSel').forEach((cb) => { cb.checked = checked; });
  $$('#alertTable tr[data-id]').forEach((tr) => tr.classList.toggle('selected', checked));
  syncBulkbar();
}

// bulkSetStatus 批量处置。
//
// 逐条调用而不是新增批量接口：告警数量级很小（一页 20 条），
// 新增一个批量端点会引入"部分成功"的状态处理，收益不抵复杂度。
// 这里串行执行，失败时明确告知哪几条没成功。
async function bulkSetStatus(status) {
  const ids = Array.from(state.alerts.selected);
  if (!ids.length) return;
  const label = STATUS_LABEL[status] || status;
  if (!confirm(`将 ${ids.length} 条告警标记为「${label}」？`)) return;

  let updated, failed;
  try {
    const r = await api.post('/api/v1/alerts/bulk-status', { ids, status, note: '批量处置' });
    updated = (r && r.updated) || [];
    failed = (r && r.failed) || [];
  } catch (e) {
    toast(`批量处置失败：${e.message}`, 'err');
    return;
  }
  toast(failed.length ? `完成 ${updated.length} 条，失败 ${failed.length} 条` : `已更新 ${updated.length} 条`, failed.length ? 'err' : 'ok');
  clearSelection();
  loadAlertTable();
}

/* ---------------- 键盘导航 ----------------
   值机场景下鼠标是瓶颈：一次判断 + 一次点击 = 两次手部位移。
   这里只做最高频的几个动作，不做全键盘化（那会变成需要记忆的负担）。 */
function isTypingTarget(el) {
  if (!el) return false;
  const tag = el.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
}

function installKeyboard() {
  document.addEventListener('keydown', (e) => {
    // ? 随时可看帮助
    if (e.key === '?' && !isTypingTarget(e.target)) { showShortcuts(); return; }

    if (e.key === 'Escape') {
      const drawer = $('#drawer');
      if (drawer && drawer.classList.contains('show')) { closeDrawer(); return; }
      if (state.alerts.selected.size) { clearSelection(); return; }
      return;
    }

    if (isTypingTarget(e.target)) return;
    if (state.route !== 'alerts') return;

    const items = state.alerts.items || [];
    if (!items.length) return;

    switch (e.key) {
      case 'j': moveFocus(1); e.preventDefault(); break;
      case 'k': moveFocus(-1); e.preventDefault(); break;
      case 'Enter': {
        const a = items[state.alerts.focus];
        if (a) { openAlert(a.id); e.preventDefault(); }
        break;
      }
      case 'x': {
        const a = items[state.alerts.focus];
        if (!a) break;
        if (state.alerts.selected.has(a.id)) state.alerts.selected.delete(a.id);
        else state.alerts.selected.add(a.id);
        redrawRowState();
        e.preventDefault();
        break;
      }
      case 'a':
        toggleSelectAll(state.alerts.selected.size !== items.length);
        e.preventDefault();
        break;
      case '/': {
        const q = $('#fQ');
        if (q) { q.focus(); q.select(); e.preventDefault(); }
        break;
      }
      case 'd':
        document.body.classList.toggle('dense');
        localStorage.setItem('hg_dense', document.body.classList.contains('dense') ? '1' : '0');
        toast(document.body.classList.contains('dense') ? '已切换为紧凑视图' : '已切换为标准视图');
        e.preventDefault();
        break;
    }
  });
}

function moveFocus(delta) {
  const items = state.alerts.items || [];
  if (!items.length) return;
  let i = state.alerts.focus + delta;
  if (i < 0) i = 0;
  if (i >= items.length) i = items.length - 1;
  state.alerts.focus = i;
  redrawRowState();
  const tr = document.querySelector(`#alertTable tr[data-idx="${i}"]`);
  if (tr) tr.scrollIntoView({ block: 'nearest' });
}

function redrawRowState() {
  const items = state.alerts.items || [];
  $$('#alertTable tr[data-id]').forEach((tr) => {
    const idx = Number(tr.dataset.idx);
    tr.classList.toggle('focused', idx === state.alerts.focus);
    tr.classList.toggle('selected', state.alerts.selected.has(tr.dataset.id));
  });
  $$('#alertTable .rowSel').forEach((cb) => {
    cb.checked = state.alerts.selected.has(cb.dataset.id);
  });
  void items;
  syncBulkbar();
}

function showShortcuts() {
  const rows = [
    ['j / k', '下一个 / 上一个告警'],
    ['Enter', '打开详情'],
    ['x', '选中 / 取消选中当前行'],
    ['a', '全选当前页'],
    ['Esc', '关闭详情 / 取消选择'],
    ['/', '聚焦搜索框'],
    ['d', '切换紧凑视图'],
    ['?', '显示本帮助'],
  ];
  const html = `<div style="max-width:420px;padding:22px;background:var(--surface-1);border:1px solid var(--line-strong);border-radius:var(--radius-lg);box-shadow:var(--shadow-3)">
    <div style="font-size:15px;font-weight:600;margin-bottom:14px">键盘快捷键</div>
    <table style="width:100%">${rows.map(([k, d]) =>
      `<tr><td style="padding:5px 0;width:96px"><span class="kbd">${k}</span></td>
        <td style="padding:5px 0;color:var(--text-dim)">${d}</td></tr>`).join('')}
    </table>
    <div style="margin-top:16px;text-align:right">
      <button class="btn sm" onclick="document.getElementById('kbdMask').remove()">关闭</button>
    </div>
  </div>`;
  const mask = document.createElement('div');
  mask.id = 'kbdMask';
  mask.style.cssText = 'position:fixed;inset:0;background:rgba(4,7,13,.7);display:flex;align-items:center;justify-content:center;z-index:200;backdrop-filter:blur(3px)';
  mask.innerHTML = html;
  mask.addEventListener('click', (e) => { if (e.target === mask) mask.remove(); });
  document.body.appendChild(mask);
}

/* ---------------- 保存视图 ----------------
   分析师通常只关心两三种固定视角（"待处理的高危"、"误报巡查"）。
   每次重进都要重新点一遍筛选，是每天重复几十次的浪费。 */
const VIEW_KEY = 'hg_saved_views';

function savedViews() {
  try { return JSON.parse(localStorage.getItem(VIEW_KEY) || '[]'); } catch (_) { return []; }
}

function saveCurrentView() {
  const f = state.alerts.filters;
  const name = prompt('为当前筛选条件命名：', '我的视图');
  if (!name) return;
  const views = savedViews().filter((v) => v.name !== name);
  views.push({ name, filters: { ...f }, pageSize: state.alerts.pageSize });
  localStorage.setItem(VIEW_KEY, JSON.stringify(views.slice(-8)));
  renderSavedViews();
  toast('视图已保存');
}

function applyView(name) {
  const v = savedViews().find((x) => x.name === name);
  if (!v) return;
  Object.assign(state.alerts.filters, { status: '', severity: '', verdict: '', q: '' }, v.filters);
  state.alerts.page = 1;
  state.alerts.selected.clear();
  viewAlerts();
}

function renderSavedViews() {
  const box = $('#savedViews');
  if (!box) return;
  const views = savedViews();
  box.innerHTML = views.length
    ? views.map((v) => `<button class="btn sm ghost" data-view="${esc(v.name)}">${esc(v.name)}</button>`).join('')
    : '';
  box.querySelectorAll('[data-view]').forEach((b) => {
    b.addEventListener('click', () => applyView(b.dataset.view));
  });
}

/* ---------------- 同主机时间线 ----------------
   单个告警脱离上下文时很难判断轻重；把它放回同一台机器的事件序列里，
   "这是一次孤立误报"还是"这是一串攻击的第 3 步"立刻就能看出来。 */
async function loadHostTimeline(a) {
  const box = $('#hostTimeline');
  if (!box) return;
  try {
    const r = await api.get('/api/v1/alerts?page_size=30&sort=oldest&q=' + encodeURIComponent(a.hostname));
    const items = (r.items || []).filter((x) => x.hostname === a.hostname).slice(-15);
    if (!items.length) {
      box.innerHTML = '<div class="empty small">该主机暂无其它告警</div>';
      return;
    }
    box.innerHTML = `<div class="timeline">${items.map((x) => `
      <div class="timeline-item sev-${esc(x.severity)}">
        <div class="t-time">${fmtTime(x.created_at)}</div>
        <div style="margin-top:2px">
          <b style="cursor:pointer" data-tl="${esc(x.id)}">${esc(x.title)}</b>
          ${x.id === a.id ? '<span class="badge info" style="margin-left:6px">当前</span>' : ''}
        </div>
        <div class="small muted" style="margin-top:2px">
          ${esc(x.process_name)} · ${x.score} 分 · ${esc(VERDICT_LABEL[x.verdict] || x.verdict)}
        </div>
      </div>`).join('')}</div>`;
    box.querySelectorAll('[data-tl]').forEach((el) => {
      el.addEventListener('click', () => openAlert(el.dataset.tl));
    });
  } catch (e) {
    box.innerHTML = `<div class="empty small">加载失败：${esc(e.message)}</div>`;
  }
}

/* ==================================================================
   v0.6：事件页 / 可排序表格 / CSV 导出 / 命令面板（Alpine）
   ================================================================== */

/* ---------------- 事件（攻击链聚类） ----------------
   单条告警是信号，连续的告警才是事件。服务端按
   "同主机 + 相邻告警间隔 ≤ 30 分钟"聚类，这里只负责呈现：
   事件卡片突出峰值严重度与 MITRE 组合，展开可直达每条告警。 */
const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

async function viewIncidents() {
  const c = $('#content');
  c.innerHTML = `<div class="card" style="padding:18px">${skeletonRows(5, 5)}</div>`;
  let r;
  try { r = await api.get('/api/v1/incidents?limit=50'); } catch (e) { return renderError(e); }
  const items = (r && r.items) || [];

  const head = `
    <div class="toolbar" style="margin-bottom:12px;align-items:center">
      <h2 style="margin:0;font-size:16px">事件</h2>
      <span class="muted small">未处置告警按「同主机 · 相邻间隔 ≤ 30 分钟」聚类 · 共 ${items.length} 个活跃事件</span>
      <div class="spacer"></div>
      <button class="btn sm" id="incRefresh">刷新</button>
    </div>`;

  if (!items.length) {
    c.innerHTML = head + `<div class="card"><div class="empty">当前没有未处置的告警聚合成事件——<br />这是好事，说明各终端都在安静运行。</div></div>`;
    const b = $('#incRefresh');
    if (b) b.addEventListener('click', viewIncidents);
    return;
  }

  c.innerHTML = head + items.map((it) => {
    const sevCls = it.peak_severity === 'critical' ? 'crit' : it.peak_severity === 'high' ? 'danger' : it.peak_severity === 'medium' ? 'warn' : 'ok';
    const dur = it.duration_sec > 0
      ? (it.duration_sec >= 3600 ? `${Math.round(it.duration_sec / 3600)} 小时` : `${Math.max(1, Math.round(it.duration_sec / 60))} 分钟`)
      : '<1 分钟';
    const alerts = it.alert_ids.map((id, i) =>
      `<button class="btn sm ghost" data-inc-alert="${esc(id)}">告警 ${i + 1}</button>`).join('');
    return `
    <div class="card incident" style="padding:16px;margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span class="badge ${sevCls}" style="font-size:13px;padding:4px 12px">${esc(it.peak_severity || 'low')}</span>
        <div style="flex:1;min-width:200px">
          <div style="font-weight:600">${esc(it.hostname)}
            <span class="badge info" style="margin-left:8px">${it.alert_count} 条告警</span>
            ${it.open_count < it.alert_count ? `<span class="badge" style="background:var(--surface-2);color:var(--text-dim)">已处置 ${it.alert_count - it.open_count}</span>` : ''}
          </div>
          <div class="small muted" style="margin-top:4px">
            ${fmtTime(it.started_at)} → ${fmtTime(it.last_at)} · 持续 ${dur} · 峰值分 <b class="mono">${it.max_score}</b>
          </div>
        </div>
        <button class="btn sm primary" data-inc-open="${esc(it.alert_ids[it.alert_ids.length - 1])}">查看最新告警</button>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:12px">
        ${(it.processes || []).slice(0, 6).map((p) => `<span class="badge" style="background:var(--surface-2);color:var(--text-dim)" title="进程">${esc(p)}</span>`).join('')}
        ${(it.mitre || []).slice(0, 6).map((m) => `<span class="badge info">${esc(m)}</span>`).join('')}
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;border-top:1px solid var(--line-soft);padding-top:10px">
        ${alerts}
      </div>
    </div>`;
  }).join('');

  $$('#content [data-inc-alert]').forEach((b) => b.addEventListener('click', () => openAlert(b.dataset.incAlert)));
  const rf = $('#incRefresh');
  if (rf) rf.addEventListener('click', viewIncidents);
}

/* ---------------- 可排序表格列 ----------------
   点击「分值/严重度/时间」表头即切换排序。服务端本就支持
   score/severity/oldest 排序，这里只是把能力暴露出来。 */
function bindSortable() {
  const map = { '时间': 'oldest', '分值': 'score', '严重度': 'severity' };
  $$('#alertTable thead th').forEach((th) => {
    const label = th.textContent.trim();
    const key = map[label];
    if (!key) return;
    th.style.cursor = 'pointer';
    th.title = `点击按${label}排序`;
    if (state.alerts.filters.sort === key || (key === 'oldest' && !state.alerts.filters.sort)) {
      th.innerHTML = `${label} <span style="opacity:.7">${key === 'oldest' && state.alerts.filters.sort === 'oldest' ? '↑' : '↓'}</span>`;
    }
    th.addEventListener('click', () => {
      state.alerts.filters.sort = (state.alerts.filters.sort === key) ? '' : key;
      state.alerts.page = 1;
      clearSelection();
      loadAlertTable();
    });
  });
}

/* ---------------- CSV 导出（带审计） ---------------- */
function exportCSV() {
  const f = state.alerts.filters;
  const qs = new URLSearchParams();
  if (f.status) qs.set('status', f.status);
  if (f.severity) qs.set('severity', f.severity);
  if (f.verdict) qs.set('verdict', f.verdict);
  if (f.q) qs.set('q', f.q);
  // 用 fetch+blob 而不是 location 跳转：复用与 api() 相同的 Bearer 认证
  // （access token 只在内存，不会出现在下载 URL 里）
  fetch('/api/v1/alerts/export?' + qs.toString(), {
    headers: api.token ? { Authorization: `Bearer ${api.token}` } : {},
    credentials: 'same-origin',
  })
    .then(async (res) => {
      if (!res.ok) throw new Error(`导出失败 (${res.status})`);
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `hostguard-alerts-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast('CSV 已导出');
    })
    .catch((e) => toast(e.message, 'err'));
}

/* ---------------- 命令面板（Alpine 组件） ----------------
   Alpine 经 defer 先于本文件执行 alpine:init？不——defer 脚本在
   DOM 解析完后按序执行，而本文件是 body 末尾的普通脚本，先于 defer。
   因此这里监听 alpine:init 注册组件，保证时序正确。 */
document.addEventListener('alpine:init', () => {
  window.Alpine.data('cmdk', () => ({
    open: false,
    q: '',
    sel: 0,
    init() {
      // Ctrl/Cmd+K 全局唤起；在输入框中也响应
      document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
          e.preventDefault();
          this.open = !this.open;
          if (this.open) { this.q = ''; this.sel = 0; }
        }
      });
    },
    items() {
      const goto = (key, label, icon) => ({ id: 'go-' + key, label: '前往：' + label, icon, hint: '导航', run: () => { location.hash = '#/' + key; } });
      const base = [
        goto('overview', '概览', '▤'),
        goto('alerts', '告警中心', '⚠'),
        goto('incidents', '事件', '⛓'),
        goto('hosts', '主机终端', '◫'),
        goto('rules', '检测规则', '⌗'),
        goto('allowlist', '白名单', '✓'),
        goto('audit', '审计日志', '≡'),
        { id: 'act-open', label: '告警：只看待处置', icon: '◐', hint: '筛选', run: () => { navigate('alerts'); state.alerts.filters.status = 'open'; state.alerts.page = 1; loadAlertTable(); } },
        { id: 'act-crit', label: '告警：严重且未处置', icon: '◆', hint: '筛选', run: () => { navigate('alerts'); state.alerts.filters.status = 'open'; state.alerts.filters.severity = 'critical'; state.alerts.page = 1; loadAlertTable(); } },
        { id: 'act-export', label: '导出当前告警筛选为 CSV', icon: '⇩', hint: '导出', run: () => exportCSV() },
        { id: 'act-dense', label: '切换紧凑视图', icon: '≡', hint: '显示', run: () => { document.body.classList.toggle('dense'); } },
        { id: 'act-keys', label: '键盘快捷键帮助', icon: '?', hint: '帮助', run: () => showShortcuts() },
      ];
      const q = this.q.trim().toLowerCase();
      if (!q) return base;
      return base.filter((x) => x.label.toLowerCase().includes(q));
    },
    get filtered() { return this.items(); },
    move(d) {
      const n = this.filtered.length;
      if (!n) return;
      this.sel = (this.sel + d + n) % n;
    },
    pick(item) { this.open = false; item.run(); },
    run() { const it = this.filtered[this.sel]; if (it) this.pick(it); },
  }));
});
