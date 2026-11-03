/* Z-EDR 本机防护 · 桌面端应用
   ------------------------------------------------------------
   设计目标：平时绝对安静，出事 3 秒看懂。
   数据全部来自 127.0.0.1 的本地接口；不引 CDN、不引框架，
   保持单二进制内嵌、零运行时依赖。 */
'use strict';

/* ------------------------------------------------------------ 基础 */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));
const fmt = (n) => {
  const v = Number(n) || 0;
  return v.toLocaleString('zh-CN');
};

const TOKEN_KEY = 'zedr_local_token';
const THEME_KEY = 'zedr_theme';
const ALERT_THRESHOLD = 38;

const SEV = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
const VERDICT = { malicious: '恶意', suspicious: '可疑', safe: '安全' };
const LAYER = { static: '静态', keyword: '关键词', rule: '规则', lineage: '血缘', behavior: '行为' };
// 持久化类型（winapi.Persist* 常量）的中文标签；未知类型回退原文。
const PERSIST_KIND = {
  registry_run: '注册表 Run',
  registry_runonce: '注册表 RunOnce',
  winlogon: 'Winlogon',
  startup_folder: '启动文件夹',
  service: '服务',
  scheduled_task: '计划任务',
  ifeo: 'IFEO 劫持防护',
};

const ICONS = {
  grid: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  activity: '<path d="M3 12h4l2.5-7 4 14L16 12h5"/>',
  chip: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="8" y="8" width="8" height="8" rx="1"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/>',
  shield: '<path d="M12 2.5 4.5 5.5v5.6c0 4.8 3.1 8.1 7.5 9.6 4.4-1.5 7.5-4.8 7.5-9.6V5.5L12 2.5Z"/>',
  shieldCheck: '<path d="M12 2.5 4.5 5.5v5.6c0 4.8 3.1 8.1 7.5 9.6 4.4-1.5 7.5-4.8 7.5-9.6V5.5L12 2.5Z"/><path d="m8.5 11.8 2.4 2.4 4.6-5"/>',
  shieldOff: '<path d="M12 2.5 4.5 5.5v5.6c0 4.8 3.1 8.1 7.5 9.6 4.4-1.5 7.5-4.8 7.5-9.6V5.5L12 2.5Z"/><path d="m9 9 6 6M15 9l-6 6"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l2 2M15 8l2 2"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5 8.5 8.5 0 1 0 20.5 14.5Z"/>',
  command: '<path d="M9 3H5a2 2 0 0 0-2 2v4M9 21H5a2 2 0 0 1-2-2v-4M15 3h4a2 2 0 0 1 2 2v4M15 21h4a2 2 0 0 0 2-2v-4"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>',
  chevronRight: '<path d="m9 18 6-6-6-6"/>',
  chevronDown: '<path d="m6 9 6 6 6-6"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  alertTriangle: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/>',
  alertOctagon: '<path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86Z"/><path d="M12 8v4M12 16h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2M19 6l-1 14a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1L5 6"/><path d="M10 11v6M14 11v6"/>',
  undo: '<path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-3"/>',
  arrowRight: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  wifiOff: '<path d="m2 2 20 20"/><path d="M8.5 8.5a10.5 10.5 0 0 1 12 2.1"/><path d="M5 12.5a10.5 10.5 0 0 1 3.5-2.4"/><path d="M8.5 16a5.5 5.5 0 0 1 7 0"/><path d="M12 20h.01"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="m2 2 20 20"/><path d="M10.6 10.6a3 3 0 0 0 4.2 4.2"/><path d="M9.9 4.6A10.9 10.9 0 0 1 12 4.4c6.5 0 10 7 10 7a18.4 18.4 0 0 1-2.1 3.1"/><path d="M6.1 6.1C3.5 7.9 2 12 2 12s3.5 7 10 7a10.7 10.7 0 0 0 4.2-.8"/>',
  file: '<path d="M6 2h8l4 4v16H6Z"/><path d="M14 2v5h5M9 13h6M9 17h6"/>',
  network: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M5 16v-2h14v2"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/>',
  winMin: '<path d="M5 12h14"/>',
  winMax: '<rect x="5.5" y="5.5" width="13" height="13" rx="1.5"/>',
  winRestore: '<rect x="4.5" y="8" width="11.5" height="11.5" rx="1.5"/><path d="M8.5 8V6a2 2 0 0 1 2-2H18a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-2"/>',
  winClose: '<path d="M6 6l12 12M18 6L6 18"/>',
  layers: '<path d="m12 2 9 4.9-9 4.9L3 6.9 12 2Z"/><path d="m3 11.8 9 4.9 9-4.9"/><path d="m3 16.7 9 4.9 9-4.9"/>',
  zap: '<path d="M13 2 4.5 13H11l-1 9L19.5 11H13Z"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4 2v-8Z"/>',
  box: '<path d="M21 8 12 3 3 8v8l9 5 9-5V8Z"/><path d="m3 8 9 5 9-5M12 13v8"/>',
  clipboardCheck: '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 2h6v4H9z"/><path d="m9 14 2 2 4-5"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
  puzzle: '<path d="M4 11h2a2 2 0 1 1 4 0h2V9a2 2 0 1 1 0-4V3h-2a2 2 0 1 0-4 0H4v4H2a2 2 0 1 0 0 4h2Z"/><rect x="4" y="13" width="9" height="8" rx="1.5"/>',
};

function icon(name, cls = '') {
  return `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.info}</svg>`;
}

const ROUTES = {
  overview: { title: '总览', sub: '本机安全状态' },
  activity: { title: '活动', sub: '告警与观察记录' },
  processes: { title: '进程', sub: '实时进程视图' },
  persist: { title: '驻留', sub: '自启动与隔离区' },
  posture: { title: '安全体检', sub: '配置姿势 · 更新 · 网络暴露面' },
  apps: { title: '软件资产', sub: '这台电脑装了什么' },
  browser: { title: '浏览器', sub: '扩展清单与劫持面' },
  trust: { title: '信任与隐私', sub: '白名单、数据说明与版本' },
};

const state = {
  route: 'overview',
  renderedRoute: null,
  status: null,
  procs: [],
  alerts: [],
  allow: [],
  persistItems: [],
  quarantine: [],
  privacy: null,
  privacyError: '',
  // 泛安全体检数据（懒加载：进入对应视图才拉取，不进轮询）
  posture: null,
  exposure: null,
  apps: null,
  browser: null,
  persistAudit: null,
  postureError: '',
  appsError: '',
  browserError: '',
  persistAuditError: '',
  appsQuery: '',
  persistFilter: 'all',
  loading: true,
  error: null,
  needToken: false,
  lastFresh: 0,
  scanning: false,
  activityFilter: 'all',
  activityQuery: '',
  procQuery: '',
  procSort: 'score',
  persistQuery: '',
  collapsedGroups: new Set(),
  expandedPid: null,
  focusAfterPaint: false,
  addFormOpen: false,
  allowType: 'path',
  addValue: '',
  addNote: '',
  addError: '',
  drawerAlert: null,
  lastFocus: null,
  palette: null,
  alertIds: new Set(),
  lastAlertToast: 0,
  coreInflight: false,
  procsInflight: false,
  // 各视图最近一次渲染的数据签名：轮询数据没变就不重建 DOM。
  // 桌面端是常驻界面，3s 全量重建几百行既费 CPU 又打断选择/焦点。
  paintedSigs: {},
  persistSig: '',
  quarantineSig: '',
};

/* ------------------------------------------------------------ 令牌 */

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
  // 兼容旧版本命名，迁移一次后删除
  const legacy = localStorage.getItem('hg_local_token');
  if (legacy && !localStorage.getItem(TOKEN_KEY)) {
    localStorage.setItem(TOKEN_KEY, legacy);
    localStorage.removeItem('hg_local_token');
    return legacy;
  }
  return localStorage.getItem(TOKEN_KEY) || '';
}

let LOCAL_TOKEN = bootstrapToken();

async function api(path, opts = {}) {
  const headers = { Accept: 'application/json' };
  if (opts.body) headers['Content-Type'] = 'application/json';
  if (LOCAL_TOKEN) headers['X-ZEDR-Token'] = LOCAL_TOKEN;

  let res;
  try {
    res = await fetch(path, {
      method: opts.method || 'GET',
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
  } catch (e) {
    throw new Error('无法连接本机探针服务');
  }

  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);

  if (res.status === 401) {
    state.needToken = true;
    showTokenGate();
    throw new Error('需要访问令牌');
  }
  if (!res.ok) {
    const e = data && data.error;
    const msg = (e && e.message) || (typeof e === 'string' ? e : '') || `请求失败 (${res.status})`;
    throw new Error(msg);
  }
  return data && Object.prototype.hasOwnProperty.call(data, 'data') ? data.data : data;
}

/* ------------------------------------------------------------ 时间 / 文案 */

function parseTime(v) {
  if (!v) return null;
  const d = new Date(v);
  if (isNaN(d) || d.getFullYear() < 2000) return null;
  return d;
}

function rel(v) {
  const d = parseTime(v);
  if (!d) return '—';
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 8) return '刚刚';
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  if (s < 172800) return '昨天';
  if (s < 2592000) return `${Math.floor(s / 86400)} 天前`;
  return `${d.getMonth() + 1} 月 ${d.getDate()} 日`;
}

function fullTime(v) {
  const d = parseTime(v);
  if (!d) return '—';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function clockTime(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function dayKey(v) {
  const d = parseTime(v);
  if (!d) return '更早';
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const t = d.getTime();
  if (t >= start) return '今天';
  if (t >= start - 86400000) return '昨天';
  return `${d.getMonth() + 1} 月 ${d.getDate()} 日`;
}

function duration(sec) {
  const s = Math.max(0, Number(sec) || 0);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d} 天 ${h} 小时`;
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分`;
  return `${s} 秒`;
}

function sevLabel(s) { return SEV[s] || s || '提示'; }
function verdictLabel(v) { return VERDICT[v] || v || '—'; }
function layerLabel(l) { return LAYER[l] || l || '—'; }
function ruleVersionLabel(s) {
  return Number(s && s.rule_version) > 0 ? `v${s.rule_version}` : '内置';
}
function shortUser(user) {
  if (!user) return '—';
  const i = user.lastIndexOf('\\');
  const host = state.status && state.status.hostname;
  if (i > 0 && host && user.slice(0, i).toUpperCase() === host.toUpperCase()) return user.slice(i + 1);
  return user;
}
function scoreClass(n) { return n >= 60 ? 's2' : n >= 30 ? 's1' : 's0'; }
function scoreBarClass(n) { return n >= 60 ? 'hot' : n >= 30 ? 'warm' : ''; }
function severityBadgeClass(s) {
  return s === 'critical' ? 'crit' : s === 'high' ? 'high' : s === 'medium' ? 'warn' : '';
}
function suppressedLabel(v) {
  return ({
    whitelist: '已在本机白名单中',
    warmup: '处于基线学习静默期',
    duplicate: '重复命中，已去重',
    below_threshold: '未达到告警线',
  })[v] || (v || '—');
}

function isStale() {
  return state.lastFresh > 0 && Date.now() - state.lastFresh > 15000;
}

/* ------------------------------------------------------------ 数据刷新 */

async function refreshCore(initial = false) {
  if (state.coreInflight) return;
  state.coreInflight = true;
  try {
    const [s, al] = await Promise.all([
      api('/api/local/status'),
      api('/api/local/alerts?limit=200'),
    ]);
    const wasEmpty = !state.status;
    state.status = s;
    state.alerts = al.items || [];
    state.error = null;
    state.loading = false;
    state.lastFresh = Date.now();
    state.needToken = false;
    removeTokenGate();

    const fresh = state.alerts.filter((a) => !state.alertIds.has(a.id)
      && (a.severity === 'critical' || a.severity === 'high'));
    state.alertIds = new Set(state.alerts.map((a) => a.id));

    if (!initial && !wasEmpty && fresh.length) {
      announce(`新告警：${fresh[0].title}`);
      // 告警风暴时不要连珠炮式弹窗：抽屉打开时不打扰，
      // 同一时间窗内只提示一次，并合并成一条。
      const now = Date.now();
      if (!state.drawerAlert && now - state.lastAlertToast > 15000) {
        state.lastAlertToast = now;
        const label = fresh.length === 1 ? `新告警：${fresh[0].title}` : `新增 ${fresh.length} 条高危告警`;
        toast(label, 'warn', {
          label: '查看',
          run: () => {
            if (fresh.length === 1) openAlert(fresh[0].id);
            else go('activity');
          },
        });
      }
    }

    renderRoute(initial || wasEmpty);
    updateChrome();
  } catch (e) {
    if (state.needToken) {
      state.loading = false;
      return;
    }
    state.error = e.message || '无法连接本机探针';
    if (!state.status) {
      state.loading = false;
      renderRoute(true);
    } else {
      paintRoute(true);
      updateChrome();
    }
  } finally {
    state.coreInflight = false;
  }
}

async function refreshProcs() {
  if (state.procsInflight) return;
  state.procsInflight = true;
  try {
    const pl = await api('/api/local/processes?limit=600');
    state.procs = pl.items || [];
    if (state.route === 'processes') paintProcesses();
    else if (state.route === 'overview') paintOverview();
    else if (state.route === 'activity') paintActivity();
  } catch (e) {
    if (!state.needToken) state.error = e.message;
  } finally {
    state.procsInflight = false;
  }
}

async function refreshAllow() {
  try {
    const aw = await api('/api/local/allowlist');
    state.allow = aw.items || [];
    if (state.route === 'trust') paintTrust();
  } catch (e) {
    if (!state.needToken) state.error = e.message;
  }
}

async function refreshPersist() {
  try {
    const p = await api('/api/local/persist');
    const items = p.items || [];
    const sig = JSON.stringify(items);
    if (sig !== state.persistSig) {
      state.persistSig = sig;
      state.persistItems = items;
      if (state.route === 'persist') paintPersist();
    }
  } catch (e) {
    if (!state.needToken) state.error = e.message;
  }
}

async function refreshQuarantine() {
  try {
    const q = await api('/api/local/quarantine');
    const items = q.items || [];
    const sig = JSON.stringify(items);
    if (sig !== state.quarantineSig) {
      state.quarantineSig = sig;
      state.quarantine = items;
      if (state.route === 'persist') paintPersist();
    }
  } catch (e) {
    if (!state.needToken) state.error = e.message;
  }
}

async function refreshPrivacy() {
  try {
    state.privacy = await api('/api/local/privacy');
    state.privacyError = '';
  } catch (e) {
    state.privacyError = e.message || '无法读取隐私说明';
  }
  if (state.route === 'trust') paintTrust();
}

/* ---- 泛安全体检（懒加载：首次进入视图时拉取；显式刷新走按钮） ---- */

async function refreshPosture() {
  try {
    const [po, ex] = await Promise.all([
      api('/api/local/posture'),
      api('/api/local/exposure').catch(() => null),
    ]);
    state.posture = po.checks || [];
    if (ex) state.exposure = ex;
  } catch (e) {
    if (!state.needToken) state.postureError = e.message;
  }
  if (state.route === 'posture') paintPosture();
  if (state.route === 'trust') paintTrust();
}

async function refreshApps() {
  try {
    const pl = await api('/api/local/apps');
    state.apps = pl.items || [];
  } catch (e) {
    if (!state.needToken) state.appsError = e.message;
  }
  if (state.route === 'apps') paintApps();
}

async function refreshBrowser() {
  try {
    state.browser = await api('/api/local/browser');
  } catch (e) {
    if (!state.needToken) state.browserError = e.message;
  }
  if (state.route === 'browser') paintBrowser();
}

async function refreshPersistAudit() {
  try {
    const pl = await api('/api/local/persist/audit');
    state.persistAudit = pl.items || [];
  } catch (e) {
    if (!state.needToken) state.persistAuditError = e.message;
  }
  if (state.route === 'persist') paintPersist();
}

async function initialLoad() {
  state.loading = !state.status;
  renderRoute(true);
  await refreshCore(true);
  await Promise.all([refreshProcs(), refreshAllow(), refreshPersist(), refreshQuarantine()]);
  if (!state.privacy && !state.needToken) refreshPrivacy();
}

/* ------------------------------------------------------------ 路由 / 壳 */

function routeFromHash() {
  const h = location.hash.replace(/^#\/?/, '').split('?')[0];
  return Object.prototype.hasOwnProperty.call(ROUTES, h) ? h : 'overview';
}

function go(route) {
  if (state.route === route) {
    renderRoute(true);
    return;
  }
  location.hash = '#/' + route;
}

function renderRoute(force = false) {
  const r = state.route;
  const rebuild = force || state.renderedRoute !== r;
  if (rebuild) {
    state.renderedRoute = r;
    // 壳是新建的，DOM 为空：清掉渲染签名让 paint* 必然重绘一次
    if (rebuild) state.paintedSigs = {};
    if (state.loading && !state.status) {
      $('#viewRoot').innerHTML = skeletonHTML(r);
    } else if (state.error && !state.status) {
      $('#viewRoot').innerHTML = errorHTML();
    } else {
      $('#viewRoot').innerHTML = pageShell(r);
    }
    $('#main').scrollTop = 0;
  }
  if (state.status && !state.loading) paintRoute();
  updateChrome();
}

function pageShell(route) {
  if (route === 'overview') return '<div id="overviewRoot"></div>';

  if (route === 'activity') {
    const f = (v, label) => `<button data-act="filter" data-filter="${v}" class="${state.activityFilter === v ? 'on' : ''}" aria-pressed="${state.activityFilter === v}">${label}</button>`;
    return `
      <div class="toolbar">
        <div class="seg" role="group" aria-label="筛选活动">${f('all', '全部')}${f('alerts', '告警')}${f('watch', '观察中')}</div>
        <div class="search-box">${icon('search')}<input type="search" id="activitySearch" placeholder="搜索告警、进程或路径" value="${esc(state.activityQuery)}" aria-label="搜索活动" /></div>
        <span class="count" id="activityCount"></span>
      </div>
      <div class="activity-summary" id="activitySummary"></div>
      <div id="activityFeed"></div>`;
  }

  if (route === 'processes') {
    const s = (v, label) => `<button data-act="sort" data-sort="${v}" class="${state.procSort === v ? 'on' : ''}" aria-pressed="${state.procSort === v}">${label}</button>`;
    return `
      <div class="toolbar">
        <div class="search-box">${icon('search')}<input type="search" id="procSearch" placeholder="搜索进程名、路径或命令行" value="${esc(state.procQuery)}" aria-label="搜索进程" /></div>
        <div class="seg" role="group" aria-label="排序方式">${s('score', '风险')}${s('name', '名称')}${s('pid', 'PID')}</div>
        <span class="count" id="procCount"></span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th style="width:92px">风险</th>
            <th>进程</th>
            <th style="width:76px">PID</th>
            <th style="width:150px">账号</th>
            <th style="width:64px">连接</th>
          </tr></thead>
          <tbody id="procBody"></tbody>
        </table>
      </div>
      <div class="faint" id="procFoot" style="margin-top:10px;font-size:10px"></div>`;
  }

  if (route === 'persist') {
    const f = (v, label) => `<button data-act="persist-filter" data-filter="${v}" class="${state.persistFilter === v ? 'on' : ''}" aria-pressed="${state.persistFilter === v}">${label}</button>`;
    return `
      <div id="persistRoot">
        <div class="toolbar">
          <div class="search-box">${icon('search')}<input type="search" id="persistSearch" placeholder="搜索命令、路径或类型" value="${esc(state.persistQuery)}" aria-label="搜索自启动项" /></div>
          <div class="seg" role="group" aria-label="体检筛选">${f('all', '全部')}${f('attention', '需关注')}</div>
          <span class="count" id="persistCount"></span>
        </div>
        <div class="faint" id="persistAuditNote" style="margin:-6px 0 10px;font-size:10px"></div>
        <div id="persistGroups"></div>

        <section class="section" aria-labelledby="quarTitle">
          <div class="section-head">
            <h2 id="quarTitle">隔离区</h2>
            <span class="count faint mono" id="quarCount"></span>
          </div>
          <div id="quarantineBlock"></div>
        </section>
      </div>`;
  }

  if (route === 'posture') {
    return `
      <div id="postureRoot">
        <div id="postureSummary"></div>
        <div id="postureChecks"></div>
        <section class="section" aria-labelledby="exposureTitle">
          <div class="section-head">
            <h2 id="exposureTitle">网络暴露面</h2>
            <button class="btn sm" data-act="refresh-hygiene">${icon('refresh')}重新体检</button>
          </div>
          <div id="exposureBlock"></div>
        </section>
      </div>`;
  }

  if (route === 'apps') {
    return `
      <div id="appsRoot">
        <div class="toolbar">
          <div class="search-box">${icon('search')}<input type="search" id="appsSearch" placeholder="搜索软件名、发布者或路径" value="${esc(state.appsQuery)}" aria-label="搜索软件" /></div>
          <span class="count" id="appsCount"></span>
        </div>
        <div id="appsBody"></div>
      </div>`;
  }

  if (route === 'browser') {
    return `
      <div id="browserRoot">
        <div id="browserSummary"></div>
        <div id="browserBody"></div>
      </div>`;
  }

  return `
    <div id="trustRoot">
      <section class="section" style="margin-top:0" aria-labelledby="trustTitle">
        <div class="section-head">
          <h2 id="trustTitle">本地信任列表</h2>
          <span class="count faint mono" id="allowCount"></span>
          <button class="btn sm" data-act="add-form">${icon('plus')}添加</button>
        </div>
        <div id="allowFormWrap"></div>
        <div class="trust-list" id="allowList"></div>
      </section>

      <section class="section" aria-labelledby="privacyTitle">
        <div class="section-head"><h2 id="privacyTitle">这个软件能看到什么</h2></div>
        <div id="privacyBlock"></div>
      </section>

      <section class="section" aria-labelledby="privSettingTitle">
        <div class="section-head"><h2 id="privSettingTitle">Windows 隐私设置体检</h2></div>
        <div id="privSettingBlock"></div>
      </section>

      <section class="section" aria-labelledby="aboutTitle">
        <div class="section-head"><h2 id="aboutTitle">关于本机</h2></div>
        <div class="about-grid" id="aboutBlock"></div>
      </section>
    </div>`;
}

function paintRoute(force = false) {
  if (force) state.paintedSigs = {};
  switch (state.route) {
    case 'overview': paintOverview(); break;
    case 'activity': paintActivity(); break;
    case 'processes': paintProcesses(); break;
    case 'persist':
      // 体检画像按需拉取一次：逐文件验签有真实成本，不进轮询
      if (state.persistAudit === null && !state.persistAuditError) refreshPersistAudit();
      paintPersist();
      break;
    case 'posture':
      if (state.posture === null && !state.postureError) refreshPosture();
      paintPosture();
      break;
    case 'apps':
      if (state.apps === null && !state.appsError) refreshApps();
      paintApps();
      break;
    case 'browser':
      if (state.browser === null && !state.browserError) refreshBrowser();
      paintBrowser();
      break;
    case 'trust':
      // 隐私设置体检复用 posture 数据；单独打开 trust 页时懒加载
      if (state.posture === null && !state.postureError) refreshPosture();
      paintTrust();
      break;
  }
}

/* ------------------------------------------------------------ 页面：总览 */

function recentAlerts() {
  const cut = Date.now() - 24 * 3600 * 1000;
  return state.alerts.filter((a) => {
    const d = parseTime(a.occurred_at);
    return d && d.getTime() >= cut;
  });
}

function watchlist() {
  return state.procs
    .filter((p) => (p.score || 0) >= 20 && (p.score || 0) < ALERT_THRESHOLD)
    .sort((a, b) => (b.score || 0) - (a.score || 0));
}

function layerStates(s) {
  const st = s.stats || {};
  const behaviorOk = (s.baseline_size || 0) > 0 || s.file_watch;
  return [
    { name: '静态指纹', state: 'ok', meta: `${fmt(st.scanned || 0)} 次扫描` },
    { name: '关键词', state: 'ok', meta: '已加载' },
    { name: '规则引擎', state: (s.rule_count || 0) > 0 ? 'ok' : 'warn', meta: `${fmt(s.rule_count || 0)} 条 · ${ruleVersionLabel(s)}` },
    { name: '血缘分析', state: 'ok', meta: `${fmt(s.proc_count || 0)} 个进程` },
    {
      name: '行为基线',
      state: s.warmup ? 'warn' : (behaviorOk ? 'ok' : 'warn'),
      meta: s.warmup
        ? '基线学习中'
        : `${fmt(s.baseline_size || 0)} 样本${s.file_watch ? ` · ${fmt(s.watched_dirs || 0)} 目录` : ''}`,
    },
  ];
}

function heroCopy(s) {
  if (isStale()) {
    return {
      kicker: '本机防护 · 数据已过期', tone: 'warn', dot: 'warn', stale: true,
      title: '与本机探针失去联系',
      sub: '界面显示的是最后一次成功读取的数据。探针可能正在重启，恢复后会自动继续。',
    };
  }
  if (s.warmup) {
    return {
      kicker: '本机防护 · 基线学习', tone: 'warn', dot: 'warn',
      title: '正在学习这台电脑的正常模样',
      sub: `静默期持续到 ${fullTime(s.warmup_until)}。这段时间只上报明确恶意的行为，以减少首次部署的误报。`,
    };
  }
  const recent = recentAlerts();
  const critical = recent.filter((a) => a.severity === 'critical').length;
  const high = recent.filter((a) => a.severity === 'high').length;
  const watch = watchlist().length;
  if (critical + high > 0) {
    const first = recent.find((a) => a.severity === 'critical' || a.severity === 'high') || recent[0];
    return {
      kicker: '本机防护 · 需要关注',
      tone: critical > 0 ? 'crit' : 'warn',
      dot: critical > 0 ? 'bad' : 'warn',
      title: `发现 ${critical + high} 项需要你关注的活动`,
      sub: `最近一次是「${first.title}」，${rel(first.occurred_at)}触发。打开活动可以看到完整证据与建议动作。`,
    };
  }
  if (!s.enrolled) {
    return {
      kicker: '本机防护 · 仅本地', tone: '', dot: 'warn',
      title: '仅本地防护模式',
      sub: '尚未连接总控服务端。检测与告警都在这台电脑上完成，数据不会离开本机。',
    };
  }
  if (!s.online) {
    return {
      kicker: '本机防护 · 总控离线', tone: 'warn', dot: 'warn',
      title: '总控连接中断，本机防护仍在工作',
      sub: '告警会先保存在本机，连接恢复后自动补报。检测能力不受影响。',
    };
  }
  if (watch > 0) {
    return {
      kicker: '本机防护 · 实时', tone: '', dot: 'ok',
      title: '运行正常，但有值得留意的信号',
      sub: `有 ${watch} 个进程接近告警线，但还没有达到需要处理的程度。探针会继续观察，你可以在活动页查看它们。`,
    };
  }
  return {
    kicker: '本机防护 · 实时', tone: 'ok', dot: 'ok',
    title: '这台电脑目前正常',
    sub: `过去 24 小时没有发现需要处理的问题。最近一次扫描在 ${rel(s.last_scan_at)}，五层检测都在工作。`,
  };
}

function polar(cx, cy, r, deg) {
  const a = (deg - 90) * Math.PI / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function arc(cx, cy, r, a0, a1) {
  const [x0, y0] = polar(cx, cy, r, a0);
  const [x1, y1] = polar(cx, cy, r, a1);
  const large = a1 - a0 > 180 ? 1 : 0;
  return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

function ringHTML(layers, stale) {
  const cx = 75, cy = 75, r = 62, gap = 8;
  const span = (360 - gap * layers.length) / layers.length;
  const segs = layers.map((l, i) => {
    const a0 = i * (span + gap);
    return `<path class="ring-seg ${stale ? 'off' : l.state}" d="${arc(cx, cy, r, a0, a0 + span)}"/>`;
  }).join('');
  const ok = stale ? 0 : layers.filter((l) => l.state === 'ok').length;
  return `
    <div class="ring-wrap" role="img" aria-label="五层检测：${ok} 层在线">
      <svg viewBox="0 0 150 150" aria-hidden="true">
        <circle class="ring-track" cx="${cx}" cy="${cy}" r="${r}"/>
        ${segs}
        <g class="ring-sweep"><path d="${arc(cx, cy, r, 0, 70)}"/></g>
        <g class="ring-core" transform="translate(63,63)" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 2.5 4.5 5.5v5.6c0 4.8 3.1 8.1 7.5 9.6 4.4-1.5 7.5-4.8 7.5-9.6V5.5L12 2.5Z"/>
          <path d="m8.5 11.8 2.4 2.4 4.6-5"/>
        </g>
      </svg>
    </div>
    <div class="ring-caption">${stale ? '等待探针响应' : `${ok} / ${layers.length} 检测层在线`}</div>`;
}

function paintOverview() {
  const s = state.status;
  const root = $('#overviewRoot');
  if (!s || !root) return;

  const copy = heroCopy(s);
  const layers = layerStates(s);
  const recent = recentAlerts();
  const watch = watchlist();
  const critical = recent.filter((a) => a.severity === 'critical').length;
  const high = recent.filter((a) => a.severity === 'high').length;
  const cpu = Number(s.cpu_percent) || 0;
  const avg = (s.stats && s.stats.avg_latency_ms) || 0;

  const stats = [
    `<div class="stat"><div class="stat-label">待处理告警 · 24 小时</div><div class="stat-value ${critical > 0 ? 'crit' : high > 0 ? 'warn' : ''}">${fmt(critical + high)}</div><div class="stat-sub">严重 ${fmt(critical)} · 高危 ${fmt(high)} · 本地共 ${fmt(state.alerts.length)} 条</div></div>`,
    `<div class="stat"><div class="stat-label">观察中</div><div class="stat-value">${fmt(watch.length)}</div><div class="stat-sub">评分 20–37，未达告警线</div></div>`,
    `<div class="stat"><div class="stat-label">监控进程</div><div class="stat-value">${fmt(s.proc_count || 0)}</div><div class="stat-sub">规则 ${fmt(s.rule_count || 0)} 条 · 基线 ${fmt(s.baseline_size || 0)} 样本</div></div>`,
    `<div class="stat"><div class="stat-label">资源占用</div><div class="stat-value ${cpu > 5 ? 'warn' : ''}">${cpu.toFixed(1)}<span class="unit">% CPU</span></div><div class="stat-sub">${fmt(Math.round(s.mem_mb || 0))} MB · 平均检测 ${fmt(avg)} ms</div></div>`,
  ].join('');

  const pipes = (copy.stale ? layers.map((l) => ({ ...l, state: 'off' })) : layers).map((l) => `
    <div class="pipe">
      <div class="pipe-top"><span class="dot ${l.state}"></span><span class="pipe-name">${esc(l.name)}</span></div>
      <div class="pipe-meta" title="${esc(l.meta)}">${esc(l.meta)}</div>
    </div>`).join('');

  let recentRows = recent.slice(0, 6).map(alertFeedRow).join('');
  let recentEmpty = '';
  if (!recentRows) {
    recentRows = watch.slice(0, 6).map(watchFeedRow).join('');
  }
  if (!recentRows) {
    recentEmpty = emptyState('shieldCheck', '过去 24 小时没有告警',
      '五层检测仍在工作。有可疑行为时，这里会出现记录。', 'ok');
  }

  const statusRows = [
    statusRow('规则版本', `${ruleVersionLabel(s)} · ${fmt(s.rule_count || 0)} 条`),
    statusRow('基线样本', fmt(s.baseline_size || 0)),
    statusRow('IOC 指标', fmt(s.ioc_count || 0)),
    statusRow('自启动项', `<a class="status-link" href="#/persist" title="查看驻留详情">${fmt(s.persist_count || 0)}</a>`),
    statusRow('落地监控', s.file_watch ? `${fmt(s.watched_dirs || 0)} 个目录` : '未启用'),
    statusRow('上报队列', `${fmt(s.pending_alerts || 0)} 待发${s.dropped_alerts ? ` · ${fmt(s.dropped_alerts)} 丢弃` : ''}`),
    statusRow('上次心跳', `<span data-rel="${esc(s.last_heartbeat)}">${rel(s.last_heartbeat)}</span>`),
    statusRow('运行时长', duration(s.uptime_sec)),
    statusRow('检测统计', `${fmt(s.stats && s.stats.scanned || 0)} 扫描 · ${fmt(s.stats && s.stats.fired || 0)} 命中`),
  ].join('');

  root.innerHTML = `
    <section class="hero ${state.scanning ? 'scanning' : ''}" aria-labelledby="heroTitle">
      <div>
        <div class="eyebrow"><span class="dot ${copy.dot}"></span>${esc(copy.kicker)}</div>
        <h1 class="hero-title ${copy.tone}" id="heroTitle">${esc(copy.title)}</h1>
        <p class="hero-sub">${esc(copy.sub)}</p>
        <div class="hero-actions">
          <button class="btn primary" data-act="${copy.stale ? 'retry' : 'scan'}" ${state.scanning ? 'disabled' : ''}>${icon('refresh')}${state.scanning ? '扫描中…' : copy.stale ? '重试连接' : '立即扫描'}</button>
          <a class="btn ghost" href="#/activity">查看活动${icon('arrowRight')}</a>
        </div>
        <div class="hero-facts">
          <div class="hero-fact"><div class="k">最近扫描</div><div class="v" data-rel="${esc(s.last_scan_at)}">${rel(s.last_scan_at)}</div></div>
          <div class="hero-fact"><div class="k">规则</div><div class="v">${esc(ruleVersionLabel(s))} · ${fmt(s.rule_count || 0)} 条</div></div>
          <div class="hero-fact"><div class="k">基线</div><div class="v">${fmt(s.baseline_size || 0)} 样本</div></div>
        </div>
      </div>
      <div class="hero-visual">${ringHTML(layers, copy.stale)}</div>
    </section>

    <div class="stat-row">${stats}</div>

    <section class="section" aria-label="五层检测状态">
      <div class="section-head"><h2>五层检测</h2></div>
      <div class="pipeline">${pipes}</div>
    </section>

    <div class="section cols">
      <section aria-labelledby="recentTitle">
        <div class="section-head">
          <h2 id="recentTitle">最近活动</h2>
          <a class="section-link" href="#/activity">全部 ${icon('chevronRight')}</a>
        </div>
        <div class="feed">${recentRows}${recentEmpty}</div>
      </section>
      <section aria-labelledby="statusTitle">
        <div class="section-head"><h2 id="statusTitle">运行状态</h2></div>
        <div class="status-list">${statusRows}</div>
      </section>
    </div>`;
}

function statusRow(k, vHTML) {
  return `<div class="status-row"><span class="status-k">${esc(k)}</span><span class="status-v">${vHTML}</span></div>`;
}

function alertFeedRow(a, member = false) {
  return `
    <div class="feed-row sev-${esc(a.severity)}${member ? ' member' : ''}" role="button" tabindex="0" data-act="open-alert" data-id="${esc(a.id)}" aria-label="查看告警：${esc(a.title)}">
      <span class="sev-dot ${esc(a.severity)}"></span>
      <span>
        <div class="feed-title">${esc(a.process_name || a.title)}</div>
        <div class="feed-meta">${esc(a.title)}${a.image_path ? ` · ${esc(a.image_path)}` : ''}</div>
      </span>
      <span class="feed-right">
        <span class="feed-time" data-rel="${esc(a.occurred_at)}">${rel(a.occurred_at)}</span>
        <span class="feed-score">${esc(a.score)} 分</span>
      </span>
    </div>`;
}

function watchFeedRow(p) {
  return `
    <div class="feed-row watch" role="button" tabindex="0" data-act="open-watch" data-name="${esc(p.name)}" aria-label="查看接近告警线的进程：${esc(p.name)}">
      <span class="sev-dot watch"></span>
      <span>
        <div class="feed-title">${esc(p.name)} 接近告警线</div>
        <div class="feed-meta">${esc(p.title || p.path || '—')}</div>
      </span>
      <span class="feed-right">
        <span class="feed-badge">观察中</span>
        <span class="feed-score">${esc(p.score)} 分</span>
      </span>
    </div>`;
}

function emptyState(iconName, title, sub, tone = '') {
  return `<div class="empty-state">
    <div class="e-ico ${tone}">${icon(iconName)}</div>
    <div class="e-title">${esc(title)}</div>
    <div class="e-sub">${esc(sub)}</div>
  </div>`;
}

/* ------------------------------------------------------------ 页面：活动 */

function activityEntries() {
  const items = [];
  for (const a of state.alerts) items.push({ kind: 'alert', at: a.occurred_at, a });
  for (const p of watchlist()) items.push({ kind: 'watch', at: p.first_seen, p });
  return items;
}

function paintActivity() {
  // 告警列表可能上百行：数据/筛选/折叠都没变就不重建
  const watchSig = state.procs
    .filter((p) => (p.score || 0) >= 20 && (p.score || 0) < ALERT_THRESHOLD)
    .map((p) => [p.pid, p.score, p.name, p.first_seen]);
  const sig = JSON.stringify([state.alerts, state.activityFilter, state.activityQuery,
    [...state.collapsedGroups].sort(), watchSig]);
  if (state.paintedSigs.activity === sig) return;
  state.paintedSigs.activity = sig;

  const all = activityEntries();
  const q = state.activityQuery.trim().toLowerCase();
  const filtered = all.filter((it) => {
    if (state.activityFilter === 'alerts' && it.kind !== 'alert') return false;
    if (state.activityFilter === 'watch' && it.kind !== 'watch') return false;
    if (!q) return true;
    const hay = it.kind === 'alert'
      ? `${it.a.title} ${it.a.process_name || ''} ${it.a.image_path || ''} ${it.a.cmdline || ''}`
      : `${it.p.name} ${it.p.title || ''} ${it.p.path || ''} ${it.p.cmdline || ''}`;
    return hay.toLowerCase().includes(q);
  }).sort((a, b) => {
    const ta = parseTime(a.at);
    const tb = parseTime(b.at);
    return (tb ? tb.getTime() : 0) - (ta ? ta.getTime() : 0);
  });

  $$('[data-filter]').forEach((b) => {
    const on = b.dataset.filter === state.activityFilter;
    b.classList.toggle('on', on);
    b.setAttribute('aria-pressed', String(on));
  });

  const count = $('#activityCount');
  if (count) count.textContent = `${fmt(filtered.length)} 条`;
  const summary = $('#activitySummary');
  if (summary) {
    const c = filtered.filter((i) => i.kind === 'alert' && i.a.severity === 'critical').length;
    const h = filtered.filter((i) => i.kind === 'alert' && i.a.severity === 'high').length;
    const m = filtered.filter((i) => i.kind === 'alert' && i.a.severity === 'medium').length;
    const w = filtered.filter((i) => i.kind === 'watch').length;
    summary.innerHTML = filtered.length
      ? `<span><i class="critical"></i>严重 ${fmt(c)}</span><span><i class="high"></i>高危 ${fmt(h)}</span><span><i class="medium"></i>中危 ${fmt(m)}</span><span><i class="watch"></i>观察中 ${fmt(w)}</span>`
      : '';
  }

  const box = $('#activityFeed');
  if (!box) return;
  if (!filtered.length) {
    box.innerHTML = emptyState(q || state.activityFilter !== 'all' ? 'search' : 'shieldCheck',
      q || state.activityFilter !== 'all' ? '没有匹配的活动' : '过去 24 小时没有告警',
      q || state.activityFilter !== 'all'
        ? '换个关键词，或把筛选切回「全部」查看所有记录。'
        : '五层检测仍在工作。有可疑行为时，这里会出现记录。',
      q || state.activityFilter !== 'all' ? '' : 'ok');
    return;
  }

  const groups = new Map();
  for (const it of filtered) {
    const k = dayKey(it.at);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(it);
  }
  let html = '';
  for (const [day, items] of groups) {
    html += `<div class="day-label">${esc(day)}</div><div class="feed">${renderActivityItems(items)}</div>`;
  }
  box.innerHTML = html;
}

// 同一时间窗内同一规则反复命中不同进程是常态（批量脚本、安装器、
// 探针自身的测试二进制），逐行平铺会让标题噪声淹没进程信息。
// 这里把连续同标题的告警聚合成一组：组头给结论和规模，成员行看进程。
// 观察中条目与标题不同的告警保持独立行。
function renderActivityItems(items) {
  const out = [];
  let run = null;
  const flush = () => {
    if (!run) return;
    out.push(run.items.length > 1 ? alertGroupHTML(run) : alertFeedRow(run.items[0].a));
    run = null;
  };
  for (const it of items) {
    if (it.kind !== 'alert') {
      flush();
      out.push(watchFeedRow(it.p));
      continue;
    }
    if (run && run.title === it.a.title && run.severity === it.a.severity) {
      run.items.push(it);
    } else {
      flush();
      run = { title: it.a.title, severity: it.a.severity, items: [it] };
    }
  }
  flush();
  return out.join('');
}

function alertGroupHTML(run) {
  const collapsed = state.collapsedGroups.has(run.title);
  const latest = run.items[0]; // 已按时间倒序，首个即最新
  const maxScore = run.items.reduce((m, it) => Math.max(m, Number(it.a.score) || 0), 0);
  return `<div class="feed-group">
    <div class="feed-group-head sev-${esc(run.severity)}" role="button" tabindex="0"
      data-act="toggle-group" data-title="${esc(run.title)}" aria-expanded="${!collapsed}"
      aria-label="${collapsed ? '展开' : '收起'}同类告警：${esc(run.title)}">
      <span class="sev-dot ${esc(run.severity)}"></span>
      <span class="feed-group-title">${esc(run.title)}</span>
      <span class="badge">${fmt(run.items.length)} 条</span>
      <span class="feed-time" data-rel="${esc(latest.at)}">${rel(latest.at)}</span>
      <span class="feed-score">最高 ${fmt(maxScore)} 分</span>
      <span class="chev">${icon(collapsed ? 'chevronRight' : 'chevronDown')}</span>
    </div>
    ${collapsed ? '' : `<div class="feed-group-body">${run.items.map((it) => alertFeedRow(it.a, true)).join('')}</div>`}
  </div>`;
}

/* ------------------------------------------------------------ 页面：进程 */

function filteredProcs() {
  const q = state.procQuery.trim().toLowerCase();
  let list = state.procs.filter((p) => {
    if (!q) return true;
    return `${p.name || ''} ${p.path || ''} ${p.cmdline || ''} ${p.title || ''}`.toLowerCase().includes(q);
  });
  if (state.procSort === 'name') list = list.slice().sort((a, b) => (a.name || '').localeCompare(b.name || '', 'zh-CN'));
  else if (state.procSort === 'pid') list = list.slice().sort((a, b) => a.pid - b.pid);
  else list = list.slice().sort((a, b) => (b.score || 0) - (a.score || 0) || (a.name || '').localeCompare(b.name || '', 'zh-CN'));
  return list;
}

function paintProcesses() {
  const body = $('#procBody');
  if (!body) return;

  // 300 行 tbody 每 3s 重建既费 CPU 又会打断文本选择：数据没变就跳过
  const sig = JSON.stringify([state.procs, state.procQuery, state.procSort, state.expandedPid, state.allow]);
  if (state.paintedSigs.processes === sig) return;
  state.paintedSigs.processes = sig;

  const focusPid = state.focusAfterPaint ? state.expandedPid : null;
  state.focusAfterPaint = false;

  $$('[data-sort]').forEach((b) => {
    const on = b.dataset.sort === state.procSort;
    b.classList.toggle('on', on);
    b.setAttribute('aria-pressed', String(on));
  });

  const list = filteredProcs();
  const count = $('#procCount');
  if (count) count.textContent = `显示 ${fmt(Math.min(list.length, 300))} / ${fmt(state.procs.length)}`;

  if (!list.length) {
    body.innerHTML = `<tr><td colspan="5">${emptyState('search', '没有匹配的进程',
      state.procQuery ? '换个关键词，或清空搜索查看全部进程。' : '探针还没有采集到进程，稍后会自动刷新。')}</td></tr>`;
  } else {
    body.innerHTML = list.slice(0, 300).map((p) => procRow(p, state.expandedPid === p.pid)).join('');
  }

  const foot = $('#procFoot');
  if (foot) {
    foot.textContent = list.length > 300
      ? `共 ${fmt(list.length)} 个匹配进程，表格只显示风险最高的 300 个。使用搜索缩小范围。`
      : '';
  }

  if (focusPid) {
    const row = body.querySelector(`tr.row[data-pid="${focusPid}"]`);
    if (row) row.focus();
  }
}

function procRow(p, expanded) {
  const score = Number(p.score) || 0;
  const path = p.path || '';
  const trusted = state.allow.some((e) => e.type === 'path' && e.value === path);
  return `
    <tr class="row ${expanded ? 'expanded' : ''}" data-act="toggle-proc" data-pid="${esc(p.pid)}" tabindex="0" aria-expanded="${expanded}">
      <td>
        <div class="score-cell">
          <span class="score-val ${scoreClass(score)}">${score}</span>
          <span class="score-bar ${scoreBarClass(score)}"><i style="width:${Math.min(100, Math.max(0, score))}%"></i></span>
        </div>
      </td>
      <td>
        <div class="proc-name">${esc(p.name)}${trusted ? ' <span class="badge ok" style="margin-left:6px">已信任</span>' : ''}</div>
        ${p.title ? `<div class="proc-title">${esc(p.title)}</div>` : ''}
        <div class="proc-path" title="${esc(path)}">${esc(path || '—')}</div>
      </td>
      <td class="pid">${esc(p.pid)}</td>
      <td class="user" title="${esc(p.user || '')}">${esc(shortUser(p.user))}</td>
      <td class="conn">${fmt(p.conn_count || 0)}</td>
    </tr>
    ${expanded ? procDetail(p, trusted) : ''}`;
}

function procDetail(p, trusted) {
  const related = state.alerts.find((a) => (p.path && a.image_path === p.path) || (a.process_name === p.name && a.pid === p.pid));
  const score = Number(p.score) || 0;
  return `
    <tr class="detail"><td colspan="5">
      <div class="proc-detail">
        <div class="full">
          <h4>命令行</h4>
          ${p.cmdline ? `<pre class="code">${esc(p.cmdline)}</pre>` : '<div class="faint" style="font-size:11px">没有记录到命令行</div>'}
        </div>
        <div>
          <h4>身份</h4>
          <dl class="kv">
            <dt>镜像路径</dt><dd>${esc(p.path || '—')}</dd>
            <dt>运行账号</dt><dd>${esc(p.user || '—')}</dd>
            <dt>PPID</dt><dd>${esc(p.ppid || '—')}</dd>
            <dt>首次发现</dt><dd>${fullTime(p.first_seen)}</dd>
          </dl>
        </div>
        <div>
          <h4>状态</h4>
          <dl class="kv">
            <dt>风险评分</dt><dd>${score} / 100</dd>
            <dt>判定</dt><dd>${esc(verdictLabel(p.verdict))}</dd>
            <dt>连接 / 模块</dt><dd>${fmt(p.conn_count || 0)} / ${fmt(p.modules || 0)}</dd>
            <dt>未告警原因</dt><dd>${esc(p.suppressed ? suppressedLabel(p.suppressed) : '—')}</dd>
          </dl>
        </div>
        <div class="full detail-actions">
          ${related ? `<button class="btn sm" data-act="open-alert" data-id="${esc(related.id)}">${icon('activity')}查看相关告警</button>` : ''}
          ${trusted
            ? `<span class="badge ok">${icon('check')} 已在此路径的信任列表中</span>`
            : `<button class="btn sm" data-act="allow-proc" data-path="${esc(p.path || '')}" ${p.path ? '' : 'disabled'}>${icon('shieldCheck')}信任此路径</button>`}
          <button class="btn sm ghost" data-act="copy-path" data-copy="${esc(p.path || '')}" ${p.path ? '' : 'disabled'}>${icon('copy')}复制路径</button>
        </div>
      </div>
    </td></tr>`;
}

/* ------------------------------------------------------------ 页面：驻留 */

// attentionFlags 是"需关注"过滤的判定集合：文件缺失/无签名/基线外/
// 最高权限。无描述（no_info）不进过滤——大量正常系统工具没有版本
// 资源，把它算进"需关注"会让过滤器失去意义。
const ATTENTION_FLAGS = new Set(['file_missing', 'unsigned', 'new', 'elevated']);

function paintPersist(force = false) {
  const root = $('#persistRoot');
  if (!root) return;
  const ae = document.activeElement;
  if (!force && ae && root.contains(ae) && ae.tagName === 'INPUT') return;

  // 423+ 行的清单不该每 3s 重建一次：数据与查询都没变就直接跳过
  const auditSig = state.persistAudit ? state.persistAudit.length : '';
  const sig = `${state.persistSig}|${state.quarantineSig}|${state.persistQuery}|${state.persistFilter}|${auditSig}`;
  if (!force && state.paintedSigs.persist === sig) return;
  state.paintedSigs.persist = sig;

  const auditByKey = new Map((state.persistAudit || []).map((a) => [a.key, a]));
  const hasAudit = state.persistAudit !== null;

  const q = state.persistQuery.trim().toLowerCase();
  let items = state.persistItems.map((it) => ({ ...it, audit: auditByKey.get(it.key) || null }));
  // 需关注过滤只对有体检画像的条目生效；画像未就绪时该档为空并给出说明
  if (state.persistFilter === 'attention') {
    items = items.filter((it) => (it.audit?.flags || []).some((f) => ATTENTION_FLAGS.has(f)));
  }
  items = items.filter((it) => !q
    || `${it.kind || ''} ${it.location || ''} ${it.value || ''}`.toLowerCase().includes(q));

  const count = $('#persistCount');
  if (count) count.textContent = `共 ${fmt(items.length)} 项`;

  const note = $('#persistAuditNote');
  if (note) {
    if (!hasAudit) {
      note.innerHTML = state.persistAuditError
        ? `体检画像读取失败：${esc(state.persistAuditError)} <button class="btn sm" data-act="refresh-hygiene">重试</button>`
        : '体检画像生成中（逐文件校验签名，首次约需数秒）…';
    } else {
      const audits = state.persistAudit || [];
      const nUnsigned = audits.filter((a) => (a.flags || []).includes('unsigned')).length;
      const nMissing = audits.filter((a) => (a.flags || []).includes('file_missing')).length;
      const nNew = audits.filter((a) => (a.flags || []).includes('new')).length;
      note.textContent = `体检：${fmt(audits.length)} 项自启动 · 未签名 ${fmt(nUnsigned)} · 文件缺失 ${fmt(nMissing)} · 基线外新增 ${fmt(nNew)}` +
        (nUnsigned + nMissing + nNew === 0 ? ' · 全部可信' : '');
    }
  }

  const box = $('#persistGroups');
  if (box) {
    if (!items.length) {
      const filtering = q || state.persistFilter === 'attention';
      box.innerHTML = emptyState(filtering ? 'search' : 'shieldCheck',
        filtering ? '没有符合条件的自启动项' : '还没有自启动项记录',
        state.persistFilter === 'attention'
          ? '全部自启动项都通过体检：没有未签名、文件缺失或基线外的新增项。这是好事。'
          : q ? '换个关键词，或清空搜索查看全部。'
            : '探针正在扫描持久化位置，首个扫描周期后会自动建立基线。');
    } else {
      // 按类型分组展示：7 类自启动位置的风险面不同，混在一起没有可读性。
      // 已知类型按固定顺序，未知类型排在最后（向前兼容新采集口径）。
      const byKind = new Map();
      for (const it of items) {
        const k = it.kind || 'unknown';
        if (!byKind.has(k)) byKind.set(k, []);
        byKind.get(k).push(it);
      }
      const order = Object.keys(PERSIST_KIND);
      const kinds = [...byKind.keys()].sort((a, b) => {
        const ia = order.indexOf(a);
        const ib = order.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
      });
      box.innerHTML = kinds.map((k) => {
        const list = byKind.get(k);
        return `<div class="day-label">${esc(PERSIST_KIND[k] || k)} · ${fmt(list.length)}</div>
          <div class="persist-list">${list.map(persistRow).join('')}</div>`;
      }).join('');
    }
  }

  const qc = $('#quarCount');
  if (qc) qc.textContent = state.quarantine.length ? `${fmt(state.quarantine.length)} 条记录` : '';
  const qb = $('#quarantineBlock');
  if (qb) qb.innerHTML = quarantineHTML();
}

// persistFlagBadges 把体检 flags 与签名/发布者画像转成行内徽标。
function persistFlagBadges(audit) {
  if (!audit) return '';
  const badges = [];
  for (const f of audit.flags || []) {
    if (f === 'file_missing') badges.push('<span class="badge warn" title="指向的文件已不存在（可能是卸载残留，也可能是恶意项先删了文件）">文件缺失</span>');
    else if (f === 'unsigned') badges.push('<span class="badge crit" title="文件存在但没有可信签名；签名校验失败（篡改）也会归入此类">未签名</span>');
    else if (f === 'no_info') badges.push('<span class="badge" title="没有发布者与描述信息">无信息</span>');
    else if (f === 'elevated') badges.push('<span class="badge warn" title="以最高权限运行">高权限</span>');
    else if (f === 'new') badges.push('<span class="badge warn" title="尚未进入持久化基线（新出现的自启动点）">新增</span>');
  }
  const who = audit.file?.signer || audit.file?.company || '';
  return `${badges.join('')}${who ? `<span class="badge ok" title="签名/版本信息里的发布者">${esc(who)}</span>` : ''}`;
}

function persistRow(it) {
  return `<div class="persist-row">
    <div class="persist-value" title="${esc(it.value)}">${esc(it.value || '—')}</div>
    <div class="persist-flags">${persistFlagBadges(it.audit)}</div>
    ${it.location ? `<div class="persist-loc" title="${esc(it.location)}">${esc(it.location)}</div>` : ''}
  </div>`;
}

function quarantineHTML() {
  if (!state.quarantine.length) {
    return emptyState('lock', '隔离区为空',
      '响应动作（文件隔离/恢复）默认双层开关关闭，只有服务端与终端两侧都显式开启时才会发生。空是正常态。', 'ok');
  }
  return `<div class="trust-list">${state.quarantine.map((e) => `
    <div class="trust-row">
      <span class="badge crit">已隔离</span>
      <div>
        <div class="trust-value">${esc(e.original_path)}</div>
        <div class="trust-note">${esc(e.reason || '—')}${e.by ? ` · 操作方：${esc(e.by)}` : ''}</div>
        <div class="trust-time">${fullTime(e.quarantined_at)} · ${fmt(Math.max(1, Math.round((e.size || 0) / 1024)))} KB</div>
      </div>
      <div class="trust-actions"></div>
    </div>`).join('')}</div>`;
}

/* ------------------------------------------------------------ 页面：安全体检 */

// 体检项三色语义与告警一致：err 红 / warn 黄 / ok 绿 / info 中性。
const CHECK_STATE_LABEL = { ok: '正常', warn: '需关注', err: '高风险', info: '说明' };

const CHECK_GROUPS = [
  { id: 'config', title: '安全配置', note: '本机设置项。改成更安全的一档需要你手动操作，这里只给指引、不代改。' },
  { id: 'update', title: '系统更新', note: '打了补丁没重启 = 保护没生效，这项体检最容易救急。' },
  { id: 'privacy', title: '隐私设置', note: '这些是知情选择而不是漏洞：开着不一定会出事，但会扩大画像。' },
];

function paintPosture(force = false) {
  const root = $('#postureRoot');
  if (!root) return;
  const ae = document.activeElement;
  if (!force && ae && root.contains(ae) && ae.tagName === 'INPUT') return;

  const summary = $('#postureSummary');
  const checksBox = $('#postureChecks');
  if (!summary || !checksBox) return;

  if (state.posture === null) {
    summary.innerHTML = '<div class="skel skel-line" style="width:40%"></div>';
    checksBox.innerHTML = Array.from({ length: 6 }).map(() => '<div class="skel skel-row"></div>').join('');
    paintExposure();
    return;
  }

  const checks = state.posture;
  const nErr = checks.filter((c) => c.state === 'err').length;
  const nWarn = checks.filter((c) => c.state === 'warn').length;
  const nOk = checks.filter((c) => c.state === 'ok').length;

  // 结论先行：一句话说清体检结果，而不是摆数字
  let verdict, detail;
  if (nErr > 0) {
    verdict = `<span class="dot bad"></span>体检发现 ${fmt(nErr)} 项高风险配置`;
    detail = '下面逐项说明了为什么重要和怎么改。改不改由你决定——这里不会替你动手。';
  } else if (nWarn > 0) {
    verdict = `<span class="dot warn"></span>没有高风险项，${fmt(nWarn)} 项值得看一眼`;
    detail = '多为"取决于你是否需要"的配置（比如远程桌面开着），逐项确认即可。';
  } else {
    verdict = `<span class="dot ok"></span>安全配置体检通过`;
    detail = `${fmt(nOk)} 项配置处于推荐状态；另有若干"说明"项是事实陈述，不需要动作。`;
  }
  summary.innerHTML = `
    <div class="posture-verdict">${verdict}<span class="posture-verdict-sub">${detail}</span></div>`;

  checksBox.innerHTML = CHECK_GROUPS.map((g) => {
    const list = checks.filter((c) => c.group === g.id);
    if (!list.length) return '';
    return `<section class="section" aria-labelledby="pg-${g.id}">
      <div class="section-head"><h2 id="pg-${g.id}">${esc(g.title)}</h2></div>
      <p class="check-group-note">${esc(g.note)}</p>
      <div class="check-list">${list.map(checkRow).join('')}</div>
    </section>`;
  }).join('');

  paintExposure();
}

function checkRow(c) {
  const dotCls = c.state === 'err' ? 'bad' : c.state;
  return `<div class="check-row">
    <span class="dot ${dotCls}" title="${CHECK_STATE_LABEL[c.state] || c.state}"></span>
    <div class="check-body">
      <div class="check-title">${esc(c.title)}<span class="check-value">${esc(c.value || '')}</span></div>
      <div class="check-why">${esc(c.why || '')}</div>
      ${c.advice ? `<div class="check-advice">怎么改：${esc(c.advice)}</div>` : ''}
    </div>
  </div>`;
}

function paintExposure() {
  const box = $('#exposureBlock');
  if (!box) return;

  if (state.exposure === null) {
    box.innerHTML = '<div class="skel skel-row"></div><div class="skel skel-row"></div>';
    return;
  }
  const exp = state.exposure;
  const listeners = exp.listeners || [];

  const scopeBadge = (s) => s === 'any'
    ? '<span class="badge crit" title="绑定在 0.0.0.0/::，同一网络里的所有设备都能连到这个端口">任意网卡可达</span>'
    : s === 'lan' ? '<span class="badge warn" title="绑定在具体网卡地址上，局域网内可达">局域网可达</span>'
      : '<span class="badge ok" title="只监听本机回环地址，外部设备连不到">仅本机</span>';

  const hostRows = (exp.hosts?.entries || []);
  const hostsHTML = !exp.hosts?.readable
    ? `<p class="check-why">${esc(exp.hosts?.note || '无法读取 hosts 文件')}</p>`
    : hostRows.length === 0
      ? `<p class="check-why">hosts 文件只有默认内容，没有自定义映射。这是好事。</p>`
      : `<p class="check-why">hosts 里有 ${fmt(hostRows.length)} 条自定义映射（默认只有 localhost）。把杀毒/银行/更新域名指到别处是经典劫持手法；本机无法验证"指得对不对"，请逐条核对是否是你或你装的软件加的：</p>
         <div class="mono host-list">${hostRows.map((h) => `<div>${esc(h.ip)}&nbsp;&nbsp;${esc(h.hostname)}</div>`).join('')}</div>`;

  const proxy = exp.proxy || {};
  const proxyHTML = (proxy.enabled && proxy.server)
    ? `<p class="check-why">系统代理已设置：<span class="mono">${esc(proxy.server)}</span>。本地代理工具（回环地址）属正常场景；不认识的代理地址值得警惕。</p>`
    : proxy.auto_config_url
      ? `<p class="check-why">系统代理走 PAC 脚本：<span class="mono">${esc(proxy.auto_config_url)}</span>。如果不是企业配置或你自己的工具设置的，应当核查。</p>`
      : `<p class="check-why">未设置系统代理，流量走直连。这是默认状态。</p>`;

  box.innerHTML = `
    <div class="day-label">监听端口 · ${fmt(listeners.length)}</div>
    ${listeners.length === 0
      ? '<p class="check-why">没有发现监听端口。这台机器对外不提供任何服务。</p>'
      : `<div class="table-wrap"><table>
          <thead><tr><th style="width:64px">协议</th><th>监听地址</th><th style="width:110px">可达范围</th><th style="width:180px">进程</th></tr></thead>
          <tbody>${listeners.map((l) => `<tr>
            <td class="mono">${esc(l.proto)}</td>
            <td class="mono">${esc(l.addr)}</td>
            <td>${scopeBadge(l.scope)}</td>
            <td>${esc(l.process || '（进程已退出或无权限）')}</td>
          </tr>`).join('')}</tbody>
        </table></div>
        <p class="check-why">不认识的监听端口是暴露面的第一线索；点进「进程」页可以看到它的完整路径与血缘。</p>`}
    <div class="day-label">hosts 文件</div>
    ${hostsHTML}
    <div class="day-label">系统代理</div>
    ${proxyHTML}`;
}

/* ------------------------------------------------------------ 页面：软件资产 */

function paintApps(force = false) {
  const root = $('#appsRoot');
  if (!root) return;
  const ae = document.activeElement;
  if (!force && ae && root.contains(ae) && ae.tagName === 'INPUT') return;

  const count = $('#appsCount');
  const body = $('#appsBody');
  if (!count || !body) return;

  if (state.apps === null) {
    count.textContent = state.appsError ? '' : '加载中…';
    body.innerHTML = state.appsError
      ? emptyState('info', '暂时读不到软件清单', esc(state.appsError))
      : Array.from({ length: 10 }).map(() => '<div class="skel skel-row"></div>').join('');
    return;
  }

  const q = state.appsQuery.trim().toLowerCase();
  const items = state.apps.filter((a) => !q
    || `${a.name || ''} ${a.publisher || ''} ${a.location || ''}`.toLowerCase().includes(q));

  const hidden = state.apps.filter((a) => a.hidden || a.no_remove).length;
  count.textContent = q ? `${fmt(items.length)} / ${fmt(state.apps.length)}` : `共 ${fmt(items.length)} 项`;

  // 结论行：隐藏卸载入口的软件正常软件极少做，值得点名
  const head = `<p class="check-why" style="margin-bottom:12px">${
    hidden > 0
      ? `共 ${fmt(state.apps.length)} 个软件，其中 <strong>${fmt(hidden)} 个</strong>把自己从系统卸载列表里藏了起来（正常软件极少这样做，常见于捆装组件）——下表已用徽标标出。`
      : `共 ${fmt(state.apps.length)} 个软件（Win32 + Microsoft Store），没有发现隐藏卸载入口的条目。`}</p>`;

  if (!items.length) {
    body.innerHTML = head + emptyState('search', '没有匹配的软件', '换个关键词，或清空搜索查看全部。');
    return;
  }

  body.innerHTML = head + `<div class="table-wrap"><table>
    <thead><tr>
      <th>软件</th><th style="width:170px">发布者</th><th style="width:110px">版本</th>
      <th style="width:96px">安装日期</th><th style="width:76px">大小</th>
    </tr></thead>
    <tbody>${items.map((a) => `<tr>
      <td><div class="proc-name">${esc(a.name)}${a.source === 'store' ? '<span class="badge" style="margin-left:6px">Store</span>' : ''}${a.hidden ? '<span class="badge warn" title="SystemComponent=1：不出现在系统\"应用和功能\"里">已隐藏</span>' : ''}${a.no_remove ? '<span class="badge crit" title="卸载入口被移除（NoRemove=1）">不可卸载</span>' : ''}</div>
        ${a.location ? `<div class="proc-path mono" title="${esc(a.location)}">${esc(a.location)}</div>` : ''}</td>
      <td>${esc(a.publisher || '—')}</td>
      <td class="mono">${esc(a.version || '—')}</td>
      <td class="mono">${esc(fmtInstallDate(a.install_date))}</td>
      <td class="mono">${a.size_kb ? fmt(Math.round(a.size_kb / 1024)) + ' MB' : '—'}</td>
    </tr>`).join('')}</tbody>
  </table></div>
  <p class="check-why">清单来自本机注册表，只读采集；大小与安装日期是系统记录的估算值，缺失属正常。</p>`;
}

function fmtInstallDate(raw) {
  // Uninstall 键的 InstallDate 通常为 yyyymmdd 字符串
  const m = /^(\d{4})(\d{2})(\d{2})$/.exec(raw || '');
  return m ? `${m[1]}-${m[2]}-${m[3]}` : (raw || '—');
}

/* ------------------------------------------------------------ 页面：浏览器 */

const BROWSER_LABEL = { chrome: 'Chrome', edge: 'Edge', firefox: 'Firefox' };

function paintBrowser(force = false) {
  const root = $('#browserRoot');
  if (!root) return;
  const ae = document.activeElement;
  if (!force && ae && root.contains(ae) && ae.tagName === 'INPUT') return;

  const summary = $('#browserSummary');
  const body = $('#browserBody');
  if (!summary || !body) return;

  if (state.browser === null) {
    summary.innerHTML = '<div class="skel skel-line" style="width:40%"></div>';
    body.innerHTML = Array.from({ length: 6 }).map(() => '<div class="skel skel-row"></div>').join('');
    return;
  }

  const exts = state.browser.extensions || [];
  const policies = state.browser.policies || [];
  const scanned = state.browser.scanned || [];
  const wide = exts.filter((e) => e.host_wide).length;
  const risky = exts.filter((e) => (e.risky_perms || []).length > 0).length;

  const scanText = scanned.map((s) => BROWSER_LABEL[s] || s).join(' · ') || '未发现已安装的浏览器';
  summary.innerHTML = `
    <p class="check-why" style="margin-bottom:12px">扫描了 ${esc(scanText)}，发现 <strong>${fmt(exts.length)}</strong> 个扩展。
      ${wide ? `其中 <strong>${fmt(wide)}</strong> 个能读取你打开的所有网页。` : '没有发现能读取全部网页的扩展。'}
      ${risky ? `${fmt(risky)} 个持有敏感权限（本机通信/代理/调试等）。` : ''}</p>
    ${policies.length ? `<p class="check-why" style="margin-bottom:12px"><strong>发现策略强装扩展（${policies.map((p) => `${BROWSER_LABEL[p.browser] || p.browser} ${p.count} 个`).join('、')}）</strong>——企业管理正常配置，但也是流氓软件与红队公认的持久化位置；若你不在这类环境里，请立即核查。</p>` : ''}`;

  if (!exts.length) {
    body.innerHTML = emptyState('shieldCheck', scanned.length ? '没有安装任何扩展' : '没有发现浏览器',
      scanned.length ? '浏览器是干净的。' : '未检测到常见浏览器，或用户数据目录尚未创建。');
    return;
  }

  const byBrowser = new Map();
  for (const e of exts) {
    if (!byBrowser.has(e.browser)) byBrowser.set(e.browser, []);
    byBrowser.get(e.browser).push(e);
  }
  body.innerHTML = [...byBrowser.entries()].map(([b, list]) => `
    <div class="day-label">${esc(BROWSER_LABEL[b] || b)} · ${fmt(list.length)}</div>
    <div class="trust-list">${list.map((e) => `<div class="trust-row">
      <div>
        <div class="trust-value">${esc(e.name)}<span class="mono" style="color:var(--ghost);font-size:9.5px;margin-left:6px">${esc(e.version || '')}</span></div>
        <div class="trust-note mono" style="word-break:break-all">${esc(e.id)}</div>
        <div class="trust-time">${esc(e.profile)}</div>
      </div>
      <div class="trust-actions" style="opacity:1">
        ${e.host_wide ? '<span class="badge warn" title="声明了 <all_urls> 或等价主机权限：能读写你访问的每个网页">全部网站</span>' : ''}
        ${(e.risky_perms || []).map((p) => `<span class="badge" title="敏感权限：${esc(p)}">${esc(p)}</span>`).join('')}
      </div>
    </div>`).join('')}</div>`).join('');
}

/* ------------------------------------------------------------ 页面：信任与隐私 */

function paintTrust(force = false) {
  const root = $('#trustRoot');
  if (!root) return;
  // 用户正在输入时不要重建，避免 15 秒轮询把光标/内容打断；
  // 添加表单打开期间整块跳过，否则点击提交的瞬间可能被轮询重绘吞掉。
  const ae = document.activeElement;
  if (!force && state.addFormOpen) return;
  if (!force && ae && root.contains(ae) && (ae.tagName === 'INPUT' || ae.tagName === 'SELECT')) return;

  const allowCount = $('#allowCount');
  if (allowCount) allowCount.textContent = state.allow.length ? `${fmt(state.allow.length)} 条` : '';

  const formWrap = $('#allowFormWrap');
  if (formWrap) formWrap.innerHTML = state.addFormOpen ? allowFormHTML() : '';

  const list = $('#allowList');
  if (list) {
    if (!state.allow.length) {
      list.innerHTML = emptyState('shieldCheck', '还没有信任任何程序',
        '当确认某个告警是误报时，可以在告警详情里把文件或路径加入这里，之后不再告警。', 'ok');
    } else {
      list.innerHTML = state.allow.map(allowRow).join('');
    }
  }

  const privacy = $('#privacyBlock');
  if (privacy) {
    if (state.privacy) {
      privacy.innerHTML = privacyHTML(state.privacy);
    } else if (state.privacyError) {
      privacy.innerHTML = `<div class="state" style="min-height:160px;padding:24px">
        <div class="state-icon">${icon('info')}</div>
        <h2 style="font-size:13px">暂时无法读取隐私说明</h2>
        <p>${esc(state.privacyError)}</p>
        <button class="btn sm" data-act="retry-privacy">重试</button>
      </div>`;
    } else {
      privacy.innerHTML = `<div class="skel skel-line" style="width:60%"></div>
        <div class="skel skel-line" style="width:90%;margin-top:10px"></div>
        <div class="skel skel-line" style="width:75%;margin-top:10px"></div>`;
    }
  }

  // Windows 隐私设置体检：复用 posture 数据（group=privacy），不单独发请求
  const privBlock = $('#privSettingBlock');
  if (privBlock) {
    if (state.posture === null) {
      privBlock.innerHTML = state.postureError
        ? `<p class="check-why">暂时读不到体检数据：${esc(state.postureError)}</p>`
        : '<div class="skel skel-line" style="width:70%"></div>';
    } else {
      const priv = state.posture.filter((c) => c.group === 'privacy');
      privBlock.innerHTML = priv.length
        ? `<p class="check-why" style="margin-bottom:10px">这些开关决定 Windows 自己收集什么。它们是知情选择而不是漏洞——这里只陈述现状与改法，不会替你改。</p>
           <div class="check-list">${priv.map(checkRow).join('')}</div>`
        : '<p class="check-why">本机暂无隐私设置体检数据。</p>';
    }
  }

  const about = $('#aboutBlock');
  if (!about) return;
  const s = state.status;
  if (!s) {
    about.innerHTML = '<div class="skel skel-line"></div>';
    return;
  }
  about.innerHTML = `
    <dl class="kv">
      <dt>主机名</dt><dd>${esc(s.hostname || '—')}</dd>
      <dt>操作系统</dt><dd>${esc(s.os_version || '—')}</dd>
      <dt>探针版本</dt><dd>${esc(s.agent_version || '—')}</dd>
      <dt>Agent ID</dt><dd>${esc(s.agent_id || '未注册')}</dd>
    </dl>
    <dl class="kv">
      <dt>规则版本</dt><dd>${esc(ruleVersionLabel(s))} · ${fmt(s.rule_count || 0)} 条</dd>
      <dt>采集器</dt><dd>${esc(s.collector || '—')}</dd>
      <dt>运行时长</dt><dd>${duration(s.uptime_sec)}</dd>
      <dt>总控</dt><dd>${s.enrolled ? esc(s.server_url || '已注册') : '未连接（仅本地）'}</dd>
    </dl>
    <div class="about-actions">
      <button class="btn sm" data-act="copy-diag">${icon('copy')}复制诊断信息</button>
      <button class="btn sm" data-act="${isStale() ? 'retry' : 'scan'}" ${state.scanning ? 'disabled' : ''}>${icon('refresh')}${state.scanning ? '扫描中…' : isStale() ? '重试连接' : '立即扫描'}</button>
      <button class="btn sm ghost" data-act="palette">${icon('command')}命令面板</button>
    </div>
    <p class="privacy-note" style="grid-column:1/-1;margin-top:14px">本地接口只绑定 127.0.0.1，并拒绝跨站请求。访问令牌保存在数据目录的 <code>local.token</code>，仅当前用户可读。</p>`;
}

function allowFormHTML() {
  const isHash = state.allowType === 'hash';
  return `
    <form class="add-form" data-form="allow" novalidate>
      <div class="seg" role="group" aria-label="信任类型">
        <button type="button" data-act="allow-type" data-type="path" class="${!isHash ? 'on' : ''}">路径</button>
        <button type="button" data-act="allow-type" data-type="hash" class="${isHash ? 'on' : ''}">SHA256</button>
      </div>
      <input id="allowValue" name="value" type="text" autocomplete="off" spellcheck="false"
        placeholder="${isHash ? '64 位 SHA256 哈希' : '绝对路径，例如 C:\\Program Files\\App\\app.exe'}"
        value="${esc(state.addValue)}" aria-label="信任对象" />
      <input id="allowNote" name="note" type="text" autocomplete="off"
        placeholder="备注（可选）" value="${esc(state.addNote)}" aria-label="备注" />
      <div style="display:flex;gap:6px">
        <button class="btn sm primary" type="submit">添加</button>
        <button class="btn sm ghost" type="button" data-act="cancel-add">取消</button>
      </div>
      ${state.addError ? `<div class="form-error">${esc(state.addError)}</div>` : ''}
    </form>`;
}

function allowRow(e) {
  const source = e.source === 'server' ? '服务端下发' : '本机添加';
  const typeLabel = e.type === 'hash' ? '哈希' : e.type === 'path' ? '路径' : e.type;
  return `
    <div class="trust-row">
      <span class="badge">${esc(typeLabel)}</span>
      <div>
        <div class="trust-value">${esc(e.value)}</div>
        <div class="trust-note">${esc(e.note || '无备注')}</div>
        <div class="trust-time">${fullTime(e.created_at)} · ${esc(source)}</div>
      </div>
      <div class="trust-actions">
        <button class="icon-btn sm" data-act="remove-allow" data-type="${esc(e.type)}" data-value="${esc(e.value)}" data-note="${esc(e.note || '')}" data-source="${esc(e.source || '')}" aria-label="移除这条信任">${icon('trash')}</button>
      </div>
    </div>`;
}

function privacyHTML(p) {
  const collected = (p.collected || []).map((c) => `
    <li>${icon('check')}<span><b>${esc(c.item)}</b><br>${esc(c.detail)}</span></li>`).join('');
  const notCollected = (p.not_collected || []).map((x) => `
    <li>${icon('x')}<span>${esc(x)}</span></li>`).join('');
  return `
    <div class="privacy">
      <div>
        <h3>${icon('eye')}会采集</h3>
        <ul>${collected}</ul>
      </div>
      <div>
        <h3>${icon('eyeOff')}不会采集</h3>
        <ul>${notCollected}</ul>
      </div>
    </div>
    <div class="privacy-note">
      <b>脱敏：</b>${esc(p.redaction || '—')}<br>
      <b>存放：</b>${esc(p.storage || '—')}
    </div>`;
}

/* ------------------------------------------------------------ 告警抽屉 */

function ensureDrawer() {
  if ($('#drawer')) return;
  $('#overlayRoot').insertAdjacentHTML('beforeend', `
    <div class="scrim" id="scrim" data-act="close-drawer"></div>
    <aside class="drawer" id="drawer" role="dialog" aria-modal="true" aria-labelledby="drawerTitle">
      <div class="drawer-head" id="drawerHead"></div>
      <div class="drawer-body" id="drawerBody"></div>
      <div class="drawer-foot" id="drawerFoot"></div>
    </aside>`);
}

async function openAlert(id) {
  if (!id) return;
  try {
    const a = await api(`/api/local/alerts/${encodeURIComponent(id)}`);
    state.drawerAlert = a;
    ensureDrawer();
    state.lastFocus = document.activeElement;
    renderDrawer(a);
    $('#scrim').classList.add('show');
    $('#drawer').classList.add('show');
    document.body.classList.add('drawer-open');
    document.body.style.overflow = 'hidden';
    $('#drawerClose')?.focus();
  } catch (e) {
    toast(e.message, 'err');
  }
}

function renderDrawer(a) {
  const ev = a.evidence || {};
  const p = ev.process || {};
  const parts = [
    ['静态', Number(ev.static_score) || 0, 'var(--chart-1)'],
    ['关键词', Number(ev.keyword_score) || 0, 'var(--chart-2)'],
    ['规则', Number(ev.rule_score) || 0, 'var(--chart-3)'],
    ['血缘', Number(ev.lineage_score) || 0, 'var(--chart-4)'],
  ];
  const score = Number(a.score) || 0;
  const bar = parts.map(([name, v, c]) => `<i style="width:${Math.min(100, Math.max(0, v))}%;background:${c}" title="${esc(name)} ${v}"></i>`).join('');
  const legend = parts.map(([name, v, c]) => `<span><i style="background:${c}"></i>${esc(name)} ${v}</span>`).join('');

  const sigs = (ev.signals || []).map((s) => `
    <div class="signal">
      <span class="signal-layer">${esc(layerLabel(s.layer))}</span>
      <span class="signal-body"><b>${esc(s.name)}</b>${s.note ? `<div class="signal-note">${esc(s.note)}</div>` : ''}</span>
      <span class="signal-pts">+${esc(s.score)}</span>
    </div>`).join('') || '<div class="faint" style="font-size:11px">没有可分解的独立信号</div>';

  const ancestry = (ev.ancestry || []).map((n) => `
    <div class="tree-node">
      <span class="tree-mark"></span>
      <b>${esc(n.name)}</b> <span class="muted">PID ${esc(n.pid)}</span>
      ${n.path ? `<div class="tree-path">${esc(n.path)}</div>` : ''}
    </div>`).join('') || '<div class="faint" style="font-size:11px">没有记录到祖先进程</div>';

  const net = (ev.network || []).map((c) => `
    <tr>
      <td>${esc(c.proto)}</td>
      <td>${esc(c.local_ip)}:${esc(c.local_port)}</td>
      <td>${esc(c.remote_ip)}:${esc(c.remote_port)}</td>
      <td>${esc(c.state)}</td>
    </tr>`).join('');

  const ruleTags = (a.rule_ids || []).map((id) => `<span class="badge">${esc(id)}</span>`).join('');
  const mitreTags = (a.mitre || []).map((id) => `<span class="badge">${esc(id)}</span>`).join('');
  const evidence = (ruleTags || mitreTags) ? `
    <section class="d-section">
      <h3>检测依据</h3>
      <div class="evidence-tags">
        ${ruleTags ? `<div class="row"><span class="tag-label">规则</span>${ruleTags}</div>` : ''}
        ${mitreTags ? `<div class="row"><span class="tag-label">ATT&CK</span>${mitreTags}</div>` : ''}
      </div>
    </section>` : '';

  const hash = p.hash_sha256 || a.hash_sha256 || '';
  const path = p.path || a.image_path || '';
  const signature = p.signature_ok ? '校验通过' : p.signed ? '有签名但不可信' : '无数字签名';

  $('#drawerHead').innerHTML = `
    <div style="flex:1;min-width:0">
      <h2 id="drawerTitle">${esc(a.title)}</h2>
      <div class="drawer-sub">
        <span class="badge ${severityBadgeClass(a.severity)}">${esc(sevLabel(a.severity))}</span>
        <span class="badge ${a.verdict === 'malicious' ? 'crit' : a.verdict === 'suspicious' ? 'warn' : 'ok'}">${esc(verdictLabel(a.verdict))}</span>
        <span>${fullTime(a.occurred_at)}</span>
        <span>· ${a.sent ? '已上报' : '待上报'}</span>
        <span class="mono">· ID ${esc(a.id)}</span>
      </div>
    </div>
    <button class="icon-btn" id="drawerClose" data-act="close-drawer" aria-label="关闭详情">${icon('x')}</button>`;

  $('#drawerBody').innerHTML = `
    <section class="d-section">
      <h3>结论</h3>
      <p class="summary-text">${esc(a.summary || '探针没有提供额外说明。建议结合下方信号与进程身份判断。')}</p>
    </section>

    <section class="d-section">
      <h3>为什么是 ${score} 分</h3>
      <div class="score-block">
        <div class="score-head">
          <span class="score-big">${score}</span>
          <span class="score-max">/ 100</span>
          <span class="score-verdict">${esc(verdictLabel(a.verdict))} · ${esc(sevLabel(a.severity))}</span>
        </div>
        <div class="score-bar-lg">
          ${bar}
          <span class="score-threshold" style="left:${ALERT_THRESHOLD}%" title="告警线 ${ALERT_THRESHOLD} 分"></span>
        </div>
        <div class="legend">
          ${legend}
          <span style="margin-left:auto;color:var(--muted)">告警线 ${ALERT_THRESHOLD}</span>
        </div>
        <p class="score-explain">评分由静态、关键词、规则、血缘四层信号合成。${ALERT_THRESHOLD} 分及以上会记录为告警；分数越高，越建议优先处理。</p>
      </div>
    </section>

    <section class="d-section">
      <h3>命中信号</h3>
      ${sigs}
    </section>

    ${evidence}

    <section class="d-section">
      <h3>进程身份</h3>
      <dl class="kv">
        <dt>进程名</dt><dd>${esc(p.name || a.process_name || '—')}</dd>
        <dt>PID / PPID</dt><dd>${esc(p.pid || a.pid || '—')} / ${esc(p.ppid || a.ppid || '—')}</dd>
        <dt>镜像路径</dt><dd>${esc(path || '—')}</dd>
        <dt>运行账号</dt><dd>${esc(p.user || a.user || '—')}</dd>
        <dt>SHA256</dt><dd>${esc(hash || '—')}${hash ? ` <button class="icon-btn sm" data-act="copy-text" data-copy="${esc(hash)}" aria-label="复制哈希">${icon('copy')}</button>` : ''}</dd>
        <dt>数字签名</dt><dd>${esc(signature)}</dd>
        <dt>签名主体</dt><dd>${esc(p.signer || a.signer || '—')}</dd>
        <dt>高权限</dt><dd>${p.elevated ? '是' : '否'}</dd>
        <dt>启动时间</dt><dd>${fullTime(p.start_time)}</dd>
      </dl>
      ${(p.cmdline || a.cmdline) ? `<pre class="code" style="margin-top:10px">${esc(p.cmdline || a.cmdline)}</pre>` : ''}
    </section>

    <section class="d-section">
      <h3>血缘链</h3>
      <div class="tree">${ancestry}</div>
    </section>

    ${net ? `<section class="d-section">
      <h3>网络连接</h3>
      <table class="meta-table">
        <thead><tr><th>协议</th><th>本地</th><th>远端</th><th>状态</th></tr></thead>
        <tbody>${net}</tbody>
      </table>
    </section>` : ''}`;

  const actions = [];
  if (hash) actions.push(`<button class="btn primary" data-act="allow-alert" data-kind="hash">这是正常程序</button>`);
  if (path) actions.push(`<button class="btn ${hash ? 'ghost' : 'primary'}" data-act="allow-alert" data-kind="path">信任此路径</button>`);
  actions.push(`<button class="btn ghost" data-act="copy-alert">${icon('copy')}复制诊断信息</button>`);
  $('#drawerFoot').innerHTML = `
    ${actions.join('')}
    <span class="spacer"></span>
    <button class="btn ghost" data-act="close-drawer">关闭</button>`;
}

function closeDrawer() {
  $('#scrim')?.classList.remove('show');
  $('#drawer')?.classList.remove('show');
  document.body.classList.remove('drawer-open');
  document.body.style.overflow = '';
  if (state.lastFocus && typeof state.lastFocus.focus === 'function') {
    try { state.lastFocus.focus(); } catch (e) { /* 元素可能已被重绘 */ }
  }
  state.lastFocus = null;
  state.drawerAlert = null;
}

async function allowAlert(kind) {
  const a = state.drawerAlert;
  if (!a) return;
  const ev = a.evidence || {};
  const p = ev.process || {};
  const isHash = kind === 'hash';
  const value = isHash ? (p.hash_sha256 || a.hash_sha256 || '') : (p.path || a.image_path || '');
  if (!value) return toast(isHash ? '这条告警没有哈希' : '这条告警没有镜像路径', 'err');

  const ok = await confirmDialog({
    title: isHash ? '把这个文件加入信任？' : '信任这个路径下的程序？',
    message: isHash
      ? `按 SHA256 加白：<br><code>${esc(value)}</code><br><br>加入后，这个文件在本机不再告警。只在你确认它可信时操作。`
      : `路径下任意程序都不再告警：<br><code>${esc(value)}</code><br><br>请确认范围可接受。之后可以在「信任与隐私」里移除。`,
    danger: true,
    okText: '加入信任',
  });
  if (!ok) return;

  try {
    await api('/api/local/allowlist', {
      method: 'POST',
      body: { type: isHash ? 'hash' : 'path', value, note: `来自告警：${a.title}` },
    });
    toast('已加入信任列表', 'ok', {
      label: '撤销',
      run: async () => {
        try {
          await api(`/api/local/allowlist?type=${encodeURIComponent(isHash ? 'hash' : 'path')}&value=${encodeURIComponent(value)}`, { method: 'DELETE' });
          toast('已撤销', 'ok');
          refreshAllow();
        } catch (e) { toast(e.message, 'err'); }
      },
    });
    closeDrawer();
    refreshAllow();
  } catch (e) {
    toast(e.message, 'err');
  }
}

function copyAlertText(a) {
  if (!a) return '';
  const ev = a.evidence || {};
  const p = ev.process || {};
  const sigs = (ev.signals || []).map((s) => `- [${layerLabel(s.layer)}] ${s.name} +${s.score}${s.note ? `（${s.note}）` : ''}`).join('\n');
  return [
    `Z-EDR 告警：${a.title}`,
    `时间：${fullTime(a.occurred_at)}`,
    `严重度：${sevLabel(a.severity)} / 判定：${verdictLabel(a.verdict)} / 评分：${a.score}`,
    `进程：${p.name || a.process_name || '—'} (PID ${p.pid || a.pid || '—'})`,
    `路径：${p.path || a.image_path || '—'}`,
    `SHA256：${p.hash_sha256 || a.hash_sha256 || '—'}`,
    `签名：${p.signature_ok ? '校验通过' : p.signed ? '有签名但不可信' : '无数字签名'}`,
    `命令行：${p.cmdline || a.cmdline || '—'}`,
    `结论：${a.summary || '—'}`,
    sigs ? `信号：\n${sigs}` : '',
  ].filter(Boolean).join('\n');
}

/* ------------------------------------------------------------ 确认框 */

function confirmDialog({ title, message, danger = false, okText = '确认', cancelText = '取消' }) {
  return new Promise((resolve) => {
    const wrap = document.createElement('div');
    wrap.className = 'confirm-scrim';
    wrap.innerHTML = `
      <div class="confirm" role="alertdialog" aria-modal="true" aria-label="${esc(title)}">
        <div class="confirm-title ${danger ? 'danger' : ''}">
          ${icon(danger ? 'alertOctagon' : 'alertTriangle')}${esc(title)}
        </div>
        <div class="confirm-msg">${message}</div>
        <div class="confirm-actions">
          <button class="btn" data-confirm="cancel">${esc(cancelText)}</button>
          <button class="btn ${danger ? 'danger' : 'primary'}" data-confirm="ok">${esc(okText)}</button>
        </div>
      </div>`;
    const cleanup = (v) => {
      wrap.remove();
      document.removeEventListener('keydown', onKey, true);
      resolve(v);
    };
    const onKey = (e) => {
      if (e.key === 'Tab') { trapFocus(wrap, e); return; }
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); cleanup(false); }
      if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); cleanup(true); }
    };
    wrap.addEventListener('click', (e) => {
      if (e.target === wrap) { cleanup(false); return; }
      const b = e.target.closest('[data-confirm]');
      if (b) cleanup(b.dataset.confirm === 'ok');
    });
    document.addEventListener('keydown', onKey, true);
    document.body.appendChild(wrap);
    wrap.querySelector('[data-confirm="ok"]')?.focus();
  });
}

/* ------------------------------------------------------------ Toast */

function toast(msg, kind = 'ok', action = null) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  const ico = kind === 'err' ? 'alertOctagon' : kind === 'warn' ? 'alertTriangle' : kind === 'info' ? 'info' : 'check';
  el.innerHTML = `<span class="t-ico">${icon(ico)}</span><span class="toast-body">${esc(msg)}</span>`;
  if (action && action.label) {
    const b = document.createElement('button');
    b.className = 'toast-action';
    b.textContent = action.label;
    b.addEventListener('click', async () => {
      dismiss();
      try { await action.run(); } catch (e) { toast(e.message || '操作失败', 'err'); }
    });
    el.appendChild(b);
  }
  $('#toasts').appendChild(el);
  const timer = setTimeout(dismiss, action ? 6000 : 3800);
  function dismiss() {
    clearTimeout(timer);
    el.classList.add('out');
    setTimeout(() => el.remove(), 260);
  }
}

function announce(msg) {
  const el = $('#liveRegion');
  if (!el) return;
  el.textContent = '';
  setTimeout(() => { el.textContent = msg; }, 30);
}

// 浮层内的 Tab 循环：抽屉/命令面板都是 aria-modal，
// 焦点不能跑到背后的页面上。
function trapFocus(container, e) {
  if (!container || e.key !== 'Tab') return;
  const nodes = Array.from(container.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  )).filter((el) => el.offsetParent !== null || el === document.activeElement);
  if (!nodes.length) return;
  const first = nodes[0];
  const last = nodes[nodes.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

/* ------------------------------------------------------------ 命令面板 */

function paletteActions() {
  const isDark = document.documentElement.dataset.theme !== 'light';
  return [
    { label: '前往总览', icon: 'grid', hint: '页面', run: () => go('overview') },
    { label: '前往活动', icon: 'activity', hint: '页面', run: () => go('activity') },
    { label: '前往进程', icon: 'chip', hint: '页面', run: () => go('processes') },
    { label: '前往驻留', icon: 'layers', hint: '页面', run: () => go('persist') },
    { label: '前往安全体检', icon: 'clipboardCheck', hint: '页面', run: () => go('posture') },
    { label: '前往软件资产', icon: 'box', hint: '页面', run: () => go('apps') },
    { label: '前往浏览器', icon: 'globe', hint: '页面', run: () => go('browser') },
    { label: '前往信任与隐私', icon: 'shieldCheck', hint: '页面', run: () => go('trust') },
    { label: isStale() ? '重试连接' : '立即扫描', icon: 'refresh', hint: '动作', run: isStale() ? initialLoad : scan },
    { label: `切换到${isDark ? '浅色' : '深色'}主题`, icon: isDark ? 'sun' : 'moon', hint: '外观', run: toggleTheme },
    { label: '复制诊断信息', icon: 'copy', hint: '动作', run: () => copyText(diagText(), '诊断信息已复制') },
    { label: '查看隐私说明', icon: 'eye', hint: '页面', run: () => {
      go('trust');
      setTimeout(() => $('#privacyBlock')?.scrollIntoView({ block: 'start', behavior: 'smooth' }), 80);
    } },
  ];
}

function openPalette() {
  if (state.palette) return;
  state.palette = { query: '', index: 0, actions: paletteActions() };
  $('#overlayRoot').insertAdjacentHTML('beforeend', `
    <div class="palette-scrim" id="paletteScrim">
      <div class="palette" role="dialog" aria-modal="true" aria-label="命令面板">
        <div class="palette-input">
          ${icon('search')}
          <input id="paletteInput" type="text" autocomplete="off" spellcheck="false" placeholder="输入命令或页面名称…" aria-label="搜索命令" />
          <kbd>Esc</kbd>
        </div>
        <div class="palette-list" id="paletteList"></div>
        <div class="palette-foot">
          <span><kbd>↑</kbd> <kbd>↓</kbd> 选择</span>
          <span><kbd>Enter</kbd> 执行</span>
          <span class="spacer"></span>
          <span>${state.status ? esc(state.status.hostname) : ''}</span>
        </div>
      </div>
    </div>`);
  $('#paletteScrim').addEventListener('click', (e) => {
    if (e.target.id === 'paletteScrim') closePalette();
  });
  renderPaletteList();
  $('#paletteInput')?.focus();
}

function filteredPalette() {
  if (!state.palette) return [];
  const q = state.palette.query.trim().toLowerCase();
  return q ? state.palette.actions.filter((a) => `${a.label} ${a.hint}`.toLowerCase().includes(q)) : state.palette.actions;
}

function renderPaletteList() {
  const list = $('#paletteList');
  if (!list || !state.palette) return;
  const items = filteredPalette();
  if (state.palette.index >= items.length) state.palette.index = Math.max(0, items.length - 1);
  if (!items.length) {
    list.innerHTML = '<div class="palette-empty">没有匹配的命令</div>';
    return;
  }
  list.innerHTML = items.map((a, i) => `
    <div class="palette-item ${i === state.palette.index ? 'on' : ''}" data-act="palette-run" data-index="${i}" role="option" aria-selected="${i === state.palette.index}">
      ${icon(a.icon)}
      <span>${esc(a.label)}</span>
      <span class="hint">${esc(a.hint)}</span>
    </div>`).join('');
  const on = list.querySelector('.palette-item.on');
  if (on) on.scrollIntoView({ block: 'nearest' });
}

function runPalette(index) {
  const items = filteredPalette();
  const a = items[index];
  if (!a) return;
  closePalette();
  a.run();
}

function closePalette() {
  $('#paletteScrim')?.remove();
  state.palette = null;
}

/* ------------------------------------------------------------ 主题 */

function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  const sysLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  setTheme(saved || (sysLight ? 'light' : 'dark'), false);
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = () => { if (!localStorage.getItem(THEME_KEY)) setTheme(mq.matches ? 'light' : 'dark', false); };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }
}

function setTheme(theme, persist = true) {
  const light = theme === 'light';
  document.documentElement.classList.toggle('light', light);
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  if (persist) localStorage.setItem(THEME_KEY, light ? 'light' : 'dark');
  const btn = $('#themeBtn');
  if (btn) {
    btn.innerHTML = icon(light ? 'moon' : 'sun');
    btn.setAttribute('aria-label', light ? '切换到深色主题' : '切换到浅色主题');
    btn.title = light ? '切换到深色主题' : '切换到浅色主题';
  }
}

function toggleTheme() {
  setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light', true);
}

/* ------------------------------------------------------------ 扫描 / 复制 */

async function scan() {
  if (state.scanning) return;
  state.scanning = true;
  paintRoute(true);
  updateChrome();
  try {
    await api('/api/local/rescan', { method: 'POST' });
    toast('已开始全量扫描', 'ok');
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    setTimeout(() => {
      state.scanning = false;
      paintRoute(true);
      updateChrome();
    }, 1200);
  }
}

async function copyText(text, okMsg = '已复制') {
  if (!text) return toast('没有可复制的内容', 'warn');
  try {
    await navigator.clipboard.writeText(text);
    toast(okMsg, 'ok');
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px;top:0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      toast(okMsg, 'ok');
    } catch (err) {
      toast('复制失败，请手动选择文本', 'err');
    } finally {
      ta.remove();
    }
  }
}

function diagText() {
  const s = state.status || {};
  const st = s.stats || {};
  return [
    'Z-EDR 本机防护诊断信息',
    `主机：${s.hostname || '—'} / ${s.os_version || '—'}`,
    `探针：${s.agent_version || '—'}（${s.agent_id || '未注册'}）`,
    `规则：${ruleVersionLabel(s)} · ${s.rule_count || 0} 条`,
    `基线：${s.baseline_size || 0} 样本 / IOC ${s.ioc_count || 0} 条`,
    `检测：扫描 ${st.scanned || 0} / 命中 ${st.fired || 0} / 抑制 ${st.suppressed || 0}`,
    `连接：${s.online ? '已连接总控' : s.enrolled ? '总控离线' : '仅本地模式'}`,
    `采集器：${s.collector || '—'}`,
    `时间：${fullTime(new Date().toISOString())}`,
  ].join('\n');
}

/* ------------------------------------------------------------ 令牌门 */

function showTokenGate() {
  if ($('#tokenGate')) return;
  $('#overlayRoot').insertAdjacentHTML('beforeend', `
    <div class="gate" id="tokenGate">
      <div class="gate-card">
        <div class="gate-brand">${icon('shield')}<span>Z-EDR · 本机防护</span></div>
        <div class="gate-icon">${icon('key')}</div>
        <h2>需要访问令牌</h2>
        <p>本地接口只允许这台电脑上的授权程序访问。令牌由探针自动生成，位于数据目录的 <code>local.token</code> 文件。</p>
        <p class="gate-path">%LOCALAPPDATA%\\zedr\\local.token</p>
        <form class="gate-form" data-form="token">
          <input type="password" id="tokenInput" placeholder="粘贴令牌" autocomplete="off" aria-label="访问令牌" />
          <button class="btn primary" type="submit">继续</button>
        </form>
        <p class="gate-note">桌面端会自动填入令牌；这里只用于浏览器直接访问。</p>
      </div>
    </div>`);
  $('#tokenInput')?.focus();
}

function removeTokenGate() {
  $('#tokenGate')?.remove();
}

/* ------------------------------------------------------------ 壳 / 状态 */

function updateChrome() {
  const s = state.status;
  const stale = isStale();
  const route = ROUTES[state.route] || ROUTES.overview;

  $('#pageTitle').textContent = route.title;
  $('#pageSub').textContent = route.sub;
  document.title = `${route.title} · Z-EDR 本机防护`;

  $$('.nav-item').forEach((a) => {
    const on = a.dataset.nav === state.route;
    a.classList.toggle('active', on);
    if (on) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });

  const recent = recentAlerts();
  const critical = recent.filter((a) => a.severity === 'critical').length;
  const high = recent.filter((a) => a.severity === 'high').length;
  const badge = $('#navAlertCount');
  if (badge) {
    const n = state.alerts.length;
    badge.hidden = n === 0;
    badge.textContent = n > 99 ? '99+' : String(n);
    badge.className = 'nav-count' + (critical > 0 ? ' crit' : high > 0 ? ' warn' : '');
  }

  const sideState = $('#sideState');
  const sideDot = $('#sideDot');
  if (!s) {
    sideState.textContent = '正在连接';
    sideDot.className = 'dot';
  } else if (stale) {
    sideState.textContent = '探针无响应';
    sideDot.className = 'dot bad';
  } else if (s.online) {
    sideState.textContent = '已连接总控';
    sideDot.className = 'dot ok';
  } else if (s.enrolled) {
    sideState.textContent = '总控离线';
    sideDot.className = 'dot warn';
  } else {
    sideState.textContent = '仅本地模式';
    sideDot.className = 'dot warn';
  }
  $('#sideVersion').textContent = s ? `Z-EDR v${s.agent_version || '—'}` : 'Z-EDR · —';

  const host = $('#hostChip');
  if (s && s.hostname) {
    host.hidden = false;
    host.textContent = `${s.hostname} · ${s.os_version || ''}`;
    host.title = `${s.hostname} · ${s.os_version || ''}`;
  } else {
    host.hidden = true;
  }

  const dot = $('#liveDot');
  const fresh = $('#freshText');
  if (!s) {
    dot.className = 'live-dot';
    fresh.textContent = '正在连接';
  } else if (stale) {
    dot.className = 'live-dot bad';
    fresh.textContent = `连接中断 · ${clockTime(state.lastFresh)}`;
  } else {
    const age = Date.now() - state.lastFresh;
    dot.className = 'live-dot ' + (age < 10000 ? 'ok' : 'warn');
    fresh.textContent = `更新于 ${clockTime(state.lastFresh)}`;
  }

  const scanBtn = $('#scanBtn');
  if (scanBtn) {
    const retryMode = stale || (!s && !!state.error);
    scanBtn.disabled = state.scanning;
    scanBtn.classList.toggle('scanning', state.scanning);
    scanBtn.dataset.act = retryMode ? 'retry' : 'scan';
    scanBtn.innerHTML = `${icon('refresh')}${state.scanning ? '扫描中…' : retryMode ? '重试' : '扫描'}`;
  }
}

function tickRel() {
  $$('[data-rel]').forEach((el) => { el.textContent = rel(el.dataset.rel); });
  updateChrome();
  // 长时间没有新数据时，把总览/活动切到"数据已过期"的叙述，
  // 避免界面在探针失联时仍然显示"一切正常"。失联是时间推导的，
  // 不在数据签名里，所以这里强制重绘。
  if (isStale() && (state.route === 'overview' || state.route === 'activity')) paintRoute(true);
}

/* ------------------------------------------------------------ 事件 */

function onHash() {
  state.route = routeFromHash();
  state.renderedRoute = null;
  state.expandedPid = null;
  if (state.route !== 'trust') {
    state.addFormOpen = false;
    state.addError = '';
  }
  closeDrawer();
  closePalette();
  renderRoute(true);
}

async function onClick(e) {
  const t = e.target.closest('[data-act]');
  if (!t) return;
  const act = t.dataset.act;
  switch (act) {
    case 'scan': scan(); break;
    case 'theme': toggleTheme(); break;
    case 'palette': openPalette(); break;
    case 'open-alert': openAlert(t.dataset.id); break;
    case 'close-drawer': closeDrawer(); break;
    case 'toggle-proc': {
      const pid = Number(t.dataset.pid);
      state.expandedPid = state.expandedPid === pid ? null : pid;
      state.focusAfterPaint = true;
      paintProcesses();
      break;
    }
    case 'open-watch':
      state.procQuery = t.dataset.name || '';
      state.procSort = 'score';
      go('processes');
      break;
    case 'toggle-group': {
      const title = t.dataset.title || '';
      if (state.collapsedGroups.has(title)) state.collapsedGroups.delete(title);
      else state.collapsedGroups.add(title);
      paintActivity();
      break;
    }
    case 'allow-proc': allowPath(t.dataset.path || ''); break;
    case 'copy-path': copyText(t.dataset.copy, '路径已复制'); break;
    case 'allow-alert': allowAlert(t.dataset.kind); break;
    case 'copy-alert': copyText(copyAlertText(state.drawerAlert), '告警信息已复制'); break;
    case 'copy-text': copyText(t.dataset.copy, '已复制'); break;
    case 'copy-diag': copyText(diagText(), '诊断信息已复制'); break;
    case 'remove-allow': removeAllow(t.dataset); break;
    case 'add-form':
      state.addFormOpen = true;
      state.addError = '';
      paintTrust(true);
      setTimeout(() => $('#allowValue')?.focus(), 0);
      break;
    case 'cancel-add':
      state.addFormOpen = false;
      state.addFormError = '';
      state.addError = '';
      paintTrust(true);
      break;
    case 'allow-type':
      state.allowType = t.dataset.type || 'path';
      state.addError = '';
      paintTrust(true);
      setTimeout(() => $('#allowValue')?.focus(), 0);
      break;
    case 'filter':
      state.activityFilter = t.dataset.filter || 'all';
      paintActivity();
      break;
    case 'persist-filter':
      state.persistFilter = t.dataset.filter || 'all';
      paintPersist(true);
      break;
    case 'refresh-hygiene': {
      // 显式重跑体检：清缓存重新拉取（驻留画像的签名缓存也在 Agent 侧
      // 按 (path,size,mtime) 失效，文件变了自然会重验）
      if (state.route === 'posture') {
        state.posture = null;
        state.exposure = null;
        state.postureError = '';
        refreshPosture();
        paintPosture(true);
      } else if (state.route === 'apps') {
        state.apps = null;
        state.appsError = '';
        refreshApps();
        paintApps(true);
      } else if (state.route === 'browser') {
        state.browser = null;
        state.browserError = '';
        refreshBrowser();
        paintBrowser(true);
      } else if (state.route === 'persist') {
        state.persistAudit = null;
        state.persistAuditError = '';
        refreshPersistAudit();
        paintPersist(true);
      }
      toast('正在重新体检…', 'info');
      break;
    }
    case 'sort':
      state.procSort = t.dataset.sort || 'score';
      paintProcesses();
      break;
    case 'palette-run':
      runPalette(Number(t.dataset.index));
      break;
    case 'retry':
      state.error = null;
      state.loading = !state.status;
      renderRoute(true);
      initialLoad();
      break;
    case 'retry-privacy':
      refreshPrivacy();
      break;
    case 'win-min':
      window.zedrHostMinimize?.();
      break;
    case 'win-max': {
      const z = await window.zedrHostMaximizeToggle?.();
      renderWinControls(Boolean(z));
      break;
    }
    case 'win-close':
      // 关闭 = 面板进程退出：WebView2 内存随之释放；
      // 托盘是独立常驻进程（Notifier），探针不受任何影响。
      window.zedrHostClose?.();
      break;
  }
}

function onKey(e) {
  // 命令面板：Ctrl/Cmd + K
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (state.palette) closePalette();
    else openPalette();
    return;
  }

  if (state.palette) {
    const items = filteredPalette();
    if (e.key === 'Tab') {
      e.preventDefault();
      trapFocus($('.palette'), e);
      return;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      closePalette();
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      state.palette.index = items.length ? (state.palette.index + 1) % items.length : 0;
      renderPaletteList();
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      state.palette.index = items.length ? (state.palette.index - 1 + items.length) % items.length : 0;
      renderPaletteList();
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      runPalette(state.palette.index);
      return;
    }
  }

  // 浮层关闭优先级：确认框 > 命令面板 > 抽屉
  if ($('#drawer')?.classList.contains('show') && !$('.confirm-scrim') && !state.palette) {
    if (e.key === 'Tab') {
      e.preventDefault();
      trapFocus($('#drawer'), e);
      return;
    }
  }
  if (e.key === 'Escape') {
    if ($('.confirm-scrim')) return; // 确认框自己处理
    if ($('#paletteScrim')) { closePalette(); return; }
    if ($('#drawer')?.classList.contains('show')) { closeDrawer(); return; }
    if (state.addFormOpen && state.route === 'trust') {
      state.addFormOpen = false;
      state.addError = '';
      paintTrust(true);
      return;
    }
  }

  // 进程表格键盘导航
  const focusRow = document.activeElement && document.activeElement.closest && document.activeElement.closest('tr.row');
  if (focusRow) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      focusRow.click();
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const rows = $$('#procBody tr.row');
      const i = rows.indexOf(focusRow);
      const next = rows[i + (e.key === 'ArrowDown' ? 1 : -1)];
      if (next) next.focus();
      return;
    }
  }

  // 通用可交互行：Enter / Space 触发
  if ((e.key === 'Enter' || e.key === ' ') && document.activeElement?.matches?.('[data-act][role="button"]')) {
    e.preventDefault();
    document.activeElement.click();
    return;
  }

  // 快捷搜索：/ 聚焦当前页搜索框
  if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
    const tag = (document.activeElement?.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
    const search = state.route === 'processes' ? $('#procSearch')
      : state.route === 'activity' ? $('#activitySearch')
        : state.route === 'persist' ? $('#persistSearch')
          : state.route === 'apps' ? $('#appsSearch')
            : null;
    if (search) {
      e.preventDefault();
      search.focus();
      search.select();
    }
  }
}

function onInput(e) {
  const t = e.target;
  if (t.id === 'procSearch') {
    state.procQuery = t.value;
    paintProcesses();
  } else if (t.id === 'activitySearch') {
    state.activityQuery = t.value;
    paintActivity();
  } else if (t.id === 'allowValue') {
    state.addValue = t.value;
    if (state.addError) {
      state.addError = '';
      t.closest('form')?.querySelector('.form-error')?.remove();
    }
  } else if (t.id === 'allowNote') {
    state.addNote = t.value;
  } else if (t.id === 'persistSearch') {
    state.persistQuery = t.value;
    paintPersist();
  } else if (t.id === 'appsSearch') {
    state.appsQuery = t.value;
    paintApps();
  } else if (t.id === 'paletteInput' && state.palette) {
    state.palette.query = t.value;
    state.palette.index = 0;
    renderPaletteList();
  }
}

async function onSubmit(e) {
  const form = e.target.closest('[data-form]');
  if (!form) return;

  if (form.dataset.form === 'token') {
    e.preventDefault();
    const v = form.querySelector('input')?.value.trim() || '';
    if (!v) return;
    localStorage.setItem(TOKEN_KEY, v);
    LOCAL_TOKEN = v;
    removeTokenGate();
    state.needToken = false;
    state.error = null;
    state.loading = !state.status;
    initialLoad();
    return;
  }

  if (form.dataset.form === 'allow') {
    e.preventDefault();
    await submitAllow();
  }
}

async function submitAllow() {
  const value = (state.addValue || '').trim();
  const note = (state.addNote || '').trim();
  let err = '';
  if (!value) {
    err = state.allowType === 'hash' ? '请填写 SHA256 哈希' : '请填写绝对路径';
  } else if (state.allowType === 'hash' && !/^[a-f0-9]{64}$/i.test(value)) {
    err = 'SHA256 应为 64 位十六进制字符';
  } else if (state.allowType === 'path' && !/^([a-zA-Z]:\\|\\\\|\/)/.test(value)) {
    err = '请填写绝对路径（例如 C:\\Program Files\\App\\app.exe）';
  }
  if (err) {
    state.addError = err;
    paintTrust(true);
    setTimeout(() => $('#allowValue')?.focus(), 0);
    return;
  }

  try {
    await api('/api/local/allowlist', {
      method: 'POST',
      body: { type: state.allowType, value: state.allowType === 'hash' ? value.toLowerCase() : value, note: note || '手动添加' },
    });
    state.addFormOpen = false;
    state.addValue = '';
    state.addNote = '';
    state.addError = '';
    toast('已加入信任列表', 'ok');
    await refreshAllow();
    paintTrust(true);
  } catch (e) {
    state.addError = e.message;
    paintTrust(true);
    setTimeout(() => $('#allowValue')?.focus(), 0);
  }
}

async function allowPath(path) {
  if (!path) return toast('这个进程没有可用的镜像路径', 'err');
  const ok = await confirmDialog({
    title: '信任这个路径下的程序？',
    message: `路径下任意程序都不再告警：<br><code>${esc(path)}</code><br><br>请确认范围可接受。之后可以在「信任与隐私」里移除。`,
    danger: true,
    okText: '加入信任',
  });
  if (!ok) return;
  try {
    await api('/api/local/allowlist', {
      method: 'POST',
      body: { type: 'path', value: path, note: '从进程列表添加' },
    });
    toast('已加入信任列表', 'ok', {
      label: '撤销',
      run: async () => {
        try {
          await api(`/api/local/allowlist?type=path&value=${encodeURIComponent(path)}`, { method: 'DELETE' });
          toast('已撤销', 'ok');
          refreshAllow();
        } catch (e) { toast(e.message, 'err'); }
      },
    });
    await refreshAllow();
    paintRoute();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function removeAllow(ds) {
  const type = ds.type;
  const value = ds.value;
  const note = ds.note || '';
  const fromServer = ds.source === 'server';
  const ok = await confirmDialog({
    title: '从信任列表移除？',
    message: `移除后，相关检测会重新生效：<br><code>${esc(value)}</code>${fromServer ? '<br><br>这条记录由服务端下发；如果服务端再次下发策略，它可能恢复。' : ''}`,
    danger: true,
    okText: '移除',
  });
  if (!ok) return;
  try {
    await api(`/api/local/allowlist?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`, { method: 'DELETE' });
    toast('已从信任列表移除', 'ok', {
      label: '撤销',
      run: async () => {
        try {
          await api('/api/local/allowlist', {
            method: 'POST',
            body: { type, value, note: note || '撤销移除' },
          });
          toast('已恢复', 'ok');
          refreshAllow();
        } catch (e) { toast(e.message, 'err'); }
      },
    });
    await refreshAllow();
    paintTrust();
  } catch (e) {
    toast(e.message, 'err');
  }
}

/* ------------------------------------------------------------ 骨架 / 错误 / 启动 */

function skeletonHTML(route) {
  if (route === 'processes') {
    return `<div class="skel" style="width:260px;height:30px;margin-bottom:14px"></div>
      <div class="table-wrap" style="padding:14px">${Array.from({ length: 8 }).map(() => '<div class="skel skel-row"></div>').join('')}</div>`;
  }
  if (route === 'persist') {
    return `<div class="skel" style="width:260px;height:30px;margin-bottom:14px"></div>
      ${Array.from({ length: 6 }).map(() => '<div class="skel skel-row"></div>').join('')}`;
  }
  if (route === 'trust') {
    return `<div class="skel" style="width:200px;height:14px"></div>
      ${Array.from({ length: 4 }).map(() => '<div class="skel skel-row"></div>').join('')}`;
  }
  if (route === 'posture') {
    return `<div class="skel" style="width:280px;height:30px;margin-bottom:14px"></div>
      ${Array.from({ length: 7 }).map(() => '<div class="skel skel-row"></div>').join('')}`;
  }
  if (route === 'apps') {
    return `<div class="skel" style="width:260px;height:30px;margin-bottom:14px"></div>
      <div class="table-wrap" style="padding:14px">${Array.from({ length: 10 }).map(() => '<div class="skel skel-row"></div>').join('')}</div>`;
  }
  if (route === 'browser') {
    return `<div class="skel" style="width:280px;height:14px;margin-bottom:14px"></div>
      ${Array.from({ length: 5 }).map(() => '<div class="skel skel-row"></div>').join('')}`;
  }
  return `<div class="skel skel-hero"></div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin-top:22px">
      ${Array.from({ length: 4 }).map(() => '<div><div class="skel skel-line" style="width:60%"></div><div class="skel" style="width:80px;height:26px;margin-top:10px"></div></div>').join('')}
    </div>
    ${Array.from({ length: 4 }).map(() => '<div class="skel skel-row"></div>').join('')}`;
}

function errorHTML() {
  return `<div class="state">
    <div class="state-icon crit">${icon('wifiOff')}</div>
    <h2>无法连接本机探针</h2>
    <p>桌面端可能刚启动，或探针进程正在重启。探针恢复后，界面会自动继续刷新。${state.error ? `<br><span class="mono" style="font-size:10px">${esc(state.error)}</span>` : ''}</p>
    <div class="state-actions">
      <button class="btn primary" data-act="retry">重试</button>
      <button class="btn" data-act="palette">${icon('command')}命令面板</button>
    </div>
  </div>`;
}

let pollTick = 0;

// ---- 无边框窗口宿主集成 ------------------------------------------------
// 桌面宿主（zedr-ui）通过 Bind 注入 zedrHost* 全局函数；浏览器直开时
// 这些函数不存在，窗口控制按钮与贴边热区自动隐藏，页面行为不变。

const HAS_WINDOW_HOST = typeof window.zedrHostMinimize === 'function';

function renderWinControls(maximized = false) {
  const box = $('#winControls');
  if (!box) return;
  box.hidden = false;
  box.innerHTML = `
    <button class="wbtn" data-act="win-min" aria-label="最小化" title="最小化">${icon('winMin')}</button>
    <button class="wbtn" data-act="win-max" aria-label="${maximized ? '还原' : '最大化'}" title="${maximized ? '还原' : '最大化'}">${icon(maximized ? 'winRestore' : 'winMax')}</button>
    <button class="wbtn wbtn-close" data-act="win-close" aria-label="关闭" title="关闭面板（托盘与防护继续运行）">${icon('winClose')}</button>`;
}

function setupWindowHost() {
  if (!HAS_WINDOW_HOST) return;
  document.body.classList.add('frameless');
  renderWinControls(false);
  // 贴边缩放热区：mousedown 交给 Windows 的模态缩放循环
  $$('.rz').forEach((zone) => {
    zone.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      window.zedrHostResizeEdge?.(zone.dataset.edge);
    });
  });
  // 双击顶栏切换最大化（app-region drag 区域内 dblclick 可能被拖动吞掉，尽力而为）
  $('.topbar')?.addEventListener('dblclick', (e) => {
    if (e.target.closest('button, input, select, a, .host-chip')) return;
    window.zedrHostMaximizeToggle?.().then?.((z) => renderWinControls(Boolean(z)));
  });
}

function boot() {
  setupWindowHost();
  initTheme();
  state.route = routeFromHash();

  window.addEventListener('hashchange', onHash);
  document.addEventListener('click', (e) => { onClick(e); });
  document.addEventListener('keydown', onKey);
  document.addEventListener('input', onInput);
  document.addEventListener('submit', onSubmit);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && state.lastFresh && Date.now() - state.lastFresh > 5000) refreshCore();
  });

  initialLoad();

  setInterval(async () => {
    if (document.hidden) return;
    pollTick++;
    await refreshCore();
    if (pollTick % 3 === 0) refreshProcs();
    if (pollTick % 5 === 0) {
      refreshAllow();
      // 驻留/隔离数据变化频率低，与白名单同节奏（15s）即可
      refreshPersist();
      refreshQuarantine();
    }
  }, 3000);

  setInterval(tickRel, 5000);
}

document.addEventListener('DOMContentLoaded', boot);
