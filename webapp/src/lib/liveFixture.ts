/* 开发期假数据（W1-F dev-only）：后端 W2 隧道代理未就绪时预览「实时文件」
   交互用。启用条件 = DEV 构建 且 localStorage['hg_live_fixture'] === '1'——
   DEV 是编译期常量，生产构建里调用方的动态 import 位于死分支，本模块不会
   进产物。数据 shape 严格按 docs/LIVE-TUNNEL.md §5.2 镜像，W3 联调时
   不改 UI 代码直接切真实 API。
   F2（v2）扩展：search/analyze/ads/info/procinfo/processes/netstat/stat，
   全部为良性演示数据（fixture 里不放任何恶意样本名）。 */
import type {
  LiveFsList, LiveFsEntry, LiveHash, LiveStat, LiveProcList, LiveNetList,
  LiveProcInfo, LiveSearchResult, LiveAnalyze, LiveAds, LiveInfo,
} from './types';
import type { LiveReadResult } from './api';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const e = (name: string, size: number, is_dir: boolean, f: Partial<Pick<LiveFsEntry, 'hidden' | 'system' | 'readonly' | 'reparse'>> = {}): LiveFsEntry => ({
  name, size, is_dir, hidden: !!f.hidden, system: !!f.system, readonly: !!f.readonly, reparse: !!f.reparse,
  mtime_unix: Math.floor(Date.now() / 1000) - 86400 * (name.length % 30),
});

/* 小目录树：覆盖盘根 / 多级 / 空目录 / 各属性徽标 / 游标分页（每页 4 条） */
const TREE: Record<string, LiveFsEntry[]> = {
  'C:\\': [
    e('bootmgr', 402, false, { hidden: true, system: true }),
    e('pagefile.sys', 2147483648, false, { hidden: true, system: true }),
    e('Documents and Settings', 0, true, { hidden: true, reparse: true }),
    e('Program Files', 0, true),
    e('Users', 0, true),
    e('Windows', 0, true),
  ],
  'C:\\Users': [
    e('Administrator', 0, true),
    e('Default', 0, true, { hidden: true }),
    e('Public', 0, true),
  ],
  'C:\\Users\\Administrator': [
    e('.gitconfig', 233, false),
    e('notes.txt', 1024, false, { readonly: true }),
    e('report.docx', 52100, false), // 演示搜索结果 ADS 徽标（带 Zone.Identifier）
    e('Desktop', 0, true),
    e('Downloads', 0, true),
    e('ntuser.dat', 1048576, false, { hidden: true, system: true }),
  ],
  'C:\\Users\\Administrator\\Downloads': [
    e('demo_app.exe', 1466368, false), // 演示 PE 徽标 + MotW zone
    e('setup.msi', 4194304, false),
  ],
  'C:\\Windows': [
    e('System32', 0, true),
    e('explorer.exe', 5253120, false),
    e('win.ini', 92, false, { readonly: true }),
    e('notepad.exe', 201216, false),
    e('Temp', 0, true),
  ],
  'C:\\Windows\\System32': [
    e('cmd.exe', 289792, false),
    e('drivers', 0, true),
    e('kernel32.dll', 739328, false, { readonly: true }),
    e('WindowsPowerShell', 0, true),
  ],
};

/* 搜索结果 quick.ads 演示集合（携 Zone.Identifier 的文件） */
const ADS_DEMO = new Set(['report.docx', 'demo_app.exe']);

/* 服务端同款排序：目录优先，名称 casefold 升序 */
const sorted = (rows: LiveFsEntry[]) => [...rows].sort((a, b) =>
  a.is_dir !== b.is_dir ? (a.is_dir ? -1 : 1) : a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1);

const PAGE = 4;

/** 与 lib/api 的 live 系列同构，UI 层据 devFixture() 返回值二选一。
   v2 增量方法（F2）与真实端点同构，W3 联调时 UI 不改直接切 API。 */
export interface LiveFixtureApi {
  fs(path: string, cursor?: string): Promise<LiveFsList>;
  read(path: string): Promise<LiveReadResult>;
  hash(path: string): Promise<LiveHash>;
  stat(path: string): Promise<LiveStat>;
  processes(): Promise<LiveProcList>;
  netstat(): Promise<LiveNetList>;
  procinfo(pid: number): Promise<LiveProcInfo>;
  search(path: string, pattern: string, depth: number, limit: number): Promise<LiveSearchResult>;
  analyze(path: string): Promise<LiveAnalyze>;
  ads(path: string): Promise<LiveAds>;
  info(): Promise<LiveInfo>;
}

export const fixture: LiveFixtureApi = {
  async fs(path: string, cursor?: string): Promise<LiveFsList> {
    await sleep(300);
    const key = path.replace(/\\+$/, '');
    const all = TREE[key] || TREE[`${key}\\`] || [];
    const off = cursor ? (parseInt(cursor.replace(/^o/, ''), 10) || 0) : 0;
    const rows = sorted(all).slice(off, off + PAGE);
    return { path, entries: rows, next_cursor: off + PAGE < all.length ? `o${off + PAGE}` : '' };
  },

  async read(path: string): Promise<LiveReadResult> {
    await sleep(350);
    if (/\.(exe|dll|sys|dat|png|zip)$/i.test(path)) {
      const bin = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]); // 假 PE 头 → 非文本分支
      return { blob: new Blob([bin]), contentType: 'application/octet-stream', size: 4096, truncated: false };
    }
    const text = [
      `# fixture 文本预览：${path}`,
      '# —— 以下为开发期假数据，仅验证渲染分支 ——',
      'HG_LIVE_FIXTURE=1',
      '…',
    ].join('\r\n');
    return { blob: new Blob([text], { type: 'text/plain' }), contentType: 'text/plain; charset=utf-8', size: text.length, truncated: false };
  },

  async hash(path: string): Promise<LiveHash> {
    await sleep(500);
    /* 确定性假 SHA256：由路径字符派生，仅用于看排版 */
    let h = '';
    for (let i = 0; i < 64; i++) h += ((path.charCodeAt(i % path.length) + i * 31) % 16).toString(16);
    const unsigned = /\.(txt|ini|md)$/i.test(path);
    return {
      path,
      sha256: h,
      size: 5253120,
      authenticode: unsigned
        ? { state: 'unsigned' }
        : { state: 'valid', subject: 'Fixture Signer Co.', issuer: 'Fixture Root CA' },
    };
  },

  /* ================= v2（F2）================= */

  async stat(path: string): Promise<LiveStat> {
    await sleep(200);
    const base = path.slice(path.lastIndexOf('\\') + 1).toLowerCase();
    let found: LiveFsEntry | null = null;
    for (const [dir, rows] of Object.entries(TREE)) {
      if (path.toLowerCase().startsWith(dir.toLowerCase())) {
        const hit = rows.find((r) => r.name.toLowerCase() === base);
        if (hit) { found = hit; break; }
      }
    }
    const en = found;
    return {
      path, exists: !!en, size: en?.size ?? 0, is_dir: en?.is_dir ?? false,
      hidden: !!en?.hidden, system: !!en?.system, readonly: !!en?.readonly,
      reparse: !!en?.reparse, mtime_unix: en?.mtime_unix ?? 0,
    };
  },

  async processes(): Promise<LiveProcList> {
    await sleep(350);
    return { items: PROCS.map((p) => ({ ...p })) };
  },

  async netstat(): Promise<LiveNetList> {
    await sleep(420);
    return { items: NET.map((r) => ({ ...r })) };
  },

  async procinfo(pid: number): Promise<LiveProcInfo> {
    await sleep(550);
    const row = PROCS.find((p) => p.pid === pid);
    if (!row) return { pid, exists: false };
    const modRows = [
      { name: 'ntdll.dll', path: 'C:\\Windows\\System32\\ntdll.dll' },
      { name: 'kernel32.dll', path: 'C:\\Windows\\System32\\kernel32.dll' },
      { name: 'user32.dll', path: 'C:\\Windows\\System32\\user32.dll' },
      { name: 'shell32.dll', path: 'C:\\Windows\\System32\\shell32.dll' },
    ];
    const unsigned = row.name === 'fixture_helper.exe' ? 1 : 0;
    if (unsigned) modRows.push({ name: 'fixture_hook.dll', path: 'C:\\Users\\Administrator\\AppData\\Local\\fixture_hook.dll' });
    return {
      pid, exists: true, name: row.name, path: row.path, cmdline: row.cmdline,
      user: row.user, session_id: row.user === 'SYSTEM' ? 0 : 1, elevated: row.user === 'SYSTEM',
      started_at: row.first_seen, cpu_percent: 1.8, mem_mb: 42,
      connections: NET.filter((c) => c.pid === pid),
      modules: modRows, unsigned_module_count: unsigned, truncated: false,
      exec_info: {
        exists: !!row.path,
        signed_state: unsigned ? 'unsigned' : 'valid',
        ads_zone_id: ADS_DEMO.has(row.name) ? 3 : null,
      },
    };
  },

  async search(root: string, pattern: string, depth: number, limit: number): Promise<LiveSearchResult> {
    await sleep(600);
    /* 通配 *? → 正则（大小写不敏感），遍历 TREE 里 root 之下 depth 层内的目录 */
    const rx = new RegExp('^' + pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) => (ch === '*' ? '.*' : ch === '?' ? '.' : `\\${ch}`)) + '$', 'i');
    const normRoot = root.replace(/\\+$/, '').toLowerCase();
    const out: LiveSearchResult['entries'] = [];
    for (const [dir, rows] of Object.entries(TREE)) {
      const dl = dir.replace(/\\+$/, '').toLowerCase();
      const rel = dl.startsWith(normRoot) ? dl.slice(normRoot.length).replace(/^\\/, '') : '';
      if (dl !== normRoot && !dl.startsWith(normRoot + '\\')) continue;
      if (rel.split('\\').filter(Boolean).length >= depth + 1) continue; // 限深
      for (const r of rows) {
        if (out.length >= limit) break;
        if (!rx.test(r.name)) continue;
        const pe = /\.(exe|dll|sys)$/i.test(r.name);
        out.push({
          ...r,
          dir: rel ? `${root.replace(/\\+$/, '')}\\${rel}` : root,
          quick: { pe, ads: ADS_DEMO.has(r.name), hidden: r.hidden, system: r.system },
        });
      }
    }
    return { path: root, pattern, entries: out, truncated: false };
  },

  async analyze(path: string): Promise<LiveAnalyze> {
    await sleep(900);
    const h = (n: number, salt: string) => {
      let s = '';
      const seed = path + salt;
      for (let i = 0; i < n; i++) s += ((seed.charCodeAt(i % seed.length) + i * 17 + salt.length) % 16).toString(16);
      return s;
    };
    const isPE = /\.(exe|dll|sys)$/i.test(path);
    const base = path.slice(path.lastIndexOf('\\') + 1);
    return {
      md5: h(32, 'md5'), sha1: h(40, 'sha1'), sha256: h(64, 'sha256'),
      size: 1466368,
      pe: isPE ? {
        machine: 'x64', subsystem: 'Windows CUI', is_dll: /\.dll$/i.test(path),
        compile_ts_unix: Math.floor(Date.now() / 1000) - 86400 * 41,
        entry_point: 0x14c0,
        sections: [
          { name: '.text', size: 393216, entropy: 6.31 },
          { name: '.rdata', size: 155648, entropy: 5.08 },
          { name: '.data', size: 24576, entropy: 4.12 },
          { name: '.rsrc', size: 884736, entropy: 7.85 }, // 演示高熵红条
        ],
        max_section_entropy: 7.85,
        imphash: h(32, 'imphash'),
        imports: {
          total: 97,
          categories: { network: 6, process_injection: 0, persistence: 2, keyboard_hook: 0, anti_debug: 0, exec: 14, fs: 9 },
          notable: [
            'kernel32.dll!CreateFileW', 'kernel32.dll!VirtualAlloc', 'kernel32.dll!LoadLibraryW',
            'ws2_32.dll!WSAStartup', 'ws2_32.dll!connect', 'ws2_32.dll!send',
            'advapi32.dll!RegSetValueExW', 'shell32.dll!ShellExecuteW', 'wininet.dll!InternetOpenUrlA',
          ],
        },
      } : null,
      packer_hints: isPE ? ['节熵 7.85（.rsrc）'] : [],
      version_resource: {
        company: 'Fixture Software Ltd.', product: 'Fixture Demo Suite',
        description: 'Fixture 演示用程序',
        original_filename: 'demo_app.exe',
        mismatch: base !== 'demo_app.exe' && isPE, // 演示改名伪装警示
      },
      strings: {
        urls: ['https://example.com/update/manifest.json', 'http://example.com/telemetry'],
        ips: ['203.0.113.10', '198.51.100.7'],
        registry_paths: ['HKCU\\Software\\Fixture', 'HKLM\\SOFTWARE\\Fixture\\Config'],
        file_paths: ['C:\\ProgramData\\Fixture\\cache.db', '%TEMP%\\fixture.log'],
        mutex: ['Global\\FixtureSingleton'],
      },
    };
  },

  async ads(path: string): Promise<LiveAds> {
    await sleep(300);
    const base = path.slice(path.lastIndexOf('\\') + 1);
    if (!ADS_DEMO.has(base)) return { streams: [], zone: null };
    return {
      streams: [{ name: ':zone.identifier:$DATA', size: 137 }],
      zone: {
        zone_id: 3, zone_name: 'Internet',
        referrer_url: 'https://example.com/downloads/page',
        host_url: 'https://example.com/downloads/demo_app.exe',
        download_time: new Date(Date.now() - 3600_000).toISOString(),
      },
    };
  },

  async info(): Promise<LiveInfo> {
    await sleep(150);
    return {
      version: '0.9.5', hostname: 'fixture-host', uptime_sec: 86400 * 3 + 7200,
      proc_count: PROCS.length, cpu_percent: 7.4, mem_mb: 6144,
      scan_interval: 2, collector: 'ntquery',
    };
  },
};

/* ---- v2 演示数据（全部良性名，不含真实恶意样本） ---- */

const iso = (secAgo: number) => new Date(Date.now() - secAgo * 1000).toISOString();
/* proc_started_at 是 unix 秒（探针 int64），不是 ISO 字符串 */
const unix = (secAgo: number) => Math.floor(Date.now() / 1000) - secAgo;

const PROCS: import('./types').LiveProcRow[] = [
  { pid: 4, ppid: 0, name: 'System', path: '', cmdline: '', user: 'SYSTEM', score: 0, verdict: '', severity: '', title: '', first_seen: iso(86400 * 3), conn_count: 0, modules: 0 },
  { pid: 512, ppid: 632, name: 'svchost.exe', path: 'C:\\Windows\\system32\\svchost.exe', cmdline: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p', user: 'SYSTEM', score: 0, verdict: '', severity: '', title: '', first_seen: iso(86400 * 3), conn_count: 2, modules: 132 },
  { pid: 1024, ppid: 288, name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe', cmdline: 'C:\\Windows\\Explorer.EXE', user: 'fixture\\administrator', score: 0, verdict: '', severity: '', title: '', first_seen: iso(86400 * 3 - 600), conn_count: 0, modules: 210 },
  { pid: 2048, ppid: 1024, name: 'notepad.exe', path: 'C:\\Windows\\System32\\notepad.exe', cmdline: '"C:\\Windows\\system32\\NOTEPAD.EXE" C:\\Users\\Administrator\\notes.txt', user: 'fixture\\administrator', score: 0, verdict: '', severity: '', title: '', first_seen: iso(1800), conn_count: 0, modules: 46 },
  { pid: 4096, ppid: 1024, name: 'demo_app.exe', path: 'C:\\Users\\Administrator\\Downloads\\demo_app.exe', cmdline: '"C:\\Users\\Administrator\\Downloads\\demo_app.exe" --mode=normal', user: 'fixture\\administrator', score: 20, verdict: '', severity: 'info', title: '', first_seen: iso(600), conn_count: 1, modules: 58 },
];

const NET: import('./types').LiveNetConn[] = [
  { proto: 'TCP', local_ip: '192.168.1.10', local_port: 52100, remote_ip: '203.0.113.10', remote_port: 443, state: 'ESTABLISHED', pid: 4096, proc_name: 'demo_app.exe', proc_path: 'C:\\Users\\Administrator\\Downloads\\demo_app.exe', proc_user: 'fixture\\administrator', proc_started_at: unix(600), proc_cmdline: '"C:\\Users\\Administrator\\Downloads\\demo_app.exe" --mode=normal', proc_elevated: false, exited: false, remote_class: 'public' },
  { proto: 'TCP', local_ip: '192.168.1.10', local_port: 52122, remote_ip: '10.0.0.5', remote_port: 445, state: 'ESTABLISHED', pid: 512, proc_name: 'svchost.exe', proc_path: 'C:\\Windows\\system32\\svchost.exe', proc_user: 'SYSTEM', proc_started_at: unix(86400 * 3), proc_cmdline: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p', proc_elevated: true, exited: false, remote_class: 'private' },
  { proto: 'TCP', local_ip: '127.0.0.1', local_port: 8843, remote_ip: '0.0.0.0', remote_port: 0, state: 'LISTEN', pid: 512, proc_name: 'svchost.exe', proc_path: 'C:\\Windows\\system32\\svchost.exe', proc_user: 'SYSTEM', proc_started_at: unix(86400 * 3), proc_cmdline: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p', proc_elevated: true, exited: false, remote_class: 'reserved' },
  { proto: 'TCP', local_ip: '127.0.0.1', local_port: 51044, remote_ip: '127.0.0.1', remote_port: 8843, state: 'ESTABLISHED', pid: 2048, proc_name: 'notepad.exe', proc_path: 'C:\\Windows\\System32\\notepad.exe', proc_user: 'fixture\\administrator', proc_started_at: unix(1800), proc_cmdline: '"C:\\Windows\\system32\\NOTEPAD.EXE"', proc_elevated: false, exited: false, remote_class: 'loopback' },
  { proto: 'TCP', local_ip: '192.168.1.10', local_port: 52099, remote_ip: '198.51.100.7', remote_port: 80, state: 'CLOSE_WAIT', pid: 9999, proc_name: '(已退出)', proc_path: '', proc_user: '', proc_started_at: 0, proc_cmdline: '', proc_elevated: false, exited: true, remote_class: 'public' },
  { proto: 'UDP', local_ip: '192.168.1.10', local_port: 5353, remote_ip: '', remote_port: 0, state: '', pid: 512, proc_name: 'svchost.exe', proc_path: 'C:\\Windows\\system32\\svchost.exe', proc_user: 'SYSTEM', proc_started_at: unix(86400 * 3), proc_cmdline: '', proc_elevated: true, exited: false, remote_class: '' },
];
