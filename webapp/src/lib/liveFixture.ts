/* 开发期假数据（W1-F dev-only）：后端 W2 隧道代理未就绪时预览「实时文件」
   交互用。启用条件 = DEV 构建 且 localStorage['hg_live_fixture'] === '1'——
   DEV 是编译期常量，生产构建里调用方的动态 import 位于死分支，本模块不会
   进产物。数据 shape 严格按 docs/LIVE-TUNNEL.md §5.2 镜像，W3 联调时
   不改 UI 代码直接切真实 API。 */
import type { LiveFsList, LiveFsEntry, LiveHash } from './types';
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
    e('Desktop', 0, true),
    e('ntuser.dat', 1048576, false, { hidden: true, system: true }),
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

/* 服务端同款排序：目录优先，名称 casefold 升序 */
const sorted = (rows: LiveFsEntry[]) => [...rows].sort((a, b) =>
  a.is_dir !== b.is_dir ? (a.is_dir ? -1 : 1) : a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1);

const PAGE = 4;

/** 与 lib/api 的 live 系列同构，UI 层据 devFixture() 返回值二选一 */
export interface LiveFixtureApi {
  fs(path: string, cursor?: string): Promise<LiveFsList>;
  read(path: string): Promise<LiveReadResult>;
  hash(path: string): Promise<LiveHash>;
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
};
