export function fmtTime(iso?: string): string {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '-';
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function relTime(iso?: string): string {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '-';
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}

export function fmtBytes(n?: number): string {
  if (!n || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export const SEV_LABEL: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
export const STATUS_LABEL: Record<string, string> = { open: '待处置', acknowledged: '已确认', resolved: '已解决', false_positive: '误报' };
export const VERDICT_LABEL: Record<string, string> = { malicious: '恶意', suspicious: '可疑', safe: '安全' };
export const LAYER_LABEL: Record<string, string> = { static: '静态指纹', keyword: '关键词', rule: '行为规则', lineage: '血缘图', behavior: '行为' };
export const ROLE_LABEL: Record<string, string> = { admin: '管理员', analyst: '分析师', viewer: '只读' };
