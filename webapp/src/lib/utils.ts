import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** 点分版本号数值比较（-1/0/1），语义对齐服务端 VERSIONING §2：
    逐段十进制数值比较、缺位补 0，禁字典序（0.10 < 0.9 是字典序的错误结论）。
    段内非数字退化字符串比较（预发布号）。非数字版本（如 "test"）与数字版本
    比较结果取决于字符串序，调用方只应把"确定更小"当可升级依据。 */
export function cmpVersion(a?: string | null, b?: string | null): number {
  const seg = (v: string) => v.trim().replace(/^v/, '').split('.');
  const as = seg(a || '0');
  const bs = seg(b || '0');
  for (let i = 0; i < as.length || i < bs.length; i++) {
    const av = as[i] ?? '0';
    const bv = bs[i] ?? '0';
    const ai = Number(av);
    const bi = Number(bv);
    if (!Number.isNaN(ai) && !Number.isNaN(bi)) {
      if (ai !== bi) return ai > bi ? 1 : -1;
      continue;
    }
    if (av !== bv) return av > bv ? 1 : -1;
  }
  return 0;
}
