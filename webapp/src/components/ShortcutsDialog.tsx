import { X } from 'lucide-react';
import { Kbd } from './ui/basics';

const GROUPS: { title: string; items: [string, string][] }[] = [
  { title: '全局', items: [
    ['Ctrl K', '命令面板：跳转页面、执行操作'],
    ['R', '刷新当前视图数据'],
    ['?', '打开 / 关闭本帮助'],
    ['Esc', '关闭抽屉 / 弹层'],
  ] },
  { title: '跳转（先按 G）', items: [
    ['G O', '概览'], ['G A', '告警中心'], ['G S', 'AI 狩猎'], ['G I', '事件'],
    ['G M', '攻击矩阵'], ['G P', '报表'], ['G H', '主机终端'], ['G R', '检测规则'],
    ['G T', '威胁情报'], ['G W', '白名单'], ['G L', '审计日志'], ['G U', '账号管理'],
  ] },
  { title: '告警中心', items: [
    ['A', '全选 / 清空当前页'],
    ['J / K', '向下 / 向上移动行焦点'],
    ['Enter', '打开焦点行详情'],
    ['1-4', '批量标记（待处置/已确认/已解决/误报）'],
  ] },
];

export function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-150 flex items-start justify-center bg-[#04070d]/65 pt-[14vh] backdrop-blur-[3px]" style={{ animation: 'mask-in 250ms cubic-bezier(.22,1,.36,1)' }} onClick={onClose}>
      <div
        className="w-[min(560px,92vw)] overflow-hidden rounded-lg border border-border-strong bg-card shadow-2xl"
        style={{ animation: 'pop-in 250ms cubic-bezier(.22,1,.36,1)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border-soft px-4 py-3">
          <b className="text-[13.5px]">键盘快捷键</b>
          <button className="cursor-pointer border-0 bg-transparent p-1 text-faint hover:text-foreground" onClick={onClose} aria-label="关闭">
            <X size={15} />
          </button>
        </div>
        <div className="grid max-h-[60vh] grid-cols-1 gap-x-8 overflow-y-auto p-4 sm:grid-cols-2">
          {GROUPS.map((g) => (
            <div key={g.title} className="mb-3">
              <div className="mb-2 text-[11px] font-semibold tracking-[.05em] text-faint uppercase">{g.title}</div>
              {g.items.map(([keys, desc]) => (
                <div key={keys} className="mb-1.5 flex items-center gap-2 text-xs text-muted-foreground">
                  <span className="flex shrink-0 gap-1">
                    {keys.split(' ').map((k) => <Kbd key={k}>{k}</Kbd>)}
                  </span>
                  <span className="truncate">{desc}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
