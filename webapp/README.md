# Z-EDR 管理台前端（webapp）

React 19 + TypeScript + Vite 7 + Tailwind CSS v4 + lucide-react。
构建产物输出到 `../internal/server/web/static/`，由 Go `go:embed` 打进
`zedr-server.exe` —— 保持**单文件交付、无 CDN、无 Node 运行时**的部署优势。

## 常用命令

```bash
npm install          # 首次（或换 registry: --registry=https://registry.npmmirror.com）
npm run dev          # 开发服务器（API 代理未配置，需自备后端或 mock）
npm run build        # tsc 类型检查 + vite 构建 → ../internal/server/web/static
```

## 架构约定

| 目录 | 职责 |
|---|---|
| `src/lib/api.ts` | API 客户端：Bearer 鉴权、401 刷新重放、5xx 退避重试、错误码中文化 |
| `src/lib/types.ts` | 与 Go domain 对齐的类型（单一事实源在 Go 侧，此处是手工镜像） |
| `src/lib/theme.ts` | 亮/暗主题与紧凑密度（dark-first，light 为变体） |
| `src/components/ui/` | shadcn/ui 模式的基础组件（basics + overlays），token 见 `index.css` |
| `src/components/charts.tsx` | 纯 SVG 图表（色彩走 CSS 变量，双主题自适应） |
| `src/pages/` | 路由页面（React Router hash 模式，embed 友好） |

## 设计 token

`src/index.css` 内含完整亮暗双主题语义变量（shadcn 语义对命名），
语义色对比度均实算 ≥ 4.5:1。改主题 = 改变量，不要写死色值。

## 注意

- 产物**必须入库**（`internal/server/web/static/assets/`），否则无 Node
  环境无法构建 Go。
- `static/**` 归前端会话所有（见 docs/AGENT-COORDINATION.md），
  `npm run build` 会 `emptyOutDir` 清空该目录——不要把非构建产物放进去。
- 桌面端（`internal/agent/localapi/static/`）暂为手写轻量版，
  后续可复用本工程组件库迁移。
