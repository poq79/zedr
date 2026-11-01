# Fonts

Geist Sans / Geist Mono（仅 latin 子集，woff2）。

- 来源：jsDelivr fontsource（`geist-sans@latest` / `geist-mono@latest`），2026-11-01 拉取
- 授权：SIL Open Font License 1.1（© Vercel）——允许再分发，随二进制内嵌合法
- 用途：界面主字族（Geist Sans）+ 数据等宽字族（Geist Mono）；CJK 回退系统字
  （Segoe UI / PingFang SC / Microsoft YaHei），打包 CJK 子集成本过高，见 DESIGN.md §3
- 离线合规：文件随仓库入库、随 go:embed 内嵌，运行时零外部请求（部署红线 §1）
