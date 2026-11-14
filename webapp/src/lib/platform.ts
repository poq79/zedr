/* 主机平台判定助手。

   为什么靠 os_version：服务端 Host 契约暂无 platform 字段（v1 以 os_version
   区分，升级契约时替换为显式字段，届时本函数整体下线）。探针侧 os_version
   恒有值——Windows 报 "Windows Server 2022 ..."，Linux 报
   "Kali GNU/Linux Rolling 6.16.8+kali-amd64 (amd64)" 之类，因此
   "不以 Windows 开头即 Linux" 在两族真实取值上都不重叠。

   所有平台分支必须走本助手，禁止在调用点散落正则——判定口径改动时
   只改这一处（例如未来契约加了 platform 字段）。 */

export function isLinuxHost(osVersion?: string | null): boolean {
  const v = (osVersion || '').trim();
  if (!v) return false;
  return !/^windows/i.test(v);
}
