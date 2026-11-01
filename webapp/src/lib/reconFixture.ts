/* 开发期假数据（F4 dev-only）：后端 recon handler 未就绪时预览「资产侦查」Tab。
   启用条件 = DEV 构建 且 localStorage['hg_recon_fixture'] === '1'——调用方的
   动态 import 位于编译期死分支，生产构建不会把本模块打进产物（同 liveFixture）。
   数据 shape 严格按 docs/LIVE-TUNNEL.md §12.2 镜像，且全部为良性演示资产：
   覆盖六类分组、五档 exposure、对象/字符串两种 Finding、AI open 与
   auth_required、Web sites、DB version、Remote NLA/shares。 */
import type { ReconResult } from './types';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const iso = (secAgo: number) => new Date(Date.now() - secAgo * 1000).toISOString();

export interface ReconFixtureApi {
  recon(): Promise<ReconResult>;
}

function build(): ReconResult {
  return {
    generated_at: new Date().toISOString(),
    duration_ms: 842,
    probed: true,
    truncated: false,
    categories: [
      {
        key: 'web',
        title: 'Web 服务',
        items: [
          {
            id: 'web-iis-1', category: 'web', kind: 'iis', title: 'IIS · Default Web Site',
            listens: [{ proto: 'TCP', addr: '0.0.0.0', port: 80 }],
            endpoint: 'http://127.0.0.1:80',
            exposure: {
              level: 'medium',
              evidence: ['监听 0.0.0.0:80（全部网卡）', '站点根目录顶层抽查到 ASPX 页面'],
            },
            details: {
              sites: [{
                name: 'Default Web Site',
                bindings: ['http:*:80:'],
                physicalPath: 'C:\\inetpub\\wwwroot',
              }],
              webroot: 'C:\\inetpub\\wwwroot',
              aspx_present: true,
              config_path: 'C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config',
              server_header: 'Microsoft-IIS/10.0',
            },
            findings: ['站点根目录存在 ASPX 动态页面——确认业务确需服务端脚本执行，并保持补丁更新。'],
          },
          {
            id: 'web-nginx-1', category: 'web', kind: 'nginx', title: 'nginx · 本地反向代理',
            process: {
              pid: 3212, name: 'nginx.exe', path: 'C:\\nginx\\nginx.exe',
              user: 'NT AUTHORITY\\SYSTEM', cmdline: '"C:\\nginx\\nginx.exe"',
              started_at: iso(86400 * 2),
            },
            listens: [{ proto: 'TCP', addr: '127.0.0.1', port: 8081 }],
            endpoint: 'http://127.0.0.1:8081',
            exposure: { level: 'low', evidence: ['仅监听回环地址 127.0.0.1'] },
            details: {
              webroot: 'C:\\nginx\\html',
              config_path: 'C:\\nginx\\conf\\nginx.conf',
              server_header: 'nginx/1.27.2',
              title: 'Welcome to nginx!',
            },
            findings: [],
          },
        ],
        findings: [{
          severity: 'medium',
          title: 'Web 根目录动态脚本面',
          advice: '核对 IIS 站点是否确需 ASPX；不需要时移除对应脚本映射与处理程序。',
        }],
      },
      {
        key: 'ai',
        title: 'AI Agent Harness',
        items: [{
          id: 'ai-ollama-1', category: 'ai', kind: 'ollama', title: 'Ollama 本地推理服务',
          process: {
            pid: 5120, name: 'ollama.exe',
            path: 'C:\\Users\\Administrator\\AppData\\Local\\Programs\\Ollama\\ollama.exe',
            user: 'fixture\\administrator', cmdline: 'ollama.exe serve', started_at: iso(7200),
          },
          listens: [{ proto: 'TCP', addr: '127.0.0.1', port: 11434 }],
          endpoint: 'http://127.0.0.1:11434',
          exposure: {
            level: 'high',
            evidence: ['/api/tags 匿名返回 200', '根页命中特征 "Ollama is running"'],
          },
          details: {
            models: ['llama3.1:8b', 'qwen2.5:7b'],
            dashboard_url: 'http://127.0.0.1:11434',
            auth_state: 'open',
          },
          findings: [
            'Ollama 能力端点匿名可访问，任意本机进程都可调用模型推理。',
            '模型列表可被匿名读取，可能泄露内部使用场景。',
          ],
        }],
        findings: [{
          severity: 'high',
          title: 'AI 推理端点未启用认证',
          advice: '在 Ollama 前加带认证的反向代理，或仅绑定回环并限制本机调用方。',
        }],
      },
      {
        key: 'db',
        title: '数据库与中间件',
        items: [
          {
            id: 'db-redis-1', category: 'db', kind: 'redis', title: 'Redis 服务',
            listens: [{ proto: 'TCP', addr: '127.0.0.1', port: 6379 }],
            exposure: { level: 'high', evidence: ['PING 返回 +PONG（未认证）'] },
            details: { version: '7.2.4', auth_state: 'open' },
            findings: ['Redis 未设置认证，PING 匿名返回 +PONG。'],
          },
          {
            id: 'db-es-1', category: 'db', kind: 'elasticsearch', title: 'Elasticsearch 9200',
            listens: [{ proto: 'TCP', addr: '127.0.0.1', port: 9200 }],
            exposure: { level: 'medium', evidence: ['GET / 匿名返回版本 JSON'] },
            details: { version: '8.15.0', auth_state: 'auth_required' },
            findings: [],
          },
        ],
        findings: [{
          severity: 'high',
          message: 'Redis 未启用认证',
          recommendation: '设置 requirepass，并仅绑定回环或受控内网地址。',
        }],
      },
      {
        key: 'remote',
        title: '远程管理面',
        items: [
          {
            id: 'remote-rdp-1', category: 'remote', kind: 'rdp', title: '远程桌面（RDP）',
            listens: [{ proto: 'TCP', addr: '0.0.0.0', port: 3389 }],
            exposure: { level: 'high', evidence: ['监听 0.0.0.0:3389', '注册表 NLA 未启用'] },
            details: { nla_enabled: false, product: 'Microsoft Terminal Services' },
            findings: ['RDP 对外监听且未启用网络级认证（NLA）。'],
          },
          {
            id: 'remote-smb-1', category: 'remote', kind: 'smb', title: 'SMB 共享服务',
            listens: [{ proto: 'TCP', addr: '0.0.0.0', port: 445 }],
            exposure: { level: 'medium', evidence: ['监听 0.0.0.0:445'] },
            details: {
              shares: [
                { name: 'Users', path: 'C:\\Users', remark: '默认用户目录共享' },
                { name: 'Data', path: 'D:\\Data', remark: '' },
              ],
            },
            findings: [],
          },
        ],
        findings: [{
          severity: 'high',
          title: 'RDP 暴露面',
          advice: '启用 NLA、限制来源网段；非必要不向公网开放 3389。',
        }],
      },
      {
        key: 'dev',
        title: '开发与自动化',
        items: [{
          id: 'dev-jupyter-1', category: 'dev', kind: 'jupyter', title: 'Jupyter Notebook',
          process: {
            pid: 7020, name: 'jupyter-lab.exe', user: 'fixture\\administrator',
            cmdline: 'jupyter-lab.exe --no-browser --NotebookApp.token=REDACTED',
            started_at: iso(5400),
          },
          listens: [{ proto: 'TCP', addr: '127.0.0.1', port: 8888 }],
          endpoint: 'http://127.0.0.1:8888',
          exposure: {
            level: 'medium',
            evidence: ['命令行携带 --NotebookApp.token（值已脱敏）', '监听回环地址'],
          },
          details: {
            product: 'jupyterlab',
            version: '4.2.5',
            auth_state: 'auth_required',
            token_in_cmdline: true,
            config_path: 'C:\\Users\\Administrator\\.jupyter\\jupyter_server_config.py',
          },
          findings: ['命令行中出现 Jupyter token（已脱敏）——同机进程可读取命令行并复用凭据。'],
        }],
        findings: [{
          severity: 'medium',
          title: 'Jupyter token 出现在命令行',
          advice: '改用配置文件或环境变量传递 token，避免通过命令行泄露。',
        }],
      },
      {
        key: 'virt',
        title: '容器与虚拟化',
        items: [
          {
            id: 'virt-wsl-1', category: 'virt', kind: 'wsl', title: 'WSL2 子系统',
            process: {
              pid: 4460, name: 'vmmemWSL', user: 'NT AUTHORITY\\SYSTEM',
              started_at: iso(86400),
            },
            listens: [],
            exposure: { level: 'info', evidence: ['未发现对外监听端口'] },
            details: { product: 'WSL2', distros: ['Ubuntu-22.04'], backend_pid: 4460 },
            findings: [],
          },
          {
            id: 'virt-docker-1', category: 'virt', kind: 'docker-desktop', title: 'Docker Desktop',
            process: {
              pid: 6120, name: 'com.docker.backend.exe', user: 'fixture\\administrator',
              started_at: iso(86400 * 3),
            },
            listens: [{ proto: 'TCP', addr: '127.0.0.1', port: 2375 }],
            exposure: {
              level: 'critical',
              evidence: ['Docker API 2375 匿名 GET /version 返回 200'],
            },
            details: {
              product: 'Docker Desktop',
              version: '4.34.2',
              backend_pid: 6120,
              api_version: '1.47',
            },
            findings: ['Docker API 无认证暴露，等同宿主机 root 权限面。'],
          },
        ],
        findings: [{
          severity: 'critical',
          title: 'Docker API 匿名可访问',
          advice: '关闭 2375 明文 API，改用 2376 TLS 客户端证书或命名管道。',
        }],
      },
    ],
  };
}

export const fixture: ReconFixtureApi = {
  async recon(): Promise<ReconResult> {
    await sleep(700);
    return build();
  },
};
