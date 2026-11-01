import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// 构建产物直接输出到 Go embed 目录，保持"单文件交付"架构：
// webapp 源码 → vite build → internal/server/web/static → go:embed
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  // dev 专用：把 /api 转发到本机 secserver，省去自备后端/mock；
  // 只影响 npm run dev，构建产物不经过这里
  server: {
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true },
    },
  },
  build: {
    outDir: '../internal/server/web/static',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
});
