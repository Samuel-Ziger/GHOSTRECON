import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: '/gui/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      '/health': 'http://127.0.0.1:8000',
      '/stats': 'http://127.0.0.1:8000',
      '/chat': 'http://127.0.0.1:8000',
      '/memory': 'http://127.0.0.1:8000',
      '/sessions': 'http://127.0.0.1:8000',
      '/ghostrecon': 'http://127.0.0.1:8000',
      '/hexstrike': 'http://127.0.0.1:8000',
      '/codescan': 'http://127.0.0.1:8000',
      '/quickprompts': 'http://127.0.0.1:8000',
      '/models': 'http://127.0.0.1:8000'
    },
  },
});
