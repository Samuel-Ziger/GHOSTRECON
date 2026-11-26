import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

const frontendRoot = fileURLToPath(new URL('.', import.meta.url));
const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

export default defineConfig({
  root: frontendRoot,
  publicDir: false,
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  server: {
    host: '127.0.0.1',
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:3847',
      '/anotacao': 'http://127.0.0.1:3847',
      '/ghostmap': 'http://127.0.0.1:3847',
      '/mitre-attack': 'http://127.0.0.1:3847',
    },
  },
  build: {
    outDir: `${repositoryRoot}/public/assets`,
    emptyOutDir: false,
    sourcemap: false,
    cssCodeSplit: false,
    lib: {
      entry: `${frontendRoot}/src/main.tsx`,
      name: 'GhostReconUI',
      formats: ['iife'],
      fileName: () => 'ghostrecon-ui.js',
      cssFileName: 'ghostrecon-ui',
    },
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
        assetFileNames: (assetInfo) => (
          assetInfo.name?.endsWith('.css')
            ? 'ghostrecon-ui.css'
            : 'ghostrecon-ui-[name][extname]'
        ),
      },
    },
  },
});
