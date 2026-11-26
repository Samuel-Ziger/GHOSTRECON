import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const root = import.meta.dirname;

function shell(title) {
  return `<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes" />
    <meta name="color-scheme" content="dark" />
    <title>${title}</title>
    <link rel="stylesheet" href="./assets/news-verifier.css" />
    <script defer src="./assets/news-verifier.js"></script>
  </head>
  <body><div id="root"></div></body>
</html>
`;
}

function offlineShells() {
  return {
    name: 'news-verifier-offline-shells',
    async closeBundle() {
      await Promise.all([
        writeFile(resolve(root, 'dist/index.html'), shell('LinkSeguro | Verificador de Confiabilidade')),
        writeFile(resolve(root, 'dist/dicas.html'), shell('LinkSeguro | Dicas &amp; Identificação')),
      ]);
    },
  };
}

export default defineConfig({
  base: './',
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  plugins: [react(), offlineShells()],
  build: {
    sourcemap: false,
    cssCodeSplit: false,
    lib: {
      entry: resolve(root, 'src/main.jsx'),
      name: 'GhostreconNewsVerifier',
      formats: ['iife'],
      fileName: () => 'news-verifier.js',
      cssFileName: 'news-verifier',
    },
    rollupOptions: {
      output: {
        entryFileNames: 'assets/news-verifier.js',
        assetFileNames: (assetInfo) => (
          assetInfo.name?.endsWith('.css')
            ? 'assets/news-verifier.css'
            : 'assets/[name][extname]'
        ),
      },
    },
  },
});
