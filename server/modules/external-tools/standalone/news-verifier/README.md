# News Verifier React

Frontend standalone do LinkSeguro, migrado para React 18 e Vite. As duas
entradas (`index.html` e `dicas.html`) usam o mesmo bundle local; não há React,
fontes ou scripts carregados por CDN.

O motor heurístico permanece em `script.js` como módulo ESM testável. A URL
é analisada localmente por padrão. A consulta opcional ao conteúdo exige que
o operador marque o consentimento exibido na tela, pois esse modo envia a URL
ao proxy público AllOrigins. Se a rede falhar, o veredito continua com os
sinais locais de domínio e URL.

```bash
npm install
npm test
npm run build
```

O catálogo GHOSTRECON aponta para `dist/index.html`; `base: './'` mantém os
assets relativos e permite abrir o artefato diretamente por `file://`.
