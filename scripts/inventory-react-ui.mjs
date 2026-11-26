import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TEMPLATE_DIR = path.join(ROOT, 'frontend', 'templates');
const argv = process.argv.slice(2);
const outputFlag = argv.indexOf('--output');
const outputPath = outputFlag >= 0 && argv[outputFlag + 1]
  ? path.resolve(ROOT, argv[outputFlag + 1])
  : null;

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function matches(source, pattern, group = 1) {
  return [...source.matchAll(pattern)].map((match) => match[group]);
}

function inventoryPage(name, source) {
  const functionDeclarations = matches(
    source,
    /\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g,
  );
  const arrowFunctions = matches(
    source,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^;=]*?\)\s*=>/g,
  );
  const ids = matches(source, /\bid=["']([^"']+)["']/g);
  const moduleValues = matches(
    source,
    /<input\b(?=[^>]*\bclass=["'][^"']*\bmod\b[^"']*["'])(?=[^>]*\bvalue=["']([^"']+)["'])[^>]*>/gi,
  );
  const apiPaths = matches(source, /(["'`])(\/api\/[A-Za-z0-9_?&=/${}.:~+-]*)\1/g, 2);
  const storageKeys = matches(source, /["'](ghostrecon(?:[._:-][A-Za-z0-9_.:${}-]+)+)["']/g);
  const externalResources = matches(
    source,
    /(?:src|href)=["'](https?:\/\/[^"']+)["']/gi,
  );
  const inlineHandlers = [...source.matchAll(/\s(on[a-z]+)=["'][\s\S]*?["']/gi)]
    .map((match) => match[1].toLowerCase());

  return {
    file: name,
    bytes: Buffer.byteLength(source),
    lines: source.split(/\r?\n/).length,
    functions: uniqueSorted([...functionDeclarations, ...arrowFunctions]),
    functionDeclarationCount: functionDeclarations.length,
    arrowFunctionCount: arrowFunctions.length,
    domIds: uniqueSorted(ids),
    domIdCount: uniqueSorted(ids).length,
    moduleValues: uniqueSorted(moduleValues),
    moduleCount: uniqueSorted(moduleValues).length,
    apiPaths: uniqueSorted(apiPaths),
    storageAndChannelKeys: uniqueSorted(storageKeys),
    externalResources: uniqueSorted(externalResources),
    inlineHandlers: inlineHandlers.reduce((counts, handler) => {
      counts[handler] = (counts[handler] || 0) + 1;
      return counts;
    }, {}),
    addEventListenerCount: (source.match(/\.addEventListener\s*\(/g) || []).length,
    fetchCallCount: (source.match(/\bfetch\s*\(/g) || []).length,
    scriptCount: (source.match(/<script\b/gi) || []).length,
  };
}

const names = (await fs.readdir(TEMPLATE_DIR))
  .filter((name) => name.endsWith('.html'))
  .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const pages = {};

for (const name of names) {
  const source = await fs.readFile(path.join(TEMPLATE_DIR, name), 'utf8');
  pages[name] = inventoryPage(name, source);
}

const cockpit = pages['index.html'];
// O controller perde declarações conforme domínios migram para TypeScript.
// O piso continua detectando truncamento acidental sem transformar extrações
// React intencionais (Manual, Auto/Forge, help, Vigolium, Pipeline, Findings e
// Exports/Integrações)
// em falha do inventário.
if (!cockpit || cockpit.functionDeclarationCount < 80 || cockpit.moduleCount < 80) {
  throw new Error('Inventário do cockpit incompleto: funções ou módulos abaixo do baseline');
}

const inventory = {
  schemaVersion: 1,
  sourceDirectory: 'frontend/templates',
  pageCount: names.length,
  pages,
};
const serialized = `${JSON.stringify(inventory, null, 2)}\n`;

if (outputPath) {
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, serialized, 'utf8');
  console.log(`UI_INVENTORY_WRITTEN ${path.relative(ROOT, outputPath)}`);
} else {
  process.stdout.write(serialized);
}
