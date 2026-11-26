import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ASSETS = path.join(ROOT, 'public', 'assets');
const GENERATED = [
  'ghostrecon-ui.js.map',
];

for (const filename of GENERATED) {
  await fs.rm(path.join(ASSETS, filename), { force: true });
}
