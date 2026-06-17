import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.join(__dirname, '../..');

export function firstIpv4FromDnsRecords(records) {
  for (const r of records || []) {
    const m = String(r).match(/^A:([\d.]+)$/);
    if (m) return m[1];
  }
  return '';
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
