/**
 * Heurísticas — possíveis segredos (mascarar na saída).
 */
import { secretMaterialFingerprint } from './db-common.js';

const PATTERNS = [
  { name: 'AWS Access Key', re: /\b(AKIA[0-9A-Z]{16})\b/g, mask: (s) => s.slice(0, 8) + '…' },
  {
    name: 'Generic API key',
    re: /\b(api[_-]?key|apikey)\s*[:=]\s*["']([a-zA-Z0-9_\-]{12,})["']/gi,
    mask: (raw) => (String(raw).length > 4 ? `${String(raw).slice(0, 4)}…` : '***'),
  },
  { name: 'Bearer JWT', re: /\bBearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)/g, mask: () => 'Bearer ***' },
  { name: 'Slack token', re: /\b(xox[baprs]-[0-9A-Za-z\-]{10,})/g, mask: (s) => s.slice(0, 10) + '…' },
  { name: 'GitHub PAT', re: /\b(gh[pousr]_[A-Za-z0-9_]{20,})\b/g, mask: (s) => s.slice(0, 8) + '…' },
  { name: 'Private key block', re: /-----BEGIN [A-Z ]+PRIVATE KEY-----/g, mask: () => '-----BEGIN … KEY-----' },
];

export function scanSecrets(text, maxPerKind = 3) {
  const findings = [];
  if (!text || text.length > 600_000) text = text.slice(0, 600_000);
  for (const { name, re, mask } of PATTERNS) {
    re.lastIndex = 0;
    let m;
    let n = 0;
    while ((m = re.exec(text)) !== null && n < maxPerKind) {
      const raw = m[2] ?? m[1] ?? m[0];
      const finding = {
        kind: name,
        masked: typeof mask === 'function' ? mask(raw) : String(raw).slice(0, 12) + '…',
        correlationFp: secretMaterialFingerprint(name, raw),
      };
      // Disponível apenas em memória para secret_validation explicitamente
      // selecionado; JSON/NDJSON/persistência nunca enumeram o material cru.
      Object.defineProperty(finding, 'rawMaterial', {
        value: raw,
        enumerable: false,
        configurable: false,
        writable: false,
      });
      findings.push(finding);
      n++;
    }
  }
  return findings;
}
