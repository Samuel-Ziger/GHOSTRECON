import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

export const moduleManifest = {
  id: 'artifact_safety_audit',
  name: 'Artifact Safety Audit',
  category: 'operational',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 15_000,
  concurrency: 2,
  outputs: ['outcome'],
};

const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_BASE64_CANDIDATES = 2_000;
const MAX_DECODED_BYTES = 2 * 1024 * 1024;

const DETECTORS = Object.freeze([
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g],
  ['bearer', /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi],
  ['aws_access_key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['aws_secret_access_key', /["']?\bAWS[_ -]?SECRET[_ -]?ACCESS[_ -]?KEY\b["']?\s*[=:]\s*["']?[^\s,"'}]{16,}/gi],
  ['aws_session_token', /["']?\b(?:AWS_SESSION_TOKEN|AWS_LAMBDA_METADATA_TOKEN|AWS_METADATA_TOKEN)\b["']?\s*[=:]\s*["']?[^\s,"'}]{12,}/gi],
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ['cvv', /["']?\b(?:cvv|cvc|card[_ -]?(?:verification|security)[_ -]?(?:value|code))\b["']?\s*[=:]\s*["']?\d{3,4}\b/gi],
]);

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function luhn(value) {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = Number(digits[i]);
    if (double) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

function detectPan(text) {
  const rows = [];
  const contextual = /\b(?:card[_ -]?number|credit[_ -]?card|payment[_ -]?card|pan)\b[^\d\r\n]{0,24}((?:\d[ -]?){13,19})/gi;
  let match;
  while ((match = contextual.exec(text)) !== null) {
    const digits = match[1].replace(/\D/g, '');
    if (luhn(digits)) rows.push({ class: 'pan', fingerprint: digest(digits), offset: match.index });
  }
  return rows;
}

function detectPlain(text, provenance) {
  const leaks = [];
  for (const [klass, pattern] of DETECTORS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      leaks.push({
        class: klass,
        fingerprint: digest(match[0]),
        provenance,
        offset: match.index,
      });
      if (match[0].length === 0) pattern.lastIndex += 1;
    }
  }
  leaks.push(...detectPan(text).map((row) => ({ ...row, provenance })));
  return leaks;
}

function decodeBase64Candidates(text) {
  const out = [];
  const pattern = /(?:^|[>"'\s:=,(])([A-Za-z0-9+/_-]{32,}={0,2})(?=$|[<"'\s,})])/g;
  let match;
  while (out.length < MAX_BASE64_CANDIDATES && (match = pattern.exec(text)) !== null) {
    const value = match[1];
    if (value.length % 4 === 1) continue;
    try {
      const decoded = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      if (!decoded.length || decoded.length > MAX_DECODED_BYTES) continue;
      const printable = decoded.toString('utf8');
      const printableChars = printable.replace(/[\x20-\x7e\r\n\t]/g, '').length;
      if (printableChars > Math.max(2, printable.length * 0.08)) continue;
      out.push({ text: printable, sourceOffset: match.index });
    } catch { /* malformed candidate */ }
  }
  return out;
}

export function auditArtifactContent(content, { artifact = '[memory]' } = {}) {
  const text = Buffer.isBuffer(content) ? content.toString('utf8') : String(content ?? '');
  const leaks = detectPlain(text, 'plain');
  for (const candidate of decodeBase64Candidates(text)) {
    for (const leak of detectPlain(candidate.text, 'base64_decoded')) {
      leaks.push({ ...leak, encodedOffset: candidate.sourceOffset });
    }
  }
  const unique = [...new Map(leaks.map((leak) => [`${leak.class}:${leak.fingerprint}:${leak.provenance}`, leak])).values()]
    .map(({ offset: _offset, encodedOffset: _encodedOffset, ...safe }) => safe);
  const classes = {};
  for (const leak of unique) classes[leak.class] = (classes[leak.class] || 0) + 1;
  return {
    artifact,
    safe: unique.length === 0,
    publicationAllowed: unique.length === 0,
    leakCount: unique.length,
    classes,
    leaks: unique,
  };
}

function isInside(root, file) {
  const rel = path.relative(root, file);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export async function runArtifactSafetyAudit({ paths = [], allowedRoot, maxFileBytes = MAX_FILE_BYTES } = {}) {
  if (!allowedRoot) throw new Error('artifact_safety_audit: allowedRoot obrigatorio');
  const root = await realpath(allowedRoot);
  const results = [];
  for (const candidate of [...new Set(paths.map((item) => path.resolve(String(item))))]) {
    let resolved;
    try {
      const stat = await lstat(candidate);
      if (stat.isSymbolicLink() || !stat.isFile()) {
        results.push({ artifact: candidate, safe: false, publicationAllowed: false, error: 'unsupported_file_type' });
        continue;
      }
      resolved = await realpath(candidate);
      if (!isInside(root, resolved)) {
        results.push({ artifact: candidate, safe: false, publicationAllowed: false, error: 'outside_allowed_root' });
        continue;
      }
      if (stat.size > maxFileBytes) {
        results.push({ artifact: resolved, safe: false, publicationAllowed: false, error: 'file_too_large' });
        continue;
      }
      results.push(auditArtifactContent(await readFile(resolved), { artifact: resolved }));
    } catch (error) {
      results.push({ artifact: candidate, safe: false, publicationAllowed: false, error: error?.code || 'read_failed' });
    }
  }
  return {
    state: results.every((item) => item.safe) ? 'completed' : 'blocked_sensitive_artifact',
    publicationAllowed: results.every((item) => item.publicationAllowed),
    filesAudited: results.length,
    leakCount: results.reduce((sum, item) => sum + Number(item.leakCount || 0), 0),
    results,
  };
}
