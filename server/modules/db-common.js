import crypto from 'crypto';

export function norm(s) {
  return String(s ?? '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

export function fingerprintFinding(target, f) {
  const raw = `${norm(target)}|${norm(f.type)}|${norm(f.value)}|${norm(f.url)}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}
