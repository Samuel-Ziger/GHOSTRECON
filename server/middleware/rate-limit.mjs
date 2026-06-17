import { clientIp } from '../lib/client-ip.mjs';

export function createReconRateLimiter(getConfig) {
  const hits = new Map();

  return function allowReconRequest(req) {
    const { max, windowMs } = getConfig();
    if (max <= 0) return true;
    const sub = req.principal?.sub;
    const engagement = String(req.headers['x-engagement-id'] || '').trim();
    const ip = clientIp(req);
    const key = sub ? `sub:${sub}` : engagement ? `eng:${engagement}` : `ip:${ip}`;
    const now = Date.now();
    const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) return false;
    arr.push(now);
    hits.set(key, arr);
    return true;
  };
}
