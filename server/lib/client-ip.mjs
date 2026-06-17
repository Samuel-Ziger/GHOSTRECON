export function isLoopbackIp(ip) {
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

export function clientIp(req) {
  const direct = String(req.socket?.remoteAddress || req.connection?.remoteAddress || '_');
  const trustProxy = /^(1|true|yes|on)$/i.test(
    String(process.env.GHOSTRECON_TRUST_PROXY || process.env.TRUST_PROXY || '').trim(),
  );
  if (trustProxy && isLoopbackIp(direct)) {
    return (
      String(req.headers['x-forwarded-for'] || '')
        .split(',')[0]
        ?.trim() || direct
    );
  }
  return direct;
}
