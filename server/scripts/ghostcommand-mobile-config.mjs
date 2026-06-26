#!/usr/bin/env node
import '../load-env.js';

const baseUrl =
  String(process.argv[2] || process.env.GHOSTCOMMAND_PUBLIC_URL || process.env.GHOSTRECON_PUBLIC_URL || '').trim() ||
  'http://SEU_IP_DA_VPS:3847';

const payload = {
  version: 1,
  app: 'GhostCommand',
  baseUrl: baseUrl.replace(/\/+$/, ''),
  ghostreconApiKey: String(process.env.GHOSTRECON_API_KEY || '').trim(),
  ghostCommandKey: String(process.env.GHOSTCOMMAND_API_KEY || process.env.GHOSTRECON_MOBILE_API_KEY || '').trim(),
};

if (!payload.ghostreconApiKey || !payload.ghostCommandKey) {
  process.stderr.write(
    'ghostcommand-mobile-config: faltando GHOSTRECON_API_KEY ou GHOSTCOMMAND_API_KEY no .env\n',
  );
  process.exit(2);
}

const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
process.stdout.write(`GHOSTCOMMAND_CONFIG=${encoded}\n`);
