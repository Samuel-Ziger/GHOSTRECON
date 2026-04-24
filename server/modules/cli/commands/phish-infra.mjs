/**
 * ghostrecon phish-infra — recon de domínio canário + fingerprint compare.
 */
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import { auditCampaignDomain, compareFingerprints } from '../../phishing-infra.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'domain', type: 'string' },
  { name: 'compare-a', type: 'string' },
  { name: 'compare-b', type: 'string' },
  { name: 'format', type: 'string', default: 'json' },
];

export async function phishInfraCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`phish-infra: ${e.message}\n`); return 2; }

  if (opts.domain) {
    const res = await auditCampaignDomain(opts.domain);
    if (opts.format === 'summary') {
      process.stdout.write(`[phish-infra] ${res.domain} · findings=${res.findings.length}\n`);
      for (const f of res.findings) process.stdout.write(`  [${(f.severity || 'info').toUpperCase()}] ${f.title}\n`);
      process.stdout.write(`SPF: ${res.summary.dns.spf || '(ausente)'}\n`);
      process.stdout.write(`DMARC: ${res.summary.dns.dmarc || '(ausente)'}\n`);
      process.stdout.write(`DKIM selectors com registro: ${(res.summary.dns.dkim || []).map((d) => d.selector).join(', ') || '(nenhum)'}\n`);
      return 0;
    }
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    return 0;
  }

  if (opts['compare-a'] && opts['compare-b']) {
    const res = await compareFingerprints(opts['compare-a'], opts['compare-b']);
    if (opts.format === 'summary') {
      process.stdout.write(`[phish-infra] score=${res.score} · verdict=${res.verdict}\n`);
      process.stdout.write(`TLS diff: ${res.tls.compare.diff.length} · Header diff: ${res.headers.compare.diff.length}\n`);
      return 0;
    }
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    return 0;
  }

  process.stderr.write('phish-infra: use --domain <d> OU --compare-a <host> --compare-b <host>\n');
  return 2;
}
