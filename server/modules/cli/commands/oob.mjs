/**
 * ghostrecon oob — controla catcher OOB local (DNS+HTTP).
 *
 * --start          inicia catcher (bloqueia)
 * --mint           cria token e imprime payloads
 * --hits TOKEN     lista hits acumulados (modo standalone via state file)
 *
 * Catcher é por-processo; em uso real o operador deixa --start rodando em
 * outro terminal e usa --mint daqui (mesmo processo). Aqui simplificamos:
 * --start abre, gera token automático e fica printando hits.
 */
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import { startCatcher, buildOobPayloads } from '../../oob-collaborator.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'start', type: 'bool', default: false },
  { name: 'host', type: 'string', default: '127.0.0.1' },
  { name: 'public-host', type: 'string' },
  { name: 'dns-port', type: 'int', default: 8053 },
  { name: 'http-port', type: 'int', default: 8054 },
  { name: 'no-dns', type: 'bool', default: false },
  { name: 'no-http', type: 'bool', default: false },
  { name: 'note', type: 'string' },
  { name: 'mint-only', type: 'bool', default: false },
];

export async function oobCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`oob: ${e.message}\n`); return 2; }

  const publicHost = opts['public-host'] || opts.host;

  if (opts['mint-only']) {
    // só imprime payloads pro operador injetar — assume catcher já rodando
    const tok = Math.random().toString(16).slice(2, 18).padEnd(16, '0').slice(0, 16);
    const p = buildOobPayloads({ token: tok, host: publicHost, httpPort: opts['http-port'] });
    process.stdout.write(JSON.stringify({ token: tok, payloads: p }, null, 2) + '\n');
    return 0;
  }

  if (!opts.start) {
    process.stderr.write('oob: --start (ou --mint-only) requerido\n');
    return 2;
  }

  const cat = await startCatcher({
    port: opts['dns-port'], httpPort: opts['http-port'],
    host: opts.host, publicHost,
    startDns: !opts['no-dns'], startHttp: !opts['no-http'],
  });
  const t = cat.mintToken({ note: opts.note || 'cli-mint' });
  const p = buildOobPayloads({ token: t.token, host: publicHost, httpPort: cat.httpPort });
  process.stdout.write(`[oob] catcher up — DNS=${cat.port} HTTP=${cat.httpPort}\n`);
  process.stdout.write(`[oob] token=${t.token}\n`);
  process.stdout.write(`[oob] dns-host=${t.dnsHost}\n`);
  process.stdout.write(`[oob] http-url=${t.httpUrl}\n\n`);
  process.stdout.write('--- payloads ---\n');
  process.stdout.write(JSON.stringify(p, null, 2) + '\n\n');
  process.stdout.write('--- aguardando hits (Ctrl+C para sair) ---\n');

  const seen = new Set();
  const tick = setInterval(() => {
    const hs = cat.hits(t.token);
    for (const h of hs) {
      const key = `${h.kind}:${h.at}:${h.query || h.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      process.stdout.write(`[hit] ${JSON.stringify(h)}\n`);
    }
  }, 500);

  process.on('SIGINT', async () => {
    clearInterval(tick);
    await cat.stop();
    process.exit(0);
  });
  // bloqueia indefinidamente
  await new Promise(() => {});
  return 0;
}
