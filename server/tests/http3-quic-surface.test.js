import test from 'node:test';
import assert from 'node:assert/strict';
import { auditHttp3QuicSurface, parseAltSvcHttp3 } from '../modules/http3-quic-surface.mjs';

test('parseAltSvcHttp3 extrai h3 e h3-29', () => {
  const out = parseAltSvcHttp3('h3=":443"; ma=86400, h3-29=":443"');
  assert.deepEqual(out.map((x) => x.protocol), ['h3', 'h3-29']);
});

test('auditHttp3QuicSurface cria achado por Alt-Svc h3', () => {
  const findings = auditHttp3QuicSurface({
    probeResults: [
      {
        r: {
          ok: true,
          url: 'https://example.test/',
          securityHeaders: { server: 'nginx', altSvc: 'h3=":443"; ma=86400' },
        },
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'http3');
  assert.match(findings[0].meta, /alt-svc/i);
});

test('auditHttp3QuicSurface aproveita evidencia Nmap', () => {
  const findings = auditHttp3QuicSurface({
    nmapFindings: [{ type: 'nmap', value: 'udp/443 host - quic', meta: 'udp - quic' }],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'http3');
});
