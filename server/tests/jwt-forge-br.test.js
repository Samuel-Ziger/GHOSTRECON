import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  collectJwtCandidates,
  forgeBrAuditToFindings,
  jwtForgeBrAvailable,
} from '../modules/jwt-forge-br.mjs';

const demoToken =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9hbyIsInJvbGUiOiJ1c2VyIn0.abcdefghijklmnopqrstuv';

describe('jwt-forge-br', () => {
  it('collectJwtCandidates extrai de auth e findings', () => {
    const tokens = collectJwtCandidates({
      auth: {
        headers: { Authorization: `Bearer ${demoToken}` },
      },
      findings: [
        { type: 'secret', value: `[JWT] ${demoToken}`, meta: 'bundle.js' },
      ],
    });
    assert.equal(tokens.length, 1);
    assert.equal(tokens[0], demoToken);
  });

  it('forgeBrAuditToFindings mapeia severidades críticas', () => {
    const rows = forgeBrAuditToFindings({
      header: { alg: 'HS256' },
      findings: [
        { severity: 'CRITICO', message: 'Secret fraca encontrada: "secret".', mitigation: 'rotacionar' },
        { severity: 'OK', message: 'Expiração em janela razoável.', mitigation: '' },
      ],
    }, 'eyJ…');
    assert.equal(rows.length, 1);
    assert.match(rows[0].value, /Secret fraca/);
    assert.equal(rows[0].prio, 'high');
  });

  it('main.py está presente em tools/jwt-forge-br/', () => {
    assert.equal(jwtForgeBrAvailable(), true);
  });
});
