import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildVigoliumAuthConfig, saveVigoliumAuthConfig } from '../../bridge/vigolium-auth-config.mjs';

describe('vigolium auth config', () => {
  it('gera sessoes primary/compare com headers, cookie e bearer', () => {
    const cfg = buildVigoliumAuthConfig({
      sessions: [
        { name: 'admin', cookie: 'sid=admin', headerLines: 'X-Team: red' },
        { name: 'user one', role: 'compare', bearer: 'token-user' },
      ],
      reauthOnStatus: [401, 403, 999, '302'],
    });

    assert.equal(cfg.sessions.length, 2);
    assert.equal(cfg.sessions[0].role, 'primary');
    assert.equal(cfg.sessions[0].headers.Cookie, 'sid=admin');
    assert.equal(cfg.sessions[0].headers['X-Team'], 'red');
    assert.equal(cfg.sessions[1].name, 'user_one');
    assert.equal(cfg.sessions[1].headers.Authorization, 'Bearer token-user');
    assert.deepEqual(cfg.scanning_strategy.session.reauth_on_status, [401, 403, 302]);
  });

  it('salva arquivo JSON em .runtime/vigolium-sessions', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-auth-'));
    try {
      const out = await saveVigoliumAuthConfig({
        name: 'api target',
        sessions: [{ cookie: 'sid=abc' }],
      }, { root });
      assert.equal(out.ok, true);
      assert.equal(path.basename(out.filePath), 'api_target.json');
      const saved = JSON.parse(await fs.readFile(out.filePath, 'utf8'));
      assert.equal(saved.sessions[0].headers.Cookie, 'sid=abc');
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
