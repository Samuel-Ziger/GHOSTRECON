import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  buildVigoliumAuthConfig,
  publicVigoliumAuthConfig,
  saveVigoliumAuthConfig,
} from '../../bridge/vigolium-auth-config.mjs';

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
      if (process.platform !== 'win32') {
        assert.equal((await fs.stat(path.dirname(out.filePath))).mode & 0o777, 0o700);
        assert.equal((await fs.stat(out.filePath)).mode & 0o777, 0o600);
      }
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('visão pública contém somente capacidades e nomes de headers', () => {
    const raw = buildVigoliumAuthConfig({
      sessions: [{
        name: 'admin',
        cookie: 'sid=opaque-cookie',
        bearer: 'opaque-bearer-token',
        headers: { 'X-Team': 'red' },
        login: { username: 'operator', password: 'opaque-password' },
        login_request: 'POST /login password=opaque-password',
      }],
    });
    const safe = publicVigoliumAuthConfig(raw);
    const serialized = JSON.stringify(safe);
    assert.equal(safe.sessionCount, 1);
    assert.deepEqual(safe.sessions[0].headerNames, ['Authorization', 'Cookie', 'X-Team']);
    assert.equal(safe.sessions[0].hasCookie, true);
    assert.equal(safe.sessions[0].hasAuthorization, true);
    assert.equal(safe.sessions[0].hasLogin, true);
    assert.equal(safe.sessions[0].hasLoginRequest, true);
    assert.doesNotMatch(serialized, /opaque-cookie|opaque-bearer-token|opaque-password|operator/);
  });

  it('recusa header injection e limita quantidade de sessões', () => {
    assert.throws(
      () => buildVigoliumAuthConfig({
        sessions: [{
          headers: { Authorization: 'Bearer safe\r\nCookie: injected=1' },
        }],
      }),
      /valor de header inválido/,
    );
    assert.throws(
      () => buildVigoliumAuthConfig({
        sessions: Array.from({ length: 65 }, (_, index) => ({
          name: `session-${index}`,
          cookie: `sid=${index}`,
        })),
      }),
      /limite de 64 sessões/,
    );
  });
});
