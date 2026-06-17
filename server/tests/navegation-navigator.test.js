import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..', '..');
const TOR_DIR = join(ROOT, '.runtime', 'tor');

describe('navegation navigator mode', () => {
  const prevNavigator = process.env.GHOSTRECON_NAVIGATOR_MODE;
  const prevSystem = process.env.GHOSTRECON_NAVEGATION_SYSTEM;

  after(() => {
    if (prevNavigator === undefined) delete process.env.GHOSTRECON_NAVIGATOR_MODE;
    else process.env.GHOSTRECON_NAVIGATOR_MODE = prevNavigator;
    if (prevSystem === undefined) delete process.env.GHOSTRECON_NAVEGATION_SYSTEM;
    else process.env.GHOSTRECON_NAVEGATION_SYSTEM = prevSystem;
  });

  it('isNavigatorModeActive exige activação explícita', async () => {
    const { isNavigatorModeActive } = await import('../modules/navegation.js');
    delete process.env.GHOSTRECON_NAVIGATOR_MODE;
    assert.equal(isNavigatorModeActive({}), false);
    assert.equal(isNavigatorModeActive({ navigatorMode: true }), true);
    assert.equal(isNavigatorModeActive({ navegation: { enabled: true } }), true);
    process.env.GHOSTRECON_NAVIGATOR_MODE = '1';
    assert.equal(isNavigatorModeActive({}), true);
  });

  it('ensureUserTorStack escreve torrc em .runtime/tor sem sudo', async () => {
    process.env.GHOSTRECON_NAVEGATION_SYSTEM = '0';
    const { ensureUserTorStack } = await import('../modules/navegation.js');
    await mkdir(TOR_DIR, { recursive: true });
    const res = await ensureUserTorStack(ROOT, { bootstrapWaitMs: 300 });
    assert.equal(res.userMode, true);
    const torrc = await readFile(join(TOR_DIR, 'torrc'), 'utf8');
    assert.match(torrc, /DataDirectory/);
    assert.match(torrc, /SocksPort 127\.0\.0\.1:9050/);
    assert.doesNotMatch(torrc, /\/etc\/tor\/torrc/);
  });

  it('executeNavegationPlaybook status em user mode não exige openvpn', async () => {
    const { executeNavegationPlaybook } = await import('../modules/navegation.js');
    const res = await executeNavegationPlaybook(ROOT, { action: 'status', userMode: true });
    assert.equal(res.userMode, true);
    assert.match(res.stdout || '', /openvpn=skipped-user-mode/);
  });
});
