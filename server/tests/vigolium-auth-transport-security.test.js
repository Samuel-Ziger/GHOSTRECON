import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  createVigoliumAuthTransport,
  inspectVigoliumAuthFileIdentities,
} from '../../bridge/vigolium-auth-transport.mjs';

async function privateFixtureRoot(prefix) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  if (process.platform !== 'win32') await fs.chmod(root, 0o700);
  return root;
}

async function writePrivateJson(filePath, value) {
  await fs.writeFile(filePath, `${JSON.stringify(value)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  if (process.platform !== 'win32') await fs.chmod(filePath, 0o600);
}

test('auth-file aprovado é copiado para transporte 0700/0600 e removido no cleanup', async () => {
  const root = await privateFixtureRoot('ghostrecon-vig-auth-secure-');
  const original = path.join(root, 'approved.json');
  const secret = 'synthetic-transport-secret';
  await writePrivateJson(original, {
    sessions: [{ name: 'fixture', headers: { Authorization: `Bearer ${secret}` } }],
  });

  try {
    const identities = await inspectVigoliumAuthFileIdentities(
      [original],
      { allowedRoots: [root] },
    );
    const transport = await createVigoliumAuthTransport({
      vigoliumRuntimeConfigFrozen: true,
      vigoliumAuthFiles: [original],
      vigoliumExpectedAuthFileIdentities: identities,
      vigoliumAuthAllowedRoots: [root],
    }, { tempRoot: root });
    const copied = transport.authFiles[0];
    try {
      assert.notEqual(copied, original);
      assert.equal(await fs.readFile(copied, 'utf8'), await fs.readFile(original, 'utf8'));
      assert.ok(transport.privateDbPath.startsWith(path.dirname(copied)));
      if (process.platform !== 'win32') {
        assert.equal((await fs.stat(path.dirname(copied))).mode & 0o777, 0o700);
        assert.equal((await fs.stat(copied)).mode & 0o777, 0o600);
      }
      assert.equal(transport.redact(`evidence ${secret}`).includes(secret), false);
    } finally {
      await transport.cleanup();
    }
    await assert.rejects(fs.access(copied));
    assert.equal((await fs.stat(original)).isFile(), true);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('troca do auth-file depois do preflight falha por identidade divergente', async () => {
  const root = await privateFixtureRoot('ghostrecon-vig-auth-mutate-');
  const original = path.join(root, 'approved.json');
  await writePrivateJson(original, { token: 'fixture-a' });
  try {
    const identities = await inspectVigoliumAuthFileIdentities(
      [original],
      { allowedRoots: [root] },
    );
    await writePrivateJson(original, { token: 'fixture-b-with-different-size' });
    await assert.rejects(
      createVigoliumAuthTransport({
        vigoliumRuntimeConfigFrozen: true,
        vigoliumAuthFiles: [original],
        vigoliumExpectedAuthFileIdentities: identities,
        vigoliumAuthAllowedRoots: [root],
      }, { tempRoot: root }),
      (error) => error?.code === 'VIGOLIUM_AUTH_FILE_IDENTITY_MISMATCH',
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('auth-file fora da raiz, symlink, hardlink e permissões amplas são recusados', async (t) => {
  const root = await privateFixtureRoot('ghostrecon-vig-auth-root-');
  const outsideRoot = await privateFixtureRoot('ghostrecon-vig-auth-outside-');
  const file = path.join(root, 'session.json');
  const outside = path.join(outsideRoot, 'outside.json');
  await writePrivateJson(file, { token: 'fixture' });
  await writePrivateJson(outside, { token: 'outside' });
  try {
    await assert.rejects(
      inspectVigoliumAuthFileIdentities([outside], { allowedRoots: [root] }),
      (error) => error?.code === 'VIGOLIUM_AUTH_FILE_OUTSIDE_ROOT',
    );
    if (process.platform === 'win32') {
      t.diagnostic('checks POSIX de symlink/hardlink/mode omitidos no Windows');
      return;
    }

    const symlink = path.join(root, 'session-link.json');
    await fs.symlink(file, symlink);
    await assert.rejects(
      inspectVigoliumAuthFileIdentities([symlink], { allowedRoots: [root] }),
      (error) => error?.code === 'VIGOLIUM_AUTH_FILE_SYMLINK',
    );

    const hardlink = path.join(root, 'session-hardlink.json');
    await fs.link(file, hardlink);
    await assert.rejects(
      inspectVigoliumAuthFileIdentities([file], { allowedRoots: [root] }),
      (error) => error?.code === 'VIGOLIUM_AUTH_FILE_LINKED',
    );
    await fs.rm(hardlink);

    await fs.chmod(file, 0o644);
    await assert.rejects(
      inspectVigoliumAuthFileIdentities([file], { allowedRoots: [root] }),
      (error) => error?.code === 'VIGOLIUM_AUTH_FILE_PERMISSIONS',
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outsideRoot, { recursive: true, force: true });
  }
});

test('root não privado, arquivo grande e signal abortado falham fechado', async (t) => {
  const root = await privateFixtureRoot('ghostrecon-vig-auth-limits-');
  const file = path.join(root, 'large.json');
  await fs.writeFile(file, Buffer.alloc((1024 * 1024) + 1), { mode: 0o600 });
  try {
    await assert.rejects(
      inspectVigoliumAuthFileIdentities([file], { allowedRoots: [root] }),
      (error) => error?.code === 'VIGOLIUM_AUTH_FILE_TOO_LARGE',
    );
    const controller = new AbortController();
    controller.abort(Object.assign(new Error('fixture cancelada'), { code: 'PROCESS_ABORTED' }));
    await assert.rejects(
      inspectVigoliumAuthFileIdentities([file], {
        allowedRoots: [root],
        signal: controller.signal,
      }),
      (error) => error?.code === 'PROCESS_ABORTED',
    );
    if (process.platform !== 'win32') {
      await fs.chmod(root, 0o755);
      await assert.rejects(
        inspectVigoliumAuthFileIdentities([file], { allowedRoots: [root] }),
        (error) => error?.code === 'VIGOLIUM_AUTH_ROOT_PERMISSIONS',
      );
    } else {
      t.diagnostic('check de modo do root omitido no Windows');
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('redactor cobre segredo após a 500ª propriedade do auth-file', async () => {
  const root = await privateFixtureRoot('ghostrecon-vig-auth-redactor-');
  const file = path.join(root, 'many-fields.json');
  const secret = 'synthetic-secret-after-field-500';
  const payload = Object.fromEntries(
    Array.from({ length: 501 }, (_, index) => [`field_${index}`, `value_${index}`]),
  );
  payload.password_after_limit = secret;
  await writePrivateJson(file, payload);
  try {
    const transport = await createVigoliumAuthTransport({
      vigoliumAuthFiles: [file],
      vigoliumAuthAllowedRoots: [root],
    }, { tempRoot: root });
    try {
      assert.equal(transport.redact(`result=${secret}`).includes(secret), false);
    } finally {
      await transport.cleanup();
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
