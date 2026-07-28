import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertVigoliumSourceIdentity,
  inspectVigoliumSourceIdentity,
  resolveVigoliumSourceAllowedRoots,
} from '../../bridge/vigolium-source-integrity.mjs';

const COMMIT_A = 'a'.repeat(40);
const COMMIT_B = 'b'.repeat(40);
const TREE_A = 'c'.repeat(40);
const TREE_B = 'd'.repeat(40);

async function fixtureSource(prefix = 'ghostrecon-vig-source-') {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  const source = path.join(root, 'clone');
  const gitDir = path.join(source, '.git');
  await fs.mkdir(gitDir, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    await fs.chmod(root, 0o700);
    await fs.chmod(source, 0o700);
    await fs.chmod(gitDir, 0o700);
  }
  return { root, source, gitDir };
}

function fakeGit({
  commit = COMMIT_A,
  tree = TREE_A,
  statusBefore = '',
  statusAfter = '',
  index = `100644 ${'e'.repeat(40)} 0\tREADME.md\0`,
} = {}) {
  const calls = [];
  let statusCalls = 0;
  const run = async (cmd, args, options) => {
    calls.push({ cmd, args: [...args], options });
    assert.equal(cmd, 'git');
    assert.equal(args.includes('--shell'), false);
    assert.equal(options.spawnOpts?.shell, undefined);
    assert.equal(options.spawnOpts?.env?.GIT_TERMINAL_PROMPT, '0');
    assert.equal(options.spawnOpts?.env?.GIT_CONFIG_NOSYSTEM, '1');
    assert.equal(options.spawnOpts?.env?.GITHUB_TOKEN, undefined);
    assert.ok(options.signal == null || options.signal instanceof AbortSignal);
    const command = args[args.indexOf('-C') + 2];
    if (command === 'status') {
      const stdout = statusCalls++ === 0 ? statusBefore : statusAfter;
      return { code: 0, stdout, stderr: '', timedOut: false };
    }
    if (command === 'ls-files') {
      return { code: 0, stdout: index, stderr: '', timedOut: false };
    }
    if (command === 'rev-parse' && args.at(-1) === 'HEAD^{commit}') {
      return { code: 0, stdout: `${commit}\n`, stderr: '', timedOut: false };
    }
    if (command === 'rev-parse' && args.at(-1) === 'HEAD^{tree}') {
      return { code: 0, stdout: `${tree}\n`, stderr: '', timedOut: false };
    }
    throw new Error(`comando fixture inesperado: ${command}`);
  };
  return { run, calls };
}

test('sela commit/tree de fonte Git limpa dentro da raiz permitida', async () => {
  const { root, source } = await fixtureSource();
  const fixture = fakeGit();
  const controller = new AbortController();
  try {
    const identity = await inspectVigoliumSourceIdentity(source, {
      allowedRoots: [root],
      signal: controller.signal,
      timeoutMs: 5_000,
      runProcessImpl: fixture.run,
      env: { PATH: process.env.PATH, GITHUB_TOKEN: 'nao-propagar' },
    });
    assert.equal(identity.kind, 'git-worktree');
    assert.equal(identity.objectFormat, 'sha1');
    assert.equal(identity.commit, COMMIT_A);
    assert.equal(identity.tree, TREE_A);
    assert.equal(identity.trackedEntries, 1);
    assert.equal(fixture.calls.length, 5);
    assert.ok(fixture.calls.every((call) => call.options.timeoutMs > 0));

    const asserted = await assertVigoliumSourceIdentity(source, identity, {
      allowedRoots: [root],
      signal: controller.signal,
      runProcessImpl: fakeGit().run,
    });
    assert.equal(asserted.commit, identity.commit);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('fontes remotas falham fechado antes de chamar Git', async () => {
  let calls = 0;
  const runProcessImpl = async () => {
    calls += 1;
    throw new Error('não deveria executar');
  };
  for (const source of [
    'https://example.invalid/repo.git',
    'ssh://git@example.invalid/repo.git',
    'git@example.invalid:repo.git',
    '\\\\server\\share\\repo',
  ]) {
    await assert.rejects(
      inspectVigoliumSourceIdentity(source, {
        allowedRoots: ['/tmp'],
        runProcessImpl,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_REMOTE_FORBIDDEN',
    );
  }
  assert.equal(calls, 0);
});

test('fonte fora da raiz, symlink e diretório gravável por outros são recusados', async (t) => {
  const inside = await fixtureSource('ghostrecon-vig-source-inside-');
  const outside = await fixtureSource('ghostrecon-vig-source-outside-');
  try {
    await assert.rejects(
      inspectVigoliumSourceIdentity(outside.source, {
        allowedRoots: [inside.root],
        runProcessImpl: fakeGit().run,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_OUTSIDE_ROOT',
    );
    if (process.platform === 'win32') {
      t.diagnostic('checks POSIX de symlink/permissão omitidos no Windows');
      return;
    }
    const linked = path.join(inside.root, 'linked-source');
    await fs.symlink(inside.source, linked);
    await assert.rejects(
      inspectVigoliumSourceIdentity(linked, {
        allowedRoots: [inside.root],
        runProcessImpl: fakeGit().run,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_SYMLINK',
    );

    await fs.chmod(inside.source, 0o777);
    await assert.rejects(
      inspectVigoliumSourceIdentity(inside.source, {
        allowedRoots: [inside.root],
        runProcessImpl: fakeGit().run,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_PERMISSIONS',
    );
  } finally {
    await fs.rm(inside.root, { recursive: true, force: true });
    await fs.rm(outside.root, { recursive: true, force: true });
  }
});

test('fonte suja/ignorada e mutação durante inspeção são recusadas sem vazar filename', async () => {
  const { root, source } = await fixtureSource();
  try {
    await assert.rejects(
      inspectVigoliumSourceIdentity(source, {
        allowedRoots: [root],
        runProcessImpl: fakeGit({ statusBefore: '?? segredo-operador.txt\0' }).run,
      }),
      (error) => {
        assert.equal(error?.code, 'VIGOLIUM_SOURCE_DIRTY');
        assert.doesNotMatch(error.message, /segredo-operador/);
        return true;
      },
    );
    await assert.rejects(
      inspectVigoliumSourceIdentity(source, {
        allowedRoots: [root],
        runProcessImpl: fakeGit({ statusAfter: '!! build-privado/\0' }).run,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_CHANGED',
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('symlink rastreado e submódulo não entram na identidade aprovada', async () => {
  const { root, source } = await fixtureSource();
  try {
    await assert.rejects(
      inspectVigoliumSourceIdentity(source, {
        allowedRoots: [root],
        runProcessImpl: fakeGit({
          index: `120000 ${'e'.repeat(40)} 0\toutside\0`,
        }).run,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_TRACKED_SYMLINK',
    );
    await assert.rejects(
      inspectVigoliumSourceIdentity(source, {
        allowedRoots: [root],
        runProcessImpl: fakeGit({
          index: `160000 ${'e'.repeat(40)} 0\tdependency\0`,
        }).run,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_SUBMODULE',
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('revalidação detecta commit/tree divergente do plano aprovado', async () => {
  const { root, source } = await fixtureSource();
  try {
    const expected = await inspectVigoliumSourceIdentity(source, {
      allowedRoots: [root],
      runProcessImpl: fakeGit({ commit: COMMIT_A, tree: TREE_A }).run,
    });
    await assert.rejects(
      assertVigoliumSourceIdentity(source, expected, {
        allowedRoots: [root],
        runProcessImpl: fakeGit({ commit: COMMIT_B, tree: TREE_B }).run,
      }),
      (error) => error?.code === 'VIGOLIUM_SOURCE_IDENTITY_MISMATCH',
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('AbortSignal e timeout terminal são preservados', async () => {
  const { root, source } = await fixtureSource();
  try {
    const controller = new AbortController();
    const reason = Object.assign(new Error('cancelamento fixture'), {
      code: 'PROCESS_ABORTED',
    });
    controller.abort(reason);
    await assert.rejects(
      inspectVigoliumSourceIdentity(source, {
        allowedRoots: [root],
        signal: controller.signal,
        runProcessImpl: fakeGit().run,
      }),
      (error) => error === reason,
    );

    const timeout = Object.assign(new Error('timeout fixture'), {
      code: 'PROCESS_TIMEOUT',
    });
    await assert.rejects(
      inspectVigoliumSourceIdentity(source, {
        allowedRoots: [root],
        runProcessImpl: async () => {
          throw timeout;
        },
      }),
      (error) => error === timeout,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('raiz de source usa configuração explícita ou clone/ por padrão', () => {
  const root = path.resolve('/workspace/ghostrecon');
  assert.deepEqual(
    resolveVigoliumSourceAllowedRoots(root, {}),
    [path.join(root, 'clone')],
  );
  assert.deepEqual(
    resolveVigoliumSourceAllowedRoots(root, {
      GHOSTRECON_VIGOLIUM_SOURCE_ROOT: '/workspace/approved-sources',
    }),
    [path.resolve('/workspace/approved-sources')],
  );
});
