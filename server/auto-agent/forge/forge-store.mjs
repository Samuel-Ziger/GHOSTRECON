import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

function slug(value, fallback = 'unknown') {
  const out = String(value || '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 100);
  return out || fallback;
}

export function resolveForgeRoot(root) {
  return path.join(root, 'dynamic', 'by-model');
}

function assertForgePathInsideRoot(root, candidate) {
  const base = path.resolve(resolveForgeRoot(root));
  const resolved = path.resolve(candidate);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error('Forge path fora do store autorizado');
  }
  return resolved;
}

async function writeForgeFile(filePath, contents) {
  await fs.writeFile(filePath, contents, { encoding: 'utf8', mode: 0o600 });
  await fs.chmod(filePath, 0o600).catch(() => {});
}

export async function createPendingForgeRequest({ root, requestRunId, target, decision, council, authorOverride = null, authorModelOverride = null, createdAt = new Date() } = {}) {
  const request = decision?.forgeRequest;
  if (!request) return null;
  if (request.intrusive) throw new Error('Module Forge intrusivo bloqueado');
  const author = slug(authorOverride || request.author || 'council');
  const resolvedModel = authorModelOverride || request.authorModel || null;
  const model = resolvedModel ? slug(resolvedModel) : null;
  const ownerDir = model ? path.join(author, model) : author;
  if (ownerDir.includes('..') || path.isAbsolute(ownerDir)) {
    throw new Error('Forge author/model path inválido');
  }
  const forgeId = `forge-${createdAt.getTime().toString(36)}-${randomBytes(3).toString('hex')}`;
  const dir = assertForgePathInsideRoot(
    root,
    path.join(resolveForgeRoot(root), ownerDir, 'pending', forgeId),
  );
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700).catch(() => {});
  const provenance = {
    schemaVersion: 1,
    forgeId,
    state: 'proposed',
    author,
    authorModel: resolvedModel,
    contributors: [...new Set(request.approvals || [])],
    requestRunId,
    target,
    createdAt: createdAt.toISOString(),
  };
  const verdict = {
    schemaVersion: 1,
    status: 'pending_council_and_operator_approval',
    approvals: request.approvals || [],
    council: decision?.council || null,
    policy: { intrusiveAllowed: false, operatorApprovalRequired: true, pipelineEnabled: false },
  };
  const transcript = [
    ...(council?.proposals || []).map((turn) => ({ phase: 'proposal', provider: turn.provider, role: turn.role, ok: turn.ok, decision: turn.decision || null, error: turn.error || null })),
    ...(council?.reviews || []).map((turn) => ({ phase: 'review', provider: turn.provider, role: turn.role, ok: turn.ok, decision: turn.decision || null, error: turn.error || null })),
  ];
  await Promise.all([
    writeForgeFile(path.join(dir, 'forge-request.json'), JSON.stringify(request, null, 2)),
    writeForgeFile(path.join(dir, 'provenance.json'), JSON.stringify(provenance, null, 2)),
    writeForgeFile(path.join(dir, 'verdict.json'), JSON.stringify(verdict, null, 2)),
    writeForgeFile(path.join(dir, 'council-transcript.json'), JSON.stringify(council || null, null, 2)),
    writeForgeFile(
      path.join(dir, 'council-transcript.ndjson'),
      transcript.map((row) => JSON.stringify(row)).join('\n') + (transcript.length ? '\n' : ''),
    ),
    writeForgeFile(path.join(dir, 'package.json'), JSON.stringify({ private: true, type: 'module' }, null, 2)),
    writeForgeFile(path.join(dir, 'README.md'), [
      `# Pending Module Forge: ${request.proposedId}`,
      '',
      `- Forge ID: \`${forgeId}\``,
      `- Author: \`${author}\``,
      `- Target: \`${target}\``,
      '- Pipeline enabled: `false`',
      '',
      'Este pacote preserva a proposta e o veredito. Ainda não contém módulo aprovado e não pode entrar no pipeline.',
    ].join('\n')),
  ]);
  return { forgeId, dir, state: 'proposed', author, model: resolvedModel };
}
