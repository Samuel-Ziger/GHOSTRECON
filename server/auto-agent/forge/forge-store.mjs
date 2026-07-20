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

export async function createPendingForgeRequest({ root, requestRunId, target, decision, council, authorOverride = null, authorModelOverride = null, createdAt = new Date() } = {}) {
  const request = decision?.forgeRequest;
  if (!request) return null;
  if (request.intrusive) throw new Error('Module Forge intrusivo bloqueado');
  const author = slug(authorOverride || request.author || 'council');
  const resolvedModel = authorModelOverride || request.authorModel || null;
  const model = resolvedModel ? slug(resolvedModel) : null;
  const ownerDir = model ? path.join(author, model) : author;
  const forgeId = `forge-${createdAt.getTime().toString(36)}-${randomBytes(3).toString('hex')}`;
  const dir = path.join(resolveForgeRoot(root), ownerDir, 'pending', forgeId);
  await fs.mkdir(dir, { recursive: true });
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
    fs.writeFile(path.join(dir, 'forge-request.json'), JSON.stringify(request, null, 2), 'utf8'),
    fs.writeFile(path.join(dir, 'provenance.json'), JSON.stringify(provenance, null, 2), 'utf8'),
    fs.writeFile(path.join(dir, 'verdict.json'), JSON.stringify(verdict, null, 2), 'utf8'),
    fs.writeFile(path.join(dir, 'council-transcript.json'), JSON.stringify(council || null, null, 2), 'utf8'),
    fs.writeFile(path.join(dir, 'council-transcript.ndjson'), transcript.map((row) => JSON.stringify(row)).join('\n') + (transcript.length ? '\n' : ''), 'utf8'),
    fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ private: true, type: 'module' }, null, 2), 'utf8'),
    fs.writeFile(path.join(dir, 'README.md'), [
      `# Pending Module Forge: ${request.proposedId}`,
      '',
      `- Forge ID: \`${forgeId}\``,
      `- Author: \`${author}\``,
      `- Target: \`${target}\``,
      '- Pipeline enabled: `false`',
      '',
      'Este pacote preserva a proposta e o veredito. Ainda não contém módulo aprovado e não pode entrar no pipeline.',
    ].join('\n'), 'utf8'),
  ]);
  return { forgeId, dir, state: 'proposed', author, model: resolvedModel };
}
