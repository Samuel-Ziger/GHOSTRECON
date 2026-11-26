import { attachRunToEngagement, getEngagement, preRunChecklist } from '../../modules/engagement.mjs';
import { parseReconTarget } from '../../modules/recon-target.js';
import { redactAutoValue } from '../../auto-agent/redaction.mjs';
import { getArtexClient } from '../artex/client.mjs';
import { syncNeuroSploitFindingsToCortex } from './cortex.mjs';
import { getNeuroSploitManager } from './manager.mjs';
import { resolveNeuroSploitProfile } from './profile.mjs';

function bounded(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, Math.floor(number))) : fallback;
}

function publicContext({ sessionId, requestRunId, target, engagementId, effectivePlan, engineOutcomes, moduleOutcomes, findings }) {
  return redactAutoValue({
    schema: 'ghostrecon.neurosploit-auto-context.v1',
    generatedAt: new Date().toISOString(),
    source: 'ghostrecon-auto',
    sessionId,
    requestRunId,
    target,
    engagementId,
    plan: {
      hash: effectivePlan?.hash || null,
      iteration: effectivePlan?.iteration || null,
      autonomyLevel: effectivePlan?.autonomyLevel || null,
      mode: effectivePlan?.mode || null,
      opsecProfile: effectivePlan?.opsecProfile || null,
      selectedModules: effectivePlan?.selectedModules || [],
      activeModules: effectivePlan?.activeModules || [],
      intrusiveModules: effectivePlan?.intrusiveModules || [],
    },
    completed: {
      engines: engineOutcomes || [],
      modules: moduleOutcomes || [],
    },
    observedFindings: (Array.isArray(findings) ? findings : []).slice(0, 500),
    instruction: 'Não repita coleta concluída sem justificativa. Valide lacunas, preserve escopo/ROE e emita apenas achados sustentados por evidência.',
  });
}

function findingKey(finding) {
  return [finding?.id, finding?.fingerprint, finding?.title, finding?.endpoint]
    .map((value) => String(value || ''))
    .join('|');
}

export async function runAutoNeuroSploit({
  root,
  sessionId,
  requestRunId,
  owner,
  target,
  engagementId,
  effectivePlan,
  engineOutcomes = [],
  moduleOutcomes = [],
  findings = [],
  signal = null,
  emit = () => {},
  artexClient = null,
  manager = null,
  getEngagementImpl = getEngagement,
} = {}) {
  const engine = effectivePlan?.engines?.neurosploit;
  if (!engine?.enabled) return { skipped: true, findings: [] };
  const parsed = parseReconTarget(target);
  if (!parsed.ok) throw new Error(parsed.message || 'alvo NeuroSploit Auto inválido');
  if (!engagementId) throw new Error('NeuroSploit no Auto exige engagement formal');
  const engagement = await getEngagementImpl(engagementId);
  const checklist = preRunChecklist({
    engagement,
    target: parsed.hostname,
    modules: [...(effectivePlan.expandedModules || []), 'neurosploit_auto'],
    intrusiveModules: ['neurosploit_auto'],
    requireFormalAuthorization: true,
  });
  if (!checklist.ok) throw new Error(`NeuroSploit Auto bloqueado pelo engagement: ${checklist.errors.join(' ')}`);

  const client = artexClient || getArtexClient({ root });
  const profile = await resolveNeuroSploitProfile(client, engine.profileId);
  if (engine.codexCli && String(profile.format || '') !== 'chatgpt-plan') {
    throw new Error('NeuroSploit Auto com MCP exige perfil Codex/ChatGPT Plan');
  }
  const artexToken = engine.codexCli ? '' : await client.login();
  const runtime = manager || getNeuroSploitManager({
    root,
    onTerminal: async (job) => {
      const cortex = await syncNeuroSploitFindingsToCortex({ job, findings: job.findings });
      if (job.engagementId && job.runId) {
        await attachRunToEngagement(job.engagementId, {
          runId: `neurosploit:${job.runId}`,
          target: job.target,
          by: job.owner,
        });
      }
      return cortex;
    },
  });
  const autoContext = publicContext({
    sessionId,
    requestRunId,
    target: parsed.target,
    engagementId,
    effectivePlan,
    engineOutcomes,
    moduleOutcomes,
    findings,
  });
  const started = await runtime.start({
    mode: 'run',
    target: parsed.explicitUrl ? parsed.targetUrl : parsed.target,
    repository: '',
    engagementId,
    authorizationConfirmed: true,
    authorizationReference: `GHOSTRECON Auto ${sessionId} · plano ${effectivePlan.hash}`,
    environment: engine.environment || 'production',
    policy: 'web',
    votes: bounded(engine.votes, 2, 1, 5),
    recon: bounded(engine.recon, 1, 1, 4),
    chainDepth: bounded(engine.chainDepth, 2, 0, 6),
    maxAgents: bounded(engine.maxAgents, 0, 0, 64),
    quick: engine.quick === true,
    focus: String(engine.focus || '').slice(0, 2_000),
    objective: String(engine.objective || 'Validar e encadear as lacunas restantes do plano Auto GHOSTRECON.').slice(0, 2_000),
    outOfScope: String(engine.outOfScope || '').slice(0, 2_000),
    agents: [],
    codexCli: engine.codexCli === true,
    mcpServers: engine.mcpServers || [],
    autoSessionId: sessionId,
    autoPlanHash: effectivePlan.hash,
    autoContext,
  }, {
    owner,
    profile,
    artexToken,
    artexBaseUrl: client.baseUrl,
    scopeHost: parsed.hostname,
  });
  emit({
    type: 'neurosploit_job_started',
    engine: 'neurosploit',
    sessionId,
    planHash: effectivePlan.hash,
    jobId: started.id,
    profileId: started.profileId,
    model: started.model,
  });
  const emitted = new Set();
  const terminal = await runtime.waitForTerminal(started.id, {
    signal,
    timeoutMs: bounded(engine.timeoutMs, 90 * 60_000, 60_000, 2 * 60 * 60_000),
    onEvent: (event) => {
      if (event?.type === 'log') {
        emit({ type: 'neurosploit_log', engine: 'neurosploit', jobId: started.id, line: event.line });
      } else if (event?.type === 'finding' && event.finding) {
        emitted.add(findingKey(event.finding));
        emit({ type: 'finding', engine: 'neurosploit', jobId: started.id, finding: event.finding });
      }
    },
  });
  for (const finding of terminal.findings || []) {
    const key = findingKey(finding);
    if (!emitted.has(key)) emit({ type: 'finding', engine: 'neurosploit', jobId: started.id, finding });
  }
  if (terminal.phase !== 'completed' || Number(terminal.exitCode) !== 0) {
    throw new Error(`NeuroSploit encerrou com estado ${terminal.phase} (exit ${terminal.exitCode})`);
  }
  return {
    jobId: terminal.id,
    runId: terminal.runId,
    status: terminal.phase,
    findings: terminal.findings || [],
    cortex: terminal.cortex || null,
    reportReady: terminal.reportReady === true,
  };
}
