export const moduleManifest = {
  id: 'runtime_endpoint_pivot',
  name: 'Runtime Endpoint Pivot',
  category: 'discovery',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 10_000,
  concurrency: 1,
  outputs: ['finding', 'intel'],
};

const ABSOLUTE_URL_RE = /https?:\/\/[^\s"'<>\\)\]]+/gi;

function classifyRuntimeProvider(url) {
  const host = url.hostname.toLowerCase();
  if (/^[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws$/.test(host)) return 'aws_lambda_function_url';
  if (host.endsWith('.cloudfunctions.net')) return 'google_cloud_function';
  if (host.endsWith('.azurewebsites.net')) return 'azure_app_service';
  if (host.endsWith('.vercel.app')) return 'vercel';
  return null;
}

function safeProvenanceURL(value) {
  try {
    const parsed = new URL(String(value || ''));
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.href;
  } catch {
    return '';
  }
}

export function extractRuntimeEndpointCandidates(observations = []) {
  const candidates = [];
  const seen = new Set();
  for (const observation of Array.isArray(observations) ? observations : []) {
    const sourceURL = safeProvenanceURL(observation?.url);
    const body = String(observation?.body || observation?.text || '').slice(0, 500_000);
    if (!body || observation?.reflectedInput === true) continue;
    for (const raw of body.match(ABSOLUTE_URL_RE) || []) {
      try {
        const parsed = new URL(raw.replace(/[.,;:]+$/, ''));
        if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password) continue;
        const provider = classifyRuntimeProvider(parsed);
        if (!provider) continue;
        parsed.hash = '';
        const href = parsed.href;
        const key = href.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        candidates.push({
          url: href,
          origin: parsed.origin,
          provider,
          sourceURL,
          state: 'scope_candidate',
          automaticallyFollowed: false,
        });
      } catch {
        // A malformed absolute URL is not a candidate.
      }
    }
  }
  return candidates;
}

export async function runRuntimeEndpointPivot({ observations = [] } = {}) {
  const candidates = extractRuntimeEndpointCandidates(observations);
  return {
    candidates,
    findings: candidates.map((candidate) => ({
      type: 'runtime_endpoint_inventory',
      prio: 'info',
      score: 20,
      value: `Endpoint runtime cloud referenciado: ${candidate.origin}`,
      meta: [
        'source=runtime_endpoint_pivot',
        'classification=inventory',
        `provider=${candidate.provider}`,
        'scope_candidate=true',
        'automatically_followed=false',
        `provenance=${candidate.sourceURL || 'unknown'}`,
      ].join(' • '),
      url: candidate.url,
    })),
    status: observations.length ? 'done' : 'skipped',
    reason: observations.length ? undefined : 'no_observations',
    metrics: { observations: observations.length, candidates: candidates.length },
  };
}
