import { useEffect, useState } from 'react';
import { formatElapsed, type PipelineStats } from '../pipeline/model';
import { useExecutionState } from './store';

type PipelineNodeDefinition = readonly [
  id: string,
  label: string,
  title: string,
  group?: string,
];

type PipelinePhaseDefinition = {
  group?: string;
  label: string;
  nodes: readonly PipelineNodeDefinition[];
  phase: string;
};

export const PIPELINE_PHASES: readonly PipelinePhaseDefinition[] = [
  {
    label: '01 RECON', phase: 'recon', nodes: [
      ['input', 'INPUT', 'Target, scope, OPSEC and engagement checks'],
      ['lovable_fingerprint', 'LOVABLE', 'Lovable/Supabase fingerprint'],
      ['supabase_audit', 'SUPA', 'Supabase RLS/Auth/Storage audit'],
      ['firebase_audit', 'FIREBASE', 'Firebase RTDB/Firestore/Storage audit'],
      ['subdomains', 'SUBS', 'crt.sh, VirusTotal, subfinder, amass'],
      ['ct_monitor', 'CT', 'Certificate Transparency monitor'],
      ['origin_discovery', 'ORIGIN', 'Origin discovery behind CDN/WAF'],
      ['dns_enrichment', 'DNS', 'TXT/MX/SPF/DMARC enrichment'],
      ['email_security_deep', 'EMAIL', 'SPF/DMARC/DKIM/BIMI/MTA-STS/TLS-RPT'],
      ['rdap', 'RDAP', 'WHOIS/RDAP registration'],
    ],
  },
  {
    label: '02 SURFACE', phase: 'surface', nodes: [
      ['alive', 'ALIVE', 'HTTP probe over http/https for discovered hosts'],
      ['wafw00f', 'WAF', 'WAF fingerprint with wafw00f'],
      ['security_headers', 'HDR/TLS', 'Security headers and TLS certificate checks'],
      ['header_intel', 'HDR INTEL', 'Suspicious response headers and vhost hints'],
      ['cookie_session_audit', 'COOKIE', 'Cookie/session flags audit'],
      ['csrf_flow_audit', 'CSRF', 'CSRF flow audit from collected forms'],
      ['http3_quic_surface', 'HTTP3', 'HTTP/3 and QUIC surface inventory'],
      ['nginx_http3_cve_2026_42530', 'CVE-42530', 'NGINX HTTP/3 CVE-2026-42530 passive check'],
      ['cve_correlation', 'CVE WEB', 'Local web CVE dataset correlation (+ optional NVD)'],
      ['panel_exposure_audit', 'PANELS', 'Common admin/status panel exposure checks'],
      ['cors_audit', 'CORS', 'Active CORS misconfiguration audit'],
      ['jwt_jwks_audit', 'JWKS', 'JWKS/OIDC key audit'],
      ['service_worker_audit', 'SW', 'Service worker and cache surface audit'],
      ['robots_sitemap', 'ROBOTS', 'robots.txt and sitemap discovery'],
      ['wellknown_security_txt', 'SEC.TXT', '.well-known/security.txt'],
      ['wellknown_openid', 'OIDC', '.well-known/openid-configuration'],
      ['surface', 'SURFACE', 'Surface aggregation checkpoint'],
      ['shodan', 'SHODAN', 'Shodan DNS + search + host'],
      ['openapi_specs', 'OPENAPI', 'OpenAPI/Swagger harvest'],
      ['api_contract_diff', 'API DIFF', 'API contract snapshot diff'],
    ],
  },
  {
    label: '03 CONTENT', phase: 'content', nodes: [
      ['urls', 'URLS', 'Wayback, Common Crawl, gau, waybackurls, Katana'],
      ['graphql_probe', 'GQL MIN', 'Minimal GraphQL introspection probe'],
      ['graphql_recon', 'GQL REC', 'GraphQL recon module'],
      ['params', 'PARAMS', 'Parameter extraction and scoring'],
      ['hpp_param_pollution', 'HPP', 'HTTP parameter pollution audit'],
      ['js', 'JS', 'JavaScript fetch and endpoint extraction'],
      ['client_auth_audit', 'AUTH JS', 'Client-side auth audit'],
      ['client_surface_audit', 'SURF JS', 'Client-side surface audit'],
      ['js_intel', 'JS INTEL', 'JS token and endpoint intelligence'],
      ['websocket_recon', 'WS', 'WebSocket recon'],
      ['dom_clobbering_audit', 'DOM', 'DOM clobbering audit'],
      ['dorks', 'DORKS', 'Google dorks'],
      ['google_cse', 'CSE', 'Google Custom Search URLs'],
      ['secrets', 'SECRETS', 'Secrets/leaks collection'],
      ['github', 'GITHUB', 'GitHub code/repo search and local clone'],
      ['pastebin', 'PASTE', 'Public paste references via CSE'],
      ['secret_validation', 'TOKENS', 'Token/secret validation'],
      ['secrets_context_ranker', 'RANK', 'Secrets context ranker'],
    ],
  },
  {
    label: '04 ATTACK', phase: 'attack', group: 'attack', nodes: [
      ['vigolium_dast', 'VIG DAST', 'Vigolium DAST Go engine'],
      ['verify', 'VERIFY', 'Heuristic verify and micro-exploit variants'],
      ['webshell_probe', 'WEBSHELL', 'Webshell heuristic probe'],
      ['sqlmap', 'SQLMAP', 'SQLmap runner'],
      ['curl_probe', 'CURL', 'Read-only GET/HEAD/OPTIONS audit'],
      ['authz_matrix', 'AUTHZ', 'Authorization matrix'],
      ['jwt_lab', 'JWT LAB', 'JWT lab'],
      ['dom_xss_verify', 'DOM XSS', 'DOM XSS verification'],
      ['payload_mutator', 'MUTATOR', 'Payload mutator'],
      ['race_harness', 'RACE', 'Race condition harness'],
      ['oob_collaborator', 'OOB', 'OOB collaborator payloads'],
      ['cred_spray', 'SPRAY', 'Credential spray planner'],
      ['kali', 'KALI', 'Kali active scan umbrella'],
      ['nmap', 'NMAP', 'Nmap TCP scan'],
      ['nmap_udp', 'UDP', 'Nmap UDP scan'],
      ['nmap_cve_match', 'NMAP CVE', 'Nmap product/version CVE matching'],
      ['nmap_backport_review', 'BACKPORT', 'Linux distro backport context review'],
      ['whois', 'WHOIS', 'WHOIS tool'],
      ['info_disclosure_hunter', 'INFO DISC', 'InfoHunter BR information disclosure scan'],
      ['info_disclosure_errors', 'ERR DISC', 'InfoHunter verbose error induction module'],
      ['ffuf', 'FFUF', 'ffuf directory fuzzing'],
      ['dirsearch', 'DIRS', 'dirsearch recursive discovery'],
      ['nuclei', 'NUCLEI', 'Nuclei general scan'],
      ['nuclei_xss', 'NUC XSS', 'Nuclei XSS templates'],
      ['nuclei_sqli', 'NUC SQLI', 'Nuclei SQLi templates'],
      ['wpscan', 'WPSCAN', 'WPScan'],
      ['dalfox', 'DALFOX', 'Dalfox XSS scan'],
      ['xss_vibes', 'XSS SAFE', 'Repeatable contextual reflection audit'],
    ],
  },
  {
    label: '05 ASSETS', phase: 'explore', nodes: [
      ['assets', 'ASSETS', 'Asset discovery and takeover candidates'],
      ['cloud_bruteforce', 'CLOUD', 'Cloud bucket brute force'],
      ['navegation', 'NAV', 'Navegation/Tor/OpenVPN playbook'],
      ['vigolium_agent', 'VIG AGENT', 'Vigolium agent umbrella', 'agent'],
      ['vigolium_audit', 'VIG AUDIT', 'Vigolium code audit', 'agent'],
      ['vigolium_swarm', 'VIG SWARM', 'Vigolium swarm agent', 'agent'],
    ],
  },
  {
    label: '06 REPORT', phase: 'report', group: 'report', nodes: [
      ['score', 'SCORE', 'Score v2, dedupe, chaining'],
      ['risk_explainer', 'RISK', 'Finding risk explanations'],
    ],
  },
] as const;

const PIPELINE_LABELS = new Map(
  PIPELINE_PHASES.flatMap((phase) => phase.nodes.map((node) => [node[0], node[1]])),
);

export function PipelineBar() {
  const { pipeline } = useExecutionState();
  return (
    <div
      className="pipeline-bar"
      id="pipelineBar"
      role="list"
      aria-label="Pipeline OSINT e DAST"
      data-rendered="react"
    >
      {PIPELINE_PHASES.map((phase) => (
        <div className="pipe-phase" data-phase={phase.phase} key={phase.phase}>
          <span className="pipe-phase-label">{phase.label}</span>
          <div className="pipe-phase-steps">
            {phase.nodes.map(([id, label, title, nodeGroup]) => {
              const node = pipeline.nodes[id];
              const state = node?.state || '';
              const detail = node?.detail || '';
              const nodeDetail = detail.slice(0, 16);
              const group = nodeGroup || phase.group || undefined;
              return (
                <div className="pipe-step" key={id}>
                  <div
                    className={`pipe-node${state ? ` ${state}` : ''}`}
                    id={`pipe-${id}`}
                    data-base-label={label}
                    data-detail={nodeDetail || undefined}
                    data-pipe-group={group}
                    title={node?.label ? `${title}: ${node.label}` : title}
                  >
                    {label}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export function ProgressFill() {
  const { pipeline } = useExecutionState();
  return <div className="progress-fill" id="progressFill" style={{ width: `${pipeline.progress}%` }} />;
}

export function ProgressPercent() {
  const { pipeline } = useExecutionState();
  return <div className="progress-pct" id="progressPct">{pipeline.progress}%</div>;
}

export function ProgressDetail() {
  const { pipeline, progressDetail, runStartedAt } = useExecutionState();
  const [, tick] = useState(0);
  useEffect(() => {
    if (!runStartedAt) return undefined;
    const timer = window.setInterval(() => tick((value) => value + 1), 1_000);
    return () => window.clearInterval(timer);
  }, [runStartedAt]);
  const current = pipeline.currentNode;
  if (!runStartedAt && !current) {
    return <div className="progress-detail" id="progressDetail">Aguardando inicio.</div>;
  }
  const node = current ? pipeline.nodes[current] : undefined;
  const label = PIPELINE_LABELS.get(current) || current || 'idle';
  const detail = progressDetail || node?.detail || node?.label || 'processando';
  const elapsed = runStartedAt ? formatElapsed(performance.now() - runStartedAt) : '0:00';
  return (
    <div className="progress-detail" id="progressDetail">
      {`Atual: ${label} - ${detail} - decorrido ${elapsed}`}
    </div>
  );
}

const STAT_IDS: Record<keyof PipelineStats, string> = {
  subs: 'st-subs',
  endpoints: 'st-end',
  params: 'st-params',
  secrets: 'st-sec',
  dorks: 'st-dorks',
  high: 'st-high',
};

export const STAT_KEY_BY_ID = Object.fromEntries(
  Object.entries(STAT_IDS).map(([name, id]) => [id, name]),
) as Record<string, keyof PipelineStats>;

export function StatValue({
  className,
  id,
  stat,
}: {
  className: string;
  id: string;
  stat: keyof PipelineStats;
}) {
  const { pipeline } = useExecutionState();
  return <span className={className} id={id}>{pipeline.stats[stat]}</span>;
}
