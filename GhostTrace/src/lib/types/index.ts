/**
 * GhostTrace — core type contracts.
 *
 * These TypeScript interfaces are the single source of truth for the
 * prototype data model. They mirror — field by field — the structure
 * of the reference DOCX report (see docs/REPORT_TEMPLATE.md) and will
 * be transcribed 1:1 to Pydantic models in the FastAPI backend.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type VulnStatus = 'unfixed' | 'fixed' | 'retest' | 'wont_fix';

export type Methodology = 'blackbox' | 'graybox' | 'whitebox';

export type ProjectStatus = 'active' | 'paused' | 'reporting' | 'closed';

export type EngagementType =
  | 'web_app'
  | 'network_internal'
  | 'network_external'
  | 'red_team'
  | 'mobile'
  | 'cloud'
  | 'bug_bounty';

export interface ToolGroup {
  purpose: string;
  tools: string[];
}

/** Metadados quando o projeto veio do pipeline GHOSTRECON (Reporte → Anotações). */
export interface GhostreconProjectMeta {
  target: string;
  importedAt: string;
  findingsCount?: number;
}

export interface Project {
  id: string;
  client: string;
  codename?: string;
  engagementType: EngagementType;
  scope: string[];
  methodology: Methodology;
  startDate: string; // ISO date
  endDate?: string;
  status: ProjectStatus;
  notes?: string;
  tools?: ToolGroup[];
  ghostrecon?: GhostreconProjectMeta;
  createdAt: string;
  updatedAt: string;
}

export interface CVSS {
  vector: string;
  score: number;
}

export interface ReproStep {
  id: string;
  order: number;
  text: string;
  command?: string;
  screenshots: string[];
}

export interface ProofOfConcept {
  id: string;
  title: string;
  description?: string;
  code?: {
    lang: string;
    content: string;
  };
  screenshots: string[];
}

export interface Vulnerability {
  id: string;
  projectId: string;
  number?: number; // assigned at report time
  title: string;
  severity: Severity;
  status: VulnStatus;
  cvss?: CVSS;
  cwe: string[];
  tags: string[];
  targets: string[];
  description: string;
  attackScenario: string;
  recommendation: string;
  remediationNotes?: string;
  additionalNotes?: string;
  steps: ReproStep[];
  pocs: ProofOfConcept[];
  isZeroDay?: boolean;
  isEasilyExploitable?: boolean;
  /** Ligação ao achado GHOSTRECON (fingerprint SHA-256). */
  ghostreconFingerprint?: string;
  createdAt: string;
  updatedAt: string;
}

export type TimelineEventType =
  | 'recon'
  | 'enumeration'
  | 'creds'
  | 'rce'
  | 'shell'
  | 'privesc'
  | 'pivot'
  | 'exfil'
  | 'lateral'
  | 'persistence'
  | 'note';

export interface TimelineEvent {
  id: string;
  projectId: string;
  ts: string; // ISO datetime
  type: TimelineEventType;
  host?: string;
  target?: string;
  title: string;
  details?: string;
  vulnerabilityId?: string;
  attachments?: string[];
}

export type ChainPrivilege = 'unauth' | 'user' | 'root';

export interface ChainStep {
  order: number;
  action: string;
  eventId?: string;
}

export interface AttackChainNode {
  id: string;
  projectId: string;
  host: string;
  ip?: string;
  privilege: ChainPrivilege;
  steps: ChainStep[];
  nextNodeIds: string[];
}

export interface Evidence {
  id: string;
  projectId: string;
  filename: string;
  mime: string;
  size: number;
  uploadedAt: string;
  vulnerabilityIds: string[];
  thumbnailUrl?: string;
  caption?: string;
}

export interface Credential {
  id: string;
  projectId: string;
  user: string;
  context: string;
  value: string;
  source?: string;
  host?: string;
  rotated?: boolean;
}

/* ───────────────────────── AI providers ───────────────────────── */

export type AIProviderId = 'gemini' | 'openrouter' | 'anthropic';

export interface AIProviderConfig {
  id: AIProviderId;
  label: string;
  apiKey?: string;
  model?: string;
  enabled: boolean;
}

export type EnhanceableField =
  | 'description'
  | 'attackScenario'
  | 'recommendation'
  | 'remediationNotes';

/* ───────────────────── Report shape (export contract) ───────────────────── */

export interface ReportShape {
  project: Project;
  generatedAt: string;
  generator: { provider: AIProviderId | 'none'; model?: string };
  summary: {
    totalUnique: number;
    bySeverity: Record<Severity, number>;
    zeroDay: number;
    easilyExploitable: number;
    fixed: number;
    retest: number;
    unfixed: number;
  };
  vulnerabilities: Vulnerability[];
  timeline: TimelineEvent[];
  attackChain: AttackChainNode[];
  credentials: Credential[];
  conclusion?: {
    priorityActions: string[];
    midTermActions: string[];
  };
}
