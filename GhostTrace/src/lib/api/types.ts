import type {
  AttackChainNode,
  Credential,
  Evidence,
  Project,
  ReportShape,
  TimelineEvent,
  Vulnerability
} from '@/lib/types';

export interface ProjectBundle {
  project: Project;
  vulnerabilities: Vulnerability[];
  timeline: TimelineEvent[];
  attackChain: AttackChainNode[];
  credentials: Credential[];
  evidence: Evidence[];
  reportConclusion?: ReportShape['conclusion'];
}

export interface ProjectSummary {
  id: string;
  client: string;
  codename?: string;
  status: Project['status'];
  engagementType: Project['engagementType'];
  updatedAt: string;
  vulnerabilityCount: number;
}
