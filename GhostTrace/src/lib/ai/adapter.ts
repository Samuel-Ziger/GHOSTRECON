import type {
  AIProviderConfig,
  AIProviderId,
  EnhanceableField,
  Project,
  Severity,
  Vulnerability
} from '@/lib/types';

export interface EnhanceFieldInput {
  field: EnhanceableField;
  input: string;
  vuln: Pick<Vulnerability, 'title' | 'severity' | 'cwe' | 'tags' | 'targets'>;
}

export interface ClassifyResult {
  severity: Severity;
  cvss?: { vector: string; score: number };
  rationale: string;
}

/** Contrato único — implementações por provider em `providers/`. */
export interface AIAdapter {
  id: AIProviderId;
  enhanceField(opts: EnhanceFieldInput): Promise<string>;
  generateExecutiveSummary(project: Project, vulns: Vulnerability[]): Promise<string>;
  classifySeverity(input: string): Promise<ClassifyResult>;
}

export type AdapterCredentials = Pick<AIProviderConfig, 'id' | 'apiKey' | 'model'>;
