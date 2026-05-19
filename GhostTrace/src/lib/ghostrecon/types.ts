/** Contrato do pacote Reporte → Anotações (GHOSTRECON). */

export interface GhostreconFinding {
  type: string;
  prio?: string;
  priority?: string;
  value: string;
  url?: string;
  meta?: string;
  score?: number;
  owasp?: string;
  mitre?: string;
  cvss?: string;
  fingerprint?: string;
}

export interface GhostreconManualValidation {
  fingerprint: string;
  notes?: string;
  snapshot?: Record<string, unknown> | null;
  validated_at?: string;
}

export interface GhostreconHandoffPayload {
  target?: string;
  updatedAt?: string;
  findings?: GhostreconFinding[];
  manualValidations?: GhostreconManualValidation[];
  subsetFilter?: string;
}

export interface GhostreconSession {
  target: string;
  importedAt: string;
  findings: GhostreconFinding[];
  validatedFingerprints: string[];
  /** fingerprint → vulnerability id */
  linkedVulnIds: Record<string, string>;
}
