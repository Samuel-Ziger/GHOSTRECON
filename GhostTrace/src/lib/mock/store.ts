'use client';

/**
 * Store operacional com persistência em localStorage.
 * API keys ficam em `lib/storage/ai-keys` (nunca no blob principal).
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { useShallow } from 'zustand/react/shallow';
import { nanoid } from 'nanoid';
import type {
  Project,
  Vulnerability,
  TimelineEvent,
  AttackChainNode,
  Credential,
  Evidence,
  AIProviderConfig,
  ReportShape
} from '@/lib/types';
import type { GhostreconFinding, GhostreconSession } from '@/lib/ghostrecon/types';
import { findingToVulnerability } from '@/lib/ghostrecon/import';
import {
  seedProject,
  seedVulnerabilities,
  seedTimeline,
  seedAttackChain,
  seedCredentials,
  seedEvidence
} from './seed';
import { DEFAULT_AI_PROVIDERS } from './defaults';
import { mergeProvidersWithStored, saveAIKeysToStorage } from '@/lib/storage/ai-keys';
import { scheduleProjectSync } from '@/lib/api/sync';

export type ApiStatus = 'idle' | 'syncing' | 'online' | 'offline';

interface StoreState {
  projects: Project[];
  vulnerabilities: Vulnerability[];
  timeline: TimelineEvent[];
  attackChain: AttackChainNode[];
  credentials: Credential[];
  evidence: Evidence[];
  aiProviders: AIProviderConfig[];
  /** Sumário / conclusão gerados por projeto (relatório) */
  reportConclusions: Record<string, NonNullable<ReportShape['conclusion']>>;
  /** Sessão GHOSTRECON por projeto (achados do Reporte ainda não documentados). */
  ghostreconSessions: Record<string, GhostreconSession>;
  apiStatus: ApiStatus;
  apiLastSync: Record<string, string>;

  getProject: (id: string) => Project | undefined;
  getVulnerabilitiesByProject: (id: string) => Vulnerability[];
  getVulnerability: (id: string) => Vulnerability | undefined;
  getTimelineByProject: (id: string) => TimelineEvent[];
  getAttackChainByProject: (id: string) => AttackChainNode[];
  getCredentialsByProject: (id: string) => Credential[];
  getEvidenceByProject: (id: string) => Evidence[];
  getActiveAIProvider: () => AIProviderConfig | undefined;
  getReportConclusion: (projectId: string) => ReportShape['conclusion'] | undefined;
  getGhostreconSession: (projectId: string) => GhostreconSession | undefined;

  setGhostreconSession: (projectId: string, session: GhostreconSession) => void;
  importFindingAsVuln: (
    projectId: string,
    finding: GhostreconFinding,
    opts?: { allowUnvalidated?: boolean }
  ) => Vulnerability | null;

  upsertProject: (
    input: Partial<Project> &
      Pick<Project, 'client' | 'methodology' | 'scope' | 'engagementType' | 'startDate'>
  ) => Project;
  upsertVulnerability: (
    vuln: Partial<Vulnerability> & Pick<Vulnerability, 'projectId' | 'title' | 'severity'>
  ) => Vulnerability;
  bulkUpsertVulnerabilities: (vulns: Vulnerability[]) => void;
  deleteVulnerability: (id: string) => void;
  addTimelineEvent: (
    evt: Partial<TimelineEvent> & Pick<TimelineEvent, 'projectId' | 'type' | 'title' | 'ts'>
  ) => TimelineEvent;
  addEvidence: (
    input: Omit<Evidence, 'id' | 'uploadedAt'> & { projectId: string }
  ) => Evidence;
  deleteEvidence: (id: string) => void;
  addCredential: (
    input: Omit<Credential, 'id'> & Pick<Credential, 'projectId' | 'user' | 'context' | 'value'>
  ) => Credential;
  setReportConclusion: (
    projectId: string,
    conclusion: NonNullable<ReportShape['conclusion']>
  ) => void;
  upsertAIProvider: (cfg: AIProviderConfig) => void;
  hydrateAIProviders: () => void;
  setApiStatus: (status: ApiStatus) => void;

  upsertAttackChainNode: (
    input: Partial<AttackChainNode> &
      Pick<AttackChainNode, 'projectId' | 'host' | 'privilege'>
  ) => AttackChainNode;
  deleteAttackChainNode: (id: string) => void;
  replaceProjectAttackChain: (projectId: string, nodes: AttackChainNode[]) => void;
  linkChainNodes: (fromId: string, toId: string) => void;
}

const nowIso = () => new Date().toISOString();

export const useStore = create<StoreState>()(
  persist(
    (set, get) => ({
      projects: [seedProject],
      vulnerabilities: seedVulnerabilities,
      timeline: seedTimeline,
      attackChain: seedAttackChain,
      credentials: seedCredentials,
      evidence: seedEvidence,
      aiProviders: DEFAULT_AI_PROVIDERS,
      reportConclusions: {},
      ghostreconSessions: {},
      apiStatus: 'idle',
      apiLastSync: {},

      getProject: (id) => get().projects.find((p) => p.id === id),
      getVulnerabilitiesByProject: (id) =>
        get().vulnerabilities.filter((v) => v.projectId === id),
      getVulnerability: (id) => get().vulnerabilities.find((v) => v.id === id),
      getTimelineByProject: (id) =>
        get()
          .timeline.filter((e) => e.projectId === id)
          .sort((a, b) => a.ts.localeCompare(b.ts)),
      getAttackChainByProject: (id) => get().attackChain.filter((n) => n.projectId === id),
      getCredentialsByProject: (id) => get().credentials.filter((c) => c.projectId === id),
      getEvidenceByProject: (id) => get().evidence.filter((e) => e.projectId === id),
      getActiveAIProvider: () => get().aiProviders.find((p) => p.enabled && p.apiKey?.trim()),
      getReportConclusion: (projectId) => get().reportConclusions[projectId],
      getGhostreconSession: (projectId) => get().ghostreconSessions[projectId],

      setGhostreconSession: (projectId, session) => {
        set((s) => ({
          ghostreconSessions: { ...s.ghostreconSessions, [projectId]: session }
        }));
      },

      importFindingAsVuln: (projectId, finding, opts) => {
        const fp = String(finding.fingerprint || '').toLowerCase();
        if (!fp) return null;
        const session = get().ghostreconSessions[projectId];
        const validated = session?.validatedFingerprints.includes(fp);
        if (!validated && !opts?.allowUnvalidated) return null;
        const existing = get().vulnerabilities.find(
          (v) => v.projectId === projectId && v.ghostreconFingerprint === fp
        );
        if (existing) return existing;
        const vuln = findingToVulnerability(finding, projectId, { forceValidated: validated });
        get().upsertVulnerability(vuln);
        if (session) {
          get().setGhostreconSession(projectId, {
            ...session,
            linkedVulnIds: { ...session.linkedVulnIds, [fp]: vuln.id }
          });
        }
        get().addTimelineEvent({
          projectId,
          ts: new Date().toISOString(),
          type: 'recon',
          host: session?.target,
          title: `Documentado: ${vuln.title.slice(0, 72)}`,
          details: [finding.type, finding.value].filter(Boolean).join(' · '),
          vulnerabilityId: vuln.id
        });
        return vuln;
      },

      upsertProject: (input) => {
        const ts = nowIso();
        const existing = input.id ? get().projects.find((p) => p.id === input.id) : undefined;
        const project: Project = existing
          ? { ...existing, ...input, updatedAt: ts }
          : ({
              id: `proj_${nanoid(8)}`,
              status: 'active',
              createdAt: ts,
              updatedAt: ts,
              ...input
            } as Project);
        set((s) => ({
          projects: existing
            ? s.projects.map((p) => (p.id === project.id ? project : p))
            : [project, ...s.projects]
        }));
        scheduleProjectSync(project.id);
        return project;
      },

      upsertVulnerability: (input) => {
        const ts = nowIso();
        const existing = input.id
          ? get().vulnerabilities.find((v) => v.id === input.id)
          : undefined;
        const vuln: Vulnerability = existing
          ? { ...existing, ...input, updatedAt: ts }
          : ({
              id: `vuln_${nanoid(8)}`,
              status: 'unfixed',
              cwe: [],
              tags: [],
              targets: [],
              description: '',
              attackScenario: '',
              recommendation: '',
              steps: [],
              pocs: [],
              createdAt: ts,
              updatedAt: ts,
              ...input
            } as Vulnerability);
        set((s) => ({
          vulnerabilities: existing
            ? s.vulnerabilities.map((v) => (v.id === vuln.id ? vuln : v))
            : [vuln, ...s.vulnerabilities]
        }));
        scheduleProjectSync(vuln.projectId);
        return vuln;
      },

      bulkUpsertVulnerabilities: (vulns) => {
        const pid = vulns[0]?.projectId;
        set((s) => {
          const ids = new Set(vulns.map((v) => v.id));
          const rest = s.vulnerabilities.filter((v) => !ids.has(v.id));
          return { vulnerabilities: [...vulns, ...rest] };
        });
        if (pid) scheduleProjectSync(pid);
      },

      deleteVulnerability: (id) => {
        const vuln = get().vulnerabilities.find((v) => v.id === id);
        set((s) => ({
          vulnerabilities: s.vulnerabilities.filter((v) => v.id !== id),
          timeline: s.timeline.map((e) =>
            e.vulnerabilityId === id ? { ...e, vulnerabilityId: undefined } : e
          )
        }));
        if (vuln) scheduleProjectSync(vuln.projectId);
      },

      addTimelineEvent: (input) => {
        const evt: TimelineEvent = {
          id: `evt_${nanoid(8)}`,
          ...input
        } as TimelineEvent;
        set((s) => ({ timeline: [...s.timeline, evt] }));
        scheduleProjectSync(input.projectId);
        return evt;
      },

      addEvidence: (input) => {
        const item: Evidence = {
          id: `ev_${nanoid(8)}`,
          uploadedAt: nowIso(),
          ...input
        };
        set((s) => ({ evidence: [item, ...s.evidence] }));
        scheduleProjectSync(input.projectId);
        return item;
      },

      deleteEvidence: (id) => {
        const ev = get().evidence.find((e) => e.id === id);
        set((s) => ({ evidence: s.evidence.filter((e) => e.id !== id) }));
        if (ev) scheduleProjectSync(ev.projectId);
      },

      addCredential: (input) => {
        const cred: Credential = { id: `cred_${nanoid(8)}`, ...input };
        set((s) => ({ credentials: [cred, ...s.credentials] }));
        scheduleProjectSync(input.projectId);
        return cred;
      },

      setReportConclusion: (projectId, conclusion) => {
        set((s) => ({
          reportConclusions: { ...s.reportConclusions, [projectId]: conclusion }
        }));
        scheduleProjectSync(projectId);
      },

      setApiStatus: (status) => set({ apiStatus: status }),

      upsertAttackChainNode: (input) => {
        const existing = input.id
          ? get().attackChain.find((n) => n.id === input.id)
          : undefined;
        const node: AttackChainNode = existing
          ? { ...existing, ...input }
          : {
              id: `node_${nanoid(8)}`,
              steps: [],
              nextNodeIds: [],
              ...input
            };
        set((s) => ({
          attackChain: existing
            ? s.attackChain.map((n) => (n.id === node.id ? node : n))
            : [...s.attackChain, node]
        }));
        scheduleProjectSync(node.projectId);
        return node;
      },

      deleteAttackChainNode: (id) => {
        const node = get().attackChain.find((n) => n.id === id);
        set((s) => ({
          attackChain: s.attackChain
            .filter((n) => n.id !== id)
            .map((n) => ({
              ...n,
              nextNodeIds: n.nextNodeIds.filter((nid) => nid !== id)
            }))
        }));
        if (node) scheduleProjectSync(node.projectId);
      },

      replaceProjectAttackChain: (projectId, nodes) => {
        set((s) => ({
          attackChain: [
            ...s.attackChain.filter((n) => n.projectId !== projectId),
            ...nodes.map((n) => ({ ...n, projectId }))
          ]
        }));
        scheduleProjectSync(projectId);
      },

      linkChainNodes: (fromId, toId) => {
        const from = get().attackChain.find((n) => n.id === fromId);
        if (!from) return;
        set((s) => ({
          attackChain: s.attackChain.map((n) =>
            n.id === fromId
              ? {
                  ...n,
                  nextNodeIds: n.nextNodeIds.includes(toId)
                    ? n.nextNodeIds
                    : [...n.nextNodeIds, toId]
                }
              : n
          )
        }));
        scheduleProjectSync(from.projectId);
      },

      upsertAIProvider: (cfg) => {
        set((s) => {
          const aiProviders = s.aiProviders.map((p) => (p.id === cfg.id ? { ...p, ...cfg } : p));
          saveAIKeysToStorage(aiProviders);
          return { aiProviders };
        });
      },

      hydrateAIProviders: () => {
        set((s) => ({
          aiProviders: mergeProvidersWithStored(s.aiProviders)
        }));
      }
    }),
    {
      name: 'ghosttrace-data-v1',
      partialize: (state) => ({
        projects: state.projects,
        vulnerabilities: state.vulnerabilities,
        timeline: state.timeline,
        attackChain: state.attackChain,
        credentials: state.credentials,
        evidence: state.evidence,
        reportConclusions: state.reportConclusions,
        ghostreconSessions: state.ghostreconSessions
      }),
      onRehydrateStorage: () => (state) => {
        state?.hydrateAIProviders();
      }
    }
  )
);

/* ───────────────── React selectors ───────────────── */

export function useProject(id: string) {
  return useStore((s) => s.projects.find((p) => p.id === id));
}

export function useVulnerability(id: string) {
  return useStore((s) => s.vulnerabilities.find((v) => v.id === id));
}

export function useProjectVulnerabilities(projectId: string) {
  return useStore(
    useShallow((s) => s.vulnerabilities.filter((v) => v.projectId === projectId))
  );
}

export function useProjectTimeline(projectId: string) {
  return useStore(
    useShallow((s) =>
      s.timeline
        .filter((e) => e.projectId === projectId)
        .sort((a, b) => a.ts.localeCompare(b.ts))
    )
  );
}

export function useProjectAttackChain(projectId: string) {
  return useStore(
    useShallow((s) => s.attackChain.filter((n) => n.projectId === projectId))
  );
}

export function useProjectCredentials(projectId: string) {
  return useStore(
    useShallow((s) => s.credentials.filter((c) => c.projectId === projectId))
  );
}

export function useProjectEvidence(projectId: string) {
  return useStore(
    useShallow((s) => s.evidence.filter((e) => e.projectId === projectId))
  );
}

export function useGhostreconSession(projectId: string) {
  return useStore((s) => s.ghostreconSessions[projectId]);
}

export function computeSummary(vulns: Vulnerability[]) {
  const bySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  let zeroDay = 0;
  let easily = 0;
  let fixed = 0;
  let retest = 0;
  let unfixed = 0;

  for (const v of vulns) {
    bySeverity[v.severity] += 1;
    if (v.isZeroDay) zeroDay += 1;
    if (v.isEasilyExploitable) easily += 1;
    if (v.status === 'fixed') fixed += 1;
    else if (v.status === 'retest') retest += 1;
    else if (v.status === 'unfixed') unfixed += 1;
  }
  return {
    totalUnique: vulns.length,
    bySeverity,
    zeroDay,
    easilyExploitable: easily,
    fixed,
    retest,
    unfixed
  };
}
