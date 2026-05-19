import { isApiEnabled } from './config';
import { checkApiHealth, fetchProjectBundle, listProjects, syncProjectBundle } from './client';
import type { ProjectBundle } from './types';
import { useStore } from '@/lib/mock/store';
import type {
  AttackChainNode,
  Credential,
  Evidence,
  Project,
  ReportShape,
  TimelineEvent,
  Vulnerability
} from '@/lib/types';

const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

export function buildProjectBundle(projectId: string): ProjectBundle | null {
  const s = useStore.getState();
  const project = s.projects.find((p) => p.id === projectId);
  if (!project) return null;
  return {
    project,
    vulnerabilities: s.vulnerabilities.filter((v) => v.projectId === projectId),
    timeline: s.timeline.filter((e) => e.projectId === projectId),
    attackChain: s.attackChain.filter((n) => n.projectId === projectId),
    credentials: s.credentials.filter((c) => c.projectId === projectId),
    evidence: s.evidence.filter((e) => e.projectId === projectId),
    reportConclusion: s.reportConclusions[projectId]
  };
}

export function applyProjectBundle(bundle: ProjectBundle): void {
  const pid = bundle.project.id;
  useStore.setState((s) => ({
    projects: s.projects.some((p) => p.id === pid)
      ? s.projects.map((p) => (p.id === pid ? bundle.project : p))
      : [bundle.project, ...s.projects],
    vulnerabilities: [
      ...s.vulnerabilities.filter((v) => v.projectId !== pid),
      ...bundle.vulnerabilities
    ],
    timeline: [...s.timeline.filter((e) => e.projectId !== pid), ...bundle.timeline],
    attackChain: [...s.attackChain.filter((n) => n.projectId !== pid), ...bundle.attackChain],
    credentials: [...s.credentials.filter((c) => c.projectId !== pid), ...bundle.credentials],
    evidence: [...s.evidence.filter((e) => e.projectId !== pid), ...bundle.evidence],
    reportConclusions: bundle.reportConclusion
      ? { ...s.reportConclusions, [pid]: bundle.reportConclusion }
      : s.reportConclusions
  }));
}

export async function syncProjectToApi(projectId: string): Promise<void> {
  if (!isApiEnabled()) return;
  const bundle = buildProjectBundle(projectId);
  if (!bundle) return;
  useStore.setState({ apiStatus: 'syncing' });
  try {
    await syncProjectBundle(bundle);
    useStore.setState((s) => ({
      apiStatus: 'online',
      apiLastSync: { ...s.apiLastSync, [projectId]: new Date().toISOString() }
    }));
  } catch {
    useStore.setState({ apiStatus: 'offline' });
  }
}

export function scheduleProjectSync(projectId: string, delayMs = 800): void {
  if (!isApiEnabled()) return;
  const prev = debounceTimers.get(projectId);
  if (prev) clearTimeout(prev);
  debounceTimers.set(
    projectId,
    setTimeout(() => {
      debounceTimers.delete(projectId);
      void syncProjectToApi(projectId);
    }, delayMs)
  );
}

/** Bootstrap: API vazia → envia local; API com dados → puxa tudo. */
export async function bootstrapFromApi(): Promise<void> {
  if (!isApiEnabled()) return;
  const ok = await checkApiHealth();
  if (!ok) {
    useStore.setState({ apiStatus: 'offline' });
    return;
  }

  useStore.setState({ apiStatus: 'syncing' });
  try {
    const summaries = await listProjects();
    if (summaries.length === 0) {
      const { projects } = useStore.getState();
      for (const p of projects) {
        await syncProjectToApi(p.id);
      }
      useStore.setState({ apiStatus: 'online' });
      return;
    }

    for (const summary of summaries) {
      const bundle = await fetchProjectBundle(summary.id);
      applyProjectBundle(bundle);
    }
    useStore.setState({ apiStatus: 'online' });
  } catch {
    useStore.setState({ apiStatus: 'offline' });
  }
}
