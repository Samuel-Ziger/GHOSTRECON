import { getApiBaseUrl, isApiEnabled } from './config';
import type { ProjectBundle, ProjectSummary } from './types';

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const base = getApiBaseUrl();
  if (!base) throw new Error('API não configurada');
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers
    }
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body.slice(0, 300)}`);
  }
  return res.json() as Promise<T>;
}

export async function checkApiHealth(): Promise<boolean> {
  if (!isApiEnabled()) return false;
  try {
    await apiFetch<{ status: string }>('/health');
    return true;
  } catch {
    return false;
  }
}

export async function listProjects(): Promise<ProjectSummary[]> {
  const data = await apiFetch<{ projects: ProjectSummary[] }>('/projects');
  return data.projects;
}

export async function fetchProjectBundle(projectId: string): Promise<ProjectBundle> {
  return apiFetch<ProjectBundle>(`/projects/${projectId}`);
}

export async function syncProjectBundle(bundle: ProjectBundle): Promise<{ updatedAt: string }> {
  return apiFetch<{ updatedAt: string }>(`/projects/${bundle.project.id}/sync`, {
    method: 'PUT',
    body: JSON.stringify(bundle)
  });
}
