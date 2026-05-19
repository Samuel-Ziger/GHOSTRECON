// Cliente HTTP fino. Em prod, trocar por openapi-fetch ou react-query mutations.

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

import type {
  GraphResponse, Project, Role, RequestList, HttpRequestItem, RoleDiffResponse,
} from "./types";

export const api = {
  // projects
  listProjects: () => req<Project[]>("/api/v1/projects"),
  createProject: (name: string) =>
    req<Project>("/api/v1/projects", { method: "POST", body: JSON.stringify({ name }) }),

  // roles
  listRoles: (projectId: string) => req<Role[]>(`/api/v1/projects/${projectId}/roles`),
  createRole: (projectId: string, name: string, color = "#7c5cff") =>
    req<Role>(`/api/v1/projects/${projectId}/roles`, {
      method: "POST", body: JSON.stringify({ name, color }),
    }),

  // requests
  listRequests: (projectId: string, opts: Partial<{ q: string; host: string; method: string;
    only_xhr: boolean; only_graphql: boolean; limit: number; offset: number }> = {}) => {
    const qs = new URLSearchParams();
    Object.entries(opts).forEach(([k, v]) => v !== undefined && qs.append(k, String(v)));
    return req<RequestList>(`/api/v1/projects/${projectId}/requests?${qs.toString()}`);
  },
  getRequest: (projectId: string, id: string) =>
    req<HttpRequestItem>(`/api/v1/projects/${projectId}/requests/${id}`),
  exportHar: (projectId: string) =>
    `${BASE}/api/v1/projects/${projectId}/requests/export/har`,

  // graph
  fetchGraph: (projectId: string, opts: Partial<{ labels: string[]; hosts: string[];
    min_heat: number; limit: number }> = {}) => {
    const qs = new URLSearchParams();
    (opts.labels ?? []).forEach((l) => qs.append("labels", l));
    (opts.hosts  ?? []).forEach((h) => qs.append("hosts", h));
    if (opts.min_heat !== undefined) qs.set("min_heat", String(opts.min_heat));
    if (opts.limit    !== undefined) qs.set("limit", String(opts.limit));
    return req<GraphResponse>(`/api/v1/projects/${projectId}/graph?${qs.toString()}`);
  },
  recomputeHeatmap: (projectId: string) =>
    req<{ endpoints_updated: number }>(
      `/api/v1/projects/${projectId}/graph/heatmap/recompute`, { method: "POST" }
    ),
  resetGraph: (projectId: string) =>
    req<{ status: string }>(`/api/v1/projects/${projectId}/graph`, { method: "DELETE" }),

  // role diff
  roleDiff: (projectId: string, baselineRoleId: string, candidateRoleIds: string[]) =>
    req<RoleDiffResponse>(`/api/v1/projects/${projectId}/graph/role-diff`, {
      method: "POST",
      body: JSON.stringify({
        project_id: projectId,
        baseline_role_id: baselineRoleId,
        candidate_role_ids: candidateRoleIds,
      }),
    }),

  // replay
  replay: (requestId: string, body: Record<string, unknown> = {}) =>
    req(`/api/v1/requests/${requestId}/replay`, { method: "POST", body: JSON.stringify(body) }),

  // ai
  runAgent: (projectId: string, agent: string, context: Record<string, unknown>) =>
    req(`/api/v1/ai/run`, {
      method: "POST",
      body: JSON.stringify({ project_id: projectId, agent, context, request_ids: [], redact: true }),
    }),
};
