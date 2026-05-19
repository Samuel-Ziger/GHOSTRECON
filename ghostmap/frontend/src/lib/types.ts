// Mantemos tipos espelhando o backend.
// Em prod, gerar via openapi-typescript a partir de /openapi.json.

export type UUID = string;

export type NodeLabel =
  | "Page" | "Endpoint" | "ApiOperation" | "GraphQLOperation"
  | "Param" | "JWT" | "Cookie" | "User" | "Role"
  | "Upload" | "File" | "Bucket" | "Integration" | "Host";

export interface GraphNode {
  id: string;
  label: NodeLabel;
  title: string;
  props: Record<string, unknown>;
  heat: number;
  cluster: string | null;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  props: Record<string, unknown>;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: Record<string, number>;
}

export interface Project {
  id: UUID;
  name: string;
  target_scope: { domains: string[]; exclude: string[] };
  created_at: string;
  updated_at: string;
}

export interface Role {
  id: UUID;
  project_id: UUID;
  name: string;
  description: string | null;
  auth_hint: Record<string, unknown> | null;
  color: string;
  created_at: string;
}

export interface HttpRequestItem {
  id: UUID;
  session_id: UUID;
  project_id: UUID;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number | null;
  duration_ms: number | null;
  is_xhr: boolean;
  is_graphql: boolean;
  graphql_op: string | null;
  occurred_at: string;
}

export interface RequestList { items: HttpRequestItem[]; total: number; }

export type SuspicionKind =
  | "privilege_escalation" | "potential_idor"
  | "hidden_endpoint" | "mass_assignment_candidate" | null;

export interface EndpointDiff {
  endpoint_id: string;
  host: string;
  method: string;
  path: string;
  seen_in_roles: string[];
  only_in: string[];
  status_codes_by_role: Record<string, number[]>;
  param_delta: Record<string, string[]>;
  suspicion: SuspicionKind;
  confidence: number;
}

export interface RoleDiffResponse {
  project_id: UUID;
  baseline: string;
  candidates: string[];
  differences: EndpointDiff[];
  summary: Record<string, unknown>;
}
