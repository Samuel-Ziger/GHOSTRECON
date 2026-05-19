/** Entrada do histórico HTTP GHOSTRECON (`GET /api/history/recon`). */
export interface HistoryEntry {
  id: number;
  url?: string;
  method?: string;
  status?: number | null;
  statusText?: string;
  error?: string;
  durationMs?: number;
  responseSize?: number;
  mimeType?: string;
  source?: string;
  target?: string;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: string;
  responseBody?: string;
  createdAt?: string;
}

export interface HistoryFilters {
  search: string;
  method: string;
  status: string;
  mime: string;
  source: string;
}

export type HistorySortCol =
  | 'id'
  | 'host'
  | 'method'
  | 'url'
  | 'status'
  | 'len'
  | 'ms';
