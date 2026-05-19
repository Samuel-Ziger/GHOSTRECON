-- GhostMap initial schema
-- PostgreSQL 16
-- Tabelas transacionais. Grafo vai para o Neo4j.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ===== Projects =====
CREATE TABLE IF NOT EXISTS projects (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    target_scope JSONB NOT NULL DEFAULT '{"domains": [], "exclude": []}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== Roles (guest, user, admin, custom...) =====
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    auth_hint   JSONB,           -- como reconhecer essa role (cookie name, JWT claim, etc.)
    color       TEXT DEFAULT '#7c3aed',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

-- ===== Capture sessions =====
CREATE TABLE IF NOT EXISTS sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role_id     UUID REFERENCES roles(id) ON DELETE SET NULL,
    label       TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    meta        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_sessions_project ON sessions(project_id);

-- ===== HTTP requests / responses =====
CREATE TABLE IF NOT EXISTS http_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    url             TEXT NOT NULL,
    host            TEXT NOT NULL,
    path            TEXT NOT NULL,
    query           JSONB,
    req_headers     JSONB NOT NULL,
    req_body        BYTEA,
    req_body_text   TEXT,
    status          INTEGER,
    resp_headers    JSONB,
    resp_body       BYTEA,
    resp_body_text  TEXT,
    duration_ms     INTEGER,
    is_xhr          BOOLEAN DEFAULT FALSE,
    is_graphql      BOOLEAN DEFAULT FALSE,
    graphql_op      TEXT,
    tags            TEXT[] DEFAULT '{}',
    occurred_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_http_session   ON http_requests(session_id);
CREATE INDEX IF NOT EXISTS idx_http_project   ON http_requests(project_id);
CREATE INDEX IF NOT EXISTS idx_http_url_trgm  ON http_requests USING gin (url gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_http_path      ON http_requests(host, path);
CREATE INDEX IF NOT EXISTS idx_http_occurred  ON http_requests(occurred_at DESC);

-- ===== WebSocket frames =====
CREATE TABLE IF NOT EXISTS ws_frames (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    direction   TEXT NOT NULL CHECK (direction IN ('client_to_server','server_to_client')),
    payload     BYTEA,
    payload_text TEXT,
    occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ws_session ON ws_frames(session_id);

-- ===== Browser DOM events =====
CREATE TABLE IF NOT EXISTS dom_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,     -- 'navigation' | 'mutation' | 'storage' | 'cookie' | 'redirect' | 'script_load'
    payload     JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dom_session ON dom_events(session_id);
CREATE INDEX IF NOT EXISTS idx_dom_kind    ON dom_events(kind);

-- ===== Findings (heatmap / AI hypotheses) =====
CREATE TABLE IF NOT EXISTS findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    request_id  UUID REFERENCES http_requests(id) ON DELETE CASCADE,
    severity    TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT,
    source      TEXT NOT NULL,    -- 'heuristic' | 'ai:<agent>' | 'manual'
    confidence  REAL DEFAULT 0.5,
    meta        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);

-- ===== AI invocations (audit) =====
CREATE TABLE IF NOT EXISTS ai_invocations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    agent       TEXT NOT NULL,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    tokens_in   INTEGER,
    tokens_out  INTEGER,
    cost_usd    NUMERIC(10,6),
    duration_ms INTEGER,
    status      TEXT NOT NULL,
    redacted    BOOLEAN NOT NULL DEFAULT TRUE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_project ON ai_invocations(project_id, occurred_at DESC);

-- ===== Replays =====
CREATE TABLE IF NOT EXISTS replays (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_id     UUID REFERENCES http_requests(id) ON DELETE SET NULL,
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    url             TEXT NOT NULL,
    req_headers     JSONB NOT NULL,
    req_body        BYTEA,
    status          INTEGER,
    resp_headers    JSONB,
    resp_body       BYTEA,
    duration_ms     INTEGER,
    label           TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_replays_project ON replays(project_id);
