-- Opcional — tabela de fila/alvos para o orquestrador VPS.
-- Ajuste RLS políticas antes de usar chaves anon em cliente público.

create table if not exists public.workflow_domains (
  id uuid primary key default gen_random_uuid(),
  domain text not null,
  root_domain text,
  source text default 'ghostrecon',
  created_at timestamptz not null default now(),
  unique (domain)
);

create index if not exists workflow_domains_root_idx on public.workflow_domains (root_domain);
create index if not exists workflow_domains_created_idx on public.workflow_domains (created_at desc);

alter table public.workflow_domains enable row level security;
