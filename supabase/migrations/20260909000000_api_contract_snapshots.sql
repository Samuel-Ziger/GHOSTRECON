-- Baselines estruturais usados por api_contract_diff e busca eficiente por alvo.
alter table public.runs
  add column if not exists findings_json jsonb,
  add column if not exists persistence_state text not null default 'complete';

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'runs_persistence_state_check'
      and conrelid = 'public.runs'::regclass
  ) then
    alter table public.runs
      add constraint runs_persistence_state_check
      check (persistence_state in ('pending', 'complete'));
  end if;
end
$$;

create index if not exists runs_target_id_idx
  on public.runs (target, id desc);

create index if not exists runs_target_state_id_idx
  on public.runs (target, persistence_state, id desc);

-- Runs e evidências não são dados públicos. O processo local escreve
-- exclusivamente com service_role; anon/authenticated não recebem acesso
-- direto às tabelas nem às sequences.
alter table public.runs enable row level security;
alter table public.findings enable row level security;
alter table public.bounty_intel enable row level security;

drop policy if exists "ghostrecon_runs_all" on public.runs;
drop policy if exists "ghostrecon_findings_all" on public.findings;
drop policy if exists "ghostrecon_intel_all" on public.bounty_intel;

revoke all on table public.runs from anon, authenticated;
revoke all on table public.findings from anon, authenticated;
revoke all on table public.bounty_intel from anon, authenticated;
revoke all on sequence public.runs_id_seq from anon, authenticated;
revoke all on sequence public.findings_id_seq from anon, authenticated;
revoke all on sequence public.bounty_intel_id_seq from anon, authenticated;

grant usage on schema public to service_role;
grant all on table public.runs to service_role;
grant all on table public.findings to service_role;
grant all on table public.bounty_intel to service_role;
grant usage, select, update on sequence public.runs_id_seq to service_role;
grant usage, select, update on sequence public.findings_id_seq to service_role;
grant usage, select, update on sequence public.bounty_intel_id_seq to service_role;
