create table if not exists public.application_state (
  id smallint primary key check (id = 1),
  revision bigint not null default 0,
  state jsonb not null
);

insert into public.application_state (id, revision, state)
values (
  1,
  0,
  '{
    "persons": [],
    "household_profiles": [],
    "registrations": [],
    "cards": [],
    "lots": [],
    "lot_cap_grants": [],
    "card_quota_ledger": [],
    "distribution_transactions": [],
    "transaction_state_history": [],
    "provisional_tokens": [],
    "failure_events": [],
    "audit_events": [],
    "distribution_nodes": [],
    "idempotency_cache": {},
    "used_nonces": {}
  }'::jsonb
)
on conflict (id) do nothing;

alter table public.application_state enable row level security;

revoke all on table public.application_state from public, anon, authenticated;
grant select, insert, update, delete on table public.application_state to service_role;

create or replace function public.save_application_state(
  expected_revision bigint,
  next_state jsonb
)
returns bigint
language sql
security definer
set search_path = ''
as $$
  update public.application_state
  set state = next_state,
      revision = revision + 1
  where id = 1
    and revision = expected_revision
  returning revision;
$$;

revoke all on function public.save_application_state(bigint, jsonb) from public, anon, authenticated;
grant execute on function public.save_application_state(bigint, jsonb) to service_role;
