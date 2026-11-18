-- SamHelp: per-user amoCRM integration foundation.
-- OAuth tokens and integration internals are server-only. The app never reads these tables directly.
create extension if not exists pgcrypto;

create table if not exists public.amo_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  account_id bigint,
  account_subdomain text,
  access_token_ciphertext text,
  refresh_token_ciphertext text,
  token_expires_at timestamptz,
  webhook_secret_hash text,
  connected_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.amo_contact_links (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.amo_connections(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  samhelp_contact_id text not null,
  amo_contact_id bigint,
  amo_lead_id bigint not null,
  pipeline_id bigint,
  status_id bigint,
  last_synced_at timestamptz,
  last_sync_source text check (last_sync_source in ('samhelp','amocrm', 'initial')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint amo_contact_links_one_samhelp_contact unique (user_id, samhelp_contact_id),
  constraint amo_contact_links_one_amo_lead unique (connection_id, amo_lead_id)
);

create table if not exists public.amo_stage_map (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.amo_connections(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  samhelp_pipeline_id text not null,
  samhelp_status_id text not null,
  amo_pipeline_id bigint not null,
  amo_status_id bigint not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint amo_stage_map_unique_pair unique
    (connection_id, samhelp_pipeline_id, samhelp_status_id),
  constraint amo_stage_map_unique_amo unique
    (connection_id, amo_pipeline_id, amo_status_id)
);

create table if not exists public.amo_sync_jobs (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.amo_connections(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  contact_link_id uuid references public.amo_contact_links(id) on delete set null,
  operation text not null check (operation in ('create_lead','update_lead_status','import_lead_status')),
  dedupe_key text not null,
  payload jsonb not null default '{}'::jsonb,
  state text not null default 'pending' check (state in ('pending','processing','done','failed')),
  attempts integer not null default 0 check (attempts >= 0),
  available_at timestamptz not null default now(),
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint amo_sync_jobs_dedupe unique (connection_id, dedupe_key)
);
create index if not exists amo_sync_jobs_ready_idx
  on public.amo_sync_jobs(state, available_at) where state in ('pending','failed');

create table if not exists public.amo_sync_events (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.amo_connections(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  contact_link_id uuid references public.amo_contact_links(id) on delete set null,
  direction text not null check (direction in ('to_amocrm','from_amocrm','system')),
  event_type text not null,
  outcome text not null check (outcome in ('success','ignored','error')),
  summary text not null default '',
  external_event_key text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create unique index if not exists amo_sync_events_external_dedupe_idx
  on public.amo_sync_events(connection_id, external_event_key)
  where external_event_key is not null;
create index if not exists amo_sync_events_user_recent_idx
  on public.amo_sync_events(user_id, created_at desc);

create table if not exists public.samhelp_notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  connection_id uuid references public.amo_connections(id) on delete cascade,
  contact_id text,
  title text not null,
  message text not null default '',
  kind text not null default 'amo_sync',
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists samhelp_notifications_user_recent_idx
  on public.samhelp_notifications(user_id, created_at desc);

-- These tables are deliberately inaccessible through the public client API.
-- Edge Functions use the service-role key and enforce the authenticated owner themselves.
alter table public.amo_connections enable row level security;
alter table public.amo_contact_links enable row level security;
alter table public.amo_stage_map enable row level security;
alter table public.amo_sync_jobs enable row level security;
alter table public.amo_sync_events enable row level security;
alter table public.samhelp_notifications enable row level security;

revoke all on public.amo_connections, public.amo_contact_links, public.amo_stage_map,
  public.amo_sync_jobs, public.amo_sync_events, public.samhelp_notifications from anon, authenticated;
grant all on public.amo_connections, public.amo_contact_links, public.amo_stage_map,
  public.amo_sync_jobs, public.amo_sync_events, public.samhelp_notifications to service_role;

create or replace function public.amo_set_updated_at()
returns trigger language plpgsql set search_path = public as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists amo_connections_updated_at on public.amo_connections;
create trigger amo_connections_updated_at before update on public.amo_connections
for each row execute function public.amo_set_updated_at();

drop trigger if exists amo_contact_links_updated_at on public.amo_contact_links;
create trigger amo_contact_links_updated_at before update on public.amo_contact_links
for each row execute function public.amo_set_updated_at();

drop trigger if exists amo_stage_map_updated_at on public.amo_stage_map;
create trigger amo_stage_map_updated_at before update on public.amo_stage_map
for each row execute function public.amo_set_updated_at();

drop trigger if exists amo_sync_jobs_updated_at on public.amo_sync_jobs;
create trigger amo_sync_jobs_updated_at before update on public.amo_sync_jobs
for each row execute function public.amo_set_updated_at();


-- OAuth state is short-lived and server-only; it prevents callback CSRF/replay.
create table if not exists public.amo_oauth_states (
  state_hash text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  expires_at timestamptz not null,
  consumed boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.amo_oauth_states enable row level security;
revoke all on public.amo_oauth_states from anon, authenticated;
grant all on public.amo_oauth_states to service_role;
create index if not exists amo_oauth_states_expiry_idx
  on public.amo_oauth_states(expires_at);
