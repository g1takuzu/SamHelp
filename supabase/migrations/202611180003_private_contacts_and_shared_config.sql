-- SamHelp: private per-user contacts + shared application configuration.
-- Contact rows are isolated by auth.uid(); admin role does not grant cross-user access.

create table if not exists public.private_contacts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  contact_id text not null,
  data jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint private_contacts_user_contact_unique unique (user_id, contact_id),
  constraint private_contacts_data_object check (jsonb_typeof(data) = 'object')
);

create index if not exists private_contacts_user_updated_idx
  on public.private_contacts(user_id, updated_at desc);

alter table public.private_contacts enable row level security;
alter table public.private_contacts force row level security;

drop policy if exists "Users read own private contacts" on public.private_contacts;
create policy "Users read own private contacts"
  on public.private_contacts for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists "Users insert own private contacts" on public.private_contacts;
create policy "Users insert own private contacts"
  on public.private_contacts for insert to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists "Users update own private contacts" on public.private_contacts;
create policy "Users update own private contacts"
  on public.private_contacts for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists "Users delete own private contacts" on public.private_contacts;
create policy "Users delete own private contacts"
  on public.private_contacts for delete to authenticated
  using (user_id = (select auth.uid()));

revoke all on public.private_contacts from anon;
grant select, insert, update, delete on public.private_contacts to authenticated;

-- Shared application data: pipelines, shared tables and shared templates/settings.
-- Personal preferences and contacts must never be placed in this document.
create table if not exists public.shared_app_config (
  id boolean primary key default true check (id = true),
  config jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id),
  constraint shared_app_config_object check (jsonb_typeof(config) = 'object')
);

alter table public.shared_app_config enable row level security;
alter table public.shared_app_config force row level security;

insert into public.shared_app_config (id, config)
values (true, '{}'::jsonb)
on conflict (id) do nothing;

drop policy if exists "Authenticated users read shared app config" on public.shared_app_config;
create policy "Authenticated users read shared app config"
  on public.shared_app_config for select to authenticated
  using ((select auth.uid()) is not null);

drop policy if exists "Editors update shared app config" on public.shared_app_config;
create policy "Editors update shared app config"
  on public.shared_app_config for update to authenticated
  using (exists (
    select 1 from public.shared_editors e where e.user_id = (select auth.uid())
  ))
  with check (exists (
    select 1 from public.shared_editors e where e.user_id = (select auth.uid())
  ) and updated_by = (select auth.uid()));

revoke all on public.shared_app_config from anon;
grant select, update on public.shared_app_config to authenticated;

create or replace function public.get_shared_app_config()
returns jsonb
language sql
security invoker
set search_path = public
as $$
  select config from public.shared_app_config where id = true;
$$;

create or replace function public.update_shared_app_config(new_config jsonb)
returns void
language plpgsql
security invoker
set search_path = public
as $$
begin
  if not exists (
    select 1 from public.shared_editors e where e.user_id = auth.uid()
  ) then
    raise exception 'Недостаточно прав: требуется роль редактора общих данных';
  end if;
  if new_config is null or jsonb_typeof(new_config) <> 'object'
     or octet_length(new_config::text) > 500000 then
    raise exception 'Некорректная конфигурация общих данных';
  end if;
  update public.shared_app_config
     set config = new_config, updated_at = now(), updated_by = auth.uid()
   where id = true;
end;
$$;

revoke all on function public.get_shared_app_config() from public, anon;
revoke all on function public.update_shared_app_config(jsonb) from public, anon;
grant execute on function public.get_shared_app_config() to authenticated;
grant execute on function public.update_shared_app_config(jsonb) to authenticated;

-- Enable database change notifications when Supabase Realtime publication exists.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'private_contacts'
    ) then
      alter publication supabase_realtime add table public.private_contacts;
    end if;
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'shared_app_config'
    ) then
      alter publication supabase_realtime add table public.shared_app_config;
    end if;
  end if;
end $$;
