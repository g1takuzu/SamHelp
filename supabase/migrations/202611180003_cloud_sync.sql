-- SamHelp cloud sync v1: private contacts and shared workspace configuration.
create table if not exists public.private_contacts (
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  contact_id text not null,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, contact_id),
  constraint private_contacts_data_object check (jsonb_typeof(data) = 'object'),
  constraint private_contacts_data_id check (data->>'id' = contact_id)
);

create index if not exists private_contacts_user_updated_idx
  on public.private_contacts(user_id, updated_at desc);

alter table public.private_contacts enable row level security;
revoke all on public.private_contacts from anon;
grant select, insert, update, delete on public.private_contacts to authenticated;

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

create or replace function public.set_private_contact_updated_at()
returns trigger language plpgsql set search_path = public as $$
begin
  new.updated_at = now();
  new.user_id = auth.uid();
  return new;
end;
$$;

drop trigger if exists private_contacts_updated_at on public.private_contacts;
create trigger private_contacts_updated_at
before insert or update on public.private_contacts
for each row execute function public.set_private_contact_updated_at();

-- One shared document contains only company-wide configuration.
-- Personal contacts and employee-owned templates never enter this table.
create table if not exists public.shared_workspace (
  id boolean primary key default true check (id = true),
  config jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id)
);

alter table public.shared_workspace enable row level security;
revoke all on public.shared_workspace from anon;
grant select, insert, update on public.shared_workspace to authenticated;

drop policy if exists "Authenticated users read shared workspace" on public.shared_workspace;
create policy "Authenticated users read shared workspace"
on public.shared_workspace for select to authenticated
using ((select auth.uid()) is not null);

drop policy if exists "Editors insert shared workspace" on public.shared_workspace;
create policy "Editors insert shared workspace"
on public.shared_workspace for insert to authenticated
with check (
  updated_by = (select auth.uid())
  and (exists (select 1 from public.shared_editors e where e.user_id = (select auth.uid()))
   or exists (select 1 from public.shared_admins a where a.user_id = (select auth.uid())))
);

drop policy if exists "Editors update shared workspace" on public.shared_workspace;
create policy "Editors update shared workspace"
on public.shared_workspace for update to authenticated
using (exists (select 1 from public.shared_editors e where e.user_id = (select auth.uid())))
with check (
  updated_by = (select auth.uid())
  and (exists (select 1 from public.shared_editors e where e.user_id = (select auth.uid()))
       or exists (select 1 from public.shared_admins a where a.user_id = (select auth.uid())))
);

create or replace function public.set_shared_workspace_updated_at()
returns trigger language plpgsql set search_path = public as $$
begin
  new.updated_at = now();
  new.updated_by = auth.uid();
  return new;
end;
$$;

drop trigger if exists shared_workspace_updated_at on public.shared_workspace;
create trigger shared_workspace_updated_at
before insert or update on public.shared_workspace
for each row execute function public.set_shared_workspace_updated_at();

-- Realtime is used for cross-device updates. Guard against installations
-- where the standard Supabase publication has not been created.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    begin
      alter publication supabase_realtime add table public.private_contacts;
    exception when duplicate_object then null;
    end;
    begin
      alter publication supabase_realtime add table public.shared_workspace;
    exception when duplicate_object then null;
    end;
  end if;
end $$;
