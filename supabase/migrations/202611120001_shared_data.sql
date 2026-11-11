-- SamHelp: общие таблицы и приложения.
-- Контакты и личные ссылки намеренно остаются в локальном хранилище приложения.

create extension if not exists pgcrypto;

create table if not exists public.shared_editors (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.shared_links (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('sheets', 'apps')),
  title text not null,
  url text not null,
  note text not null default '',
  group_name text not null default '',
  icon text not null default '',
  created_by uuid not null default auth.uid() references auth.users(id),
  updated_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists shared_links_kind_idx
  on public.shared_links(kind);

create or replace function public.set_shared_links_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  new.updated_by = auth.uid();
  -- Автор исходной записи не меняется при редактировании другим редактором.
  new.created_by = old.created_by;
  return new;
end;
$$;

drop trigger if exists shared_links_updated_at on public.shared_links;
create trigger shared_links_updated_at
before update on public.shared_links
for each row execute function public.set_shared_links_updated_at();

alter table public.shared_editors enable row level security;
alter table public.shared_links enable row level security;

-- Каждый вошедший пользователь может узнать только собственную запись редактора.
drop policy if exists "Editors can read own editor flag" on public.shared_editors;
create policy "Editors can read own editor flag"
on public.shared_editors
for select
to authenticated
using (user_id = (select auth.uid()));

-- Список общих ссылок доступен всем вошедшим пользователям.
drop policy if exists "Authenticated users can read shared links" on public.shared_links;
create policy "Authenticated users can read shared links"
on public.shared_links
for select
to authenticated
using ((select auth.uid()) is not null);

-- Изменять общий раздел могут только пользователи из shared_editors.
drop policy if exists "Editors can insert shared links" on public.shared_links;
create policy "Editors can insert shared links"
on public.shared_links
for insert
to authenticated
with check (
  exists (
    select 1 from public.shared_editors e
    where e.user_id = (select auth.uid())
  )
  and created_by = (select auth.uid())
  and updated_by = (select auth.uid())
);

drop policy if exists "Editors can update shared links" on public.shared_links;
create policy "Editors can update shared links"
on public.shared_links
for update
to authenticated
using (
  exists (
    select 1 from public.shared_editors e
    where e.user_id = (select auth.uid())
  )
)
with check (
  exists (
    select 1 from public.shared_editors e
    where e.user_id = (select auth.uid())
  )
  and updated_by = (select auth.uid())
);

drop policy if exists "Editors can delete shared links" on public.shared_links;
create policy "Editors can delete shared links"
on public.shared_links
for delete
to authenticated
using (
  exists (
    select 1 from public.shared_editors e
    where e.user_id = (select auth.uid())
  )
);

grant select on public.shared_editors to authenticated;
grant select, insert, update, delete on public.shared_links to authenticated;

-- После регистрации пользователя добавьте его в редакторы через SQL Editor Supabase:
-- insert into public.shared_editors (user_id)
-- select id from auth.users where email = 'user@example.com'
-- on conflict (user_id) do nothing;
