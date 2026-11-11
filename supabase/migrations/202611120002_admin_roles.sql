-- SamHelp: отдельная роль администратора проекта.
-- Запускать после 202611120001_shared_data.sql.

create table if not exists public.shared_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.shared_admins enable row level security;

drop policy if exists "Admins can read own admin flag" on public.shared_admins;
create policy "Admins can read own admin flag"
on public.shared_admins
for select
to authenticated
using (user_id = (select auth.uid()));

grant select on public.shared_admins to authenticated;

-- Первого администратора назначьте вручную после его регистрации.
-- Замените email на адрес вашей учётной записи и выполните в SQL Editor:
--
-- insert into public.shared_admins (user_id)
-- select id from auth.users where email = 'admin@example.com'
-- on conflict (user_id) do nothing;
--
-- Администратор также должен быть редактором общего раздела:
-- insert into public.shared_editors (user_id)
-- select id from auth.users where email = 'admin@example.com'
-- on conflict (user_id) do nothing;
--
-- Добавление обычного редактора (без прав администратора):
-- insert into public.shared_editors (user_id)
-- select id from auth.users where email = 'editor@example.com'
-- on conflict (user_id) do nothing;
