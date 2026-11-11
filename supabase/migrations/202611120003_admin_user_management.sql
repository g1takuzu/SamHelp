-- SamHelp: управление ролями пользователей через интерфейс администратора.
-- Безопасное управление выполняется только через RPC SECURITY DEFINER.
-- Обычные клиенты не получают прямого доступа к таблице профилей.

create table if not exists public.shared_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null default '',
  display_name text not null default '',
  created_at timestamptz not null default now()
);

alter table public.shared_profiles enable row level security;

create or replace function public.sync_shared_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.shared_profiles (user_id, email, display_name, created_at)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data ->> 'display_name', ''),
    coalesce(new.created_at, now())
  )
  on conflict (user_id) do update
    set email = excluded.email,
        display_name = excluded.display_name;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_sync_profile on auth.users;
create trigger on_auth_user_created_sync_profile
after insert or update on auth.users
for each row execute function public.sync_shared_profile();

-- Заполнить профили уже зарегистрированных пользователей.
insert into public.shared_profiles (user_id, email, display_name, created_at)
select id, coalesce(email, ''), coalesce(raw_user_meta_data ->> 'display_name', ''), coalesce(created_at, now())
from auth.users
on conflict (user_id) do update
  set email = excluded.email,
      display_name = excluded.display_name;

create or replace function public.admin_list_users()
returns table (
  user_id uuid,
  email text,
  display_name text,
  role text,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not exists (
    select 1 from public.shared_admins a where a.user_id = auth.uid()
  ) then
    raise exception 'Недостаточно прав: требуется роль администратора';
  end if;

  return query
  select
    p.user_id,
    p.email,
    p.display_name,
    case
      when exists (select 1 from public.shared_admins a where a.user_id = p.user_id) then 'admin'
      when exists (select 1 from public.shared_editors e where e.user_id = p.user_id) then 'editor'
      else 'user'
    end as role,
    p.created_at
  from public.shared_profiles p
  order by p.created_at asc, p.email asc;
end;
$$;

create or replace function public.admin_set_user_role(target_user_id uuid, new_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_is_admin boolean;
  admin_total integer;
begin
  if not exists (
    select 1 from public.shared_admins a where a.user_id = auth.uid()
  ) then
    raise exception 'Недостаточно прав: требуется роль администратора';
  end if;

  if target_user_id is null or target_user_id = auth.uid() then
    raise exception 'Нельзя изменить собственную роль';
  end if;

  if new_role not in ('user', 'editor', 'admin') then
    raise exception 'Неизвестная роль';
  end if;

  if not exists (select 1 from public.shared_profiles p where p.user_id = target_user_id) then
    raise exception 'Пользователь не найден';
  end if;

  select exists (
    select 1 from public.shared_admins a where a.user_id = target_user_id
  ) into target_is_admin;

  if target_is_admin and new_role <> 'admin' then
    select count(*) into admin_total from public.shared_admins;
    if admin_total <= 1 then
      raise exception 'Нельзя снять роль последнего администратора';
    end if;
  end if;

  if new_role = 'admin' then
    insert into public.shared_admins (user_id) values (target_user_id)
    on conflict (user_id) do nothing;
    insert into public.shared_editors (user_id) values (target_user_id)
    on conflict (user_id) do nothing;
  elsif new_role = 'editor' then
    delete from public.shared_admins where user_id = target_user_id;
    insert into public.shared_editors (user_id) values (target_user_id)
    on conflict (user_id) do nothing;
  else
    delete from public.shared_admins where user_id = target_user_id;
    delete from public.shared_editors where user_id = target_user_id;
  end if;
end;
$$;

revoke all on function public.admin_list_users() from public, anon;
revoke all on function public.admin_set_user_role(uuid, text) from public, anon;
grant execute on function public.admin_list_users() to authenticated;
grant execute on function public.admin_set_user_role(uuid, text) to authenticated;
