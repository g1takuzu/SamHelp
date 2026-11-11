-- SamHelp: username-based registration without user-facing email addresses.
alter table public.shared_profiles
  add column if not exists login text not null default '';

update public.shared_profiles p
set login = coalesce(
  nullif(u.raw_user_meta_data ->> 'login', ''),
  nullif(split_part(coalesce(u.email, ''), '@', 1), '')
)
from auth.users u
where u.id = p.user_id
  and (p.login = '' or p.login is null);

create or replace function public.sync_shared_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.shared_profiles (user_id, email, login, display_name, created_at)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(nullif(new.raw_user_meta_data ->> 'login', ''), nullif(split_part(coalesce(new.email, ''), '@', 1), ''), ''),
    coalesce(new.raw_user_meta_data ->> 'display_name', ''),
    coalesce(new.created_at, now())
  )
  on conflict (user_id) do update
    set email = excluded.email,
        login = excluded.login,
        display_name = excluded.display_name;
  return new;
end;
$$;

drop function if exists public.admin_list_users();

create function public.admin_list_users()
returns table (
  user_id uuid,
  login text,
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
    p.login,
    p.email,
    p.display_name,
    case
      when exists (select 1 from public.shared_admins a where a.user_id = p.user_id) then 'admin'
      when exists (select 1 from public.shared_editors e where e.user_id = p.user_id) then 'editor'
      else 'user'
    end as role,
    p.created_at
  from public.shared_profiles p
  order by p.created_at asc, p.login asc;
end;
$$;

revoke all on function public.admin_list_users() from public, anon;
grant execute on function public.admin_list_users() to authenticated;
