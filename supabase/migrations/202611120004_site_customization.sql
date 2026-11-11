-- Shared visual customization for SamHelp. Only admins can write.
create table if not exists public.site_customizations (
  id boolean primary key default true check (id = true),
  config jsonb not null default '{"elements":{},"theme":{}}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id)
);
alter table public.site_customizations enable row level security;
revoke all on public.site_customizations from anon, authenticated;

insert into public.site_customizations (id, config)
values (true, '{"elements":{},"theme":{}}'::jsonb)
on conflict (id) do nothing;

create or replace function public.get_site_customizations()
returns jsonb
language sql
security definer
set search_path = public
as $$
  select config from public.site_customizations where id = true;
$$;

create or replace function public.admin_update_site_customizations(new_config jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not exists (select 1 from public.shared_admins a where a.user_id = auth.uid()) then
    raise exception 'Недостаточно прав: требуется роль администратора';
  end if;
  if new_config is null or jsonb_typeof(new_config) <> 'object'
     or octet_length(new_config::text) > 200000 then
    raise exception 'Некорректные настройки оформления';
  end if;
  if jsonb_typeof(new_config->'elements') <> 'object'
     or jsonb_typeof(new_config->'theme') <> 'object' then
    raise exception 'Некорректная структура настроек';
  end if;
  insert into public.site_customizations (id, config, updated_at, updated_by)
  values (true, new_config, now(), auth.uid())
  on conflict (id) do update
    set config = excluded.config, updated_at = now(), updated_by = auth.uid();
end;
$$;

revoke all on function public.get_site_customizations() from public, anon;
revoke all on function public.admin_update_site_customizations(jsonb) from public, anon;
grant execute on function public.get_site_customizations() to authenticated;
grant execute on function public.admin_update_site_customizations(jsonb) to authenticated;
