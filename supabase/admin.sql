-- Минитраты: безопасная админ-панель.
-- 1) Выполни этот файл в Supabase Dashboard -> SQL Editor ПОСЛЕ schema.sql.
-- 2) Чтобы выдать права, найди UUID своего аккаунта в Authentication -> Users
--    и выполни запрос в конце файла, заменив UUID на свой.
-- НИКОГДА не помещай service_role key в браузер.

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.admin_users enable row level security;
revoke all on public.admin_users from anon, authenticated;

create or replace function public.is_current_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.admin_users a
    where a.user_id = (select auth.uid())
  );
$$;
revoke all on function public.is_current_admin() from public, anon;
grant execute on function public.is_current_admin() to authenticated;

create or replace function public.admin_list_accounts()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare result jsonb;
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
    'user_id', u.id,
    'email', u.email,
    'created_at', u.created_at,
    'last_sign_in_at', u.last_sign_in_at,
    'user_metadata', coalesce(u.raw_user_meta_data, '{}'::jsonb),
    'display_name', coalesce(u.raw_user_meta_data->>'username', u.raw_user_meta_data->>'name', ''),
    'total_spent', coalesce(cur.total,0) + coalesce(hist.total,0),
    'expense_count', coalesce(cur.cnt,0) + coalesce(hist.cnt,0),
    'data_updated_at', d.updated_at
  ) order by u.created_at desc), '[]'::jsonb)
  into result
  from auth.users u
  left join public.user_data d on d.user_id = u.id
  left join lateral (
    select coalesce(sum((x->>'price')::numeric * coalesce((x->>'qty')::numeric,1)),0) as total,
           count(*) as cnt
    from jsonb_array_elements(coalesce(d.data->'current','[]'::jsonb)) x
  ) cur on true
  left join lateral (
    select coalesce(sum((x->>'price')::numeric * coalesce((x->>'qty')::numeric,1)),0) as total,
           count(*) as cnt
    from jsonb_each(coalesce(d.data->'history','{}'::jsonb)) h
    cross join lateral jsonb_array_elements(case when jsonb_typeof(h.value)='array' then h.value else '[]'::jsonb end) x
  ) hist on true;
  return result;
end;
$$;
revoke all on function public.admin_list_accounts() from public, anon;
grant execute on function public.admin_list_accounts() to authenticated;

create or replace function public.admin_get_account_data(target_user_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare result jsonb;
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  select coalesce(d.data, '{"current":[],"history":{}}'::jsonb)
    into result
    from auth.users u
    left join public.user_data d on d.user_id = u.id
   where u.id = target_user_id;
  if not found then raise exception 'Аккаунт не найден'; end if;
  return result;
end;
$$;
revoke all on function public.admin_get_account_data(uuid) from public, anon;
grant execute on function public.admin_get_account_data(uuid) to authenticated;

create or replace function public.admin_save_account_data(target_user_id uuid, new_data jsonb)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  if jsonb_typeof(new_data) <> 'object'
     or jsonb_typeof(new_data->'current') <> 'array'
     or jsonb_typeof(new_data->'history') <> 'object' then
    raise exception 'Некорректный формат данных расходов';
  end if;
  if not exists (select 1 from auth.users where id = target_user_id) then
    raise exception 'Аккаунт не найден';
  end if;
  insert into public.user_data(user_id, data, updated_at)
  values(target_user_id, new_data, now())
  on conflict(user_id) do update set data=excluded.data, updated_at=now();
  return true;
end;
$$;
revoke all on function public.admin_save_account_data(uuid, jsonb) from public, anon;
grant execute on function public.admin_save_account_data(uuid, jsonb) to authenticated;

-- Выдай себе права администратора после выполнения файла:
-- insert into public.admin_users(user_id) values ('ВСТАВЬ-СЮДА-UUID-АККАУНТА');

create or replace function public.admin_update_user_profile(target_user_id uuid, display_name text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  if length(trim(coalesce(display_name,''))) > 32 then
    raise exception 'Имя не должно быть длиннее 32 символов';
  end if;
  update auth.users
     set raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb)
           || jsonb_build_object('username', trim(coalesce(display_name,''))),
         updated_at = now()
   where id = target_user_id;
  if not found then raise exception 'Аккаунт не найден'; end if;
  return true;
end;
$$;
revoke all on function public.admin_update_user_profile(uuid, text) from public, anon;
grant execute on function public.admin_update_user_profile(uuid, text) to authenticated;
