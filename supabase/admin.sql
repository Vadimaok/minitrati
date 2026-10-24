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
create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'employee' check (role in ('employee','shift_senior')),
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.user_roles enable row level security;
revoke all on public.user_roles from anon, authenticated;

create table if not exists public.admin_tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(trim(title)) between 1 and 100),
  description text not null default '',
  assignee_id uuid references auth.users(id) on delete set null,
  created_by uuid not null references auth.users(id) on delete cascade,
  status text not null default 'new' check (status in ('new','taken','done')),
  taken_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists admin_tasks_assignee_idx on public.admin_tasks(assignee_id, status, created_at desc);
alter table public.admin_tasks enable row level security;
revoke all on public.admin_tasks from anon, authenticated;

create table if not exists public.admin_notebooks (
  admin_id uuid primary key references auth.users(id) on delete cascade,
  content text not null default '',
  updated_at timestamptz not null default now()
);
alter table public.admin_notebooks enable row level security;
revoke all on public.admin_notebooks from anon, authenticated;

create table if not exists public.user_notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  task_id uuid references public.admin_tasks(id) on delete set null,
  kind text not null default 'new_task',
  title text not null,
  body text not null default '',
  created_at timestamptz not null default now(),
  read_at timestamptz
);
create index if not exists user_notifications_unread_idx on public.user_notifications(user_id, created_at desc) where read_at is null;
alter table public.user_notifications enable row level security;
revoke all on public.user_notifications from anon, authenticated;

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
    'role', coalesce((select r.role from public.user_roles r where r.user_id = u.id), 'employee'),
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
-- Или выдай роль по email (замени адрес на почту своего аккаунта):
-- insert into public.admin_users(user_id)
-- select id from auth.users where lower(email) = lower('твоя-почта@example.com')
-- on conflict (user_id) do nothing;

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


-- Роли сотрудников: изменять может только администратор.
create or replace function public.admin_set_user_role(target_user_id uuid, new_role text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  if new_role not in ('employee','shift_senior') then
    raise exception 'Недопустимая роль';
  end if;
  if not exists(select 1 from auth.users where id=target_user_id) then
    raise exception 'Аккаунт не найден';
  end if;
  insert into public.user_roles(user_id,role,updated_by,updated_at)
  values(target_user_id,new_role,(select auth.uid()),now())
  on conflict(user_id) do update set role=excluded.role,updated_by=excluded.updated_by,updated_at=now();
  return true;
end;
$$;
revoke all on function public.admin_set_user_role(uuid,text) from public, anon;
grant execute on function public.admin_set_user_role(uuid,text) to authenticated;

-- Облачные задачи, доступные только администратору для управления.
create or replace function public.admin_list_tasks()
returns table(id uuid,title text,description text,assignee_id uuid,status text,created_at timestamptz,updated_at timestamptz,taken_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  return query
    select t.id,t.title,t.description,t.assignee_id,t.status,t.created_at,t.updated_at,t.taken_at
    from public.admin_tasks t order by t.updated_at desc;
end;
$$;
revoke all on function public.admin_list_tasks() from public, anon;
grant execute on function public.admin_list_tasks() to authenticated;

create or replace function public.admin_upsert_task(task_id uuid, title text, description text, assignee_id uuid, status text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare saved_id uuid; old_assignee uuid; was_new boolean := task_id is null;
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  if length(trim(coalesce(title,''))) < 1 or length(trim(title)) > 100 then
    raise exception 'Название задачи должно быть от 1 до 100 символов';
  end if;
  if status not in ('new','taken','done') then raise exception 'Недопустимый статус задачи'; end if;
  if assignee_id is not null and not exists(select 1 from auth.users where id=assignee_id) then
    raise exception 'Исполнитель не найден';
  end if;
  if task_id is null then
    insert into public.admin_tasks(title,description,assignee_id,created_by,status,taken_at)
    values(trim(title),coalesce(description,''),assignee_id,(select auth.uid()),status,case when status='taken' then now() else null end)
    returning id into saved_id;
  else
    select t.assignee_id into old_assignee from public.admin_tasks t where t.id=task_id;
    if not found then raise exception 'Задача не найдена'; end if;
    update public.admin_tasks t set title=trim(admin_upsert_task.title),
      description=coalesce(admin_upsert_task.description,''),assignee_id=admin_upsert_task.assignee_id,
      status=admin_upsert_task.status,
      taken_at=case when admin_upsert_task.status='taken' then
        case when t.status='taken' and t.assignee_id is not distinct from admin_upsert_task.assignee_id then t.taken_at else now() end
        else null end,
      updated_at=now()
    where t.id=task_id returning t.id into saved_id;
  end if;
  if assignee_id is not null and (was_new or old_assignee is distinct from assignee_id) then
    insert into public.user_notifications(user_id,task_id,kind,title,body)
    values(assignee_id,saved_id,'new_task','Новая задача: '||trim(title),coalesce(nullif(trim(description),''),'Администратор назначил тебе новую задачу.'));
  end if;
  return saved_id;
end;
$$;
revoke all on function public.admin_upsert_task(uuid,text,text,uuid,text) from public, anon;
grant execute on function public.admin_upsert_task(uuid,text,text,uuid,text) to authenticated;

create or replace function public.admin_delete_task(task_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  delete from public.admin_tasks where id=task_id;
  return found;
end;
$$;
revoke all on function public.admin_delete_task(uuid) from public, anon;
grant execute on function public.admin_delete_task(uuid) to authenticated;

create or replace function public.admin_get_notebook()
returns text
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  return coalesce((select n.content from public.admin_notebooks n where n.admin_id=(select auth.uid())), '');
end;
$$;
revoke all on function public.admin_get_notebook() from public, anon;
grant execute on function public.admin_get_notebook() to authenticated;

create or replace function public.admin_save_notebook(new_notebook text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not public.is_current_admin() then
    raise exception 'Доступ запрещён: нужны права администратора' using errcode = '42501';
  end if;
  if length(coalesce(new_notebook,'')) > 20000 then raise exception 'Заметки слишком длинные'; end if;
  insert into public.admin_notebooks(admin_id,content,updated_at)
  values((select auth.uid()),coalesce(new_notebook,''),now())
  on conflict(admin_id) do update set content=excluded.content,updated_at=now();
  return true;
end;
$$;
revoke all on function public.admin_save_notebook(text) from public, anon;
grant execute on function public.admin_save_notebook(text) to authenticated;

-- Пользователь получает только собственные уведомления. После выдачи они помечаются прочитанными.
create or replace function public.user_get_task_notifications()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare result jsonb;
begin
  if (select auth.uid()) is null then raise exception 'Нужна авторизация' using errcode = '42501'; end if;
  with picked as (
    select n.id,n.title,n.body,n.created_at
    from public.user_notifications n
    where n.user_id=(select auth.uid()) and n.read_at is null
    order by n.created_at asc
    limit 20
    for update
  ), marked as (
    update public.user_notifications n set read_at=now()
    where n.id in (select p.id from picked p)
    returning n.id
  )
  select coalesce(jsonb_agg(jsonb_build_object('id',p.id,'title',p.title,'body',p.body,'created_at',p.created_at) order by p.created_at),'[]'::jsonb)
  into result from picked p;
  return result;
end;
$$;
revoke all on function public.user_get_task_notifications() from public, anon;
grant execute on function public.user_get_task_notifications() to authenticated;
