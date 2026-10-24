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
  role text not null default 'employee' check (role in ('employee','employee_knz','shift_senior')),
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.user_roles drop constraint if exists user_roles_role_check;
alter table public.user_roles add constraint user_roles_role_check check (role in ('employee','employee_knz','shift_senior'));
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
  if new_role not in ('employee','employee_knz','shift_senior') then
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


-- Роль текущего пользователя для компактного бейджа в профиле.
create or replace function public.user_get_my_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((select r.role from public.user_roles r where r.user_id=(select auth.uid())), 'employee');
$$;
revoke all on function public.user_get_my_role() from public, anon;
grant execute on function public.user_get_my_role() to authenticated;


-- Управление доступом к инструментам СТ.Смены и КНЗ.
alter table public.admin_tasks add column if not exists completion_note text not null default '';
alter table public.admin_tasks add column if not exists screenshot_data text;
create table if not exists public.role_feature_flags (
  role text primary key check (role in ('shift_senior','employee_knz')),
  is_enabled boolean not null default true,
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.role_feature_flags enable row level security;
revoke all on public.role_feature_flags from anon, authenticated;
insert into public.role_feature_flags(role,is_enabled) values ('shift_senior',true),('employee_knz',true)
on conflict(role) do nothing;

create or replace function public.user_get_role_features()
returns jsonb language sql stable security definer set search_path=''
as $$
 select jsonb_build_object(
  'shift_senior',coalesce((select f.is_enabled from public.role_feature_flags f where f.role='shift_senior'),true),
  'employee_knz',coalesce((select f.is_enabled from public.role_feature_flags f where f.role='employee_knz'),true)
 );
$$;
revoke all on function public.user_get_role_features() from public,anon;
grant execute on function public.user_get_role_features() to authenticated;

create or replace function public.admin_set_role_feature(target_role text,is_enabled boolean)
returns boolean language plpgsql security definer set search_path=''
as $role_feature$
declare enabled_value boolean := is_enabled;
begin
 if not public.is_current_admin() then raise exception 'Доступ запрещён: нужны права администратора' using errcode='42501'; end if;
 if target_role not in ('shift_senior','employee_knz') then raise exception 'Недопустимая роль'; end if;
 insert into public.role_feature_flags(role,is_enabled,updated_by,updated_at)
 values(target_role,enabled_value,(select auth.uid()),now())
 on conflict(role) do update set is_enabled=excluded.is_enabled,updated_by=excluded.updated_by,updated_at=now();
 return true;
end; $role_feature$;
revoke all on function public.admin_set_role_feature(text,boolean) from public,anon;
grant execute on function public.admin_set_role_feature(text,boolean) to authenticated;

create or replace function public.shift_list_knz_employees()
returns jsonb language plpgsql stable security definer set search_path=''
as $$
declare result jsonb;
begin
 if (select auth.uid()) is null or coalesce((select r.role from public.user_roles r where r.user_id=(select auth.uid())),'employee') <> 'shift_senior' or not coalesce((select f.is_enabled from public.role_feature_flags f where f.role='shift_senior'),true) then
  raise exception 'Доступ запрещён' using errcode='42501';
 end if;
 select coalesce(jsonb_agg(jsonb_build_object('user_id',u.id,'email',u.email,'display_name',coalesce(u.raw_user_meta_data->>'display_name',u.raw_user_meta_data->>'username',u.email)) order by u.email),'[]'::jsonb)
 into result from auth.users u join public.user_roles r on r.user_id=u.id and r.role='employee_knz';
 return result;
end; $$;
revoke all on function public.shift_list_knz_employees() from public,anon;
grant execute on function public.shift_list_knz_employees() to authenticated;

create or replace function public.shift_list_tasks()
returns jsonb language plpgsql stable security definer set search_path=''
as $$
declare result jsonb; uid uuid := (select auth.uid());
begin
 if uid is null or coalesce((select r.role from public.user_roles r where r.user_id=uid),'employee') <> 'shift_senior' or not coalesce((select f.is_enabled from public.role_feature_flags f where f.role='shift_senior'),true) then raise exception 'Доступ запрещён' using errcode='42501'; end if;
 select coalesce(jsonb_agg(jsonb_build_object('id',t.id,'title',t.title,'description',t.description,'assignee_id',t.assignee_id,'assignee_email',u.email,'assignee_name',coalesce(u.raw_user_meta_data->>'display_name',u.raw_user_meta_data->>'username',u.email),'status',t.status,'created_at',t.created_at,'updated_at',t.updated_at,'taken_at',t.taken_at,'completion_note',t.completion_note,'screenshot_data',t.screenshot_data) order by t.updated_at desc),'[]'::jsonb)
 into result from public.admin_tasks t left join auth.users u on u.id=t.assignee_id where t.created_by=uid and t.assignee_id is not null;
 return result;
end; $$;
revoke all on function public.shift_list_tasks() from public,anon;
grant execute on function public.shift_list_tasks() to authenticated;

create or replace function public.shift_upsert_task(task_id uuid,task_title text,task_description text,target_assignee uuid)
returns uuid language plpgsql security definer set search_path=''
as $$
declare uid uuid := (select auth.uid()); saved uuid;
begin
 if uid is null or coalesce((select r.role from public.user_roles r where r.user_id=uid),'employee') <> 'shift_senior' or not coalesce((select f.is_enabled from public.role_feature_flags f where f.role='shift_senior'),true) then raise exception 'Доступ запрещён' using errcode='42501'; end if;
 if length(trim(coalesce(task_title,''))) not between 1 and 100 then raise exception 'Название задачи должно быть от 1 до 100 символов'; end if;
 if not exists(select 1 from public.user_roles r where r.user_id=target_assignee and r.role='employee_knz') then raise exception 'Назначать можно только сотрудникам КНЗ'; end if;
 if task_id is null then
  insert into public.admin_tasks(title,description,assignee_id,created_by,status) values(trim(task_title),coalesce(task_description,''),target_assignee,uid,'new') returning id into saved;
 else
  update public.admin_tasks set title=trim(task_title),description=coalesce(task_description,''),assignee_id=target_assignee,updated_at=now()
   where id=task_id and created_by=uid and status<>'done' returning id into saved;
  if saved is null then raise exception 'Задача не найдена или уже завершена'; end if;
 end if;
 insert into public.user_notifications(user_id,task_id,kind,title,body) values(target_assignee,saved,'new_task','Новая задача от СТ.Смены: '||trim(task_title),coalesce(nullif(trim(task_description),''),'Тебе назначили новую задачу.'));
 return saved;
end; $$;
revoke all on function public.shift_upsert_task(uuid,text,text,uuid) from public,anon;
grant execute on function public.shift_upsert_task(uuid,text,text,uuid) to authenticated;

create or replace function public.user_list_my_knz_tasks()
returns jsonb language plpgsql stable security definer set search_path=''
as $$
declare result jsonb; uid uuid := (select auth.uid());
begin
 if uid is null or coalesce((select r.role from public.user_roles r where r.user_id=uid),'employee') <> 'employee_knz' or not coalesce((select f.is_enabled from public.role_feature_flags f where f.role='employee_knz'),true) then raise exception 'Доступ запрещён или функция отключена' using errcode='42501'; end if;
 select coalesce(jsonb_agg(jsonb_build_object('id',t.id,'title',t.title,'description',t.description,'status',t.status,'created_at',t.created_at,'updated_at',t.updated_at,'taken_at',t.taken_at,'completion_note',t.completion_note,'screenshot_data',t.screenshot_data) order by t.created_at desc),'[]'::jsonb)
 into result from public.admin_tasks t where t.assignee_id=uid;
 return result;
end; $$;
revoke all on function public.user_list_my_knz_tasks() from public,anon;
grant execute on function public.user_list_my_knz_tasks() to authenticated;

create or replace function public.user_take_knz_task(task_id uuid)
returns boolean language plpgsql security definer set search_path=''
as $$
declare uid uuid := (select auth.uid());
begin
 if uid is null or coalesce((select r.role from public.user_roles r where r.user_id=uid),'employee') <> 'employee_knz' or not coalesce((select f.is_enabled from public.role_feature_flags f where f.role='employee_knz'),true) then raise exception 'Доступ запрещён или функция отключена' using errcode='42501'; end if;
 update public.admin_tasks set status='taken',taken_at=now(),updated_at=now() where id=task_id and assignee_id=uid and status='new';
 if not found then raise exception 'Задача недоступна или уже взята в работу'; end if;
 return true;
end; $$;
revoke all on function public.user_take_knz_task(uuid) from public,anon;
grant execute on function public.user_take_knz_task(uuid) to authenticated;

create or replace function public.user_submit_knz_task(task_id uuid,completion_note text,screenshot_data text)
returns boolean language plpgsql security definer set search_path=''
as $$
declare uid uuid := (select auth.uid());
begin
 if uid is null or coalesce((select r.role from public.user_roles r where r.user_id=uid),'employee') <> 'employee_knz' or not coalesce((select f.is_enabled from public.role_feature_flags f where f.role='employee_knz'),true) then raise exception 'Доступ запрещён или функция отключена' using errcode='42501'; end if;
 if length(coalesce(completion_note,''))>1000 then raise exception 'Комментарий слишком длинный'; end if;
 if screenshot_data is not null and (length(screenshot_data)>1800000 or screenshot_data not like 'data:image/%;base64,%') then raise exception 'Некорректный или слишком большой скриншот'; end if;
 update public.admin_tasks set status='done',completion_note=coalesce(completion_note,''),screenshot_data=coalesce(screenshot_data,public.admin_tasks.screenshot_data),updated_at=now()
 where id=task_id and assignee_id=uid and status='taken';
 if not found then raise exception 'Сначала возьми задачу в работу'; end if;
 insert into public.user_notifications(user_id,task_id,kind,title,body)
 select created_by,task_id,'task_done','Задача выполнена: '||title,coalesce(nullif(trim(completion_note),''),'Сотрудник КНЗ отправил результат.')
 from public.admin_tasks where id=task_id;
 return true;
end; $$;
revoke all on function public.user_submit_knz_task(uuid,text,text) from public,anon;
grant execute on function public.user_submit_knz_task(uuid,text,text) to authenticated;
