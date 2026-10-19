-- Минитраты: приватное облачное хранилище по одному JSON-документу на пользователя.
-- Выполни весь файл в Supabase Dashboard -> SQL Editor.
create table if not exists public.user_data (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{"current":[],"history":{}}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.user_data enable row level security;

drop policy if exists "Users read own minitrati data" on public.user_data;
create policy "Users read own minitrati data"
  on public.user_data for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users insert own minitrati data" on public.user_data;
create policy "Users insert own minitrati data"
  on public.user_data for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users update own minitrati data" on public.user_data;
create policy "Users update own minitrati data"
  on public.user_data for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

grant select, insert, update on public.user_data to authenticated;
