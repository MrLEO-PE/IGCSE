-- IGCSE PE Workbook — class tracking setup (syllabus checklist + teacher dashboard)
--
-- Run once: Supabase dashboard → SQL Editor → New query → paste this file → Run.
-- It is safe to run again; it only creates what is missing.
--
-- Afterwards, make yourself a teacher (step 4 at the bottom).

-- 1. One row per AI-marked answer (practice, spaced review or quiz) -----------
create table if not exists public.question_attempts (
  id          bigint generated always as identity primary key,
  user_id     uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  chapter_id  text not null,
  question_id int  not null,
  score       int  not null check (score >= 0),
  max_score   int  not null check (max_score > 0 and score <= max_score),
  source      text not null default 'practice' check (source in ('practice', 'review', 'quiz')),
  created_at  timestamptz not null default now()
);
create index if not exists question_attempts_user_time_idx
  on public.question_attempts (user_id, created_at);
alter table public.question_attempts enable row level security;

-- 2. Teachers — rows are added by hand here, never from the app ---------------
create table if not exists public.teachers (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.teachers enable row level security;

-- security definer so policies can check it without recursing through RLS
create or replace function public.is_teacher()
returns boolean
language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.teachers where user_id = auth.uid()) $$;

-- 3. Access rules --------------------------------------------------------------
-- Students: add and read only their own answers. Teachers: read everyone's.
drop policy if exists "attempts: insert own"          on public.question_attempts;
drop policy if exists "attempts: read own"            on public.question_attempts;
drop policy if exists "attempts: teachers read all"   on public.question_attempts;
drop policy if exists "teachers: read own row"        on public.teachers;
drop policy if exists "profiles: teachers read all"   on public.profiles;

create policy "attempts: insert own" on public.question_attempts
  for insert to authenticated with check (user_id = auth.uid());
create policy "attempts: read own" on public.question_attempts
  for select to authenticated using (user_id = auth.uid());
create policy "attempts: teachers read all" on public.question_attempts
  for select to authenticated using (public.is_teacher());

-- lets the app check "am I a teacher?" (no insert/update policy = nobody can add themselves)
create policy "teachers: read own row" on public.teachers
  for select to authenticated using (user_id = auth.uid());

-- teachers need every student's name and class code for the dashboard
create policy "profiles: teachers read all" on public.profiles
  for select to authenticated using (public.is_teacher());

-- 4. Make a teacher ------------------------------------------------------------
-- The teacher first creates a normal account in the app (any class code),
-- then run this with their email:
--
--   insert into public.teachers (user_id)
--   select id from auth.users where email = 'teacher@yourschool.org'
--   on conflict do nothing;
--
-- Remove a teacher:
--   delete from public.teachers
--   where user_id = (select id from auth.users where email = 'teacher@yourschool.org');
