-- IGCSE PE Workbook — complete database setup for a NEW Supabase project
--
-- Run once: Supabase dashboard → SQL Editor → New query → paste this whole file → Run.
-- Safe to run again: it only creates what is missing and refreshes the access rules.
--
-- Creates: student profiles, quiz leaderboard, per-question results (syllabus
-- checklist + teacher dashboard), the teacher list, and the profile-photo bucket.
-- After running it, make yourself a teacher (step 6 at the bottom).

-- 1. Student profiles ----------------------------------------------------------
-- One row per account, created by the app straight after sign-up.
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null check (char_length(name) between 1 and 80),
  class_code  text not null check (char_length(class_code) between 1 and 40),
  avatar_url  text,
  created_at  timestamptz not null default now()
);
alter table public.profiles enable row level security;

-- 2. Quiz leaderboard: best score per student, chapter and quiz length --------
create table if not exists public.quiz_scores (
  user_id         uuid not null references public.profiles(id) on delete cascade,
  chapter_filter  text not null,
  question_count  int  not null,
  score           int  not null check (score >= 0),
  max_score       int  not null check (max_score > 0),
  pct             int  not null check (pct between 0 and 100),
  achieved_at     timestamptz not null default now(),
  primary key (user_id, chapter_filter, question_count)
);
alter table public.quiz_scores enable row level security;

-- 3. One row per AI-marked answer (practice, spaced review or quiz) -----------
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

-- 4. Teachers — rows are added by hand here, never from the app ---------------
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

-- 5. Access rules (row level security) ------------------------------------------
-- Profiles: signed-in users can read names and class codes (needed for the
-- leaderboard); each student can only create and edit their own row.
drop policy if exists "profiles: signed-in read"      on public.profiles;
drop policy if exists "profiles: insert own"          on public.profiles;
drop policy if exists "profiles: update own"          on public.profiles;
drop policy if exists "profiles: teachers read all"   on public.profiles;
create policy "profiles: signed-in read" on public.profiles
  for select to authenticated using (true);
create policy "profiles: insert own" on public.profiles
  for insert to authenticated with check (id = auth.uid());
create policy "profiles: update own" on public.profiles
  for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- Leaderboard: everyone signed in can read it; students write only their own rows.
drop policy if exists "quiz_scores: signed-in read"   on public.quiz_scores;
drop policy if exists "quiz_scores: insert own"       on public.quiz_scores;
drop policy if exists "quiz_scores: update own"       on public.quiz_scores;
create policy "quiz_scores: signed-in read" on public.quiz_scores
  for select to authenticated using (true);
create policy "quiz_scores: insert own" on public.quiz_scores
  for insert to authenticated with check (user_id = auth.uid());
create policy "quiz_scores: update own" on public.quiz_scores
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Answers: students add and read only their own; teachers read everyone's.
drop policy if exists "attempts: insert own"          on public.question_attempts;
drop policy if exists "attempts: read own"            on public.question_attempts;
drop policy if exists "attempts: teachers read all"   on public.question_attempts;
create policy "attempts: insert own" on public.question_attempts
  for insert to authenticated with check (user_id = auth.uid());
create policy "attempts: read own" on public.question_attempts
  for select to authenticated using (user_id = auth.uid());
create policy "attempts: teachers read all" on public.question_attempts
  for select to authenticated using (public.is_teacher());

-- Teachers: the app can check "am I a teacher?"; nobody can add themselves.
drop policy if exists "teachers: read own row"        on public.teachers;
create policy "teachers: read own row" on public.teachers
  for select to authenticated using (user_id = auth.uid());

-- Profile photos: public bucket; each student can only write inside their own
-- folder (<user id>/avatar.jpg). Images only, 5 MB max.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 5242880, array['image/jpeg', 'image/png', 'image/webp', 'image/gif'])
on conflict (id) do update
  set public = true, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "avatars: read own"    on storage.objects;
drop policy if exists "avatars: upload own"  on storage.objects;
drop policy if exists "avatars: replace own" on storage.objects;
create policy "avatars: read own" on storage.objects
  for select to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatars: upload own" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatars: replace own" on storage.objects
  for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- 6. Make a teacher ------------------------------------------------------------
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
