-- IGCSE PE Workbook: class login setup (class code, then name, then a 4-digit PIN)
--
-- Run this whole file once in Supabase > SQL Editor. It is safe to run again.
--
-- BEFORE THE FIRST RUN: set the teacher PIN in step 6 (search for CHANGE-ME-FIRST).
-- The script stops with an error until you do, so nobody can log in as teacher with a default PIN.
--
-- How it works
--   Teacher: logs in with the shared teacher PIN (12 hour session), creates classes with a class code,
--            and adds the students by name (typed, pasted or imported from Excel/CSV in the app).
--   Student: picks the class, types the class code, picks their name and types a 4-digit PIN.
--            The first login creates the PIN. 5 wrong PINs lock the name for 10 minutes.
--            A forgotten PIN is reset by the teacher (the student can send a request).
--
-- Security model: the browser never reads or writes the tables directly.
-- Row level security is on with no policies, so the public anon key can only call the pe_* functions below.
-- Each function checks a class code, a PIN or a login token. PINs are stored as bcrypt hashes and
-- login tokens as SHA-256 hashes, so a copy of the database cannot be used to log in.
--
-- The older email/password tables (profiles, quiz_scores, question_attempts, teachers) are not touched here.
-- Once the new version of the app is live, run supabase/retire-old-accounts.sql to lock them.

create extension if not exists pgcrypto with schema extensions;

/* ---------- 1. Tables ---------- */

create table if not exists public.pe_settings (
  id int primary key default 1 check (id = 1),
  teacher_pin_hash text not null,
  failed_attempts int not null default 0,
  locked_until timestamptz
);

create table if not exists public.pe_classes (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  code text not null,
  created_at timestamptz not null default now()
);
create unique index if not exists pe_classes_name on public.pe_classes (lower(trim(name)));

create table if not exists public.pe_students (
  id uuid primary key default gen_random_uuid(),
  class_id uuid not null references public.pe_classes(id) on delete cascade,
  name text not null,
  pin_hash text,
  failed_attempts int not null default 0,
  locked_until timestamptz,
  is_teacher boolean not null default false,   -- the TEACHER entry that every class has: opens with the teacher PIN
  avatar text,                                 -- small profile picture as a data URL, set by the student
  created_at timestamptz not null default now()
);
create unique index if not exists pe_students_class_name on public.pe_students (class_id, lower(name));

create table if not exists public.pe_tokens (
  token_hash text primary key,
  role text not null check (role in ('teacher', 'student')),
  student_id uuid references public.pe_students(id) on delete cascade,
  expires_at timestamptz not null
);

-- A student who forgot their PIN sends a request; the teacher accepts (PIN cleared) or declines
create table if not exists public.pe_pin_requests (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.pe_students(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'done', 'declined')),
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create unique index if not exists pe_pin_req_pending on public.pe_pin_requests (student_id) where status = 'pending';

-- One row per AI-marked answer (practice, spaced review or quiz)
create table if not exists public.pe_attempts (
  id bigint generated always as identity primary key,
  student_id uuid not null references public.pe_students(id) on delete cascade,
  chapter_id text not null,
  question_id int not null,
  score int not null check (score >= 0),
  max_score int not null check (max_score > 0 and score <= max_score),
  source text not null default 'practice' check (source in ('practice', 'review', 'quiz')),
  created_at timestamptz not null default now()
);
create index if not exists pe_attempts_student on public.pe_attempts (student_id, created_at);

-- Best quiz score per student, chapter and quiz length (the class leaderboard)
create table if not exists public.pe_scores (
  student_id uuid not null references public.pe_students(id) on delete cascade,
  chapter_filter text not null,
  question_count int not null,
  score int not null check (score >= 0),
  max_score int not null check (max_score > 0),
  pct int not null check (pct between 0 and 100),
  achieved_at timestamptz not null default now(),
  primary key (student_id, chapter_filter, question_count)
);

-- Every class has a TEACHER entry (also for classes that already exist)
insert into public.pe_students (class_id, name, is_teacher)
  select c.id, 'TEACHER', true from public.pe_classes c
   where not exists (select 1 from public.pe_students s where s.class_id = c.id and s.is_teacher)
  on conflict do nothing;

/* ---------- 2. Lock the tables: no direct access from the browser ---------- */

do $$ declare t text; p record; begin
  foreach t in array array['pe_settings','pe_classes','pe_students','pe_tokens','pe_pin_requests','pe_attempts','pe_scores'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on table public.%I from anon, authenticated', t);
    for p in select policyname from pg_policies where schemaname = 'public' and tablename = t loop
      execute format('drop policy %I on public.%I', p.policyname, t);
    end loop;
  end loop;
end $$;

/* ---------- 3. Internal helpers (not callable from the browser) ---------- */

create or replace function public.pe__hash(t text) returns text
language sql immutable set search_path = public, extensions as $$
  select encode(extensions.digest(t, 'sha256'), 'hex')
$$;

create or replace function public.pe__new_token(p_role text, p_student uuid, p_ttl interval) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(extensions.gen_random_bytes(32), 'hex');
begin
  delete from pe_tokens where expires_at < now();
  insert into pe_tokens (token_hash, role, student_id, expires_at) values (pe__hash(t), p_role, p_student, now() + p_ttl);
  return t;
end $$;

create or replace function public.pe__teacher(p_token text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from pe_tokens k where k.token_hash = pe__hash(coalesce(p_token, ''))
                 and k.role = 'teacher' and k.expires_at > now()) then
    raise exception 'Your teacher session has expired. Please log in again.';
  end if;
end $$;

create or replace function public.pe__student(p_token text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid;
begin
  select k.student_id into sid from pe_tokens k
   where k.token_hash = pe__hash(coalesce(p_token, '')) and k.role = 'student' and k.expires_at > now();
  if sid is null then raise exception 'Your session has expired. Please log in again.'; end if;
  return sid;
end $$;

-- Checks the shared teacher PIN. Returns an error message, or null when the PIN is right.
-- 10 wrong attempts in a row lock the teacher PIN for 15 minutes (counted for every way of logging in as teacher).
create or replace function public.pe__teacher_pin_check(p_pin text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare st pe_settings;
begin
  select * into st from pe_settings where id = 1 for update;
  if not found then return 'The teacher PIN is not set up yet. Run supabase/setup.sql again.'; end if;
  if st.locked_until > now() then return 'Too many wrong attempts. Try again in 15 minutes.'; end if;
  if st.teacher_pin_hash <> crypt(coalesce(p_pin, ''), st.teacher_pin_hash) then
    update pe_settings
       set failed_attempts = case when failed_attempts >= 9 then 0 else failed_attempts + 1 end,
           locked_until    = case when failed_attempts >= 9 then now() + interval '15 minutes' end
     where id = 1;
    return 'Wrong teacher PIN.';
  end if;
  update pe_settings set failed_attempts = 0, locked_until = null where id = 1;
  return null;
end $$;

/* ---------- 4. Student functions ---------- */

create or replace function public.pe_list_classes()
returns table (id uuid, name text)
language sql stable security definer set search_path = public as $$
  select c.id, c.name from pe_classes c order by c.name
$$;

create or replace function public.pe_list_students(p_class_id uuid, p_code text)
returns table (id uuid, name text, has_pin boolean, is_teacher boolean)
language plpgsql stable security definer set search_path = public as $$
begin
  if not exists (select 1 from pe_classes c where c.id = p_class_id
                 and lower(trim(c.code)) = lower(trim(coalesce(p_code, '')))) then
    raise exception 'That class code is not right. Check with your teacher.';
  end if;
  return query select s.id, s.name, (s.pin_hash is not null or s.is_teacher), s.is_teacher from pe_students s
                where s.class_id = p_class_id order by s.is_teacher, s.name;
end $$;

-- The first login of a student creates their PIN. The TEACHER entry opens with the teacher PIN and
-- gives a teacher session (12 hours) instead of a student session (30 days).
create or replace function public.pe_student_login(p_student_id uuid, p_code text, p_pin text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare s pe_students; c pe_classes; err text;
begin
  select * into s from pe_students where id = p_student_id;
  if not found then return jsonb_build_object('error', 'Name not found. Ask your teacher.'); end if;
  select * into c from pe_classes where id = s.class_id;
  if lower(trim(c.code)) <> lower(trim(coalesce(p_code, ''))) then
    return jsonb_build_object('error', 'That class code is not right. Check with your teacher.');
  end if;
  if s.is_teacher then
    err := pe__teacher_pin_check(p_pin);
    if err is not null then return jsonb_build_object('error', err); end if;
    return jsonb_build_object('role', 'teacher', 'token', pe__new_token('teacher', null, interval '12 hours'));
  end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then
    return jsonb_build_object('error', 'Your PIN must be 4 digits.');
  end if;
  if s.locked_until > now() then
    return jsonb_build_object('error', 'Too many wrong PINs. Wait 10 minutes or ask your teacher to reset it.');
  end if;
  if s.pin_hash is null then
    update pe_students set pin_hash = crypt(p_pin, gen_salt('bf')), failed_attempts = 0, locked_until = null where id = s.id;
  elsif s.pin_hash <> crypt(p_pin, s.pin_hash) then
    update pe_students
       set failed_attempts = case when failed_attempts >= 4 then 0 else failed_attempts + 1 end,
           locked_until    = case when failed_attempts >= 4 then now() + interval '10 minutes' end
     where id = s.id;
    return jsonb_build_object('error', case when s.failed_attempts >= 4
      then 'Too many wrong PINs. Wait 10 minutes or ask your teacher to reset it.'
      else 'Wrong PIN. Ask your teacher to reset it if you forgot.' end);
  else
    update pe_students set failed_attempts = 0, locked_until = null where id = s.id;
  end if;
  return jsonb_build_object('role', 'student', 'token', pe__new_token('student', s.id, interval '30 days'),
    'student', jsonb_build_object('id', s.id, 'name', s.name, 'avatar', s.avatar),
    'cls', jsonb_build_object('id', c.id, 'name', c.name));
end $$;

-- Who is logged in: used to check a saved session when the page opens
create or replace function public.pe_me(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare k pe_tokens; s pe_students; c pe_classes;
begin
  select * into k from pe_tokens where token_hash = pe__hash(coalesce(p_token, '')) and expires_at > now();
  if not found then raise exception 'Your session has expired. Please log in again.'; end if;
  if k.role = 'teacher' then return jsonb_build_object('role', 'teacher'); end if;
  select * into s from pe_students where id = k.student_id;
  select * into c from pe_classes where id = s.class_id;
  return jsonb_build_object('role', 'student',
    'student', jsonb_build_object('id', s.id, 'name', s.name, 'avatar', s.avatar),
    'cls', jsonb_build_object('id', c.id, 'name', c.name));
end $$;

create or replace function public.pe_logout(p_token text) returns void
language sql security definer set search_path = public, extensions as $$
  delete from pe_tokens where token_hash = pe__hash(coalesce(p_token, ''))
$$;

create or replace function public.pe_request_pin_reset(p_student_id uuid, p_code text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare s pe_students; c pe_classes;
begin
  select * into s from pe_students where id = p_student_id;
  if not found or s.is_teacher then return jsonb_build_object('error', 'Name not found. Ask your teacher.'); end if;
  select * into c from pe_classes where id = s.class_id;
  if lower(trim(c.code)) <> lower(trim(coalesce(p_code, ''))) then
    return jsonb_build_object('error', 'That class code is not right. Check with your teacher.');
  end if;
  if s.pin_hash is null then return jsonb_build_object('status', 'nopin'); end if;
  if exists (select 1 from pe_pin_requests where student_id = s.id and status = 'pending') then
    return jsonb_build_object('status', 'pending');
  end if;
  insert into pe_pin_requests (student_id) values (s.id);
  return jsonb_build_object('status', 'sent');
end $$;

create or replace function public.pe_set_avatar(p_token text, p_data text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := pe__student(p_token);
begin
  if p_data is null or length(p_data) > 60000 or p_data !~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$' then
    raise exception 'That picture is not valid. Choose a smaller photo.';
  end if;
  update pe_students set avatar = p_data where id = sid;
end $$;

-- Save marked answers: [{"c":"ch1","q":3,"s":2,"m":4,"src":"quiz"}, ...]
create or replace function public.pe_record(p_token text, p_rows jsonb) returns int
language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := pe__student(p_token); n int;
begin
  if jsonb_typeof(p_rows) is distinct from 'array' or jsonb_array_length(p_rows) > 100 then
    raise exception 'Too many answers at once.';
  end if;
  with r as (
    select e ->> 'c' as c, (e ->> 'q')::int as q, (e ->> 's')::int as s, (e ->> 'm')::int as m,
           case when e ->> 'src' in ('practice', 'review', 'quiz') then e ->> 'src' else 'practice' end as src
      from jsonb_array_elements(p_rows) e),
  ins as (
    insert into pe_attempts (student_id, chapter_id, question_id, score, max_score, source)
    select sid, r.c, r.q, r.s, r.m, r.src from r
     where r.c ~ '^ch[0-9]{1,2}$' and r.q between 1 and 999 and r.m between 1 and 20 and r.s between 0 and r.m
    returning 1)
  select count(*) into n from ins;
  return n;
end $$;

-- The student's latest result for every question: [{"c":"ch1","q":3,"sc":2,"m":4,"t":1700000000000}, ...]
create or replace function public.pe_my_attempts(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := pe__student(p_token);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('c', a.chapter_id, 'q', a.question_id, 'sc', a.score, 'm', a.max_score,
                     't', (extract(epoch from a.created_at) * 1000)::bigint))
    from (select distinct on (chapter_id, question_id) * from pe_attempts where student_id = sid
           order by chapter_id, question_id, created_at desc, id desc) a), '[]'::jsonb);
end $$;

-- Keep only the best score for this chapter and quiz length
create or replace function public.pe_submit_score(p_token text, p_chapter_filter text, p_question_count int, p_score int, p_max int)
returns void
language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := pe__student(p_token);
begin
  if p_chapter_filter !~ '^(all|ch[0-9]{1,2})$' or p_question_count not between 1 and 50
     or p_max not between 1 and 400 or p_score not between 0 and p_max then
    raise exception 'That score is not valid.';
  end if;
  insert into pe_scores (student_id, chapter_filter, question_count, score, max_score, pct)
  values (sid, p_chapter_filter, p_question_count, p_score, p_max, round(p_score * 100.0 / p_max)::int)
  on conflict (student_id, chapter_filter, question_count) do update
    set score = excluded.score, max_score = excluded.max_score, pct = excluded.pct, achieved_at = now()
    where excluded.pct > pe_scores.pct;
end $$;

-- The leaderboard of the student's own class
create or replace function public.pe_leaderboard(p_token text, p_chapter_filter text, p_question_count int)
returns table (name text, avatar text, pct int, achieved_at timestamptz)
language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := pe__student(p_token);
begin
  return query
    select s.name, s.avatar, sc.pct, sc.achieved_at
      from pe_scores sc join pe_students s on s.id = sc.student_id
     where s.class_id = (select x.class_id from pe_students x where x.id = sid)
       and sc.chapter_filter = p_chapter_filter and sc.question_count = p_question_count
     order by sc.pct desc, sc.achieved_at limit 50;
end $$;

/* ---------- 5. Teacher functions (all need a teacher login token) ---------- */

create or replace function public.pe_teacher_login(p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare err text := pe__teacher_pin_check(p_pin);
begin
  if err is not null then return jsonb_build_object('error', err); end if;
  return jsonb_build_object('role', 'teacher', 'token', pe__new_token('teacher', null, interval '12 hours'));
end $$;

create or replace function public.pe_t_change_pin(p_token text, p_old text, p_new text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  perform pe__teacher(p_token);
  err := pe__teacher_pin_check(p_old);
  if err is not null then return jsonb_build_object('error', err); end if;
  if length(coalesce(p_new, '')) < 4 then
    return jsonb_build_object('error', 'The new PIN must be at least 4 characters.');
  end if;
  update pe_settings set teacher_pin_hash = crypt(p_new, gen_salt('bf')) where id = 1;
  delete from pe_tokens where role = 'teacher' and token_hash <> pe__hash(p_token);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.pe_t_classes(p_token text)
returns table (id uuid, name text, code text, students bigint, answers bigint)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  return query
    select c.id, c.name, c.code,
           (select count(*) from pe_students s where s.class_id = c.id and not s.is_teacher),
           (select count(*) from pe_attempts a join pe_students s on s.id = a.student_id where s.class_id = c.id)
      from pe_classes c order by c.name;
end $$;

create or replace function public.pe_t_add_class(p_token text, p_name text, p_code text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare new_id uuid;
begin
  perform pe__teacher(p_token);
  if length(trim(coalesce(p_name, ''))) = 0 or length(trim(coalesce(p_code, ''))) < 3 then
    raise exception 'Enter a class name and a class code of at least 3 characters.';
  end if;
  begin
    insert into pe_classes (name, code) values (left(trim(p_name), 60), trim(p_code)) returning pe_classes.id into new_id;
  exception when unique_violation then
    raise exception 'A class with that name already exists.';
  end;
  insert into pe_students (class_id, name, is_teacher) values (new_id, 'TEACHER', true) on conflict do nothing;
  return new_id;
end $$;

create or replace function public.pe_t_update_class(p_token text, p_id uuid, p_name text, p_code text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  if length(trim(coalesce(p_name, ''))) = 0 then raise exception 'The class needs a name.'; end if;
  if length(trim(coalesce(p_code, ''))) < 3 then raise exception 'The class code needs at least 3 characters.'; end if;
  begin
    update pe_classes set name = left(trim(p_name), 60), code = trim(p_code) where id = p_id;
  exception when unique_violation then
    raise exception 'A class with that name already exists.';
  end;
end $$;

create or replace function public.pe_t_delete_class(p_token text, p_id uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  delete from pe_classes where id = p_id;
end $$;

create or replace function public.pe_t_students(p_token text, p_class_id uuid)
returns table (id uuid, name text, has_pin boolean)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  return query select s.id, s.name, s.pin_hash is not null from pe_students s
                where s.class_id = p_class_id and not s.is_teacher order by s.name;
end $$;

-- Add students by name. Names already in the class are skipped, so adding the same list twice is safe.
create or replace function public.pe_t_add_students(p_token text, p_class_id uuid, p_names text[]) returns int
language plpgsql security definer set search_path = public, extensions as $$
declare n int;
begin
  perform pe__teacher(p_token);
  with src as (
    select distinct on (lower(regexp_replace(trim(u.nm), '\s+', ' ', 'g')))
           left(regexp_replace(trim(u.nm), '\s+', ' ', 'g'), 80) as nm
      from unnest(p_names) as u(nm) where trim(coalesce(u.nm, '')) <> ''),
  ins as (
    insert into pe_students (class_id, name) select p_class_id, src.nm from src
    on conflict do nothing returning 1)
  select count(*) into n from ins;
  return n;
end $$;

-- Every student of every class, so an import can find students who are already in another class
create or replace function public.pe_t_all_students(p_token text)
returns table (id uuid, name text, class_id uuid)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  return query select s.id, s.name, s.class_id from pe_students s where not s.is_teacher order by s.id;
end $$;

-- Move students to another class. Their PIN and results go with them.
-- A student whose name is already in the target class stays where they are.
create or replace function public.pe_t_move_students(p_token text, p_to uuid, p_ids uuid[]) returns int
language plpgsql security definer set search_path = public, extensions as $$
declare n int;
begin
  perform pe__teacher(p_token);
  if not exists (select 1 from pe_classes where id = p_to) then raise exception 'Class not found.'; end if;
  with mv as (
    update pe_students s set class_id = p_to
     where s.id = any(coalesce(p_ids, '{}')) and not s.is_teacher and s.class_id <> p_to
       and not exists (select 1 from pe_students t where t.class_id = p_to and lower(t.name) = lower(s.name))
    returning s.id)
  select count(*) into n from mv;
  return n;
end $$;

-- Clear the PIN of several students: each creates a new PIN at their next login. Results are kept.
create or replace function public.pe_t_reset_pins(p_token text, p_ids uuid[]) returns int
language plpgsql security definer set search_path = public, extensions as $$
declare n int;
begin
  perform pe__teacher(p_token);
  with u as (update pe_students set pin_hash = null, failed_attempts = 0, locked_until = null
              where id = any(coalesce(p_ids, '{}')) and not is_teacher returning id)
    select count(*) into n from u;
  delete from pe_tokens where student_id = any(coalesce(p_ids, '{}'));
  update pe_pin_requests set status = 'done', resolved_at = now() where student_id = any(coalesce(p_ids, '{}')) and status = 'pending';
  return n;
end $$;

create or replace function public.pe_t_remove_student(p_token text, p_student_id uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  delete from pe_students where id = p_student_id and not is_teacher;
end $$;

create or replace function public.pe_t_pin_requests(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  return coalesce((select jsonb_agg(jsonb_build_object('id', r.id, 'student_id', s.id, 'name', s.name, 'class_name', k.name,
                                                       'created_at', r.created_at) order by r.created_at)
    from pe_pin_requests r join pe_students s on s.id = r.student_id join pe_classes k on k.id = s.class_id
   where r.status = 'pending'), '[]'::jsonb);
end $$;

create or replace function public.pe_t_pin_resolve(p_token text, p_id uuid, p_accept boolean) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare r pe_pin_requests;
begin
  perform pe__teacher(p_token);
  select * into r from pe_pin_requests where id = p_id and status = 'pending';
  if not found then return; end if;
  if p_accept then
    update pe_students set pin_hash = null, failed_attempts = 0, locked_until = null where id = r.student_id;
    delete from pe_tokens where student_id = r.student_id;
  end if;
  update pe_pin_requests set status = case when p_accept then 'done' else 'declined' end, resolved_at = now() where id = r.id;
end $$;

-- Everything the class dashboard needs: the students, and the latest result for each question they answered
create or replace function public.pe_t_class_data(p_token text, p_class_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform pe__teacher(p_token);
  return jsonb_build_object(
    'students', coalesce((
      select jsonb_agg(jsonb_build_object('id', s.id, 'name', s.name, 'has_pin', s.pin_hash is not null,
               'attempts', coalesce(a.n, 0), 'last_at', (extract(epoch from a.last_at) * 1000)::bigint) order by s.name)
        from pe_students s
        left join (select student_id, count(*) n, max(created_at) last_at from pe_attempts group by student_id) a on a.student_id = s.id
       where s.class_id = p_class_id and not s.is_teacher), '[]'::jsonb),
    'results', coalesce((
      select jsonb_agg(jsonb_build_object('s', r.student_id, 'c', r.chapter_id, 'q', r.question_id, 'sc', r.score, 'm', r.max_score,
               't', (extract(epoch from r.created_at) * 1000)::bigint))
        from (select distinct on (student_id, chapter_id, question_id) * from pe_attempts
               where student_id in (select id from pe_students where class_id = p_class_id)
               order by student_id, chapter_id, question_id, created_at desc, id desc) r), '[]'::jsonb));
end $$;

/* ---------- 6. The teacher PIN ---------- */
-- Put your own teacher PIN (at least 4 characters) on the next line. It is stored as a bcrypt hash.
-- Change it later from the app: Class tab > Classes and students > Teacher PIN.

do $$
declare v_pin text := 'CHANGE-ME-FIRST';   -- <<< EDIT THIS, then run the file
begin
  if not exists (select 1 from public.pe_settings) then
    if v_pin = 'CHANGE-ME-FIRST' or length(v_pin) < 4 then
      raise exception 'Set your teacher PIN first: edit CHANGE-ME-FIRST near the end of this file (at least 4 characters), then run it again.';
    end if;
    insert into public.pe_settings (id, teacher_pin_hash) values (1, extensions.crypt(v_pin, extensions.gen_salt('bf')));
  end if;
end $$;

/* ---------- 7. Permissions: helpers are private, pe_* functions are public ---------- */

do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig, p.proname from pg_proc p
           join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.proname like 'pe\_%' loop
    if f.proname like 'pe\_\_%' then
      execute format('revoke all on function %s from public, anon, authenticated', f.sig);
    else
      execute format('grant execute on function %s to anon, authenticated', f.sig);
    end if;
  end loop;
end $$;

-- Make the Supabase API see the new functions straight away.
notify pgrst, 'reload schema';
