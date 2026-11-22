-- Lock the old email/password tables. Run this ONCE, AFTER the new class-login version of the app is live.
--
-- The old app stored students in profiles, quiz_scores and question_attempts, readable with the public key.
-- The new app does not use them. This keeps the data but removes all access from the browser, so
-- student names, class codes and scores stop being readable by anyone with the public key.
-- (Delete the tables yourself later if you do not need the old data.)

do $$ declare t text; p record; begin
  foreach t in array array['profiles', 'quiz_scores', 'question_attempts', 'teachers'] loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I enable row level security', t);
      execute format('revoke all on table public.%I from anon, authenticated', t);
      for p in select policyname from pg_policies where schemaname = 'public' and tablename = t loop
        execute format('drop policy %I on public.%I', p.policyname, t);
      end loop;
    end if;
  end loop;
end $$;

drop function if exists public.is_teacher();

-- Two more things to do by hand in the Supabase dashboard:
--   1. Authentication > Sign In / Providers > turn off "Allow new users to sign up" (nobody needs an email account now).
--   2. Storage > avatars > delete the bucket (old profile photos are public links; students set new ones in the app).
