begin;

create extension if not exists pgcrypto;

alter table public.learning_notes
  add column if not exists owner_id uuid;

do $$
declare
  current_type text;
begin
  select data_type into current_type
  from information_schema.columns
  where table_schema = 'public'
    and table_name = 'learning_notes'
    and column_name = 'id';

  if current_type is distinct from 'uuid' then
    alter table public.learning_notes
      add column if not exists note_uuid uuid default gen_random_uuid();

    update public.learning_notes
      set note_uuid = gen_random_uuid()
      where note_uuid is null;

    alter table public.learning_notes
      alter column note_uuid set not null;

    alter table public.learning_notes
      drop constraint if exists learning_notes_pkey;

    alter table public.learning_notes
      drop column if exists id;

    alter table public.learning_notes
      rename column note_uuid to id;

    alter table public.learning_notes
      add primary key (id);
  end if;
end
$$;

alter table public.learning_notes
  alter column id set default gen_random_uuid();

alter table public.learning_notes enable row level security;
revoke all on table public.learning_notes from anon, authenticated;

commit;
