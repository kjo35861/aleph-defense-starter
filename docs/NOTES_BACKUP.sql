-- 10단계: 비공개 가상 메모 사본 테이블.
-- Supabase SQL Editor에서 침해 시험 전에 실행합니다.
-- 실제 비밀번호·토큰·사용자 이메일을 이 파일에 넣지 않습니다.
-- 복원 API: POST /api/notes/restore
-- content_sha256 = SHA-256(title UTF-8 || 0x00 || content UTF-8)

create extension if not exists pgcrypto;

begin;

create table if not exists public.learning_notes_backup (
  id uuid primary key,
  owner_id uuid not null,
  title text not null check (char_length(title) between 1 and 5000),
  content text not null check (char_length(content) <= 5000),
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at timestamptz not null default now()
);

alter table public.learning_notes_backup enable row level security;
revoke all on table public.learning_notes_backup from public, anon, authenticated;

commit;

-- 침해 시험 전 사본 생성. 이미 보관한 ID는 덮어쓰지 않습니다.
insert into public.learning_notes_backup (id, owner_id, title, content, content_sha256)
select
  id,
  owner_id,
  title,
  content,
  encode(
    digest(
      convert_to(title, 'UTF8') || decode('00', 'hex') || convert_to(content, 'UTF8'),
      'sha256'
    ),
    'hex'
  )
from public.learning_notes
where owner_id is not null
on conflict (id) do nothing;

-- 읽기 전용 검증: hash_mismatch는 0이어야 합니다.
select
  count(*) as backups,
  count(*) filter (
    where content_sha256 <> encode(
      digest(
        convert_to(title, 'UTF8') || decode('00', 'hex') || convert_to(content, 'UTF8'),
        'sha256'
      ),
      'hex'
    )
  ) as hash_mismatch
from public.learning_notes_backup;

-- 비공개 여부 확인: anon/authenticated의 모든 결과가 false, rls_on은 true여야 합니다.
select
  role_name,
  privilege,
  has_table_privilege(role_name, 'public.learning_notes_backup', privilege) as allowed
from (values ('anon'), ('authenticated')) as roles(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) as privileges(privilege)
order by role_name, privilege;

select relrowsecurity as rls_on
from pg_class
where oid = 'public.learning_notes_backup'::regclass;


-- 복원 함수: service_role만 실행합니다.
-- 같은 트랜잭션에서 사본과 현재 행을 잠그고, 사본을 다시 읽어 해시를 검증한 뒤 지정한 한 건만 복원합니다.
create or replace function public.restore_verified_learning_note(
  p_note_id uuid,
  p_actor_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  b public.learning_notes_backup%rowtype;
  n public.learning_notes%rowtype;
  restored public.learning_notes%rowtype;
  calculated_hash text;
begin
  if p_note_id is null or p_actor_id is null then
    raise exception 'restore_rejected';
  end if;

  -- 실제 복원 직전 비공개 사본을 다시 읽고 잠급니다.
  select *
    into b
    from public.learning_notes_backup
   where id = p_note_id
     and owner_id = p_actor_id
   for update;

  if not found then
    raise exception 'backup_unverified';
  end if;

  calculated_hash := encode(
    extensions.digest(
      convert_to(b.title, 'UTF8') || decode('00', 'hex') || convert_to(b.content, 'UTF8'),
      'sha256'
    ),
    'hex'
  );

  if b.id is distinct from p_note_id
     or b.owner_id is distinct from p_actor_id
     or b.content_sha256 is null
     or b.content_sha256 !~ '^[0-9a-f]{64}$'
     or calculated_hash is distinct from b.content_sha256 then
    raise exception 'backup_unverified';
  end if;

  -- 현재 대상 한 건만 잠급니다. 다른 소유자의 같은 ID는 복원하지 않습니다.
  select *
    into n
    from public.learning_notes
   where id = p_note_id
   for update;

  if found and n.owner_id is distinct from p_actor_id then
    raise exception 'restore_rejected';
  end if;

  if found then
    update public.learning_notes
       set title = b.title,
           content = b.content
     where id = p_note_id
       and owner_id = p_actor_id;
  else
    insert into public.learning_notes (id, owner_id, title, content)
    values (b.id, b.owner_id, b.title, b.content);
  end if;

  -- 같은 트랜잭션에서 복원된 한 건을 다시 읽어 ID·소유자·내용 해시를 재검증합니다.
  select *
    into restored
    from public.learning_notes
   where id = p_note_id
     and owner_id = p_actor_id;

  if not found
     or restored.id is distinct from b.id
     or restored.owner_id is distinct from b.owner_id
     or encode(
       extensions.digest(
         convert_to(restored.title, 'UTF8') || decode('00', 'hex') || convert_to(restored.content, 'UTF8'),
         'sha256'
       ),
       'hex'
     ) is distinct from b.content_sha256 then
    raise exception 'restore_mismatch';
  end if;

  return jsonb_build_object(
    'id', restored.id,
    'restored', true,
    'verified', true,
    'contentSha256', b.content_sha256
  );
end
$$;

revoke all on function public.restore_verified_learning_note(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.restore_verified_learning_note(uuid, uuid)
  to service_role;
