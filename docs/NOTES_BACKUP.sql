-- 10단계: 비공개 가상 메모 사본과 독립 검증 기준.
-- Supabase SQL Editor에서 침해 시험 전에 준비합니다.
-- 실제 비밀번호·토큰·사용자 이메일은 넣지 않습니다.
-- 복원 API: POST /api/notes/restore
-- 내용 지문: SHA-256(title UTF-8 || 0x00 || content UTF-8)

create extension if not exists pgcrypto;

-- 1. 비공개 메모 사본
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

-- 소유자가 확인된 메모만 사본으로 보관합니다.
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

-- 2. 사본과 분리된 검증 기준
create table if not exists public.learning_notes_backup_verification (
  id uuid primary key,
  owner_id uuid not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at timestamptz not null,
  verified_at timestamptz not null default now(),
  manifest_sha256 text not null check (manifest_sha256 ~ '^[0-9a-f]{64}$')
);

-- 이전 실습에서 세 칼럼짜리 검증 테이블을 만든 경우 안전하게 확장합니다.
alter table public.learning_notes_backup_verification
  add column if not exists backed_up_at timestamptz,
  add column if not exists verified_at timestamptz default now(),
  add column if not exists manifest_sha256 text;

update public.learning_notes_backup_verification v
set
  backed_up_at = b.backed_up_at,
  manifest_sha256 = encode(
    digest(
      convert_to(
        b.id::text || '|' || b.owner_id::text || '|' || b.content_sha256 || '|'
        || to_char(b.backed_up_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US'),
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
from public.learning_notes_backup b
where v.id = b.id
  and (v.backed_up_at is null or v.manifest_sha256 is null);

alter table public.learning_notes_backup_verification
  alter column backed_up_at set not null,
  alter column verified_at set not null,
  alter column manifest_sha256 set not null;

alter table public.learning_notes_backup_verification enable row level security;
revoke all on table public.learning_notes_backup_verification from public, anon, authenticated;

-- 아직 검증 기준이 없는 사본만 한 번 봉인합니다. 기존 검증 기준은 덮어쓰지 않습니다.
insert into public.learning_notes_backup_verification (
  id, owner_id, content_sha256, backed_up_at, manifest_sha256
)
select
  b.id,
  b.owner_id,
  b.content_sha256,
  b.backed_up_at,
  encode(
    digest(
      convert_to(
        b.id::text || '|' || b.owner_id::text || '|' || b.content_sha256 || '|'
        || to_char(b.backed_up_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US'),
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
from public.learning_notes_backup b
on conflict (id) do nothing;

-- 3. 읽기 전용 확인
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

select
  count(*) as verification_rows,
  count(*) filter (
    where v.owner_id is distinct from b.owner_id
       or v.content_sha256 is distinct from b.content_sha256
       or v.backed_up_at is distinct from b.backed_up_at
       or v.verified_at < v.backed_up_at
       or v.manifest_sha256 is distinct from encode(
         digest(
           convert_to(
             b.id::text || '|' || b.owner_id::text || '|' || b.content_sha256 || '|'
             || to_char(b.backed_up_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US'),
             'UTF8'
           ),
           'sha256'
         ),
         'hex'
       )
  ) as verification_mismatch
from public.learning_notes_backup_verification v
join public.learning_notes_backup b using (id);

-- 4. 검증된 한 건 복원
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
  v public.learning_notes_backup_verification%rowtype;
  n public.learning_notes%rowtype;
  restored public.learning_notes%rowtype;
  calculated_content_hash text;
  calculated_manifest_hash text;
begin
  if p_note_id is null or p_actor_id is null then
    raise exception 'restore_rejected';
  end if;

  -- 실제 복원 직전에 사본과 독립 검증 기준을 다시 읽고 잠급니다.
  select *
    into b
    from public.learning_notes_backup
   where id = p_note_id
     and owner_id = p_actor_id
   for update;

  select *
    into v
    from public.learning_notes_backup_verification
   where id = p_note_id
     and owner_id = p_actor_id
   for update;

  if b.id is null or v.id is null then
    raise exception 'backup_unverified';
  end if;

  calculated_content_hash := encode(
    digest(
      convert_to(b.title, 'UTF8') || decode('00', 'hex') || convert_to(b.content, 'UTF8'),
      'sha256'
    ),
    'hex'
  );

  calculated_manifest_hash := encode(
    digest(
      convert_to(
        b.id::text || '|' || b.owner_id::text || '|' || b.content_sha256 || '|'
        || to_char(b.backed_up_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US'),
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  );

  -- 사본 자체 검증 + 침해 전에 별도로 봉인한 기준과 재대조.
  if b.id is distinct from p_note_id
     or b.owner_id is distinct from p_actor_id
     or calculated_content_hash is distinct from b.content_sha256
     or v.id is distinct from b.id
     or v.owner_id is distinct from b.owner_id
     or v.content_sha256 is distinct from b.content_sha256
     or v.backed_up_at is distinct from b.backed_up_at
     or v.verified_at < v.backed_up_at
     or v.verified_at >= statement_timestamp()
     or v.manifest_sha256 is distinct from calculated_manifest_hash then
    raise exception 'backup_unverified';
  end if;

  -- 현재 대상 한 건만 잠급니다. 다른 소유자의 같은 ID는 건드리지 않습니다.
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

  -- 같은 트랜잭션에서 복원 결과를 다시 읽어 검증합니다.
  select *
    into restored
    from public.learning_notes
   where id = p_note_id
     and owner_id = p_actor_id;

  if not found
     or restored.id is distinct from b.id
     or restored.owner_id is distinct from b.owner_id
     or encode(
       digest(
         convert_to(restored.title, 'UTF8') || decode('00', 'hex') || convert_to(restored.content, 'UTF8'),
         'sha256'
       ),
       'hex'
     ) is distinct from v.content_sha256 then
    raise exception 'restore_mismatch';
  end if;

  return jsonb_build_object(
    'id', restored.id,
    'restored', true,
    'verified', true,
    'contentSha256', v.content_sha256
  );
end
$$;

revoke all on function public.restore_verified_learning_note(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.restore_verified_learning_note(uuid, uuid)
  to service_role;
