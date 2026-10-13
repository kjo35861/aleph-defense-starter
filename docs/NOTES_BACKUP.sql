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
