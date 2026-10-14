-- 11단계 기기 승인용 서버 레코드
-- 브라우저에는 기기 개인키를 저장하지 않습니다.
-- 서버가 발급한 비밀이 아닌 기기 ID와 사용자 소유권만 저장합니다.

create table if not exists public.learning_devices (
  id uuid primary key,
  owner_id uuid not null,
  approved_at timestamptz not null default now(),
  revoked_at timestamptz
);

create index if not exists learning_devices_owner_active_idx
  on public.learning_devices(owner_id)
  where revoked_at is null;

alter table public.learning_devices enable row level security;
revoke all on table public.learning_devices from public, anon, authenticated;

-- 서버 전용 키를 사용하는 API만 이 테이블을 읽고 씁니다.
