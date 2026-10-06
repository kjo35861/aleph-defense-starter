# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계 시작 상태에서는 `/`에서 점령된 가상 자료실을 보고 `/data.json`에서 같은 가상 메모가 공개되는 것을 확인합니다. 현재 저장소는 2단계 작업으로 정적 `/data.json`의 메모를 비웠습니다.

## 2단계 현재 상태 — 자료를 코드 밖으로 이동

가상 메모 네 건은 학습용 Supabase의 `learning_notes` 테이블에 두고, 화면은 Vercel 서버 함수 `/api/notes`를 통해 읽습니다. 서버 함수는 Vercel 환경변수 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 읽으며, 실제 키 값을 브라우저 파일·응답·로그에 넣지 않습니다.

정적 `/data.json`에는 메모가 없습니다. **2단계 당시에는 `/api/notes` 주소가 공개 상태**여서 로그인하지 않은 방문자도 가상 메모를 읽을 수 있었고, 이 약점은 3단계에서 로그인 토큰 검증으로 막았습니다.

Supabase 초기 학습 테이블과 가상 메모 네 건은 **1회 실행용 SQL 파일**로 SQL Editor에서 적용합니다. 이 파일에는 가상 메모 본문이 있으므로 GitHub에는 커밋하지 않고, `.gitignore`의 `supabase/step2_learning_notes_once.sql` 경로로만 보관합니다. `owner_id uuid` 컬럼은 준비하되 `auth.users` 외래키는 걸지 않고, RLS를 켠 뒤 `anon`·`authenticated`에는 테이블 권한을 주지 않습니다. 실제 비밀키는 저장소에 넣지 않습니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 단계별 실제 공격 점검에 맞춰 갱신해야 합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 2단계 노출 확인 절차

가상 메모가 정적 공개 파일에서 빠졌는지는 **현재 배포 파일**과 **GitHub 최신 커밋의 파일**을 따로 확인합니다. 과거에 공개된 커밋이나 예전 Vercel 배포 URL이 남아 있으면 그 시점의 노출까지 사라졌다고 기록하지 않습니다.

### 현재 배포 파일 확인

1. 현재 Vercel 주소의 `/`, `/data.json`, `/aleph.json`을 비로그인 창에서 엽니다.
2. 개발자 도구 Network에서 `document`, `js`, `json` 응답을 확인하고, 가상 메모 본문 문구가 정적 응답에 포함되는지 검색합니다.
3. `/data.json`은 `notes: []`여야 합니다.
4. 화면이 네 카드를 표시하더라도 카드 내용은 `/api/notes` 응답에서 온 것이어야 하며 정적 파일에 박혀 있으면 실패로 기록합니다.
5. 결과에는 확인한 배포 URL, 확인 시각, 정적 파일 검색 결과를 적고, 실행하지 않은 확인은 “미실행”으로 남깁니다.

### GitHub 최신 파일 확인

최신 커밋에서 아래처럼 검색합니다.

```bash
git pull
git grep -n -E "실습용 가상 (과제|포트폴리오|리추얼|행정) 기록"
```

**현재 HEAD에서는 이 검색이 0건이어야 합니다.** 가상 메모 본문이 들어 있는 1회 실행용 SQL은 Git에 커밋하지 않습니다. `data.json`, `public/data.json`, 브라우저 파일, 서버 함수 소스에도 메모 본문을 하드코딩하지 않습니다.

### 현재 확인 결과와 남은 약점

- 정적 `data.json` 및 `public/data.json`: 현재 최신 GitHub 파일에서는 메모 배열이 비어 있습니다.
- 1회 실행 SQL: 가상 메모 초기 적재 문장이 있으므로 Git에 커밋하지 않고 로컬에서만 SQL Editor에 사용합니다.
- 2단계 당시 공개 API: `/api/notes`는 비로그인 호출이 가능했지만, 3단계 현재는 로그인 토큰 검증에 실패하면 401로 거부합니다.
- 과거 노출: 옛 공개 Git 커밋이나 옛 Vercel 배포가 접근 가능한 동안에는 과거의 공개 노출이 해소됐다고 쓰지 않습니다. 현재 정적 파일에서 빠졌다는 사실과 과거 노출의 존속 여부를 별도로 기록합니다.

## 2단계 저장점

현재 작동 대상으로 기록한 기능은 다음과 같습니다. 과제 1번의 “세 개”와 2번의 “네 건”이 충돌하지만, R5 시작 틀과 화면 확인 조건이 네 건이므로 이 저장점은 **네 건**을 기준으로 합니다.

- 정적 `/data.json`에는 가상 메모 본문이 없고 `notes: []`만 남습니다.
- 화면은 `/api/notes` 서버 함수를 통해 학습용 Supabase의 가상 메모 네 건을 읽도록 구현되어 있습니다.
- 서버 함수는 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수 이름만 참조하며 비밀값을 브라우저 코드·응답·로그에 넣지 않습니다.
- 이 항목은 2단계 저장 당시의 기록이며, 3단계 현재는 `/api/notes`가 무로그인 요청을 401로 거부합니다.
- 옛 공개 커밋·옛 배포가 접근 가능한 동안에는 과거 노출이 해소됐다고 기록하지 않습니다.

다시 확인할 때는 Vercel에서 현재 프로젝트를 재배포한 뒤 `/`에서 네 카드, `/data.json`에서 빈 `notes` 배열을 확인합니다. GitHub 최신 파일은 `git pull` 후 README의 “2단계 노출 확인 절차”에 따라 검색합니다. 실제 Supabase 환경변수 값은 저장소나 문서에 기록하지 않습니다.

## 3단계 저장점 — 진짜 로그인과 메모 CRUD

현재 자료 API는 `src/verify-login.mjs`로 Bearer 토큰을 검사하고, 토큰이 없거나 검증에 실패하면 자료 없이 401로 거부합니다. 브라우저가 임의로 보낸 `userId`나 `role`은 신뢰하지 않으며, 서버가 검증한 사용자 ID만 사용합니다.

로그인한 사용자는 `GET /api/notes`, `POST /api/notes`로 자신의 메모 목록을 읽고 새 메모를 추가할 수 있습니다. 새 메모의 `owner_id`는 서버가 확인한 사용자 ID로 저장합니다. 한 건 조회·수정·삭제는 `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`를 사용합니다.

현재 3단계에서는 한 건 경로에 아직 `owner_id` 조건을 걸지 않았습니다. 따라서 로그인한 B가 A 메모의 UUID를 알면 접근할 수 있는 허점이 의도적으로 남아 있으며, 이 소유자 검사는 4단계에서 고칩니다. 무로그인 요청은 허용하지 않습니다.

Supabase의 `learning_notes.id`를 UUID로 맞추려면 `supabase/step3_notes_uuid.sql`을 SQL Editor에서 한 번 실행합니다. 실행 후 Vercel 최신 배포에서 A 계정으로 로그인하여 메모 추가·수정·삭제가 되는지 확인하고, 삭제한 UUID를 다시 GET했을 때 404인지 확인합니다. 로그아웃 또는 시크릿 창에서 `/api/notes`를 직접 요청하면 401이어야 합니다.

현재 설정은 `aleph.config.json`의 `step: 3`, Supabase 로그인 발급자 정보, 그리고 실제 GET·POST·PUT·DELETE 경로를 `allowedRoutes`에 기록합니다. `src/attack-check.mjs`도 3단계 기준으로 갱신되어 무로그인 `/api/notes`의 401 거부와 정적 `/data.json` 비노출을 자기점검합니다. 비밀번호·JWT·서버 전용 키는 Git이나 README에 기록하지 않습니다. 또한 최신 `vercel.json`은 첫 화면 `/` 응답에 `X-Content-Type-Options: nosniff` 보안 헤더를 추가해 2단계·3단계의 보안 헤더 가점 조건을 충족하도록 구성되어 있습니다.

## 4단계 저장점 — 로그인해도 내 자료만

자료 API는 `src/verify-login.mjs`가 확인한 사용자 ID를 소유권의 기준으로 사용합니다. 목록 조회는 `owner_id = verified.userId`인 행만 반환하고, 새 메모의 `owner_id`도 서버가 확인한 ID로만 저장합니다. URL이나 요청 본문의 `owner_id`는 신뢰하지 않습니다.

한 건 `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`는 DB의 기존 `owner_id`와 검증된 사용자 ID가 일치할 때만 동작합니다. 수정 요청은 `{title,body}` 형식을 유지하고 소유자 변경 입력을 받지 않으며, 다른 사용자의 메모는 존재 여부를 노출하지 않도록 404로 거부합니다.

학습 DB의 `learning_notes`에는 RLS를 켜고 `anon`의 테이블 권한을 제거했습니다. `authenticated`에는 SELECT·INSERT·UPDATE·DELETE만 허용하고, SELECT·DELETE는 `USING (auth.uid() = owner_id)`, INSERT는 `WITH CHECK`, UPDATE는 기존 행 `USING`과 새 행 `WITH CHECK` 모두 같은 소유자 조건을 사용합니다. 이 SQL은 Supabase SQL Editor에서 적용한 DB 설정이며 비밀값은 저장소에 기록하지 않습니다.

`aleph.config.json`은 4단계와 실제 GET·POST·PUT·DELETE 경로를 기록합니다. `src/attack-check.mjs`는 공개 요청으로 확인 가능한 무로그인 메모 목록의 401/403 JSON 거부, `/aleph.json` 접근, 첫 화면의 `X-Content-Type-Options: nosniff`를 자기점검합니다. A/B 교차 소유권 시험은 로그인 자격 증명을 저장소나 제출 묶음에 넣지 않고 앱에서 직접 확인합니다.

다시 확인할 때는 Vercel 최신 배포에서 A와 B가 각자 자기 메모 CRUD를 유지하고 상대 메모 GET·PUT·DELETE가 거부되는지 확인합니다. 시크릿 창의 `GET /api/notes`는 401 또는 403 JSON이어야 하고, `/aleph.json`은 열리며 첫 화면 응답에는 `X-Content-Type-Options: nosniff`가 있어야 합니다.

## 5단계 저장점 — 자료 요청을 서버 한곳으로

브라우저의 메모 읽기·추가·수정·삭제는 모두 기존 Vercel 서버 함수 `/api/notes`, `/api/notes/:id`를 통해서만 수행합니다. 브라우저 코드에는 Supabase 자료 테이블 직접 호출이 없습니다.

5단계 100점 조건에 맞춰 브라우저의 Supabase SDK와 공개 키도 제거했습니다. 로그인·회원가입은 `/api/auth/login`, `/api/auth/signup` 서버 함수가 처리하고, 서버 함수만 Vercel의 Supabase 환경변수를 읽습니다. 브라우저는 로그인 결과의 접근 토큰만 세션 저장소에 두고 메모 서버 함수의 Bearer 인증에 사용합니다.

`aleph.config.json`은 `step: 5`와 원본 학습 자료 API 주소를 `originalApiUrl`에 기록합니다. 배포 빌드가 만드는 `/aleph.json`에는 실제 `allowedRoutes`와 `originalApiUrl`도 포함합니다. 기존 4단계 소유자 검사와 RLS는 그대로 유지합니다.

다시 확인할 때는 최신 Vercel 배포의 `/aleph.json`에서 `allowedRoutes`가 비어 있지 않은지, 첫 화면 응답에 `X-Content-Type-Options: nosniff`가 있는지, 페이지 소스에 `sb_publishable_` 또는 Supabase 공개 키 상수가 없는지 확인합니다. 로그인 후 자기 메모 CRUD와 상대 메모 거부도 이전 단계와 동일하게 유지되어야 합니다.
