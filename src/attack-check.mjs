// Step 5 self-check: public checks for deployment metadata, security header, and browser key removal.
export async function runAttackChecks(config) {
  if (config.step !== 5) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

  const app = new URL(config.publicAppUrl);
  const request = async (path, json = false) => {
    try {
      const response = await fetch(new URL(path, app), {
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: json ? { accept: 'application/json' } : {},
      });
      const text = await response.text();
      let body = null;
      if (json) {
        try { body = JSON.parse(text); } catch {}
      }
      return { status: response.status, headers: response.headers, text, body };
    } catch (error) {
      return { status: null, headers: null, text: '', body: null, error: error?.name || 'fetch_error' };
    }
  };

  const identity = await request('/aleph.json', true);
  const routesOk = identity.status === 200 && Array.isArray(identity.body?.allowedRoutes)
    && identity.body.allowedRoutes.length > 0;

  const home = await request('/');
  const nosniff = home.status === 200
    && home.headers?.get('x-content-type-options')?.toLowerCase() === 'nosniff';
  const browserKeyAbsent = !/sb_publishable_|SUPABASE_PUBLISHABLE_KEY|createClient\s*\(/u.test(home.text);

  return [
    {
      attackId: 'deployment_allowed_routes',
      expected: '/aleph.json의 allowedRoutes에 허용 경로가 하나 이상 있어야 함',
      observed: routesOk
        ? `/aleph.json allowedRoutes ${identity.body.allowedRoutes.length}개 확인`
        : `/aleph.json allowedRoutes 점검 실패 (HTTP ${identity.status ?? identity.error ?? 'unknown'})`,
    },
    {
      attackId: 'home_nosniff_header',
      expected: '첫 화면 응답에 X-Content-Type-Options: nosniff가 있어야 함',
      observed: nosniff
        ? '첫 화면 응답에서 X-Content-Type-Options: nosniff 확인'
        : `첫 화면 보안 헤더 점검 실패 (HTTP ${home.status ?? home.error ?? 'unknown'})`,
    },
    {
      attackId: 'browser_supabase_key_absent',
      expected: '화면 코드에 Supabase 공개 키나 브라우저 Supabase 클라이언트가 없어야 함',
      observed: browserKeyAbsent
        ? '첫 화면 코드에서 Supabase 공개 키와 브라우저 클라이언트 패턴이 없음'
        : '첫 화면 코드에 Supabase 공개 키 또는 브라우저 클라이언트 패턴이 남아 있음',
    },
  ];
}
