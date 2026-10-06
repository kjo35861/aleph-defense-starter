// Step 4 self-check: public checks that need no saved credentials.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 4) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const request = async (path, { json = false } = {}) => {
    try {
      const response = await fetch(new URL(path, app), {
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: json ? { accept: 'application/json' } : {},
      });
      let body = null;
      if (json) {
        try { body = await response.json(); } catch {}
      }
      return { status: response.status, headers: response.headers, body };
    } catch (error) {
      return { status: null, headers: null, body: null, error: error?.name || 'fetch_error' };
    }
  };

  const anonymousApi = await request('/api/notes', { json: true });
  const anonymousDenied = [401, 403].includes(anonymousApi.status)
    && typeof anonymousApi.body?.error === 'string'
    && anonymousApi.body.error.length > 0;

  const identity = await request('/aleph.json', { json: true });
  const identityVisible = identity.status === 200 && identity.body && typeof identity.body === 'object';

  const home = await request('/');
  const nosniff = home.status === 200
    && home.headers?.get('x-content-type-options')?.toLowerCase() === 'nosniff';

  return [
    {
      attackId: 'anonymous_notes_api_denied_json',
      expected: '비로그인 메모 목록 요청은 401 또는 403 JSON 오류로 거부되어야 함',
      observed: anonymousDenied
        ? `비로그인 /api/notes가 HTTP ${anonymousApi.status} JSON 오류로 거부됨`
        : `비로그인 /api/notes 거부 점검 실패 (HTTP ${anonymousApi.status ?? anonymousApi.error ?? 'unknown'})`,
    },
    {
      attackId: 'deployment_identity_visible',
      expected: '/aleph.json이 HTTP 200 JSON으로 열려야 함',
      observed: identityVisible
        ? '/aleph.json이 HTTP 200 JSON으로 열림'
        : `/aleph.json 점검 실패 (HTTP ${identity.status ?? identity.error ?? 'unknown'})`,
    },
    {
      attackId: 'home_nosniff_header',
      expected: '첫 화면 응답에 X-Content-Type-Options: nosniff가 있어야 함',
      observed: nosniff
        ? '첫 화면 응답에서 X-Content-Type-Options: nosniff 확인'
        : `첫 화면 보안 헤더 점검 실패 (HTTP ${home.status ?? home.error ?? 'unknown'})`,
    },
  ];
}
