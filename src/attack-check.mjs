// Step 3 self-check: anonymous note API access must be denied and static data must stay empty.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 3) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

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

  const request = async (path) => {
    try {
      const response = await fetch(new URL(path, app), {
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: { accept: 'application/json' },
      });
      let body = null;
      try { body = await response.json(); } catch {}
      return { status: response.status, body };
    } catch (error) {
      return { status: null, error: error?.name || 'fetch_error' };
    }
  };

  const staticData = await request('/data.json');
  const staticEmpty = staticData.status === 200
    && Array.isArray(staticData.body?.notes)
    && staticData.body.notes.length === 0;

  const anonymousApi = await request('/api/notes');
  const anonymousDenied = anonymousApi.status === 401;

  return [
    {
      attackId: 'anonymous_static_note_read',
      expected: '비로그인 /data.json에는 메모가 없어야 함',
      observed: staticEmpty
        ? '비로그인 /data.json의 notes 배열이 비어 있음'
        : `비로그인 /data.json 확인 실패 (HTTP ${staticData.status ?? staticData.error ?? 'unknown'})`,
    },
    {
      attackId: 'anonymous_notes_api_denied',
      expected: '비로그인 /api/notes 요청은 401로 거부되어야 함',
      observed: anonymousDenied
        ? '비로그인 /api/notes 요청이 HTTP 401로 거부됨'
        : `비로그인 /api/notes 거부 확인 실패 (HTTP ${anonymousApi.status ?? anonymousApi.error ?? 'unknown'})`,
    },
  ];
}
