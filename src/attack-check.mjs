// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

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

  const checkJson = async (path) => {
    try {
      const response = await fetch(new URL(path, app), {
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: { accept: 'application/json' },
      });
      let body = null;
      if (response.ok) {
        try {
          body = await response.json();
        } catch {
          // Non-JSON is recorded as an observed failure below.
        }
      }
      return { status: response.status, ok: response.ok, body };
    } catch (error) {
      return { status: null, ok: false, body: null, error: error?.name || 'fetch_error' };
    }
  };

  const staticData = await checkJson('/data.json');
  const staticEmpty = staticData.ok && Array.isArray(staticData.body?.notes)
    && staticData.body.notes.length === 0;

  const notesApi = await checkJson('/api/notes');
  const apiCount = notesApi.ok && Array.isArray(notesApi.body?.notes)
    ? notesApi.body.notes.length : null;

  return [
    {
      attackId: 'anonymous_static_note_read',
      expected: '비로그인 /data.json에는 가상 메모 본문이 없어야 함',
      observed: staticEmpty
        ? '비로그인 /data.json의 notes 배열이 비어 있음'
        : `비로그인 /data.json 정적 노출 점검 실패 (${staticData.status ?? staticData.error ?? 'unknown'})`,
    },
    {
      attackId: 'anonymous_notes_api_read',
      expected: '현재 2단계의 공개 API 약점을 확인',
      observed: apiCount === null
        ? `비로그인 /api/notes 확인 불가 (${notesApi.status ?? notesApi.error ?? 'unknown'})`
        : `비로그인 /api/notes에서 가상 메모 ${apiCount}건 접근 가능`,
    },
  ];
}
