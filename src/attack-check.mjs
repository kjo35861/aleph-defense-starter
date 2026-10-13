import { decide } from './decider.mjs';

// Step 7 self-check: keep earlier checks and add composite step-up decision practice.
export async function runAttackChecks(config) {
  if (config.step !== 7) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

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

  const registered = await decide({
    requestId: 'self-check-registered-device',
    deviceRegistered: true,
  });
  const unregistered = await decide({
    requestId: 'self-check-unregistered-device',
    deviceRegistered: false,
  });
  const suspicious = await decide({
    requestId: 'self-check-composite-anomaly',
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
    signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
  });
  const reauthenticated = await decide({
    requestId: 'self-check-composite-reauthenticated',
    deviceRegistered: true,
    stepUp: { verified: true, authAgeSeconds: 60 },
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
    signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
  });

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
    {
      attackId: 'registered_device_allow',
      expected: '등록 기기 가상 요청은 allow여야 함',
      observed: `${registered.decision} / ${registered.reasonCode}`,
    },
    {
      attackId: 'unregistered_device_deny',
      expected: '미등록 기기 가상 요청은 deny / device_not_registered여야 함',
      observed: `${unregistered.decision} / ${unregistered.reasonCode}`,
    },
    {
      attackId: 'composite_anomaly_step_up',
      expected: '정해진 복합 이상 가상 요청은 step_up / step_up_required여야 함',
      observed: `${suspicious.decision} / ${suspicious.reasonCode}`,
    },
    {
      attackId: 'composite_reauthenticated_allow',
      expected: '최근 재인증된 같은 복합 이상 가상 요청은 allow여야 함',
      observed: `${reauthenticated.decision} / ${reauthenticated.reasonCode}`,
    },
  ];
}
