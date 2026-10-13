// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 계약에 없는 브라우저 헤더·사용자 번호·역할·기기 키·토큰은 신뢰하거나 보정하지 않습니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zone',
]);

const SUBJECT_ID = /^[A-Za-z0-9_-]{1,128}$/u;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const RESOURCE_ID_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/u;

const STUDENT_ALLOWED = new Set([
  'GET /notes/:id',
  'PUT /notes/:id',
]);

const INSTRUCTOR_ONLY = new Set([
  'POST /notices/:id',
  'PUT /notices/:id',
  'PATCH /notices/:id',
  'DELETE /notices/:id',
]);

const SERVICE_PREFIX = Object.freeze({
  notes: '/notes',
  notices: '/notices',
});

function inspectEngineInput(request) {
  const signals = request?.signals && typeof request.signals === 'object'
    && !Array.isArray(request.signals) ? request.signals : null;
  const source = typeof signals?.source === 'string' ? signals.source : null;

  const provenance = source === 'judge_fixture'
    ? 'judge_fixture'
    : source === 'none'
      ? 'none'
      : 'unknown';

  return {
    deviceRegistered: request?.deviceRegistered === true,
    stepUpVerified: request?.stepUp?.verified === true,
    authAgeSeconds: Number.isInteger(request?.stepUp?.authAgeSeconds)
      ? request.stepUp.authAgeSeconds
      : null,
    accessContext: {
      provenance,
      region: typeof signals?.region === 'string' ? signals.region : null,
      hour: Number.isInteger(signals?.hour) ? signals.hour : null,
      network: typeof signals?.network === 'string' ? signals.network : null,
      recentEvents: Array.isArray(request?.recentEvents) ? request.recentEvents : null,
    },
  };
}

function exactResource(request) {
  if (typeof request?.subjectId !== 'string' || !SUBJECT_ID.test(request.subjectId)
      || typeof request?.deviceId !== 'string' || !DEVICE_ID.test(request.deviceId)
      || request.queryLength !== 0) {
    return null;
  }

  const { method, route, path, service } = request;
  if (typeof method !== 'string' || typeof route !== 'string'
      || typeof path !== 'string' || typeof service !== 'string') {
    return null;
  }

  const knownRoute = STUDENT_ALLOWED.has(route) || INSTRUCTOR_ONLY.has(route);
  if (!knownRoute || !route.startsWith(`${method} `)) return null;

  const prefix = SERVICE_PREFIX[service];
  if (!prefix) return null;

  const template = route.slice(method.length + 1);
  if (template !== `${prefix}/:id`) return null;

  if (!path.startsWith(`${prefix}/`)) return null;
  const segment = path.slice(prefix.length + 1);

  // 자료 ID는 정확히 한 경로 칸만 허용합니다. export 같은 기능 경로를 같은 깊이에 두지 않습니다.
  if (!RESOURCE_ID_SEGMENT.test(segment) || segment === 'export') return null;

  return route;
}

function needsStepUp(input) {
  const context = input.accessContext;
  const unusualHour = Number.isInteger(context.hour) && (context.hour < 6 || context.hour >= 23);
  const unfamiliarNetwork = context.network === 'unusual';
  const bulkRead = Array.isArray(context.recentEvents)
    && context.recentEvents.some(event => event?.kind === 'risk_signal'
      && Number.isInteger(event?.count) && event.count >= 20);

  return context.provenance === 'judge_fixture'
    && unusualHour && unfamiliarNetwork && bulkRead;
}

function recentStepUp(input) {
  return input.stepUpVerified
    && input.authAgeSeconds !== null
    && input.authAgeSeconds >= 0
    && input.authAgeSeconds <= 900;
}

function respond(request, decision, reasonCode, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  };
}

export async function decide(request) {
  const input = inspectEngineInput(request);

  if (!input.deviceRegistered) {
    return respond(request, 'deny', 'device_not_registered', 'device_registered');
  }

  const resourceRoute = exactResource(request);
  if (!resourceRoute) {
    return respond(request, 'deny', 'route_not_allowed', 'resource_zone');
  }

  // 계약에 강사 역할이 없으므로 공지/강사 자료 쓰기는 누구에게도 허용하지 않습니다.
  if (INSTRUCTOR_ONLY.has(resourceRoute)) {
    return respond(request, 'deny', 'instructor_role_required', 'resource_zone');
  }

  if (resourceRoute === 'GET /notes/:id' && needsStepUp(input) && !recentStepUp(input)) {
    return respond(request, 'step_up', 'step_up_required', 'step_up_required');
  }

  if (STUDENT_ALLOWED.has(resourceRoute)) {
    return respond(request, 'allow', 'approved', 'resource_zone');
  }

  return respond(request, 'deny', 'route_not_allowed', 'resource_zone');
}
