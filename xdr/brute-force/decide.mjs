import { patterns } from './patterns.mjs';
import { safeText } from './redact.mjs';

const PATTERNS = new Map(
  patterns.map(pattern => [pattern.name, {
    ...pattern,
    matchers: pattern.matchAll.map(source => new RegExp(source, 'u')),
  }]),
);

const NORMAL_TEXT = /(로그인이 성공|로그아웃|세션 유지|자료실 화면|비밀번호 변경이 성공|뒤에 성공)/u;
const JEV_TIMEOUT_MS = 1000;

function clamp(value) {
  if (typeof value !== 'number') return null;
  const n = value;
  if (!Number.isFinite(n) || n < 0 || n > 1) return null;
  return n;
}

function descriptionOf(alert) {
  if (typeof alert?.description === 'string') return safeText(alert.description);
  if (typeof alert?.rule?.description === 'string') return safeText(alert.rule.description);
  return '';
}

function levelOf(alert) {
  return Number(alert?.ruleLevel ?? alert?.rule?.level ?? 0);
}

function countOf(alert) {
  const direct = Number(alert?.count ?? alert?.data?.count);
  if (Number.isFinite(direct) && direct > 0) return direct;

  const match = descriptionOf(alert).match(/(?:로그인 실패|실패(?:가)?)\s*(\d+)건/u);
  return match ? Number(match[1]) : 0;
}

function accountCountOf(alert) {
  const match = descriptionOf(alert).match(/(?:계정|서로 다른 계정)\s*(\d+)개/u);
  return match ? Number(match[1]) : 0;
}

function bruteForceSignal(alert) {
  const mitre = alert?.rule?.mitre;
  const ids = Array.isArray(mitre) ? mitre : Array.isArray(mitre?.id) ? mitre.id : [];
  if (ids.some(id => typeof id === 'string' && /^T1110(?:\.\d{3})?$/.test(id))) return true;
  const description = descriptionOf(alert);
  return /(로그인 실패|실패\s*\d+건|실패가\s*\d+건|비밀번호|여러 계정|계정\s*\d+개|계정 이름을 바꿔)/u.test(description);
}

function matchedPattern(alert) {
  const description = descriptionOf(alert);
  // 더 구체적인 다중 계정 패턴을 먼저 평가한다.
  for (const name of ['same-password-multi-account', 'same-source-burst-failures']) {
    const pattern = PATTERNS.get(name);
    if (pattern?.matchers.length && pattern.matchers.every(regex => regex.test(description))) return name;
  }
  return null;
}

function localAssessment(alert) {
  const description = descriptionOf(alert);
  const level = levelOf(alert);
  const count = countOf(alert);
  const accountCount = accountCountOf(alert);
  const pattern = matchedPattern(alert);

  if (!bruteForceSignal(alert)) {
    return { kind: 'normal', confidence: 0.1, pattern: 'no-matching-pattern' };
  }

  if (pattern === 'same-password-multi-account' && level >= 10) {
    return { kind: 'clear', confidence: 0.95, pattern };
  }

  // 설명 문구가 달라도 Wazuh가 T1110으로 태깅했고 규칙 수준이 높으며
  // 짧은 시간 대량 실패 건수가 확인되면 명확한 brute-force로 본다.
  if (level >= 10 && (count >= 20 || accountCount >= 20)) {
    return { kind: 'clear', confidence: 0.95, pattern: 'same-source-burst-failures' };
  }

  // 뒤따른 로그인 성공만으로 앞선 대량 실패를 정상 처리하지 않는다.
  if (NORMAL_TEXT.test(description) && count < 20 && accountCount < 20) {
    return { kind: 'normal', confidence: 0.1, pattern: 'no-matching-pattern' };
  }

  return { kind: 'ambiguous', confidence: 0.5, pattern: pattern ?? 'no-matching-pattern' };
}

async function askJev(alert, patternName) {
  const hook = globalThis?.Jev?.classify;
  if (typeof hook !== 'function') return null;

  let timeoutId;
  const timeout = new Promise(resolve => {
    timeoutId = setTimeout(() => resolve(null), JEV_TIMEOUT_MS);
  });

  try {
    const response = await Promise.race([
      hook({
        task: 'brute-force-confidence',
        pattern: patternName,
        alert: {
          timestamp: safeText(alert?.timestamp),
          sourceAddress: safeText(alert?.sourceAddress ?? alert?.data?.srcip),
          account: safeText(alert?.account ?? alert?.data?.srcuser),
          ruleLevel: alert?.ruleLevel ?? alert?.rule?.level ?? null,
          description: descriptionOf(alert),
        },
      }),
      timeout,
    ]);
    return clamp(response?.confidence);
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

function actionFor(confidence) {
  if (confidence >= 0.85) return 'block';
  if (confidence >= 0.5) return 'alert';
  return 'record';
}

export async function decide(alert) {
  const local = localAssessment(alert);

  if (local.kind === 'normal') {
    return {
      action: 'record',
      confidence: local.confidence,
      reason: local.pattern,
    };
  }

  if (local.kind === 'clear') {
    return {
      action: 'block',
      confidence: local.confidence,
      reason: local.pattern,
    };
  }

  const jevConfidence = await askJev(alert, local.pattern);
  if (jevConfidence === null) {
    return {
      action: 'alert',
      confidence: 0.5,
      reason: local.pattern,
    };
  }

  return {
    action: actionFor(jevConfidence),
    confidence: jevConfidence,
    reason: local.pattern,
  };
}
