import { readFile } from 'node:fs/promises';

const patternDoc = JSON.parse(
  await readFile(new URL('./patterns.json', import.meta.url), 'utf8'),
);

const PATTERNS = new Map(
  (patternDoc.patterns ?? []).map(pattern => [pattern.name, pattern]),
);

const NORMAL_TEXT = /(로그인이 성공|로그아웃|세션 유지|자료실 화면|비밀번호 변경이 성공|뒤에 성공)/u;
const SPRAY_ACCOUNT_TEXT = /(여러 계정|계정\s*\d+개|서로 다른 계정)/u;
const SAME_PASSWORD_TEXT = /같은 비밀번호/u;
const BURST_TEXT = /(\d+분 안|1분 안|2분 안|로그인 실패 \d+건|실패가 \d+건|실패 \d+건|계정\s*\d+개.*로그인 실패|계정 이름을 바꿔)/u;
const JEV_TIMEOUT_MS = 1000;

function clamp(value) {
  if (typeof value !== 'number') return null;
  const n = value;
  if (!Number.isFinite(n) || n < 0 || n > 1) return null;
  return n;
}

function descriptionOf(alert) {
  if (typeof alert?.description === 'string') return alert.description;
  if (typeof alert?.rule?.description === 'string') return alert.rule.description;
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
  if (Array.isArray(alert?.rule?.mitre)) return alert.rule.mitre.includes('T1110');
  const description = descriptionOf(alert);
  return /(로그인 실패|실패\s*\d+건|실패가\s*\d+건|비밀번호|여러 계정|계정\s*\d+개|계정 이름을 바꿔)/u.test(description);
}

function matchedPattern(alert) {
  const description = descriptionOf(alert);
  if (SAME_PASSWORD_TEXT.test(description) && SPRAY_ACCOUNT_TEXT.test(description)) {
    return 'same-password-multi-account';
  }
  if (BURST_TEXT.test(description)) return 'same-source-burst-failures';
  return null;
}

function localAssessment(alert) {
  const description = descriptionOf(alert);
  const level = levelOf(alert);
  const count = countOf(alert);
  const accountCount = accountCountOf(alert);
  const pattern = matchedPattern(alert);

  if (!bruteForceSignal(alert) || NORMAL_TEXT.test(description)) {
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
          timestamp: alert?.timestamp ?? null,
          sourceAddress: alert?.sourceAddress ?? alert?.data?.srcip ?? null,
          account: alert?.account ?? alert?.data?.srcuser ?? null,
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
