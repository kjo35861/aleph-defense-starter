import { readFile } from 'node:fs/promises';

const patternDoc = JSON.parse(
  await readFile(new URL('./patterns.json', import.meta.url), 'utf8'),
);

const PATTERNS = new Map(
  (patternDoc.patterns ?? []).map(pattern => [pattern.name, pattern]),
);

const NORMAL_TEXT = /(로그인이 성공|로그아웃|세션 유지|자료실 화면|비밀번호 변경이 성공|뒤에 성공)/u;
const SPRAY_TEXT = /(여러 계정|계정\s*\d+개|서로 다른 계정|같은 비밀번호)/u;
const BURST_TEXT = /(\d+분 안|1분 안|2분 안|로그인 실패 \d+건|실패가 \d+건|실패 \d+건|계정 이름을 바꿔)/u;

function clamp(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.min(1, n));
}

function matchedPattern(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  if (SPRAY_TEXT.test(description)) return 'same-password-multi-account';
  if (BURST_TEXT.test(description)) return 'same-source-burst-failures';
  return null;
}

function localAssessment(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = Number(alert?.rule?.level ?? 0);
  const count = Number(alert?.data?.count ?? 0);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const pattern = matchedPattern(alert);

  if (!mitre.includes('T1110') || NORMAL_TEXT.test(description)) {
    return { kind: 'normal', confidence: 0.1, pattern: 'no-matching-pattern' };
  }

  if (pattern === 'same-password-multi-account' && level >= 10) {
    return { kind: 'clear', confidence: 0.95, pattern };
  }

  // 설명 문구가 달라도 Wazuh가 T1110으로 태깅했고 규칙 수준이 높으며
  // 짧은 시간 대량 실패 건수가 확인되면 명확한 brute-force로 본다.
  if (level >= 10 && count >= 20) {
    return { kind: 'clear', confidence: 0.95, pattern: 'same-source-burst-failures' };
  }

  return { kind: 'ambiguous', confidence: 0.5, pattern: pattern ?? 'no-matching-pattern' };
}

async function askJev(alert, patternName) {
  const hook = globalThis?.Jev?.classify;
  if (typeof hook !== 'function') return null;

  try {
    const response = await hook({
      task: 'brute-force-confidence',
      pattern: patternName,
      alert: {
        timestamp: alert?.timestamp ?? null,
        sourceAddress: alert?.data?.srcip ?? null,
        account: alert?.data?.srcuser ?? null,
        ruleLevel: alert?.rule?.level ?? null,
        description: alert?.rule?.description ?? null,
      },
    });
    return clamp(response?.confidence);
  } catch {
    return null;
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
