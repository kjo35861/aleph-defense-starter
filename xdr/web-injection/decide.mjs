const PATTERNS = [
  {
    name: 'repeated-sql-syntax',
    condition: '같은 출발 주소의 요청 인자에서 SQL 구문 표기가 짧은 시간 동안 반복된다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션의 취약점 악용을 다루며, 요청 인자에 반복되는 SQL 구문은 SQL 주입 시도의 근거다.',
  },
  {
    name: 'repeated-script-tag',
    condition: '같은 출발 주소의 요청 인자에서 스크립트 태그 또는 스크립트 삽입 표기가 짧은 시간 동안 반복된다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션의 취약점 악용을 다루며, 요청 인자에 반복되는 스크립트 태그는 스크립트 주입 시도의 근거다.',
  },
  {
    name: 'repeated-path-traversal',
    condition: '같은 출발 주소의 요청 인자에서 ../처럼 상위 경로로 거슬러 올라가는 표기가 짧은 시간 동안 반복된다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 애플리케이션의 취약점 악용을 다루며, 요청 인자에 반복되는 상위 경로 표기는 경로 순회 시도의 근거다.',
  },
];

const SQL_SIGNAL = /(sql\s*(?:구문|표식)|데이터베이스 조회를 이어 붙|명령 구분자|doc-(?:sql|cmd-separator)|(?:union\s+select|select\s+.+\s+from|(?:'|%27)\s*or\s+))/iu;
const SCRIPT_SIGNAL = /(스크립트 (?:삽입 표기|표식)|doc-(?:script-marker|mixed-marker)|<\s*script\b|%3c\s*script\b)/iu;
const PATH_SIGNAL = /(경로를 여러 단계 거슬러|경로 이탈 표기|doc-up-repeat|(?:\.\.\/){2,}|(?:%2e%2e(?:%2f|\/)){2,})/iu;

function text(value) {
  return typeof value === 'string' ? value : '';
}

function descriptionOf(alert) {
  return text(alert?.description || alert?.rule?.description);
}

function levelOf(alert) {
  const level = Number(alert?.ruleLevel ?? alert?.rule?.level);
  return Number.isFinite(level) ? level : 0;
}

function countOf(alert) {
  const direct = Number(alert?.count ?? alert?.data?.count);
  if (Number.isFinite(direct) && direct > 0) return direct;

  const match = descriptionOf(alert).match(/(\d+)\s*(?:번|건)/u);
  return match ? Number(match[1]) : 1;
}

function hasT1190(alert) {
  const mitre = alert?.rule?.mitre ?? alert?.mitre;
  const ids = Array.isArray(mitre) ? mitre : Array.isArray(mitre?.id) ? mitre.id : [];
  return ids.some(id => id === 'T1190');
}

function signalText(alert) {
  return `${descriptionOf(alert)} ${text(alert?.url || alert?.data?.url)}`;
}

function matchedPattern(alert) {
  const value = signalText(alert);
  if (SQL_SIGNAL.test(value)) return PATTERNS[0].name;
  if (SCRIPT_SIGNAL.test(value)) return PATTERNS[1].name;
  if (PATH_SIGNAL.test(value)) return PATTERNS[2].name;
  return null;
}

function actionFor(confidence) {
  if (confidence >= 0.85) return 'block';
  if (confidence >= 0.5) return 'alert';
  return 'record';
}

export function decide(alert) {
  const pattern = matchedPattern(alert);
  const level = levelOf(alert);
  const count = countOf(alert);

  let confidence;
  if (pattern && count >= 8 && level >= 10) {
    confidence = 0.95;
  } else if (pattern || hasT1190(alert) || level >= 5) {
    confidence = pattern ? 0.65 : 0.5;
  } else {
    confidence = 0.1;
  }

  return {
    action: actionFor(confidence),
    confidence,
    reason: pattern ?? 'no-matching-pattern',
  };
}
