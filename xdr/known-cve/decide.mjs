const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'jndi-lookup-in-header',
    condition: '요청 머리글 값에 ${jndi:...} 형태의 원격 조회 구문이 포함된다.',
    evidence: 'CVE-2021-44228 형태 요청은 머리글에 삽입된 JNDI 원격 조회 구문을 통해 외부 공개 애플리케이션의 취약점 악용을 시도할 수 있으며 MITRE ATT&CK T1190에 해당한다.',
  }),
  Object.freeze({
    name: 'jndi-lookup-in-argument',
    condition: 'URL 또는 요청 인자 값에 ${jndi:...} 형태의 원격 조회 구문이 포함된다.',
    evidence: 'CVE-2021-44228 형태 요청은 URL·요청 인자에 삽입된 JNDI 원격 조회 구문을 통해 취약점 악용을 시도할 수 있으며 MITRE ATT&CK T1190에 해당한다.',
  }),
  Object.freeze({
    name: 'known-cve-scan-trace',
    condition: '경보 설명에 알려진 취약점 점검 흔적과 CVE-2021-44228 형태 요청이 함께 나타난다.',
    evidence: '알려진 취약점 점검 흔적이 CVE-2021-44228 형태의 악용 신호와 함께 나타나면 외부 공개 애플리케이션 취약점 탐색·악용 시도로 볼 근거가 되며 MITRE ATT&CK T1190에 해당한다.',
  }),
]);

const JNDI_LOOKUP = /\$\{\s*jndi\s*:[^}]+\}/iu;
const CVE_NAME = /CVE-2021-44228/iu;
const JNDI_WORD = /\bjndi\b/iu;
const SCAN_TRACE = /(알려진 취약점 점검|취약점 점검|점검 도구|scanner|scan)/iu;

function text(value) {
  return typeof value === 'string' ? value : '';
}

function levelOf(alert) {
  const level = Number(alert?.ruleLevel ?? alert?.rule?.level);
  return Number.isFinite(level) ? level : 0;
}

function hasT1190(alert) {
  const mitre = alert?.rule?.mitre ?? alert?.mitre;
  const ids = Array.isArray(mitre)
    ? mitre
    : Array.isArray(mitre?.id)
      ? mitre.id
      : [];
  return ids.some(id => id === 'T1190');
}

function descriptionOf(alert) {
  return text(alert?.description || alert?.rule?.description);
}

function headerText(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  return [
    text(alert?.useragent),
    text(data.useragent),
    text(alert?.headers),
    text(data.headers),
  ].join(' ');
}

function argumentText(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  return [
    text(alert?.url),
    text(data.url),
    text(alert?.query),
    text(data.query),
  ].join(' ');
}

function actionFor(confidence) {
  if (confidence >= 0.85) return 'block';
  if (confidence >= 0.5) return 'alert';
  return 'record';
}

function assess(alert) {
  const description = descriptionOf(alert);
  const headers = headerText(alert);
  const args = argumentText(alert);
  const level = levelOf(alert);
  const t1190 = hasT1190(alert);

  const headerLookup = JNDI_LOOKUP.test(headers);
  const argumentLookup = JNDI_LOOKUP.test(args);
  const explicitCve = CVE_NAME.test(description) || CVE_NAME.test(headers) || CVE_NAME.test(args);
  const jndiMention = JNDI_WORD.test(description) || JNDI_WORD.test(headers) || JNDI_WORD.test(args);
  const scanTrace = SCAN_TRACE.test(description) && explicitCve;

  if (headerLookup && t1190 && level >= 10) {
    return { confidence: 0.95, pattern: PATTERNS[0].name };
  }

  if (argumentLookup && t1190 && level >= 10) {
    return { confidence: 0.95, pattern: PATTERNS[1].name };
  }

  if (scanTrace && t1190 && level >= 8) {
    return { confidence: 0.9, pattern: PATTERNS[2].name };
  }

  if (headerLookup) {
    return { confidence: 0.75, pattern: PATTERNS[0].name };
  }

  if (argumentLookup) {
    return { confidence: 0.75, pattern: PATTERNS[1].name };
  }

  if (t1190 && level >= 5) {
    let pattern = PATTERNS[2].name;
    if (/(머리글|header|중괄호)/iu.test(description)) {
      pattern = PATTERNS[0].name;
    } else if (jndiMention || /(조회 형태|lookup|인자|주소)/iu.test(description)) {
      pattern = PATTERNS[1].name;
    } else if (explicitCve || SCAN_TRACE.test(description) || /(취약점|라이브러리)/u.test(description)) {
      pattern = PATTERNS[2].name;
    }
    return { confidence: 0.5, pattern };
  }

  return { confidence: 0.1, pattern: 'no-matching-pattern' };
}

export function decide(alert) {
  const assessment = assess(alert);
  return {
    action: actionFor(assessment.confidence),
    confidence: assessment.confidence,
    reason: assessment.pattern,
  };
}
