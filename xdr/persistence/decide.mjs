const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'unsigned-new-service',
    condition: '새 서비스가 등록되거나 서비스 실행 파일이 바뀌었고, 서명이 없거나 임시 폴더의 실행 파일을 가리킨다.',
    evidence: 'MITRE ATT&CK T1543은 시스템 프로세스 생성·변경을 통한 지속성 확보를 다루며, 서명 없는 새 서비스 등록이나 서비스 실행 파일 변경은 그 근거가 된다.',
  }),
  Object.freeze({
    name: 'unfamiliar-scheduled-task',
    condition: '처음 보는 예약 작업이 만들어졌거나 예약 작업이 임시 폴더의 프로그램을 비정상적인 시각에 실행한다.',
    evidence: 'MITRE ATT&CK T1053은 예약 작업·작업 스케줄러를 이용한 지속성을 다루며, 낯선 예약 작업과 비정상 실행 대상은 그 근거가 된다.',
  }),
  Object.freeze({
    name: 'startup-folder-change',
    condition: '시작 폴더 또는 시작 프로그램 목록에 평소 없던 실행 항목이 새로 추가되거나 변경된다.',
    evidence: 'MITRE ATT&CK T1543의 시스템 프로세스·서비스 변경 맥락에서 시작 시 자동 실행되도록 항목을 추가하는 변화는 지속성 확보 신호로 볼 근거가 된다.',
  }),
]);

const CLEAR_UNSIGNED_SERVICE = /(서명 없는 (?:새 )?서비스|서비스 등록.*서명 없|서비스 실행 파일이 바뀌었고 서명이 없|평소 목록에 없는 서비스.*등록)/u;
const CLEAR_SCHEDULED_TASK = /(처음 보는 예약 작업|예약 작업 이름이 임의 문자열|예약 작업.*임시 폴더|수업 시간 밖에 실행)/u;
const CLEAR_STARTUP = /(시작 폴더.*평소 목록에 없는.*추가|시작 프로그램.*같은 임시 파일|시작 폴더.*실행 항목.*추가)/u;
const NORMAL_CONTEXT = /(로그인했습니다|로그아웃했습니다|평소 시각에 그대로|기존 .*서명된 채로 실행|목록을 읽기만|정의 업데이트가 평소 저장소|기존 예약 작업.*마쳤|자료실 화면이 열렸)/u;

function text(value) {
  return typeof value === 'string' ? value : '';
}

function descriptionOf(alert) {
  return text(alert?.description || alert?.rule?.description);
}

function pathOf(alert) {
  return text(alert?.path || alert?.data?.path);
}

function levelOf(alert) {
  const level = Number(alert?.ruleLevel ?? alert?.rule?.level);
  return Number.isFinite(level) ? level : 0;
}

function mitreIds(alert) {
  const mitre = alert?.rule?.mitre ?? alert?.mitre;
  if (Array.isArray(mitre)) return mitre;
  if (Array.isArray(mitre?.id)) return mitre.id;
  return [];
}

function hasMitre(alert, id) {
  return mitreIds(alert).some(value => value === id);
}

function actionFor(confidence) {
  if (confidence >= 0.85) return 'block';
  if (confidence >= 0.5) return 'alert';
  return 'record';
}

function assess(alert) {
  const description = descriptionOf(alert);
  const path = pathOf(alert);
  const level = levelOf(alert);
  const t1543 = hasMitre(alert, 'T1543');
  const t1053 = hasMitre(alert, 'T1053');
  const tempPath = /(?:\\|\/)Temp(?:\\|\/)/iu.test(path);

  if (NORMAL_CONTEXT.test(description)) {
    return { confidence: 0.1, pattern: 'no-matching-pattern' };
  }

  if (t1543 && level >= 10 && (CLEAR_UNSIGNED_SERVICE.test(description)
      || (/(서비스|service)/iu.test(description) && tempPath && /(서명 없|등록|바뀌)/u.test(description)))) {
    return { confidence: 0.95, pattern: PATTERNS[0].name };
  }

  if (t1053 && level >= 10 && (CLEAR_SCHEDULED_TASK.test(description)
      || (/(예약 작업|scheduled task)/iu.test(description) && tempPath))) {
    return { confidence: 0.95, pattern: PATTERNS[1].name };
  }

  if (t1543 && level >= 10 && (CLEAR_STARTUP.test(description)
      || (/(시작 폴더|시작 프로그램|startup)/iu.test(description)
          && /(평소 목록에 없|추가|같은 임시 파일)/u.test(description)))) {
    return { confidence: 0.9, pattern: PATTERNS[2].name };
  }

  if ((t1543 || t1053) && level >= 5) {
    let pattern = PATTERNS[0].name;
    if (t1053 && /(예약 작업|scheduled task)/iu.test(description)) {
      pattern = PATTERNS[1].name;
    } else if (/(시작 폴더|시작 항목|시작 프로그램|startup)/iu.test(description)) {
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
