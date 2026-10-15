const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'unexpected-admin-group-addition',
    condition: '일반 계정이 관리자 그룹에 새로 추가되거나 여러 계정이 단시간에 관리자 그룹에 추가되며 승인된 변경이라는 근거가 없다.',
    evidence: 'MITRE ATT&CK T1078은 정상 계정의 악용으로 권한을 확대하는 행위를 다루며, 예상하지 못한 관리자 그룹 편입은 계정 권한 남용을 조사할 신호다.',
  }),
  Object.freeze({
    name: 'unfamiliar-admin-command',
    condition: '기존과 다른 출발 주소·계정 권한으로 관리자 명령이 실행되거나 관리자 권한 변경 직후 관리자 명령이 실행된다.',
    evidence: 'MITRE ATT&CK T1078은 탈취·오용된 정상 계정의 권한 사용을 다루며, 낯선 관리자 명령은 그 의심 신호다; T1068에 해당하려면 취약점 악용 증거가 추가로 필요하다.',
  }),
  Object.freeze({
    name: 'out-of-hours-privilege-use',
    condition: '수업·업무 시간 밖에 관리자 권한이 사용되고 처음 보는 주소 또는 관리자 그룹 변경·명령 실행 같은 이상 징후가 함께 관찰된다.',
    evidence: 'MITRE ATT&CK T1078의 탐지 근거에는 비정상 시간·출발지의 계정 사용이 포함되며, T1068은 별도 취약점 악용 정황이 있을 때만 연결한다.',
  }),
]);

function decideAction(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason,
  };
}

export function decide(alert) {
  const description = typeof (alert?.rule?.description ?? alert?.description) === 'string'
    ? (alert.rule?.description ?? alert.description) : '';
  const levelValue = alert?.rule?.level ?? alert?.ruleLevel;
  const level = levelValue === '' || levelValue == null ? 0 : Number(levelValue);
  const mitre = alert?.rule?.mitre ?? alert?.mitre;
  const ids = Array.isArray(mitre) ? mitre : Array.isArray(mitre?.id) ? mitre.id : [];
  const relevant = ids.includes('T1068') || ids.includes('T1078');

  if (!relevant || !Number.isFinite(level) || level < 5) {
    return decideAction(0.1, 'no-matching-pattern');
  }

  const adminGroup = /관리자 그룹|관리자로 들어|관리자 그룹에 들어|관리자로 등록/u.test(description);
  const groupChange = /(추가|들어가|들어왔|다시 관리자로|편입)/u.test(description);
  const multiAccount = /계정\s*[2-9]\d*개/u.test(description);
  const adminCommand = /관리자 명령|권한 명령/u.test(description);
  const unfamiliar = /처음 보|원격 주소|다른 계정의 권한|방금 관리자가|곧바로|권한으로 바뀌/u.test(description);
  const outsideHours = /시간 밖|업무처럼 보이지 않는 시각/u.test(description);
  const authorityChange = /관리자 권한으로 바뀌|관리자 그룹 추가/u.test(description);

  // 단순 로그인, 권한 조회, 변경 없는 이벤트를 공격으로 승격하지 않는다.
  if (level >= 10) {
    if (adminGroup && groupChange && !/관리자 그룹은 아닙니다/u.test(description)) {
      return decideAction(0.95, PATTERNS[0].name);
    }
    if (adminCommand && (unfamiliar || /다른 계정의 권한/u.test(description))) {
      return decideAction(0.94, PATTERNS[1].name);
    }
    if (outsideHours && (adminCommand || authorityChange)) {
      return decideAction(0.92, PATTERNS[2].name);
    }
    if (authorityChange && unfamiliar) {
      return decideAction(0.9, PATTERNS[1].name);
    }
    if (multiAccount && adminGroup) {
      return decideAction(0.93, PATTERNS[0].name);
    }
  }

  if (level >= 5) {
    if (outsideHours) return decideAction(0.55, PATTERNS[2].name);
    if (/그룹/u.test(description)) return decideAction(0.5, PATTERNS[0].name);
    if (/관리자 명령|권한 상승|권한|계정 종류/u.test(description)) {
      return decideAction(0.5, PATTERNS[1].name);
    }
  }

  return decideAction(0.1, 'no-matching-pattern');
}
