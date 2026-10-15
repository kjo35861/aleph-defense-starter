const PATTERNS = [
  { name: 'unfamiliar-destination-bulk-transfer', condition: '처음 보는 외부 목적지로 자료 묶음·대용량 파일이 짧은 시간에 전송되거나 동일 목적지로 대량 전송이 반복된다.', evidence: 'MITRE ATT&CK T1041·T1048은 외부로 자료를 유출하는 전송을 다루며, 낯선 목적지와 비정상 대량 전송의 결합은 유출 의심 신호다.' },
  { name: 'out-of-hours-archive-transfer', condition: '업무·수업 시간 밖에 압축 파일이 평소 쓰지 않는 외부 주소로 전송되거나 압축 파일 여러 개가 연속 반출된다.', evidence: 'MITRE ATT&CK T1048은 명령 통로 이외 경로로 자료를 반출하는 행위를 다루며, 비정상 시각의 압축 파일 외부 전송은 확인할 만한 정황이다.' },
  { name: 'command-channel-repeated-exfiltration', condition: '경보에서 명령 통로를 통한 파일 전송이 명시되고 큰 파일 또는 자료 묶음이 외부 목적지로 반복 전송된다.', evidence: 'MITRE ATT&CK T1041은 명령·제어 통신 통로를 이용한 정보 유출 기법으로, 해당 통로에서 확인된 반복 파일 전송이 직접적인 조사 근거다.' },
];

export function decide(alert) {
  const description = String(alert?.rule?.description ?? alert?.description ?? '');
  const level = Number(alert?.rule?.level ?? alert?.ruleLevel ?? 0);
  const mitre = alert?.rule?.mitre ?? alert?.mitre ?? [];
  const ids = Array.isArray(mitre) ? mitre : Array.isArray(mitre?.id) ? mitre.id : [];
  let confidence = 0.1;
  let reason = 'no-matching-pattern';
  if (Number.isFinite(level) && level >= 5 && (ids.includes('T1041') || ids.includes('T1048'))) {
    const newDestination = /처음 보는|평소에 쓰지 않던|다른 주소|외부 주소/.test(description);
    const large = /대용량|큰 파일|묶음|자료실 전체|자료 200건|자료 이름이 연속/.test(description);
    const many = /반복|연속|8번|15번/.test(description);
    const archive = /압축 파일/.test(description);
    const outOfHours = /시간 밖/.test(description);
    const channel = /명령 통로/.test(description);
    const transfer = /전송|나갔|올라갔|복사됐/.test(description);
    confidence = 0.5;
    reason = PATTERNS[0].name;
    if (archive) reason = PATTERNS[1].name;
    if (channel) reason = PATTERNS[2].name;
    if (level >= 10 && transfer) {
      if (channel && (large || many)) confidence = 0.95;
      else if (archive && (newDestination || outOfHours || many)) confidence = 0.95;
      else if ((newDestination && large) || (large && many) || (many && /전송/.test(description))) confidence = 0.93;
    }
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
