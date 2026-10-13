// 9단계 가상 사건 탐지와 회수 제안입니다.
// 실제 회수 API 호출·기기 권한 변경·토큰 기록은 하지 않습니다.

const SUBJECT = /^[A-Za-z0-9_-]{1,128}$/u;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
  const subject = event.identity?.sub;
  if (typeof subject !== 'string' || !SUBJECT.test(subject)) return null;
  if (event.method !== 'GET') return null;
  const at = Date.parse(event.at);
  if (!Number.isFinite(at)) return null;
  return { subject, at };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const bySubject = new Map();
  for (const event of events) {
    const read = readEvent(event);
    if (!read) continue;
    const list = bySubject.get(read.subject) ?? [];
    list.push(read.at);
    bySubject.set(read.subject, list);
  }

  for (const [subject, times] of bySubject) {
    times.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] >= WINDOW_MS) start += 1;
      if (end - start + 1 > LIMIT) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
        };
      }
    }
  }

  return { action: 'observe' };
}

// 탐지 결과와 엔진이 확인한 가상 사용자·기기 한 쌍을 결합해
// 실제 집행이 아닌 "회수 제안" 결과만 만듭니다.
export function proposeRevocation(detection, verified) {
  if (!detection || typeof detection !== 'object' || Array.isArray(detection)
      || detection.action !== 'propose_revocation'
      || detection.reasonCode !== 'burst_read'
      || typeof detection.subject !== 'string') {
    return null;
  }

  if (!verified || typeof verified !== 'object' || Array.isArray(verified)
      || Object.keys(verified).sort().join(',') !== 'deviceId,subjectId'
      || verified.subjectId !== detection.subject
      || !DEVICE_ID.test(verified.deviceId ?? '')) {
    return null;
  }

  return {
    action: 'propose_revocation',
    reasonCode: detection.reasonCode,
    target: {
      subjectId: verified.subjectId,
      deviceId: verified.deviceId,
    },
  };
}
