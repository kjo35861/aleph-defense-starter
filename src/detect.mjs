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


// 9단계 복합 가상 사건 전용 탐지입니다.
// 기존 detect(events) 계약은 유지하고, 엔진/심판이 확인한 가상 기기 사건만 별도로 읽습니다.
// 메모 내용·토큰·실명·지역은 읽지 않으며, 같은 사용자·같은 기기의 GET allow 사건만 묶습니다.
export function detectDeviceEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const groups = new Map();
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) continue;

    const subject = event.subjectId;
    const deviceId = event.deviceId;
    const at = Date.parse(event.at);

    if (event.source !== 'local_virtual_fixture'
        || event.method !== 'GET'
        || event.decision !== 'allow'
        || typeof subject !== 'string' || !SUBJECT.test(subject)
        || typeof deviceId !== 'string' || !DEVICE_ID.test(deviceId)
        || !Number.isFinite(at)
        || !['usual', 'unusual'].includes(event.network)) {
      continue;
    }

    const key = `${subject}:${deviceId}`;
    const group = groups.get(key) ?? { subject, deviceId, events: [] };
    group.events.push({ at, unusual: event.network === 'unusual' });
    groups.set(key, group);
  }

  for (const { subject, deviceId, events: items } of groups.values()) {
    items.sort((a, b) => a.at - b.at);
    let start = 0;
    let unusualCount = 0;

    for (let end = 0; end < items.length; end += 1) {
      unusualCount += Number(items[end].unusual);

      while (items[end].at - items[start].at >= WINDOW_MS) {
        unusualCount -= Number(items[start].unusual);
        start += 1;
      }

      // 대량 조회와 평소와 다른 네트워크가 같은 10분 창에 함께 있을 때만 의심으로 봅니다.
      if (end - start + 1 > LIMIT && unusualCount > 0) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
          deviceId,
        };
      }
    }
  }

  return { action: 'observe' };
}
