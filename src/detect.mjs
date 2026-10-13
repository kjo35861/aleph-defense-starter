// 9단계 가상 사건 탐지와 회수 제안입니다.
// 실제 회수 API 호출·기기 권한 변경·토큰 기록은 하지 않습니다.

const SUBJECT = /^[A-Za-z0-9_-]{1,128}$/u;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const DECISIONS = new Set(['allow', 'deny', 'step_up']);
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// 제공된 가상 사건에서 판정에 필요한 최소 값만 새 객체로 옮깁니다.
// 메모 본문·토큰·실명·헤더 같은 나머지 값은 읽거나 저장하지 않습니다.
function readEvent(event) {
  if (!isPlainObject(event) || !isPlainObject(event.identity)) return null;

  const subject = event.identity.sub;
  const method = event.method;
  const time = typeof event.at === 'string' ? Date.parse(event.at) : Number.NaN;

  if (typeof subject !== 'string' || !SUBJECT.test(subject)
      || typeof method !== 'string' || !METHODS.has(method)
      || !Number.isFinite(time)) {
    return null;
  }

  return Object.freeze({
    subject,
    deviceId: typeof event.deviceId === 'string' && DEVICE_ID.test(event.deviceId)
      ? event.deviceId
      : null,
    method,
    decision: DECISIONS.has(event.decision) ? event.decision : null,
    time,
  });
}

export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  return events.map(readEvent).filter(Boolean);
}

function findBurst(events) {
  const bySubject = new Map();

  for (const event of readDetectionEvents(events)) {
    if (event.method !== 'GET') continue;
    const list = bySubject.get(event.subject) ?? [];
    list.push(event);
    bySubject.set(event.subject, list);
  }

  for (const [subject, reads] of bySubject) {
    reads.sort((a, b) => a.time - b.time);
    let start = 0;

    for (let end = 0; end < reads.length; end += 1) {
      while (reads[end].time - reads[start].time >= WINDOW_MS) start += 1;
      if (end - start + 1 > LIMIT) {
        return {
          subject,
          window: reads.slice(start, end + 1),
        };
      }
    }
  }

  return null;
}

export function detect(events) {
  const found = findBurst(events);
  return found
    ? { action: 'propose_revocation', reasonCode: 'burst_read', subject: found.subject }
    : { action: 'observe' };
}

// 탐지 결과와 엔진이 확인한 가상 사용자·기기 한 쌍을 결합해
// 실제 집행이 아닌 "회수 제안" 결과만 만듭니다.
export function proposeRevocation(detection, verified) {
  if (!isPlainObject(detection)
      || detection.action !== 'propose_revocation'
      || detection.reasonCode !== 'burst_read'
      || typeof detection.subject !== 'string') {
    return null;
  }

  if (!isPlainObject(verified)
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
// 기존 detect(events) 계약은 유지하고, 확인된 가상 기기 사건만 별도로 읽습니다.
// 지역은 사용하지 않고, 같은 사용자·같은 기기의 GET allow + unusual 네트워크를 묶습니다.
export function detectDeviceEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const groups = new Map();
  for (const event of events) {
    if (!isPlainObject(event)) continue;

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
