import { decide } from './decider.mjs';
import { detect, detectDeviceEvents, proposeRevocation } from './detect.mjs';

const baseRequest = {
  schema: 'aleph.decision.v1',
  classId: 'class_fixture',
  projectId: 'project_fixture',
  subjectId: 'learner_fixture',
  deviceId: 'a'.repeat(16),
  service: 'notes',
  method: 'GET',
  path: '/notes/demo',
  route: 'GET /notes/:id',
  queryLength: 0,
  querySha256: '0'.repeat(64),
  at: '2026-10-01T00:00:00.000Z',
  policyRevision: 1,
  deviceRegistered: true,
  stepUp: { verified: false, authAgeSeconds: null },
  recentEvents: [],
  signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
};

function legacyReads(count) {
  const start = Date.UTC(2026, 9, 1, 0, 0, 0);
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * 2000).toISOString(),
    method: 'GET',
    identity: { sub: 'learner_fixture' },
  }));
}

function deviceReads(count, patch = {}) {
  const start = Date.UTC(2026, 9, 1, 0, 0, 0);
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * 2000).toISOString(),
    subjectId: 'learner_fixture',
    deviceId: 'a'.repeat(16),
    method: 'GET',
    decision: 'allow',
    network: 'unusual',
    source: 'local_virtual_fixture',
    ...patch,
  }));
}

// Step 12 self-check: preserve prior access/detection regressions while the operations room and measured retest table are added.
export async function runAttackChecks(config) {
  if (config.step !== 12) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

  const registered = await decide({ ...baseRequest, requestId: 'self-check-registered-device' });
  const unregistered = await decide({
    ...baseRequest, requestId: 'self-check-unregistered-device', deviceRegistered: false,
  });
  const suspicious = await decide({
    ...baseRequest,
    requestId: 'self-check-composite-anomaly',
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
    signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
  });
  const reauthenticated = await decide({
    ...baseRequest,
    requestId: 'self-check-composite-reauthenticated',
    stepUp: { verified: true, authAgeSeconds: 60 },
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
    signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
  });

  const normalDetection = detect(legacyReads(30));
  const burstDetection = detect(legacyReads(121));
  const compositeNormal = detectDeviceEvents(deviceReads(121, { network: 'usual' }));
  const compositeSuspicious = detectDeviceEvents(deviceReads(121));
  const proposal = proposeRevocation(burstDetection, {
    subjectId: 'learner_fixture',
    deviceId: 'a'.repeat(16),
  });

  return [
    {
      attackId: 'registered_device_allow',
      expected: '등록 기기의 허용된 메모 한 건 GET은 allow',
      observed: `${registered.decision} / ${registered.reasonCode}`,
    },
    {
      attackId: 'unregistered_device_deny',
      expected: '미등록 기기는 deny / device_not_registered',
      observed: `${unregistered.decision} / ${unregistered.reasonCode}`,
    },
    {
      attackId: 'composite_anomaly_step_up',
      expected: '기존 복합 이상 요청은 step_up / step_up_required',
      observed: `${suspicious.decision} / ${suspicious.reasonCode}`,
    },
    {
      attackId: 'composite_reauthenticated_allow',
      expected: '최근 재인증된 같은 요청은 allow',
      observed: `${reauthenticated.decision} / ${reauthenticated.reasonCode}`,
    },
    {
      attackId: 'normal_reads_observed',
      expected: '정상 조회 30건은 observe',
      observed: normalDetection.action,
    },
    {
      attackId: 'burst_read_detected',
      expected: '10분 안 조회 121건은 propose_revocation / burst_read',
      observed: `${burstDetection.action} / ${burstDetection.reasonCode ?? 'none'}`,
    },
    {
      attackId: 'composite_normal_observed',
      expected: '평소 네트워크의 대량 조회는 복합 의심으로 탐지하지 않음',
      observed: compositeNormal.action,
    },
    {
      attackId: 'composite_unusual_detected',
      expected: 'unusual 네트워크와 대량 조회가 함께 있을 때만 propose_revocation',
      observed: `${compositeSuspicious.action} / ${compositeSuspicious.reasonCode ?? 'none'}`,
    },
    {
      attackId: 'revocation_proposal_target',
      expected: '회수 제안은 확인된 가상 기기 한 개와 이유 코드를 포함',
      observed: proposal
        ? `${proposal.action} / ${proposal.reasonCode} / targeted=${Boolean(proposal.target?.deviceId)}`
        : 'no proposal',
    },
  ];
}
