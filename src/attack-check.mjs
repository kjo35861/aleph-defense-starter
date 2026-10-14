// 12단계 제출용 자기점검 목록입니다.
// 실제 요청 기록이 없는 항목은 결과를 추정하지 않고 not_run으로 남깁니다.

export async function runAttackChecks(config) {
  if (config.step !== 12) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

  return [
    {
      attackId: 'registered_device_allow',
      expected: '등록 기기의 허용된 메모 한 건 GET은 allow',
      observed: 'not_run',
    },
    {
      attackId: 'unregistered_device_deny',
      expected: '미등록 기기는 deny / device_not_registered',
      observed: 'not_run',
    },
    {
      attackId: 'composite_anomaly_step_up',
      expected: '기존 복합 이상 요청은 step_up / step_up_required',
      observed: 'not_run',
    },
    {
      attackId: 'composite_reauthenticated_allow',
      expected: '최근 재인증된 같은 요청은 allow',
      observed: 'not_run',
    },
    {
      attackId: 'normal_reads_observed',
      expected: '정상 조회 30건은 observe',
      observed: 'not_run',
    },
    {
      attackId: 'burst_read_detected',
      expected: '10분 안 조회 121건은 propose_revocation / burst_read',
      observed: 'not_run',
    },
    {
      attackId: 'composite_normal_observed',
      expected: '평소 네트워크의 대량 조회는 복합 의심으로 탐지하지 않음',
      observed: 'not_run',
    },
    {
      attackId: 'composite_unusual_detected',
      expected: 'unusual 네트워크와 대량 조회가 함께 있을 때만 propose_revocation',
      observed: 'not_run',
    },
    {
      attackId: 'revocation_proposal_target',
      expected: '회수 제안은 확인된 가상 기기 한 개와 이유 코드를 포함',
      observed: 'not_run',
    },
  ];
}
