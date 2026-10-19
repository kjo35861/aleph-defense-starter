// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions } = {}) {
      const root = document.createElement('section');
      const deviceLabels = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionLabels = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };

      function line(parent, label, value) {
        const p = document.createElement('p');
        p.textContent = label + ': ' + (value == null || value === '' ? '확인 불가' : String(value));
        parent.appendChild(p);
      }

      function section(title, resource, showData) {
        const group = document.createElement('section');
        const heading = document.createElement('h3');
        heading.textContent = title;
        group.appendChild(heading);
        const mode = resource?.mode;
        if (mode === 'demo') line(group, '자료 모드', '예제 자료');
        if (mode === 'disconnected') line(group, '연결 상태', '연결 없음');
        if (mode === 'unknown') line(group, '연결 상태', '확인 불가');

        if (resource?.status === 'loading') {
          line(group, '조회 상태', '불러오는 중');
        } else if (resource?.status === 'error') {
          const message = resource.error?.message;
          line(group, '조회 상태', '연결 실패' + (typeof message === 'string' && message ? ': ' + message : ''));
        } else if (resource?.status === 'ok') {
          showData(group, resource.data);
        } else {
          line(group, '조회 상태', '확인 불가');
        }
        root.appendChild(group);
      }

      section('현재 계정 및 로그인 정보', me, (group, data) => {
        line(group, '사용자 이름', data?.user?.label);
        line(group, '사용자 ID', data?.user?.id);
        line(group, '현재 기기 이름', data?.device?.label);
        line(group, '현재 기기 ID', data?.device?.id);
        line(group, '현재 기기 보안 상태', (deviceLabels[data?.device?.status] ?? '확인 불가') + ' (' + (data?.device?.status ?? 'unknown') + ')');
        line(group, '현재 세션 ID', data?.session?.id);
        line(group, '현재 세션 상태', (sessionLabels[data?.session?.status] ?? '확인 불가') + ' (' + (data?.session?.status ?? 'unknown') + ')');
      });

      section('기기 목록', devices, (group, data) => {
        if (!Array.isArray(data)) {
          line(group, '기기 정보', '확인 불가');
          return;
        }
        if (data.length === 0) line(group, '기기 목록', '등록된 기기 없음');
        for (const device of data) {
          const item = document.createElement('div');
          line(item, '기기 이름', device?.label);
          line(item, '기기 ID', device?.id);
          line(item, '보안 상태', (deviceLabels[device?.status] ?? '확인 불가') + ' (' + (device?.status ?? 'unknown') + ')');
          group.appendChild(item);
        }
      });

      section('세션 목록', sessions, (group, data) => {
        if (!Array.isArray(data)) {
          line(group, '세션 정보', '확인 불가');
          return;
        }
        if (data.length === 0) line(group, '세션 목록', '세션 없음');
        for (const session of data) {
          const item = document.createElement('div');
          line(item, '세션 ID', session?.id);
          line(item, '세션 상태', (sessionLabels[session?.status] ?? '확인 불가') + ' (' + (session?.status ?? 'unknown') + ')');
          group.appendChild(item);
        }
      });
      return root;
    },
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
