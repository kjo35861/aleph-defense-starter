// patterns.json의 실행용 조건. 회귀 테스트에서 원본과 일치하는지 검사한다.
// 심판에서는 파일 시스템 및 npm 모듈을 사용할 수 없다.
export const patterns = [
  {
    name: 'same-source-burst-failures',
    matchAll: ['(\\d+분 안|로그인 실패\\s*\\d+건|실패가\\s*\\d+건|실패\\s*\\d+건|계정\\s*\\d+개.*로그인 실패|계정 이름을 바꿔)'],
  },
  {
    name: 'same-password-multi-account',
    matchAll: ['같은 비밀번호', '(여러 계정|계정\\s*\\d+개|서로 다른 계정)'],
  },
];
