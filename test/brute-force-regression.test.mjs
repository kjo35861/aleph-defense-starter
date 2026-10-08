import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/brute-force/decide.mjs';
import { readAlerts } from '../xdr/brute-force/read-alerts.mjs';

const description = '같은 주소에서 2분 안에 로그인 실패 48건이 쌓였습니다.';
function alert(mitre, text = description, count = '48', level = 12) {
  return { rule: { mitre, description: text, level }, data: { count, srcip: '203.0.113.10' } };
}

test('명확한 공격은 MITRE 태그 누락이나 하위 기법 표기에도 차단한다', async () => {
  for (const mitre of [undefined, [], ['T1110'], ['T1110.001'], { id: ['T1110.001'] }]) {
    assert.equal((await decide(alert(mitre))).action, 'block');
  }
});

test('대량 실패 뒤 성공은 공격 근거를 없애지 않는다', async () => {
  assert.equal((await decide(alert(['T1110'], '같은 주소에서 2분 안에 로그인 실패 48건 뒤에 성공했습니다.'))).action, 'block');
  assert.equal((await decide(alert(['T1110'], '같은 계정 로그인 실패 1건 뒤에 성공했습니다.', '1', 3))).action, 'record');
  assert.equal((await decide(alert([], '로그인이 성공했습니다.', '0', 3))).action, 'record');
});

test('약한 실패 신호는 태그가 없어도 알림을 유지한다', async () => {
  assert.equal((await decide(alert([], '같은 주소에서 로그인 실패 6건이 있습니다.', '6', 6))).action, 'alert');
});

test('중간 수준 반복 실패 뒤 성공은 정상 기록으로 낮추지 않는다', async () => {
  for (const text of [
    '같은 계정 로그인 실패 4건 뒤에 성공했습니다.',
    '수업 시작 무렵 로그인 실패 4건 뒤에 성공했습니다.',
    '로그인 실패 4건이 있고 그 뒤 성공했습니다.',
  ]) {
    assert.equal((await decide(alert(['T1110'], text, '4', 6))).action, 'alert');
    assert.equal((await decide({ ruleLevel: 6, description: text })).action, 'alert');
  }
});

test('원본 및 다섯 필드 추출 입력의 모든 반환값이 일치한다', async () => {
  const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  for (let i = 0; i < rows.length; i++) {
    assert.deepEqual(await decide(rows[i]), await decide(fixture.alerts[i]), fixture.alerts[i].id);
  }
});
