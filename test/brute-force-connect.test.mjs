import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from '../xdr/brute-force/connect.mjs';

test('근거·신뢰도·주소 검증, 재판정, 중복, 만료 및 로그', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'xdr-connect-test-'));
  const now = Date.parse('2026-10-08T00:00:00Z');
  const options = { directory, now };
  const rules = async () => JSON.parse(await readFile(join(directory, 'deny-rules.json'), 'utf8')).rules;
  const block = { action: 'block', confidence: 0.95, reason: 'same-source-burst-failures' };
  const source = { id: 'test-attack', timestamp: '2020-01-01T00:00:00Z', data: { srcip: '203.0.113.10' } };
  await connect(source, block, options);
  await connect(source, block, options);
  assert.equal((await rules()).length, 1);
  assert.equal((await rules())[0].expiresAt, '2026-10-08T00:15:00.000Z');
  for (const candidate of [
    { sourceAddress: '203.0.113.12' },
    { alertId: 'bad-address', sourceAddress: 'invalid' },
  ]) await connect(candidate, block, options);
  await connect({ alertId: 'weak', sourceAddress: '203.0.113.13' }, { ...block, confidence: 0.5 }, options);
  assert.equal((await rules()).length, 1);
  await connect(source, { action: 'record', confidence: 0.1, reason: 'no-matching-pattern' }, options);
  assert.equal((await rules()).length, 0);
  await connect({ alertId: 'flat', sourceAddress: '203.0.113.14' }, block, options);
  assert.equal((await rules()).length, 1);
  await connect({ id: 'normal' }, { action: 'record', confidence: 0.1 }, { directory, now: now + 900000 });
  assert.equal((await rules()).length, 0);
  const logs = (await readFile(join(directory, 'alerts.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(logs.length, 6);
  assert.ok(logs.every(line => line.action === 'block'));
});

test('손상된 규칙 파일을 덮어쓰지 않는다', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'xdr-connect-test-'));
  const file = join(directory, 'deny-rules.json');
  await writeFile(file, '{broken');
  await assert.rejects(connect({ id: 'test' }, { action: 'record', confidence: 0.1 }, { directory }));
  assert.equal(await readFile(file, 'utf8'), '{broken');
});
