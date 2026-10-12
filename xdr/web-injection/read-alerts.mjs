// 로컬 확인 전용. 격리 환경에서 실행하는 decide.mjs에서는 import하지 않는다.
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { safeText } from '../brute-force/redact.mjs';

const DEFAULT_FIXTURE = new URL('../fixtures/web-injection.json', import.meta.url);

function safeLevel(value) {
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  if (typeof value === 'string' && !value.trim()) return null;
  const level = Number(value);
  return Number.isFinite(level) ? level : null;
}

export async function readAlerts(source = DEFAULT_FIXTURE) {
  let fixture;
  try {
    fixture = JSON.parse(await readFile(source, 'utf8'));
  } catch {
    // 파싱 오류에 원본 경보나 비밀값 일부가 포함되지 않도록 한다.
    throw new Error('web-injection 경보 파일을 읽거나 JSON으로 해석할 수 없습니다.');
  }
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('web-injection 경보 묶음 형식을 확인해 주세요.');
  }
  return fixture.alerts.map(alert => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: safeLevel(alert?.rule?.level),
    description: safeText(alert?.rule?.description),
  }));
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    for (const row of await readAlerts()) {
      process.stdout.write(`${JSON.stringify(row)}\n`);
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
