// 확인용 읽기 모듈입니다. privilege decide.mjs에서는 import하지 않습니다.
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { safeText } from '../brute-force/redact.mjs';

const DEFAULT_FIXTURE = new URL('../fixtures/privilege.json', import.meta.url);

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
    // 원본 경보 내용이나 오류에 포함된 비밀값을 노출하지 않습니다.
    throw new Error('privilege 경보 파일을 읽거나 JSON으로 해석할 수 없습니다.');
  }

  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('privilege 경보 묶음 형식을 확인해 주세요.');
  }

  const rows = fixture.alerts.map(alert => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: safeLevel(alert?.rule?.level),
    description: safeText(alert?.rule?.description),
  }));

  if (rows.length !== fixture.alerts.length) {
    throw new Error('경보 건수와 추출 건수가 다릅니다.');
  }

  return rows;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    for (const row of await readAlerts()) {
      process.stdout.write(`${JSON.stringify(row)}\n`);
    }
  } catch {
    console.error('privilege 경보 읽기 또는 추출에 실패했습니다.');
    process.exitCode = 1;
  }
}
