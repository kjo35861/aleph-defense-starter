import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { safeText } from './redact.mjs';

const DEFAULT_FIXTURE = new URL('../fixtures/brute-force.json', import.meta.url);

function safeLevel(value) {
  return Number.isFinite(Number(value)) ? Number(value) : null;
}

export async function readAlerts(source = DEFAULT_FIXTURE) {
  const fixture = JSON.parse(await readFile(source, 'utf8'));
  if (!Array.isArray(fixture.alerts)) {
    throw new Error('brute-force fixture의 alerts 배열을 확인해 주세요.');
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
  const rows = await readAlerts();
  for (const row of rows) {
    process.stdout.write(`${JSON.stringify(row)}\n`);
  }
}
