import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const planPath = resolve(root, 'docs', 'STAGE12_RETEST_PLAN.json');
const resultsPath = resolve(root, 'artifacts', 'stage12-retest-results.json');
const tablePath = resolve(root, 'artifacts', 'stage12-retest-table.md');

const REQUEST_ID = /^[A-Za-z0-9._:-]{1,160}$/u;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

function escapeCell(value) {
  return String(value ?? '').replace(/\|/gu, '\\|').replace(/\r?\n/gu, ' ');
}

async function loadJson(path, fallback = null) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return fallback;
    throw error;
  }
}

function validatePlan(plan) {
  if (plan?.schema !== 'aleph.retest.plan.v1' || !Array.isArray(plan.cases)
      || plan.cases.length !== 41 || plan.total !== 41) {
    throw new Error('12단계 재시험 계획은 정확히 41개여야 합니다.');
  }
  const ids = new Set();
  for (const item of plan.cases) {
    if (!item?.id || ids.has(item.id) || !Number.isInteger(item.stage)
        || item.stage < 1 || item.stage > 11
        || !['normal', 'forbidden'].includes(item.kind)
        || typeof item.request !== 'string' || typeof item.expected !== 'string') {
      throw new Error(`잘못된 재시험 계획 항목: ${item?.id ?? 'unknown'}`);
    }
    ids.add(item.id);
  }
  return ids;
}

function validateObservation(entry, knownIds) {
  if (!knownIds.has(entry?.id)) throw new Error(`알 수 없는 시험 ID: ${entry?.id ?? 'unknown'}`);
  if (typeof entry.actual !== 'string' || !entry.actual.trim()) {
    throw new Error(`${entry.id}: 실제 결과가 필요합니다.`);
  }
  if (typeof entry.requestId !== 'string' || !REQUEST_ID.test(entry.requestId)) {
    throw new Error(`${entry.id}: 요청 ID가 필요합니다.`);
  }
  if (typeof entry.checkedAt !== 'string' || !UTC.test(entry.checkedAt)
      || !Number.isFinite(Date.parse(entry.checkedAt))) {
    throw new Error(`${entry.id}: UTC 확인 시각이 필요합니다.`);
  }
  return Object.freeze({
    id: entry.id,
    actual: entry.actual.trim(),
    requestId: entry.requestId,
    checkedAt: entry.checkedAt,
  });
}

function toTable(plan, observed) {
  const lines = [
    '# 1~11단계 정상·금지 요청 실측표',
    '',
    '> 실제 요청/판정 결과가 기록되지 않은 항목은 모두 `미실행`입니다. 기대 결과만으로 통과 처리하지 않습니다.',
    '',
    '| ID | 단계 | 구분 | 요청 | 기대 결과 | 실제 API/판정 결과 | 요청 ID | 확인 시각 | 상태 |',
    '|---|---:|---|---|---|---|---|---|---|',
  ];
  for (const item of plan.cases) {
    const result = observed.get(item.id);
    lines.push([
      item.id,
      item.stage,
      item.kind === 'normal' ? '정상' : '금지',
      item.request,
      item.expected,
      result?.actual ?? '-',
      result?.requestId ?? '-',
      result?.checkedAt ?? '-',
      result ? '실측' : '미실행',
    ].map(escapeCell).join(' | ').replace(/^/u, '| ').replace(/$/u, ' |'));
  }
  const normalMeasured = plan.cases.filter(x => x.kind === 'normal' && observed.has(x.id)).length;
  const forbiddenMeasured = plan.cases.filter(x => x.kind === 'forbidden' && observed.has(x.id)).length;
  const measured = observed.size;
  lines.push('', `실측 ${measured}/41 · 정상 요청 실측 ${normalMeasured}건 · 금지 요청 실측 ${forbiddenMeasured}건 · 미실행 ${41 - measured}건`, '');
  return lines.join('\n');
}

const plan = await loadJson(planPath);
const knownIds = validatePlan(plan);
const command = process.argv[2];

await mkdir(resolve(root, 'artifacts'), { recursive: true });

if (command === '--record') {
  const [id, actual, requestId, checkedAt] = process.argv.slice(3);
  const next = validateObservation({ id, actual, requestId, checkedAt }, knownIds);
  const current = await loadJson(resultsPath, { schema: 'aleph.retest.results.v1', results: [] });
  if (current?.schema !== 'aleph.retest.results.v1' || !Array.isArray(current.results)) {
    throw new Error('실측 결과 파일 형식이 올바르지 않습니다.');
  }
  const results = current.results
    .filter(item => item?.id !== id)
    .map(item => validateObservation(item, knownIds));
  results.push(next);
  await writeFile(resultsPath, JSON.stringify({ schema: 'aleph.retest.results.v1', results }, null, 2) + '\n', 'utf8');
  console.log(`${id} 실측 결과를 기록했습니다. 통과 여부는 자동으로 만들지 않습니다.`);
}

const saved = await loadJson(resultsPath, { schema: 'aleph.retest.results.v1', results: [] });
if (saved?.schema !== 'aleph.retest.results.v1' || !Array.isArray(saved.results)) {
  throw new Error('실측 결과 파일 형식이 올바르지 않습니다.');
}
const observed = new Map();
for (const raw of saved.results) {
  const entry = validateObservation(raw, knownIds);
  observed.set(entry.id, entry);
}

await writeFile(tablePath, toTable(plan, observed) + '\n', 'utf8');
console.log(`재시험 표 생성: ${tablePath}`);
console.log(`실측 ${observed.size}/41 · 미실행 ${41 - observed.size}/41`);
