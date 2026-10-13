import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(import.meta.dirname, '..');
const DEFAULT_SNAPSHOT = 'policy/verified-policy.json';
const SCHEMA = 'aleph.policy.verified.v1';
const COMMIT = /^[0-9a-f]{40}$/u;
const BLOB = /^[0-9a-f]{40}$/u;
const MAX_SNAPSHOT_BYTES = 64 * 1024;
const VERIFIED_SNAPSHOT_SHA256 = '1e017e0123aee650efbd0a07e00b0378de77c601738f25421530f5ef3804c0fd';
const UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

function git(args) {
  return execFileSync('git', ['-C', ROOT, ...args], {
    encoding: 'utf8',
    timeout: 5000,
    maxBuffer: 2 * 1024 * 1024,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'ignore'],
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
  }).trim();
}

function stop(stage, reason) {
  return { ok: false, stage, reason };
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function verifySnapshot(snapshotPath = DEFAULT_SNAPSHOT) {
  const fullPath = resolve(ROOT, snapshotPath);
  let snapshot;

  try {
    if (!existsSync(fullPath)) return stop('missing', `검증된 안전 정책 사본이 없습니다: ${snapshotPath}`);
    const info = statSync(fullPath);
    if (!info.isFile() || info.size > MAX_SNAPSHOT_BYTES) {
      return stop('invalid', '안전 정책 사본 파일 형식이나 크기가 올바르지 않습니다.');
    }
    const raw = readFileSync(fullPath);
    // Git의 Windows 체크아웃(CRLF)과 저장소 원본(LF)은 같은 정책 사본으로 봅니다.
    // 줄바꿈만 정규화하고 JSON 내용 자체가 바뀌면 고정 지문 검증은 실패합니다.
    const normalizedRaw = raw.toString('utf8').replace(/\r\n/gu, '\n');
    const snapshotHash = createHash('sha256').update(normalizedRaw, 'utf8').digest('hex');
    if (snapshotHash !== VERIFIED_SNAPSHOT_SHA256) {
      return stop('unverified', '안전 정책 사본 자체의 고정 지문이 침해 전 검증값과 다릅니다.');
    }
    snapshot = JSON.parse(normalizedRaw);
  } catch {
    return stop('invalid', '안전 정책 사본을 읽거나 검증할 수 없습니다.');
  }

  if (!plainObject(snapshot)
      || snapshot.schema !== SCHEMA
      || !COMMIT.test(snapshot.verifiedCommit ?? '')
      || typeof snapshot.label !== 'string'
      || !snapshot.label.trim()
      || typeof snapshot.capturedAt !== 'string'
      || !UTC_TIME.test(snapshot.capturedAt)
      || typeof snapshot.verifiedAt !== 'string'
      || !UTC_TIME.test(snapshot.verifiedAt)
      || !plainObject(snapshot.files)
      || !Object.keys(snapshot.files).length
      || Object.entries(snapshot.files).some(([path, blob]) =>
        path.startsWith('/') || path.includes('..') || !BLOB.test(blob ?? ''))) {
    return stop('invalid', '안전 정책 사본의 항목·커밋·파일 지문 형식이 맞지 않습니다.');
  }

  try {
    git(['cat-file', '-e', `${snapshot.verifiedCommit}^{commit}`]);
    git(['merge-base', '--is-ancestor', snapshot.verifiedCommit, 'HEAD']);
  } catch {
    return stop('unverified', '사본 커밋이 현재 자료실의 검증 가능한 이전 기록이 아닙니다.');
  }

  const actualLabel = git(['log', '-1', '--format=%s', snapshot.verifiedCommit]);
  if (actualLabel !== snapshot.label) {
    return stop('unverified', '사본 이름과 기준 커밋 제목이 일치하지 않습니다.');
  }

  const capturedAt = Date.parse(snapshot.capturedAt);
  const verifiedAt = Date.parse(snapshot.verifiedAt);
  const checkpointAt = Date.parse(git(['show', '-s', '--format=%cI', snapshot.verifiedCommit]));
  if (!Number.isFinite(capturedAt) || !Number.isFinite(verifiedAt) || !Number.isFinite(checkpointAt)
      || capturedAt > verifiedAt || verifiedAt !== checkpointAt) {
    return stop('unverified', '안전 정책 사본의 사전 검증 시각이 9단계 저장점과 일치하지 않습니다.');
  }

  for (const [path, expectedBlob] of Object.entries(snapshot.files)) {
    let actualBlob;
    try {
      actualBlob = git(['rev-parse', `${snapshot.verifiedCommit}:${path}`]);
    } catch {
      return stop('unverified', `사본 커밋에 정책 파일이 없습니다: ${path}`);
    }
    if (actualBlob !== expectedBlob) {
      return stop('unverified', `안전 정책 사본 검증 실패: ${path} 지문 불일치`);
    }
  }

  return {
    ok: true,
    commit: snapshot.verifiedCommit,
    label: snapshot.label,
    capturedAt: snapshot.capturedAt,
    verifiedAt: snapshot.verifiedAt,
    files: Object.keys(snapshot.files).sort(),
  };
}

export function inspectPolicy(snapshotPath = DEFAULT_SNAPSHOT) {
  const verified = verifySnapshot(snapshotPath);
  if (!verified.ok) return verified;

  const literalPaths = verified.files.map(path => `:(literal)${path}`);
  let numstat;
  let diff;

  try {
    numstat = git(['diff', '--no-color', '--no-ext-diff', '--numstat',
      verified.commit, '--', ...literalPaths]);
    diff = git(['diff', '--no-color', '--no-ext-diff',
      verified.commit, '--', ...literalPaths]);
  } catch {
    return stop('compare_failed', '현재 시험 정책과 안전 사본의 차이를 계산하지 못했습니다.');
  }

  const changes = numstat
    ? numstat.split(/\r?\n/u).filter(Boolean).map(line => {
      const [added, removed, file] = line.split('\t');
      return { file, added, removed };
    })
    : [];

  return {
    ok: true,
    version: {
      commit: verified.commit,
      label: verified.label,
      capturedAt: verified.capturedAt,
      verifiedAt: verified.verifiedAt,
    },
    checkedFiles: verified.files,
    changes,
    diff,
  };
}

export function formatReport(result) {
  if (!result.ok) {
    return [
      `중단: ${result.reason}`,
      '복원 실행·파일 수정·운영 정책 변경은 하지 않았습니다.',
      '',
    ].join('\n');
  }

  const lines = [
    `복원할 버전: ${result.version.commit.slice(0, 12)} 「${result.version.label}」`,
    `사본 검증: 통과 (정책 파일 ${result.checkedFiles.length}개)`,
    `사본 시각: ${result.version.capturedAt}`,
    `검증 시각: ${result.version.verifiedAt}`,
  ];

  if (!result.changes.length) {
    lines.push('변경 범위: 없음 (현재 시험 정책과 안전 사본이 같습니다)');
  } else {
    lines.push(`변경 범위: 정책 파일 ${result.changes.length}개`);
    for (const item of result.changes) {
      lines.push(`  ${item.file}  +${item.added} / -${item.removed}`);
    }
    lines.push('', '--- 안전 사본(복원할 버전) / +++ 현재 시험 정책');
    lines.push(result.diff);
  }

  lines.push('', '미리보기만 수행했습니다. 실제 운영 정책과 파일은 변경하지 않았습니다.');
  return `${lines.join('\n')}\n`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const at = process.argv.indexOf('--snapshot');
  const snapshotPath = at >= 0 && process.argv[at + 1] ? process.argv[at + 1] : DEFAULT_SNAPSHOT;
  const result = inspectPolicy(snapshotPath);
  process.stdout.write(formatReport(result));
  if (!result.ok) process.exitCode = 1;
}
