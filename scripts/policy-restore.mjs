import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectPolicy } from './policy-diff.mjs';

const ROOT = resolve(import.meta.dirname, '..');

function git(args, encoding = 'utf8') {
  return execFileSync('git', ['-C', ROOT, ...args], {
    encoding,
    timeout: 5000,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'ignore'],
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
  });
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function currentFingerprint(path) {
  const full = resolve(ROOT, path);
  return existsSync(full) ? sha256(readFileSync(full)) : 'missing';
}

function changeSetId(result) {
  const state = result.changes
    .map(item => [item.file, currentFingerprint(item.file)])
    .sort((a, b) => a[0].localeCompare(b[0]));
  return sha256(JSON.stringify([result.version.commit, state])).slice(0, 12);
}

function planLines(result, id) {
  const lines = [
    `복원할 버전: ${result.version.commit.slice(0, 12)} 「${result.version.label}」`,
    '사본 검증: 통과',
  ];

  if (!result.changes.length) {
    lines.push('되돌릴 항목: 없음');
    lines.push('현재 시험 정책이 검증된 안전 정책과 같습니다.');
    return lines;
  }

  lines.push(`되돌릴 항목 (${result.changes.length}개):`);
  for (const item of result.changes) {
    lines.push(`  ${item.file}  +${item.added} / -${item.removed}`);
  }
  lines.push(
    '',
    `변경세트 ID: ${id}`,
    `실행하려면: npm run policy:restore -- --confirm ${id}`,
    '',
    '대상 목록 밖의 다른 서비스 규칙·감사 이력·DB 자료는 변경하지 않습니다.',
  );
  return lines;
}

export function restoreVerifiedPolicy({ confirm = null } = {}) {
  const result = inspectPolicy();
  if (!result.ok) {
    return {
      ok: false,
      applied: false,
      output: `중단: ${result.reason}\n복원하지 않았습니다.\n`,
    };
  }

  const id = changeSetId(result);
  const plan = planLines(result, id);

  if (!result.changes.length) {
    return { ok: true, applied: false, output: `${plan.join('\n')}\n` };
  }

  if (confirm === null) {
    return { ok: true, applied: false, output: `${plan.join('\n')}\n` };
  }

  if (confirm !== id) {
    return {
      ok: false,
      applied: false,
      output: `${plan.join('\n')}\n\n중단: 확인한 변경세트 ID가 현재 상태와 다릅니다. 다시 미리보기하세요.\n`,
    };
  }

  // 확인 직후 다시 계산해 미리보기 이후 정책 파일이 바뀌었는지 확인합니다.
  const fresh = inspectPolicy();
  if (!fresh.ok) {
    return { ok: false, applied: false, output: `중단: ${fresh.reason}\n복원하지 않았습니다.\n` };
  }
  const freshId = changeSetId(fresh);
  if (freshId !== id) {
    return {
      ok: false,
      applied: false,
      output: '중단: 미리보기 이후 정책 파일이 바뀌었습니다. 다시 미리보기하세요.\n',
    };
  }

  const changed = new Set(fresh.changes.map(item => item.file));
  for (const path of fresh.checkedFiles) {
    if (!changed.has(path)) continue;
    const baseline = git(['show', `${fresh.version.commit}:${path}`], 'buffer');
    writeFileSync(resolve(ROOT, path), baseline, { flag: 'w' });
  }

  const after = inspectPolicy();
  if (!after.ok || after.changes.length) {
    return {
      ok: false,
      applied: true,
      output: '복원 파일을 썼지만 사후 검증이 끝나지 않았습니다. 추가 변경 없이 상태를 확인하세요.\n',
    };
  }

  return {
    ok: true,
    applied: true,
    output: [
      ...plan,
      '',
      `복원 완료: 정책 파일 ${changed.size}개`,
      '사후 검증: 안전 정책 사본과 일치',
      '다른 서비스 규칙·감사 이력·DB 자료는 변경하지 않았습니다.',
      '',
    ].join('\n'),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const at = process.argv.indexOf('--confirm');
  const confirm = at >= 0 && process.argv[at + 1] ? process.argv[at + 1] : null;
  const result = restoreVerifiedPolicy({ confirm });
  process.stdout.write(result.output);
  if (!result.ok) process.exitCode = 1;
}
