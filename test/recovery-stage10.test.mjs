import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { inspectPolicy, verifySnapshot } from '../scripts/policy-diff.mjs';
import { restoreVerifiedPolicy } from '../scripts/policy-restore.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const SNAPSHOT = resolve(ROOT, 'policy/verified-policy.json');
const sha256 = value => createHash('sha256').update(value).digest('hex');

test('verified policy snapshot is anchored to the stage 9 checkpoint time', () => {
  const result = verifySnapshot();
  assert.equal(result.ok, true);
  assert.equal(result.capturedAt, '2026-10-13T07:29:34.000Z');
  assert.equal(result.verifiedAt, '2026-10-13T07:29:34.000Z');
});

test('missing or modified snapshot fails closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aleph-stage10-'));
  try {
    const missing = verifySnapshot(join(dir, 'missing.json'));
    assert.equal(missing.ok, false);

    const raw = readFileSync(SNAPSHOT, 'utf8');
    const copy = join(dir, 'verified-policy.json');
    writeFileSync(copy, raw, 'utf8');
    assert.equal(verifySnapshot(copy).ok, true);

    writeFileSync(copy, raw.replace('"label"', '"tamperedLabel"'), 'utf8');
    const tampered = verifySnapshot(copy);
    assert.equal(tampered.ok, false);
    assert.equal(tampered.stage, 'unverified');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('restore performs no policy write when backup verification fails', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aleph-stage10-'));
  const guarded = [
    'api/notes.js',
    'api/notes/[id].js',
    'src/decider.mjs',
    'src/detect.mjs',
    'src/resource-id.mjs',
  ];
  const before = new Map(guarded.map(path => [
    path,
    sha256(readFileSync(resolve(ROOT, path))),
  ]));

  try {
    const raw = readFileSync(SNAPSHOT, 'utf8');
    const copy = join(dir, 'verified-policy.json');
    writeFileSync(copy, raw + '\n', 'utf8');

    const result = restoreVerifiedPolicy({
      confirm: '000000000000',
      snapshotPath: copy,
    });

    assert.equal(result.ok, false);
    assert.equal(result.applied, false);

    for (const path of guarded) {
      assert.equal(
        sha256(readFileSync(resolve(ROOT, path))),
        before.get(path),
        `verification failure changed ${path}`,
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('preview reports the restore version, verification time, and change scope', () => {
  const result = inspectPolicy();
  assert.equal(result.ok, true);
  assert.match(result.version.commit, /^[0-9a-f]{40}$/u);
  assert.equal(result.version.verifiedAt, '2026-10-13T07:29:34.000Z');
  assert.ok(Array.isArray(result.changes));
});
