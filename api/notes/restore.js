import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { RESOURCE_IDS } from '../../src/resource-id.mjs';

const config = JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
let verifyLogin;

function verifier(secretKey) {
  verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifyLogin;
}

function parseBody(request) {
  if (request.body && typeof request.body === 'object' && !Array.isArray(request.body)) return request.body;
  if (typeof request.body === 'string') {
    try {
      const parsed = JSON.parse(request.body);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
  return null;
}

function contentSha256(title, content) {
  return createHash('sha256')
    .update(String(title), 'utf8')
    .update(Buffer.from([0]))
    .update(String(content), 'utf8')
    .digest('hex');
}

function validBackup(row, id, ownerId) {
  return row
    && row.id === id
    && row.owner_id === ownerId
    && typeof row.title === 'string'
    && row.title.trim().length > 0
    && row.title.length <= 5000
    && typeof row.content === 'string'
    && row.content.length <= 5000
    && SHA256.test(row.content_sha256 ?? '')
    && contentSha256(row.title, row.content) === row.content_sha256;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Aleph-Resource-Id', RESOURCE_IDS.notes);

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });

  const verified = await verifier(secretKey)(request.headers.authorization);
  if (!verified?.userId) return response.status(401).json({ error: 'UNAUTHORIZED' });

  const payload = parseBody(request);
  if (!payload || Object.keys(payload).sort().join(',') !== 'id' || !UUID.test(payload.id ?? '')) {
    return response.status(400).json({ error: 'INVALID_NOTE_ID' });
  }
  const id = payload.id.toLowerCase();

  const supabase = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // 비공개 사본에서 로그인한 본인의 지정 ID 한 건만 읽습니다.
  const { data: backup, error: backupError } = await supabase
    .from('learning_notes_backup')
    .select('id,owner_id,title,content,content_sha256')
    .eq('id', id)
    .eq('owner_id', verified.userId)
    .maybeSingle();

  if (backupError) return response.status(500).json({ error: 'BACKUP_READ_FAILED' });
  if (!backup) return response.status(404).json({ error: 'NOT_FOUND' });
  if (!validBackup(backup, id, verified.userId)) {
    return response.status(409).json({ error: 'BACKUP_UNVERIFIED' });
  }

  const firstBackupFingerprint = contentSha256(
    `${safeBackup.id}\0${safeBackup.owner_id}\0${safeBackup.content_sha256}`,
    `${safeBackup.title}\0${safeBackup.content}`,
  );

  // 복원 실행 직전에 비공개 사본을 다시 읽습니다. 처음 검증한 사본과 조금이라도 달라졌거나
  // 두 번째 검증이 실패하면 쓰기 전에 중단합니다.
  const { data: verifiedBackup, error: verifyBackupError } = await supabase
    .from('learning_notes_backup')
    .select('id,owner_id,title,content,content_sha256')
    .eq('id', id)
    .eq('owner_id', verified.userId)
    .maybeSingle();
  if (verifyBackupError) return response.status(500).json({ error: 'BACKUP_READ_FAILED' });
  if (!verifiedBackup || !validBackup(verifiedBackup, id, verified.userId)) {
    return response.status(409).json({ error: 'BACKUP_UNVERIFIED' });
  }
  const secondBackupFingerprint = contentSha256(
    `${verifiedBackup.id}\0${verifiedBackup.owner_id}\0${verifiedBackup.content_sha256}`,
    `${verifiedBackup.title}\0${verifiedBackup.content}`,
  );
  if (secondBackupFingerprint !== firstBackupFingerprint) {
    return response.status(409).json({ error: 'BACKUP_UNVERIFIED' });
  }

  // 아래부터는 두 번 검증한 동일 사본만 사용합니다.
  const safeBackup = verifiedBackup;

  // 같은 ID가 다른 소유자에게 속해 있으면 존재 여부를 넓게 공개하지 않고 복원을 거부합니다.
  const { data: existing, error: existingError } = await supabase
    .from('learning_notes')
    .select('id,owner_id')
    .eq('id', id)
    .maybeSingle();
  if (existingError) return response.status(500).json({ error: 'NOTE_READ_FAILED' });
  if (existing && existing.owner_id !== verified.userId) {
    return response.status(404).json({ error: 'NOT_FOUND' });
  }

  if (existing) {
    const { error } = await supabase
      .from('learning_notes')
      .update({ title: safeBackup.title, content: safeBackup.content })
      .eq('id', id)
      .eq('owner_id', verified.userId);
    if (error) return response.status(500).json({ error: 'NOTE_RESTORE_FAILED' });
  } else {
    const { error } = await supabase.from('learning_notes').insert({
      id,
      owner_id: verified.userId,
      title: safeBackup.title,
      content: safeBackup.content,
    });
    if (error?.code === '23505') return response.status(404).json({ error: 'NOT_FOUND' });
    if (error) return response.status(500).json({ error: 'NOTE_RESTORE_FAILED' });
  }

  // 복원 직후 대상 한 건만 다시 읽어 ID·소유자·내용 해시를 사본과 재대조합니다.
  const { data: restored, error: checkError } = await supabase
    .from('learning_notes')
    .select('id,owner_id,title,content')
    .eq('id', id)
    .eq('owner_id', verified.userId)
    .maybeSingle();
  if (checkError) return response.status(500).json({ error: 'RESTORE_CHECK_FAILED' });

  const restoredHash = restored ? contentSha256(restored.title, restored.content) : null;
  if (!restored
      || restored.id !== safeBackup.id
      || restored.owner_id !== safeBackup.owner_id
      || restoredHash !== safeBackup.content_sha256) {
    return response.status(500).json({ error: 'RESTORE_MISMATCH' });
  }

  // 감사 이력에는 쓰지 않습니다. 서버 로그에도 사용자/메모/본문을 남기지 않습니다.
  return response.status(200).json({
    id: restored.id,
    restored: true,
    contentSha256: restoredHash,
  });
}
