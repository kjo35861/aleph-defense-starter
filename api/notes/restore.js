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

  // DB 함수가 같은 트랜잭션 안에서 비공개 사본을 다시 읽어 잠그고,
  // ID·소유자·내용 해시 검증에 성공한 경우에만 지정한 한 건을 복원합니다.
  const { data, error } = await supabase.rpc('restore_verified_learning_note', {
    p_note_id: id,
    p_actor_id: verified.userId,
  });

  if (error) {
    const message = String(error.message ?? '').toLowerCase();
    if (message.includes('backup_unverified')) {
      return response.status(409).json({ error: 'BACKUP_UNVERIFIED' });
    }
    if (message.includes('restore_rejected')) {
      return response.status(404).json({ error: 'NOT_FOUND' });
    }
    if (message.includes('restore_mismatch')) {
      return response.status(500).json({ error: 'RESTORE_MISMATCH' });
    }
    if (error.code === '42883' || error.code === 'PGRST202') {
      return response.status(503).json({ error: 'RESTORE_NOT_CONFIGURED' });
    }
    return response.status(500).json({ error: 'NOTE_RESTORE_FAILED' });
  }

  if (!data || data.id !== id || data.restored !== true || data.verified !== true
      || !SHA256.test(data.contentSha256 ?? '')) {
    return response.status(500).json({ error: 'RESTORE_MISMATCH' });
  }

  // 사용자/메모 본문/토큰을 로그에 남기지 않고, 감사 기록 테이블도 수정하지 않습니다.
  return response.status(200).json({
    id: data.id,
    restored: true,
    contentSha256: data.contentSha256,
  });
}
