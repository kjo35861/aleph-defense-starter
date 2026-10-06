// Step 4: authenticated item API enforcing verified owner on every operation.
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
let verifyLogin;

function verifier(secretKey) {
  verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifyLogin;
}

function parseBody(request) {
  if (request.body && typeof request.body === 'object') return request.body;
  if (typeof request.body === 'string') {
    try { return JSON.parse(request.body); } catch { return null; }
  }
  return null;
}

function validText(value) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= 5000;
}

function noteResponse(row) {
  return { id: row.id, title: row.title, body: row.content };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });

  const verified = await verifier(secretKey)(request.headers.authorization);
  if (!verified?.userId) return response.status(401).json({ error: 'UNAUTHORIZED' });

  const id = Array.isArray(request.query?.id) ? request.query.id[0] : request.query?.id;
  if (!UUID.test(id ?? '')) return response.status(400).json({ error: 'INVALID_NOTE_ID' });

  const supabase = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // Read ownership from the DB, not URL parameters or request body.
  const { data: existing, error: lookupError } = await supabase
    .from('learning_notes')
    .select('id,owner_id')
    .eq('id', id)
    .maybeSingle();
  if (lookupError) return response.status(500).json({ error: 'NOTE_READ_FAILED' });
  // 404 does not disclose whether a note belongs to someone else.
  if (!existing || existing.owner_id !== verified.userId) {
    return response.status(404).json({ error: 'NOT_FOUND' });
  }

  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('learning_notes')
      .select('id,title,content')
      .eq('id', id)
      .eq('owner_id', verified.userId)
      .maybeSingle();
    if (error) return response.status(500).json({ error: 'NOTE_READ_FAILED' });
    if (!data) return response.status(404).json({ error: 'NOT_FOUND' });
    return response.status(200).json(noteResponse(data));
  }

  if (request.method === 'PUT') {
    const payload = parseBody(request);
    if (!payload || Object.hasOwn(payload, 'owner_id')
        || !validText(payload.title) || !validText(payload.body)) {
      return response.status(400).json({ error: 'INVALID_NOTE' });
    }
    const { data, error } = await supabase
      .from('learning_notes')
      .update({ title: payload.title.trim(), content: payload.body })
      .eq('id', id)
      .eq('owner_id', verified.userId)
      .select('id,title,content')
      .maybeSingle();
    if (error) return response.status(500).json({ error: 'NOTE_UPDATE_FAILED' });
    if (!data) return response.status(404).json({ error: 'NOT_FOUND' });
    return response.status(200).json(noteResponse(data));
  }

  if (request.method === 'DELETE') {
    const { data, error } = await supabase
      .from('learning_notes')
      .delete()
      .eq('id', id)
      .eq('owner_id', verified.userId)
      .select('id')
      .maybeSingle();
    if (error) return response.status(500).json({ error: 'NOTE_DELETE_FAILED' });
    if (!data) return response.status(404).json({ error: 'NOT_FOUND' });
    return response.status(204).end();
  }

  response.setHeader('Allow', 'GET, PUT, DELETE');
  return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}
