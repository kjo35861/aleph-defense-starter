// Step 4: authenticated collection API scoped to the verified owner.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
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

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });

  const verified = await verifier(secretKey)(request.headers.authorization);
  if (!verified?.userId) return response.status(401).json({ error: 'UNAUTHORIZED' });

  const supabase = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('learning_notes')
      .select('id,title,content')
      .eq('owner_id', verified.userId)
      .order('created_at', { ascending: true });
    if (error) return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
    return response.status(200).json((data ?? []).map(note => ({
      id: note.id,
      title: note.title,
      body: note.content,
    })));
  }

  if (request.method === 'POST') {
    const payload = parseBody(request);
    const id = payload?.id ?? randomUUID();
    if (!payload || Object.hasOwn(payload, 'owner_id') || !UUID.test(id)
        || !validText(payload.title) || !validText(payload.body)) {
      return response.status(400).json({ error: 'INVALID_NOTE' });
    }

    const { error } = await supabase.from('learning_notes').insert({
      id,
      owner_id: verified.userId,
      title: payload.title.trim(),
      content: payload.body,
    });
    if (error?.code === '23505') return response.status(409).json({ error: 'NOTE_EXISTS' });
    if (error) return response.status(500).json({ error: 'NOTE_CREATE_FAILED' });
    return response.status(201).json({ id });
  }

  response.setHeader('Allow', 'GET, POST');
  return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}
