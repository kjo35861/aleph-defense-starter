// Step 3: require a verified Supabase login before returning notes.
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let verifyLogin;

function getVerifier(secretKey) {
  verifyLogin ??= createLoginVerifier({
    config,
    supabaseSecretKey: secretKey,
  });
  return verifyLogin;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
    return;
  }

  const verified = await getVerifier(secretKey)(request.headers.authorization);
  if (!verified || verified.kind !== 'student') {
    response.status(401).json({ error: 'UNAUTHORIZED' });
    return;
  }

  const supabase = createClient(url, secretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  const { data, error } = await supabase
    .from('learning_notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
    return;
  }

  response.status(200).json({ notes: data ?? [] });
}
