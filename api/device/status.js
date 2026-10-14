import { createClient } from '@supabase/supabase-js';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { approvedDevice, requestAuthorization } from '../../src/browser-session.mjs';

const config = JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
let verifyLogin;
function verifier(secretKey) {
  verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifyLogin;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });

  const authorization = requestAuthorization(request);
  const verified = await verifier(secretKey)(authorization);
  if (!verified?.userId) return response.status(401).json({ authenticated: false, approved: false });

  const supabase = createClient(url, secretKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const approved = await approvedDevice({ request, verified, supabase, secretKey });
  return response.status(200).json({ authenticated: true, approved });
}
