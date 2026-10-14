import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { deviceCookie, requestAccessToken, requestAuthorization } from '../../src/browser-session.mjs';

const config = JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
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

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });

  const authorization = requestAuthorization(request);
  const verified = await verifier(secretKey)(authorization);
  const token = requestAccessToken(request);
  if (!verified?.userId || verified.kind !== 'student' || !token) {
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }

  const body = parseBody(request);
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!password) return response.status(400).json({ error: 'PASSWORD_REQUIRED' });

  const supabase = createClient(url, secretKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: userData, error: userError } = await supabase.auth.getUser(token);
  const email = userData?.user?.email;
  if (userError || !email) return response.status(401).json({ error: 'UNAUTHORIZED' });

  const { data: reauth, error: reauthError } = await supabase.auth.signInWithPassword({ email, password });
  if (reauthError || reauth?.user?.id !== verified.userId) {
    return response.status(403).json({ error: 'DEVICE_APPROVAL_REAUTH_FAILED' });
  }

  const deviceId = randomUUID();
  const { error } = await supabase.from('learning_devices').insert({
    id: deviceId,
    owner_id: verified.userId,
  });
  if (error) return response.status(500).json({ error: 'DEVICE_APPROVAL_FAILED' });

  response.setHeader('Set-Cookie', deviceCookie(deviceId, secretKey));
  return response.status(200).json({ approved: true });
}
