import { createHmac, timingSafeEqual } from 'node:crypto';

const SESSION_COOKIE = 'bb_session';
const DEVICE_COOKIE = 'bb_device';
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function cookies(request) {
  const raw = typeof request?.headers?.cookie === 'string' ? request.headers.cookie : '';
  const out = new Map();
  for (const part of raw.split(';')) {
    const at = part.indexOf('=');
    if (at < 1) continue;
    const key = part.slice(0, at).trim();
    const value = part.slice(at + 1).trim();
    if (key) out.set(key, decodeURIComponent(value));
  }
  return out;
}

export function requestAuthorization(request) {
  const direct = request?.headers?.authorization;
  if (typeof direct === 'string' && BEARER.test(direct)) return direct;
  const token = cookies(request).get(SESSION_COOKIE);
  return token ? \`Bearer \${token}\` : null;
}

export function requestAccessToken(request) {
  const authorization = requestAuthorization(request);
  const match = typeof authorization === 'string' ? BEARER.exec(authorization) : null;
  return match?.[1] ?? null;
}

export function sessionCookie(token) {
  return \`\${SESSION_COOKIE}=\${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600\`;
}

export function clearSessionCookie() {
  return \`\${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0\`;
}

function signDeviceId(deviceId, secret) {
  return createHmac('sha256', secret).update(\`byteback-device:\${deviceId}\`).digest('base64url');
}

export function deviceCookie(deviceId, secret) {
  const proof = signDeviceId(deviceId, secret);
  return \`\${DEVICE_COOKIE}=\${encodeURIComponent(\`\${deviceId}.\${proof}\`)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000\`;
}

export function readVerifiedDeviceId(request, secret) {
  if (typeof secret !== 'string' || !secret) return null;
  const value = cookies(request).get(DEVICE_COOKIE);
  if (!value) return null;
  const at = value.indexOf('.');
  if (at < 1) return null;
  const deviceId = value.slice(0, at);
  const proof = value.slice(at + 1);
  if (!UUID.test(deviceId) || !proof) return null;
  const expected = signDeviceId(deviceId, secret);
  const a = Buffer.from(proof);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  return deviceId;
}

export async function approvedDevice({ request, verified, supabase, secretKey }) {
  if (!verified?.userId) return false;
  if (verified.kind === 'judge') return true;
  const deviceId = readVerifiedDeviceId(request, secretKey);
  if (!deviceId) return false;
  const { data, error } = await supabase
    .from('learning_devices')
    .select('id')
    .eq('id', deviceId)
    .eq('owner_id', verified.userId)
    .is('revoked_at', null)
    .maybeSingle();
  return !error && Boolean(data?.id);
}
