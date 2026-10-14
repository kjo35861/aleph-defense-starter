import { clearSessionCookie } from '../../src/browser-session.mjs';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  response.setHeader('Set-Cookie', clearSessionCookie());
  return response.status(204).end();
}
