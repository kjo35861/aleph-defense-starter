import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { RULE_IDS } from '../../src/decider.mjs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { approvedDevice, requestAuthorization } from '../../src/browser-session.mjs';

const config = JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
const recovery = JSON.parse(readFileSync(new URL('../../policy/verified-policy.json', import.meta.url), 'utf8'));

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

  const verified = await verifier(secretKey)(requestAuthorization(request));
  if (!verified?.userId) return response.status(401).json({ error: 'UNAUTHORIZED' });

  const supabase = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  if (!await approvedDevice({ request, verified, supabase, secretKey })) {
    return response.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
  }

  const generatedAt = new Date().toISOString();
  const requestId = randomUUID();
  const rules = RULE_IDS.map(ruleId => ({ ruleId, status: 'configured' }));

  return response.status(200).json({
    schema: 'aleph.operations.summary.v1',
    generatedAt,
    requestId,
    policy: {
      source: 'server_code',
      status: 'configured',
      ruleCount: rules.length,
      rules,
    },
    detection: {
      source: 'runtime',
      status: 'not_run',
      counts: { total: 0, block: 0, alert: 0, record: 0 },
      records: [],
    },
    revocation: {
      source: 'runtime',
      status: 'not_run',
      executed: false,
      activeCount: null,
    },
    recovery: {
      source: 'verified_snapshot',
      status: 'not_run',
      executed: false,
      version: recovery.verifiedCommit,
      label: recovery.label,
      verifiedAt: recovery.verifiedAt,
      fileCount: Object.keys(recovery.files ?? {}).length,
    },
    apiEvidence: [
      {
        method: 'GET',
        path: '/api/ops/summary',
        status: 200,
        requestId,
        checkedAt: generatedAt,
      },
    ],
    redaction: {
      omitted: ['subject', 'deviceId', 'token', 'noteTitle', 'noteContent'],
    },
  });
}
