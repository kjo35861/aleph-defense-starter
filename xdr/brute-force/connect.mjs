import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const alertsLog = join(root, 'xdr', 'alerts.log');
const denyRulesFile = join(root, 'xdr', 'deny-rules.json');
const BLOCK_TTL_MS = 15 * 60 * 1000;

async function readRules() {
  try {
    const parsed = JSON.parse(await readFile(denyRulesFile, 'utf8'));
    return Array.isArray(parsed?.rules) ? parsed.rules : [];
  } catch {
    return [];
  }
}

function expiresAt() {
  return new Date(Date.now() + BLOCK_TTL_MS).toISOString();
}

export async function connect(alert, decision) {
  const alertId = typeof alert?.id === 'string'
    ? alert.id
    : typeof alert?.alertId === 'string' ? alert.alertId : '';
  const sourceAddress = typeof alert?.sourceAddress === 'string'
    ? alert.sourceAddress
    : typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '';
  const reason = typeof decision?.reason === 'string' ? decision.reason : 'unknown';

  if (decision?.action === 'alert' || decision?.action === 'block') {
    const line = JSON.stringify({
      at: alert?.timestamp ?? null,
      alertId,
      action: decision.action,
      reason,
    });
    await appendFile(alertsLog, `${line}\n`, 'utf8');
  }

  if (decision?.action !== 'block' || !alertId || !sourceAddress) return;

  const rules = await readRules();
  const rule = {
    kind: 'deny_source',
    sourceAddress,
    expiresAt: expiresAt(),
    evidenceAlertId: alertId,
    reason,
  };

  const withoutSameEvidence = rules.filter(item => item?.evidenceAlertId !== alertId);
  await writeFile(denyRulesFile, `${JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    rules: [...withoutSameEvidence, rule],
  }, null, 2)}\n`, 'utf8');
}
