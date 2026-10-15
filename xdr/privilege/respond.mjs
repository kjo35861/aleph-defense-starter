import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const BLOCK_TTL_MS = 15 * 60 * 1000;
const BLOCK_PATTERNS = new Set([
  'unexpected-admin-group-addition',
  'unfamiliar-admin-command',
  'out-of-hours-privilege-use',
]);

function oneLine(value) {
  return typeof value === 'string'
    ? value.replace(/[\r\n\u2028\u2029]+/gu, ' ').trim()
    : '';
}

function validDecision(value) {
  return value && typeof value === 'object'
    && ['block', 'alert', 'record'].includes(value.action)
    && Number.isFinite(value.confidence)
    && value.confidence >= 0 && value.confidence <= 1
    && typeof value.reason === 'string';
}

async function readRules(file) {
  try {
    const document = JSON.parse(await readFile(file, 'utf8'));
    if (document?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(document.rules)) {
      throw new Error('XDR 거부 규칙 파일 형식이 올바르지 않습니다.');
    }
    return document.rules;
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

export async function respond(
  alert,
  decision,
  { directory = join(root, 'xdr'), now = Date.now() } = {},
) {
  if (!validDecision(decision)) throw new Error('XDR 결정 형식이 올바르지 않습니다.');
  if (!Number.isFinite(now)) throw new Error('XDR 적용 시각이 올바르지 않습니다.');

  const alertId = oneLine(alert?.id ?? alert?.alertId);
  const sourceAddress = oneLine(alert?.sourceAddress ?? alert?.data?.srcip);
  const reason = oneLine(decision.reason);
  await mkdir(directory, { recursive: true });

  if (decision.action === 'block' || decision.action === 'alert') {
    await appendFile(join(directory, 'alerts.log'), JSON.stringify({
      at: oneLine(alert?.timestamp),
      alertId,
      action: decision.action,
      confidence: decision.confidence,
      reason,
    }) + '\n', 'utf8');
  }

  const denyRulesFile = join(directory, 'deny-rules.json');
  const activeRules = (await readRules(denyRulesFile))
    .filter(rule => Date.parse(rule?.expiresAt) > now);
  const isBlockCandidate = decision.action === 'block'
    && decision.confidence >= 0.85
    && BLOCK_PATTERNS.has(reason)
    && Boolean(alertId)
    && isIP(sourceAddress) !== 0;
  // A re-evaluated alert can replace its own rule, but never remove another module's rules.
  const nextRules = activeRules.filter(rule => rule?.evidenceAlertId !== alertId || !alertId);
  let expiresAt = null;
  if (isBlockCandidate) {
    expiresAt = new Date(now + BLOCK_TTL_MS).toISOString();
    nextRules.push({
      kind: 'deny_source',
      sourceAddress,
      expiresAt,
      evidenceAlertId: alertId,
      reason,
    });
  }

  await writeFile(denyRulesFile, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    rules: nextRules,
  }, null, 2) + '\n', 'utf8');

  return { blocked: isBlockCandidate, alertId, expiresAt };
}
