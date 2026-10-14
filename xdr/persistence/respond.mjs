import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const BLOCK_TTL_MS = 15 * 60 * 1000;
const BLOCK_PATTERNS = new Set([
  'unsigned-new-service',
  'unfamiliar-scheduled-task',
  'startup-folder-change',
]);

function oneLine(value, fallback = '') {
  if (typeof value !== 'string') return fallback;
  const clean = value.replace(/[\r\n\u2028\u2029]+/gu, ' ').trim();
  return clean || fallback;
}

function validDecision(decision) {
  return Boolean(decision)
    && ['block', 'alert', 'record'].includes(decision.action)
    && Number.isFinite(decision.confidence)
    && decision.confidence >= 0
    && decision.confidence <= 1
    && typeof decision.reason === 'string';
}

async function readRules(path) {
  try {
    const document = JSON.parse(await readFile(path, 'utf8'));
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
  if (!validDecision(decision)) {
    throw new Error('XDR 결정 형식이 올바르지 않습니다.');
  }
  if (!Number.isFinite(now)) throw new Error('XDR 적용 시각이 올바르지 않습니다.');

  const alertId = oneLine(alert?.id ?? alert?.alertId);
  const sourceAddress = oneLine(alert?.sourceAddress ?? alert?.data?.srcip);
  const reason = oneLine(decision.reason, 'no-matching-pattern');
  const alertsLog = join(directory, 'alerts.log');
  const denyRulesFile = join(directory, 'deny-rules.json');

  await mkdir(directory, { recursive: true });

  if (decision.action === 'alert' || decision.action === 'block') {
    const line = JSON.stringify({
      at: oneLine(alert?.timestamp),
      alertId,
      action: decision.action,
      confidence: decision.confidence,
      reason,
    });
    await appendFile(alertsLog, `${line}\n`, 'utf8');
  }

  const rules = await readRules(denyRulesFile);
  const activeRules = rules.filter(rule => Date.parse(rule?.expiresAt) > now);

  const isBlockCandidate = decision.action === 'block'
    && decision.confidence >= 0.85
    && BLOCK_PATTERNS.has(reason)
    && Boolean(alertId)
    && isIP(sourceAddress) !== 0;

  const nextRules = activeRules.filter(rule => rule?.evidenceAlertId !== alertId);

  if (isBlockCandidate) {
    nextRules.push({
      kind: 'deny_source',
      sourceAddress,
      expiresAt: new Date(now + BLOCK_TTL_MS).toISOString(),
      evidenceAlertId: alertId,
      reason,
    });
  }

  await writeFile(denyRulesFile, `${JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    rules: nextRules,
  }, null, 2)}\n`, 'utf8');

  return {
    blocked: isBlockCandidate,
    alertId,
    expiresAt: isBlockCandidate ? new Date(now + BLOCK_TTL_MS).toISOString() : null,
  };
}
