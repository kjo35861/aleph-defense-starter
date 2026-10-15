import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const TTL_MS = 15 * 60 * 1000;
const PATTERNS = new Set([
  'unfamiliar-destination-bulk-transfer',
  'out-of-hours-archive-transfer',
  'command-channel-repeated-exfiltration',
]);

function singleLine(value) {
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

async function loadRules(file) {
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
  if (!Number.isFinite(now) || now < 0 || !Number.isFinite(now + TTL_MS)) {
    throw new Error('XDR 적용 시각이 올바르지 않습니다.');
  }

  const alertId = singleLine(alert?.id ?? alert?.alertId);
  const sourceAddress = singleLine(alert?.sourceAddress ?? alert?.data?.srcip);
  const reason = singleLine(decision.reason);
  const blockCandidate = decision.action === 'block'
    && decision.confidence >= 0.85
    && PATTERNS.has(reason)
    && Boolean(alertId)
    && isIP(sourceAddress) !== 0;

  await mkdir(directory, { recursive: true });
  if (decision.action === 'block' || decision.action === 'alert') {
    await appendFile(join(directory, 'alerts.log'), JSON.stringify({
      at: singleLine(alert?.timestamp),
      alertId,
      action: decision.action,
      confidence: decision.confidence,
      reason,
    }) + '\n', 'utf8');
  }

  const file = join(directory, 'deny-rules.json');
  const active = (await loadRules(file))
    .filter(rule => Date.parse(rule?.expiresAt) > now);
  const rules = active.filter(rule =>
    !(alertId && rule?.evidenceAlertId === alertId && PATTERNS.has(rule?.reason))
  );
  let expiresAt = null;
  if (blockCandidate) {
    expiresAt = new Date(now + TTL_MS).toISOString();
    rules.push({
      kind: 'deny_source',
      sourceAddress,
      expiresAt,
      evidenceAlertId: alertId,
      reason,
    });
  }

  await writeFile(file, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    rules,
  }, null, 2) + '\n', 'utf8');

  return { blocked: blockCandidate, alertId, expiresAt };
}
