import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { safeText } from './redact.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const BLOCK_TTL_MS = 15 * 60 * 1000;

async function readRules(denyRulesFile) {
  try {
    const parsed = JSON.parse(await readFile(denyRulesFile, 'utf8'));
    if (parsed?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(parsed.rules)) {
      throw new Error('XDR 거부 규칙 파일 형식이 올바르지 않습니다.');
    }
    return parsed.rules;
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

export async function connect(alert, decision, { directory = join(root, 'xdr'), now = Date.now() } = {}) {
  const alertsLog = join(directory, 'alerts.log');
  const denyRulesFile = join(directory, 'deny-rules.json');
  if (!['block', 'alert', 'record'].includes(decision?.action)
      || !Number.isFinite(decision?.confidence)
      || decision.confidence < 0 || decision.confidence > 1) {
    throw new Error('XDR 결정 형식이 올바르지 않습니다.');
  }
  if (!Number.isFinite(now)) throw new Error('XDR 적용 시각이 올바르지 않습니다.');
  const alertId = typeof alert?.id === 'string'
    ? alert.id
    : typeof alert?.alertId === 'string' ? alert.alertId : '';
  const sourceAddress = typeof alert?.sourceAddress === 'string'
    ? alert.sourceAddress
    : typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '';
  const reason = safeText(decision?.reason) || 'unknown';
  // 잘못된 기존 파일을 빈 규칙으로 덮어쓰지 않는다.
  const rules = await readRules(denyRulesFile);

  if (decision?.action === 'alert' || decision?.action === 'block') {
    const line = JSON.stringify({
      at: safeText(alert?.timestamp),
      alertId: safeText(alertId),
      action: decision.action,
      reason,
    });
    await appendFile(alertsLog, `${line}\n`, 'utf8');
  }

  const nextRules = rules.filter(item =>
    Date.parse(item?.expiresAt) > now && item?.evidenceAlertId !== alertId);
  if (decision.action === 'block' && decision.confidence >= 0.85
      && alertId.trim() && safeText(alertId) === alertId && isIP(sourceAddress)) {
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
}
