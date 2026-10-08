// 명시적인 자격 증명 표기와 일반적인 토큰 형식을 가린다.
export function safeText(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g, '[REDACTED]')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,})\b/g, '[REDACTED]')
    .replace(/((?:["']?)(?:password|passwd|pwd|token|secret|api[_-]?key|비밀번호|토큰|비밀키)(?:["']?)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}&]+)/gi, '$1[REDACTED]');
}
