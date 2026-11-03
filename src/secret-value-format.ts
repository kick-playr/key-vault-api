import { requireCondition as check } from './errors.js';
import type { Namespace } from './types.js';
export type SecretValueFormat = 'text' | 'base64' | 'hex64';
function canonicalBase64(value: string): boolean {
  if (!value || value.length % 4 !== 0) return false;
  const bytes = Buffer.from(value, 'base64');
  try { return bytes.toString('base64') === value; } finally { bytes.fill(0); }
}
export function validateSecretValueFormat(value: string, format: unknown = 'text'): SecretValueFormat {
  check(format === 'text' || format === 'base64' || format === 'hex64');
  check(format === 'text' || (format === 'hex64' ? /^[a-fA-F0-9]{64}$/.test(value) : canonicalBase64(value)));
  return format;
}
export function inferSecretValueFormat(value: string): SecretValueFormat {
  return /^[a-fA-F0-9]{64}$/.test(value) ? 'hex64' : canonicalBase64(value) ? 'base64' : 'text';
}
/** Classify missing declarations only; never rewrite values or versions. */
export function classifySecretVersions(ns: Namespace, dryRun = false): number {
  let count = 0;
  for (const versions of Object.values(ns.secrets)) for (const item of versions) {
    if (item.valueFormat !== undefined) continue;
    check(typeof item.value === 'string');
    const format = inferSecretValueFormat(item.value);
    if (!dryRun) item.valueFormat = format;
    count++;
  }
  return count;
}
