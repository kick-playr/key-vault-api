import { requireCondition as check } from './errors.js';
export function object(value: unknown, allowed: string[]): Record<string, unknown> {
  check(value !== null && typeof value === 'object' && !Array.isArray(value));
  const record = value as Record<string, unknown>;
  check(Object.keys(record).every(k => allowed.includes(k)));
  return record;
}
export function identifier(value: unknown): string {
  check(typeof value === 'string' && /^[a-zA-Z0-9-]{1,127}$/.test(value));
  return value;
}
export function scopePart(value: unknown): string {
  check(typeof value === 'string' && /^(?:[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}|_shared)$/.test(value));
  return value;
}
export function attributes(value: unknown): { enabled?: boolean; nbf?: number; exp?: number } {
  if (value === undefined) return {};
  const attr = object(value, ['enabled', 'nbf', 'exp']);
  if (attr.enabled !== undefined) check(typeof attr.enabled === 'boolean');
  for (const key of ['nbf', 'exp']) if (attr[key] !== undefined) check(Number.isSafeInteger(attr[key]) && (attr[key] as number) >= 0);
  if (attr.nbf !== undefined && attr.exp !== undefined) check((attr.nbf as number) < (attr.exp as number));
  return attr as ReturnType<typeof attributes>;
}
export function tags(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  check(value !== null && typeof value === 'object' && !Array.isArray(value));
  check(Object.keys(value).length <= 15 && Object.entries(value).every(([k, v]) => k.length <= 512 && typeof v === 'string' && v.length <= 512));
  return value as Record<string, string>;
}
export function envName(value: unknown): string {
  check(typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(value));
  check(!/^(PUBLIC_|NEXT_PUBLIC_|VITE_|NUXT_PUBLIC_|REACT_APP_)/.test(value));
  check(!/^(NODE_|NPM_|VAULT_)/.test(value) && !['PATH', 'HOME', 'SHELL', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH'].includes(value));
  return value;
}
