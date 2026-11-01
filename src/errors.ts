export class VaultError extends Error {
  constructor(public readonly status: number, public readonly code: string) { super(code); }
}
export function fail(status: number, code: string): never { throw new VaultError(status, code); }
export function requireCondition(condition: unknown, code = 'BadParameter'): asserts condition {
  if (!condition) fail(400, code);
}
