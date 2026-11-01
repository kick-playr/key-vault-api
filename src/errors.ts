export class VaultError extends Error {
  constructor(public readonly status: number, public readonly code: string, public readonly startupDetail?: string) { super(code); }
}
export function fail(status: number, code: string, startupDetail?: string): never { throw new VaultError(status, code, startupDetail); }
export function requireCondition(condition: unknown, code = 'BadParameter'): asserts condition {
  if (!condition) fail(400, code);
}

const errorNames = new Set(['Error', 'TypeError', 'URIError', 'MongoParseError', 'MongoInvalidArgumentError', 'MongoServerSelectionError', 'MongoNetworkError', 'MongoNetworkTimeoutError', 'MongoServerError', 'MongoWriteConcernError', 'MongoTopologyClosedError']);
const errorCodes = new Set(['ECONNREFUSED', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT', 'EADDRINUSE', 'EACCES', 'EPERM', 'EISDIR', 'ENOENT', 'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID']);

/** Never include arbitrary driver messages, URLs, stack traces or error objects. */
export function describeSystemError(error: unknown): string {
  const parts = new Set<string>(), visited = new Set<object>();
  const visit = (value: unknown, depth: number) => {
    if (!value || typeof value !== 'object' || depth > 5 || visited.has(value)) return;
    visited.add(value);
    const item = value as { name?: unknown; code?: unknown; cause?: unknown; reason?: unknown; error?: unknown; servers?: unknown };
    if (typeof item.name === 'string' && errorNames.has(item.name)) parts.add(item.name);
    if (typeof item.code === 'string' && errorCodes.has(item.code)) parts.add(item.code);
    if (typeof item.code === 'number' && Number.isSafeInteger(item.code) && item.code >= 0 && item.code < 1000000) parts.add(`MongoDB code ${item.code}`);
    visit(item.cause, depth + 1); visit(item.reason, depth + 1); visit(item.error, depth + 1);
    if (item.servers instanceof Map) for (const server of [...item.servers.values()].slice(0, 32)) visit(server, depth + 1);
  };
  visit(error, 0);
  const summary = [...parts].join(', ') || 'Unexpected error';
  let hint = '';
  if (parts.has('MongoDB code 18')) hint = 'Check MongoDB credentials and authSource in VAULT_MONGODB_URI.';
  else if (parts.has('MongoDB code 13')) hint = 'MongoDB user needs read/write access to the selected database and vault collections.';
  else if (parts.has('ECONNREFUSED')) hint = 'MongoDB refused the connection; check that the server is running and the URL host/port are correct.';
  else if (parts.has('ENOTFOUND') || parts.has('EAI_AGAIN')) hint = 'MongoDB hostname lookup failed; check the URL hostname and DNS.';
  else if (parts.has('EADDRINUSE')) hint = 'The API port is already in use; stop the other listener or change VAULT_BASE_URL.';
  else if (parts.has('EACCES') || parts.has('EPERM')) hint = 'Check filesystem or listener permissions.';
  else if ([...parts].some(p => /CERT|TLS/.test(p))) hint = 'Check MongoDB TLS certificates and trust configuration.';
  else if (parts.has('MongoParseError') || parts.has('MongoInvalidArgumentError')) hint = 'Check VAULT_MONGODB_URI syntax and connection options.';
  else if (parts.has('MongoServerSelectionError') || parts.has('MongoNetworkTimeoutError') || parts.has('ETIMEDOUT')) hint = 'Check MongoDB availability, network access, TLS and replica-set settings.';
  return hint ? `${summary}. ${hint}` : summary;
}
export function formatStartupError(error: unknown): string {
  return error instanceof VaultError ? `${error.code}: ${error.startupDetail ?? 'Check bootstrap configuration and database availability.'}` : describeSystemError(error);
}
