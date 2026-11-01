import { fail } from './errors.js';

/** Require an explicit path; authSource names an auth database, not the vault database. */
export function databaseFromMongoUri(uri: unknown): string {
  if (typeof uri !== 'string' || !/^mongodb(?:\+srv)?:\/\/\S+$/.test(uri)) {
    fail(500, 'InvalidBootstrap', 'VAULT_MONGODB_URI is required and must be a mongodb:// or mongodb+srv:// URL.');
  }
  const path = uri.match(/^mongodb(?:\+srv)?:\/\/[^/?#]+(?:\/([^?#]*))?/)?.[1];
  let database = '';
  try { database = path ? decodeURIComponent(path) : ''; } catch { /* Use the safe diagnostic below. */ }
  if (!database || /[\/\\\0\s]/.test(database)) {
    fail(500, 'InvalidBootstrap', 'VAULT_MONGODB_URI must include an explicit database name in its URL path, for example mongodb://127.0.0.1:27017/key-vault. No default database is used.');
  }
  return database;
}
