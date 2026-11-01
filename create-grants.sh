#!/bin/sh
exec node --input-type=module <<'JS'
import { randomBytes } from 'node:crypto';
const grants = [{
  token: randomBytes(32).toString('base64url'),
  environment: 'dev',
  tenant: 'tenant-123',
  permissions: ['read', 'write', 'crypto', 'list'],
}];
console.log(`VAULT_GRANTS='${JSON.stringify(grants)}'`);
JS
