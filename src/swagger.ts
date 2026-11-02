import { applyDecorators, INestApplication } from '@nestjs/common';
import { ApiBody, ApiOperation, ApiQuery, ApiResponse, ApiTags, DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import type { OperationObject, ParameterObject } from '@nestjs/swagger';
import { schemas } from './swagger-schemas.js';

export function VaultEndpoint(tag: string, summary: string, permission: string, response: string, body?: string, local = false) {
  const decorators = [ApiTags(tag), ApiOperation({ summary, description: `Required permission: ${permission}.` }),
    ApiResponse({ status: 200, description: 'Success', schema: { $ref: `#/components/schemas/${response}` } })];
  if (body) decorators.push(ApiBody({ schema: { $ref: `#/components/schemas/${body}` } }));
  if (!local) decorators.push(ApiQuery({ name: 'api-version', required: true, enum: ['2025-07-01'] }));
  for (const [status, description] of Object.entries({ 400: 'Invalid or unsupported input', 401: 'Missing/invalid bearer token', 403: 'Permission, namespace or key/secret status forbids access', 404: 'Resource not found', 409: 'Revision, manifest or storage conflict', 413: 'Request too large', 500: 'Internal error', 503: 'Storage unavailable', 507: 'Namespace exceeds storage limit' })) {
    decorators.push(ApiResponse({ status: Number(status), description, schema: { $ref: '#/components/schemas/VaultError' } }));
  }
  return applyDecorators(...decorators);
}
export function InventoryQueries(local = false) {
  const decorators = [
    ApiQuery({ name: 'maxresults', required: false, schema: { type: 'integer', minimum: 1, maximum: 25, default: 25 } }),
    ApiQuery({ name: '$skiptoken', required: false, description: 'Opaque continuation token from nextLink. Bound to the namespace, filters and current generation.', schema: { type: 'string' } }),
  ];
  if (local) {
    decorators.push(ApiQuery({ name: 'search', required: false, description: 'Case-insensitive literal substring of physical name OR purpose tag. Applied before pagination; combines with other filters using AND.', schema: { type: 'string', minLength: 1, maxLength: 512 } }));
    decorators.push(ApiQuery({ name: 'kind', required: false, enum: ['key', 'secret'] }));
    for (const name of ['name', 'namePrefix', 'purpose', 'tagName', 'tagValue']) decorators.push(ApiQuery({ name, required: false, schema: { type: 'string' } }));
    decorators.push(ApiQuery({ name: 'enabled', required: false, enum: ['true', 'false'] }));
    decorators.push(ApiQuery({ name: 'expiresBefore', required: false, description: 'Include objects expiring at/before these Unix epoch seconds.', schema: { type: 'integer', minimum: 0 } }));
  }
  return applyDecorators(...decorators);
}

const docsPaths = new Set(['/docs', '/docs/', '/docs-json', ...['swagger-ui.css', 'swagger-ui-bundle.js', 'swagger-ui-standalone-preset.js', 'swagger-ui-init.js', 'favicon-16x16.png', 'favicon-32x32.png'].map(p => '/docs/' + p)]);
export const isDocumentationRequest = (method: string, path: string) => ['GET', 'HEAD'].includes(method) && docsPaths.has(path);

export function setupSwagger(app: INestApplication, baseUrl: string) {
  const config = new DocumentBuilder().setTitle('Key Vault API').setVersion('0.1.0')
    .setDescription('Local development Azure Key Vault REST subset, API version 2025-07-01. Local bearer grants replace Entra ID. Deletion permanently removes all versions. Version lists are unpaginated. Keys remain non-exportable. Tenant values belong in tenant-scoped server runtime snapshots, never browser bundles. Select the matching environment and tenant headers for every API request.')
    .addTag('Applications', 'Editable application models and canonical resource associations. Metadata only; saved links are not runtime adoption.')
    .addTag('Provisioning', 'Start here: automatically provision manifest-defined keys and supplied secrets. Revisioned reconciliation is idempotent and requires read and write permissions.')
    .addTag('Runtime', 'Load complete validated mappings for a tenant/environment before initializing application clients. Requires read permission.')
    .addTag('Connection', 'Authenticate a caller token for one namespace without requiring list, read, write or crypto permission.')
    .addTag('Inventory', 'List and search latest key/secret metadata with pagination. Requires the separate list permission; returns no secret values or key material.')
    .addTag('Keys', 'Generate and manage RSA keys, public JWKs, versions and metadata. Private key material remains in the vault. Deletion removes all versions.')
    .addTag('Secrets', 'Store and read versioned secret values, update metadata, and permanently delete secrets. Metadata/version lists omit values.')
    .addTag('Cryptography', 'Encrypt or decrypt one block with an explicit RSA key version using RSA-OAEP-256. Requires crypto permission.')
    .addTag('Namespace aliases', 'Alternative URLs containing environment and tenant in the path. They use the same bodies and permissions as the primary endpoints; path identifiers must match the required headers.')
    .addServer(baseUrl).addBearerAuth({ type: 'http', scheme: 'bearer', description: 'A saved caller token from grant creation or legacy migration. Grants are stored in MongoDB. Paste the token only, without the Bearer prefix.' }, 'bearer').build();
  const doc = SwaggerModule.createDocument(app, config, { autoTagControllers: false });
  doc.components = { ...doc.components, schemas: { ...doc.components?.schemas, ...schemas } };
  for (const [path, methods] of Object.entries(doc.paths)) {
    for (const [method, raw] of Object.entries(methods)) {
      if (!['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method)) continue;
      const operation = raw as OperationObject;
      if (path.startsWith('/namespaces/')) operation.tags = ['Namespace aliases'];
      operation.operationId = method + '_' + path.replace(/[^a-zA-Z0-9]+/g, '_');
      const parameters = (operation.parameters ?? []).filter(p => !('in' in p) || p.in !== 'path');
      for (const match of path.matchAll(/\{([^}]+)\}/g)) {
        const name = match[1]!;
        const parameter: ParameterObject = { name, in: 'path', required: true, schema: { type: 'string' } };
        parameters.push(parameter);
      }
      operation.parameters = parameters;
    }
  }
  SwaggerModule.setup('docs', app, doc, { jsonDocumentUrl: '/docs-json', raw: ['json'], customSiteTitle: 'Key Vault API', swaggerOptions: { persistAuthorization: false, validatorUrl: null, docExpansion: 'none', filter: true, operationsSorter: 'method' } });
}
