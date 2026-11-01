import 'reflect-metadata';
import { ArgumentsHost, Body, CanActivate, Catch, Controller, Delete, ExceptionFilter, ExecutionContext, Get, HttpCode, INestApplication, Module, Param, Patch, Post, Put, Query, Req, SetMetadata, UseGuards } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NextFunction, Request, Response, json } from 'express';
import { Permission, validateConfig, VaultConfig } from './config.js';
import { VaultError, fail } from './errors.js';
import { GrantService } from './grants.js';
import { MongoStore } from './store.js';
import { Scope } from './types.js';
import { scopePart } from './validation.js';
import { VaultService } from './vault.js';
import { ProvisioningService } from './provisioning.js';
import { RuntimeSnapshotService } from './runtime-snapshot.js';
import { ApiBearerAuth, ApiHeaders } from '@nestjs/swagger';
import { InventoryQueries, isDocumentationRequest, setupSwagger, VaultEndpoint } from './swagger.js';
import { TenantKeyTreeService } from './tenant-key-tree.js';
import { InventoryService } from './inventory.js';
import { AuditService, AuditRequest, auditDestinations } from './audit.js';

type ScopedRequest = AuditRequest & { vaultScope: Scope };
const Permissions = (...permissions: Permission[]) => SetMetadata('vault-permissions', permissions);
@Catch()
class SafeErrors implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();
    let status = error instanceof VaultError ? error.status : 500;
    let code = error instanceof VaultError ? error.code : 'InternalError';
    if (!(error instanceof VaultError) && error && typeof error === 'object' && 'status' in error) {
      const s = (error as { status: number }).status;
      if (s === 400 || s === 413) { status = s; code = 'BadParameter'; }
      if (s === 404) { status = 404; code = 'NotFound'; }
    }
    res.status(status).json({ error: { code, message: code } });
  }
}

// Closure-backed providers keep bootstrap credentials out of Nest metadata/logs.
export async function createApp(input: VaultConfig): Promise<INestApplication> {
  const config = validateConfig(input);
  const store = await MongoStore.open(config);
  const grants = new GrantService(store);
  const audit = new AuditService(auditDestinations(config.audit), store);
  const vault = new VaultService(store, config.baseUrl.replace(/\/$/, ''));
  const provisioning = new ProvisioningService(vault);
  const runtimeSnapshots = new RuntimeSnapshotService(vault);
  const keyTree = new TenantKeyTreeService(vault);
  const inventory = new InventoryService(vault, config.masterKey);
  class HandlerPermissions implements CanActivate {
    async canActivate(context: ExecutionContext) {
      const req = context.switchToHttp().getRequest<ScopedRequest>();
      if (req.params.environment !== undefined &&
          (req.params.environment !== req.vaultScope.environment || req.params.tenant !== req.vaultScope.tenant)) fail(403, 'Forbidden');
      const permissions: Permission[] = Reflect.getMetadata('vault-permissions', context.getHandler()) ?? ['write'];
      await grants.authorize(req.headers.authorization, req.vaultScope, permissions);
      return true;
    }
  }
  @Controller(['', 'namespaces/:environment/:tenant'])
  @UseGuards(HandlerPermissions)
  @ApiBearerAuth('bearer')
  @ApiHeaders([
    { name: 'x-vault-environment', required: true, description: 'Exact environment authorized by the caller grant.', schema: { type: 'string' } },
    { name: 'x-vault-tenant', required: true, description: 'Exact tenant authorized by the caller grant; _shared for process scope.', schema: { type: 'string' } },
  ])
  class VaultController {
    @VaultEndpoint('Connection', 'Validate the exact caller token for this namespace without reading resources', 'valid scoped grant', 'Session', undefined, true)
    @Get('local/session') @Permissions()
    session(@Req() req: ScopedRequest) { return { authenticated: true, environment: req.vaultScope.environment, tenant: req.vaultScope.tenant }; }
    @VaultEndpoint('Inventory', 'Browse tenant key sets and roles as a metadata-only tree', 'list', 'TenantKeyTree', undefined, true)
    @Get('local/key-tree') @Permissions('list')
    tree(@Req() req: ScopedRequest) { return keyTree.tree(req.vaultScope); }
    @VaultEndpoint('Inventory', 'List latest key metadata without key material', 'list', 'KeyInventory')
    @InventoryQueries() @Get('keys') @Permissions('list')
    listKeys(@Req() req: ScopedRequest, @Query() query: unknown) { return inventory.list(req.vaultScope, 'keys', query); }
    @VaultEndpoint('Inventory', 'List latest secret metadata without values', 'list', 'SecretInventory')
    @InventoryQueries() @Get('secrets') @Permissions('list')
    listSecrets(@Req() req: ScopedRequest, @Query() query: unknown) { return inventory.list(req.vaultScope, 'secrets', query); }
    @VaultEndpoint('Inventory', 'Search combined key and secret metadata within one namespace', 'list', 'Inventory', undefined, true)
    @InventoryQueries(true) @Get('local/inventory') @Permissions('list')
    search(@Req() req: ScopedRequest, @Query() query: unknown) { return inventory.list(req.vaultScope, 'local/inventory', query); }
    @VaultEndpoint('Provisioning', 'Reconcile the required manifest atomically', 'write and read', 'Snapshot', 'Reconcile', true)
    @Post('local/reconcile') @HttpCode(200) @Permissions('write', 'read')
    reconcile(@Req() req: ScopedRequest, @Body() body: unknown) { return provisioning.reconcile(req.vaultScope, body); }
    @VaultEndpoint('Runtime', 'Load a complete validated runtime snapshot', 'read', 'Snapshot', 'SnapshotRequest', true)
    @Post('local/snapshot') @HttpCode(200) @Permissions('read')
    snapshot(@Req() req: ScopedRequest, @Body() body: unknown) { return provisioning.snapshot(req.vaultScope, body); }
    @VaultEndpoint('Runtime', 'Read a complete pinned runtime secret/key set atomically without provisioning', 'read', 'RuntimeSnapshot', 'RuntimeSnapshotRequest', true)
    @Post('local/runtime-snapshot') @HttpCode(200) @Permissions('read')
    runtimeSnapshot(@Req() req: ScopedRequest, @Body() body: unknown) { return runtimeSnapshots.snapshot(req.vaultScope, body); }
    @VaultEndpoint('Secrets', 'Set a secret and create a new version', 'write', 'SecretBundle', 'SetSecret')
    @Put('secrets/:name') @HttpCode(200)
    set(@Req() req: ScopedRequest, @Param('name') name: string, @Body() body: unknown) { return vault.create(req.vaultScope, 'secrets', name, body); }
    @VaultEndpoint('Keys', 'Generate an RSA key and create a new version', 'write', 'KeyBundle', 'CreateKey')
    @Post('keys/:name/create') @HttpCode(200)
    create(@Req() req: ScopedRequest, @Param('name') name: string, @Body() body: unknown) { return vault.create(req.vaultScope, 'keys', name, body); }
    @VaultEndpoint('Secrets', 'List all secret version metadata without values', 'read', 'SecretVersions')
    @Get('secrets/:name/versions') @Permissions('read') secretVersions(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.versions(req.vaultScope, 'secrets', name); }
    @VaultEndpoint('Keys', 'List all key version metadata', 'read', 'KeyVersions')
    @Get('keys/:name/versions') @Permissions('read') keyVersions(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.versions(req.vaultScope, 'keys', name); }
    @VaultEndpoint('Secrets', 'Read the latest or a specific active secret version', 'read', 'SecretBundle')
    @Get(['secrets/:name', 'secrets/:name/:version']) @Permissions('read') getSecret(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version?: string) { return vault.get(req.vaultScope, 'secrets', name, version); }
    @VaultEndpoint('Keys', 'Read the public JWK of the latest or a specific active version', 'read', 'KeyBundle')
    @Get(['keys/:name', 'keys/:name/:version']) @Permissions('read') getKey(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version?: string) { return vault.get(req.vaultScope, 'keys', name, version); }
    @VaultEndpoint('Secrets', 'Update secret metadata; response excludes the value', 'write', 'SecretMetadata', 'PatchSecret')
    @Patch('secrets/:name/:version') patchSecret(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.update(req.vaultScope, 'secrets', name, version, body); }
    @VaultEndpoint('Keys', 'Update key metadata and permitted operations', 'write', 'KeyBundle', 'PatchKey')
    @Patch('keys/:name/:version') patchKey(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.update(req.vaultScope, 'keys', name, version, body); }
    @VaultEndpoint('Secrets', 'Permanently delete every version of a secret', 'write', 'SecretMetadata')
    @Delete('secrets/:name') deleteSecret(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.delete(req.vaultScope, 'secrets', name); }
    @VaultEndpoint('Keys', 'Permanently delete every version of a key', 'write', 'KeyMetadata')
    @Delete('keys/:name') deleteKey(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.delete(req.vaultScope, 'keys', name); }
    @VaultEndpoint('Cryptography', 'Encrypt one block using RSA-OAEP-256', 'crypto', 'CryptoResult', 'CryptoInput')
    @Post('keys/:name/:version/encrypt') @HttpCode(200) @Permissions('crypto') encrypt(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.crypto(req.vaultScope, name, version, 'encrypt', body); }
    @VaultEndpoint('Cryptography', 'Decrypt with an explicit RSA key version', 'crypto', 'CryptoResult', 'CryptoInput')
    @Post('keys/:name/:version/decrypt') @HttpCode(200) @Permissions('crypto') decrypt(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.crypto(req.vaultScope, name, version, 'decrypt', body); }
  }
  @Module({ controllers: [VaultController], providers: [{ provide: 'STORE_LIFECYCLE', useValue: { onModuleDestroy: async () => { await audit.close(); await store.close(); } } }] })
  class VaultModule {}
  try {
    const app = await NestFactory.create(VaultModule, { logger: false, bodyParser: false, abortOnError: false });
    app.use(async (req: ScopedRequest, res: Response, next: NextFunction) => {
      audit.attach(req, res);
      res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
      try {
        const host = req.headers.host ?? '';
        if (!/^127\.0\.0\.1(?::\d+)?$/.test(host)) fail(403, 'Forbidden');
        if (req.headers.origin && req.headers.origin !== `http://${host}`) fail(403, 'Forbidden');
        if (isDocumentationRequest(req.method, req.path)) { next(); return; }
        if (!req.headers.authorization) fail(401, 'Unauthorized');
        const match = req.path.match(/^\/namespaces\/([^/]+)\/([^/]+)(\/.*)$/i);
        const scope = { environment: scopePart(req.headers['x-vault-environment']), tenant: scopePart(req.headers['x-vault-tenant']) };
        req.vaultScope = scope;
        if (match && (match[1] !== scope.environment || match[2] !== scope.tenant)) fail(403, 'Forbidden');
        const path = match ? match[3]! : req.path;
        const authorized = await grants.authenticatedGrants(req.headers.authorization, scope);
        req.vaultGrantIds = authorized.map(grant => grant.id);
        req.vaultScope = scope;
        if (!/^\/local\//i.test(path) && req.query['api-version'] !== '2025-07-01') fail(400, 'BadParameter');
        req.vaultScope = scope; next();
      } catch (e) { const err = e instanceof VaultError ? e : new VaultError(500, 'InternalError'); res.status(err.status).json({ error: { code: err.code, message: err.code } }); }
    });
    const ordinaryJson = json({ limit: '128kb', strict: true });
    const runtimeJson = json({ limit: '64kb', strict: true });
    app.use((req: Request, res: Response, next: NextFunction) => {
      const runtimeRead = /^(?:\/namespaces\/[^/]+\/[^/]+)?\/local\/runtime-snapshot\/?$/i.test(req.path);
      return (runtimeRead ? runtimeJson : ordinaryJson)(req, res, next);
    });
    app.useGlobalFilters(new SafeErrors());
    setupSwagger(app, config.baseUrl);
    return app;
  } catch (e) { await store.close(); throw e; }
}
