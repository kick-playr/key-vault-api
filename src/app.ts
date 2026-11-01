import 'reflect-metadata';
import { ArgumentsHost, Body, CanActivate, Catch, Controller, Delete, ExceptionFilter, ExecutionContext, Get, HttpCode, INestApplication, Module, Param, Patch, Post, Put, Req, SetMetadata, UseGuards } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NextFunction, Request, Response, json } from 'express';
import { authorize, Permission, validateConfig, VaultConfig } from './config';
import { VaultError, fail } from './errors';
import { EncryptedStore } from './store';
import { Scope } from './types';
import { scopePart } from './validation';
import { VaultService } from './vault';
import { ProvisioningService } from './provisioning';

type ScopedRequest = Request & { vaultScope: Scope };
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
  const store = await EncryptedStore.open(config);
  const vault = new VaultService(store, config.baseUrl.replace(/\/$/, ''));
  const provisioning = new ProvisioningService(vault);
  class HandlerPermissions implements CanActivate {
    canActivate(context: ExecutionContext) {
      const req = context.switchToHttp().getRequest<ScopedRequest>();
      if (req.params.environment !== undefined &&
          (req.params.environment !== req.vaultScope.environment || req.params.tenant !== req.vaultScope.tenant)) fail(403, 'Forbidden');
      const permissions: Permission[] = Reflect.getMetadata('vault-permissions', context.getHandler()) ?? ['write'];
      for (const permission of permissions) authorize(config, req.headers.authorization, req.vaultScope, permission);
      return true;
    }
  }
  @Controller(['', 'namespaces/:environment/:tenant'])
  @UseGuards(HandlerPermissions)
  class VaultController {
    @Post('local/reconcile') @HttpCode(200) @Permissions('write', 'read')
    reconcile(@Req() req: ScopedRequest, @Body() body: unknown) { return provisioning.reconcile(req.vaultScope, body); }
    @Post('local/snapshot') @HttpCode(200) @Permissions('read')
    snapshot(@Req() req: ScopedRequest, @Body() body: unknown) { return provisioning.snapshot(req.vaultScope, body); }
    @Put('secrets/:name') @HttpCode(200)
    set(@Req() req: ScopedRequest, @Param('name') name: string, @Body() body: unknown) { return vault.create(req.vaultScope, 'secrets', name, body); }
    @Post('keys/:name/create') @HttpCode(200)
    create(@Req() req: ScopedRequest, @Param('name') name: string, @Body() body: unknown) { return vault.create(req.vaultScope, 'keys', name, body); }
    @Get('secrets/:name/versions') @Permissions('read') secretVersions(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.versions(req.vaultScope, 'secrets', name); }
    @Get('keys/:name/versions') @Permissions('read') keyVersions(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.versions(req.vaultScope, 'keys', name); }
    @Get(['secrets/:name', 'secrets/:name/:version']) @Permissions('read') getSecret(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version?: string) { return vault.get(req.vaultScope, 'secrets', name, version); }
    @Get(['keys/:name', 'keys/:name/:version']) @Permissions('read') getKey(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version?: string) { return vault.get(req.vaultScope, 'keys', name, version); }
    @Patch('secrets/:name/:version') patchSecret(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.update(req.vaultScope, 'secrets', name, version, body); }
    @Patch('keys/:name/:version') patchKey(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.update(req.vaultScope, 'keys', name, version, body); }
    @Delete('secrets/:name') deleteSecret(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.delete(req.vaultScope, 'secrets', name); }
    @Delete('keys/:name') deleteKey(@Req() req: ScopedRequest, @Param('name') name: string) { return vault.delete(req.vaultScope, 'keys', name); }
    @Post('keys/:name/:version/encrypt') @HttpCode(200) @Permissions('crypto') encrypt(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.crypto(req.vaultScope, name, version, 'encrypt', body); }
    @Post('keys/:name/:version/decrypt') @HttpCode(200) @Permissions('crypto') decrypt(@Req() req: ScopedRequest, @Param('name') name: string, @Param('version') version: string, @Body() body: unknown) { return vault.crypto(req.vaultScope, name, version, 'decrypt', body); }
  }
  @Module({ controllers: [VaultController], providers: [{ provide: 'STORE_LIFECYCLE', useValue: { onModuleDestroy: () => store.close() } }] })
  class VaultModule {}
  try {
    const app = await NestFactory.create(VaultModule, { logger: false, bodyParser: false, abortOnError: false });
    app.use((req: ScopedRequest, res: Response, next: NextFunction) => {
      res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
      try {
        if (req.headers.origin || !/^127\.0\.0\.1(?::\d+)?$/.test(req.headers.host ?? '')) fail(403, 'Forbidden');
        if (!req.headers.authorization) fail(401, 'Unauthorized');
        const match = req.path.match(/^\/namespaces\/([^/]+)\/([^/]+)(\/.*)$/i);
        const scope = { environment: scopePart(req.headers['x-vault-environment']), tenant: scopePart(req.headers['x-vault-tenant']) };
        if (match && (match[1] !== scope.environment || match[2] !== scope.tenant)) fail(403, 'Forbidden');
        const path = match ? match[3]! : req.path;
        authorize(config, req.headers.authorization, scope);
        if (!/^\/local\//i.test(path) && req.query['api-version'] !== '2025-07-01') fail(400, 'BadParameter');
        req.vaultScope = scope; next();
      } catch (e) { const err = e instanceof VaultError ? e : new VaultError(500, 'InternalError'); res.status(err.status).json({ error: { code: err.code, message: err.code } }); }
    });
    app.use(json({ limit: '128kb', strict: true }));
    app.useGlobalFilters(new SafeErrors());
    return app;
  } catch (e) { await store.close(); throw e; }
}
