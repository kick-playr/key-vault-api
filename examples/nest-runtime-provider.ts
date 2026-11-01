// Consumer-side example, not part of the vault server. Adapt imports to your package layout.
import { Module } from '@nestjs/common';
import { RuntimeVault } from '../src/runtime';

export interface ConsumerBootstrap {
  environment: string;
  tenantId: string;
  revision: number;
  vaultUrl: string;
  vaultToken: string;
  manifest: unknown;
  // Delivered by the database/API credential provisioner on the first event.
  // Keep the same event payload for retries; omit already stored values on new events.
  suppliedSecrets: Record<string, string>;
}

export function tenantRuntimeModule(bootstrap: ConsumerBootstrap) {
  @Module({
    providers: [{
      provide: 'TENANT_RUNTIME',
      useFactory: async () => {
        const runtime = new RuntimeVault({ baseUrl: bootstrap.vaultUrl, token: () => bootstrap.vaultToken });
        const scope = { environment: bootstrap.environment, tenant: bootstrap.tenantId };
        // Nest awaits async providers before constructing dependent clients. Rejecting
        // this promise aborts startup, rather than bringing up a partially ready app.
        await runtime.initialize(scope, bootstrap.manifest, bootstrap.revision, bootstrap.suppliedSecrets);
        return { runtime, scope };
      },
    }],
    exports: ['TENANT_RUNTIME'],
  })
  class TenantRuntimeModule {}
  return TenantRuntimeModule;
}
