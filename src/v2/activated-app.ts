import { GrantService } from "./grants.js";
import { DeploymentGrantDelivery, PrivateDirectoryGrantSink } from "./grant-delivery.js";
import { bindProvisioning } from "./provisioning-proof.js";
import { V2MongoStore, scopeFilter } from "./mongo-store.js";
import { createV2HttpApp } from "./app.js";
import { BootstrapService } from "./bootstrap.js";
import { InstanceService, hash } from "./instances.js";
import { Authorization, AccessDenied } from "./authorization.js";
import { ControlRoleAuthority } from "./control-authority.js";
import { consentReader, ConsentService } from "./consents.js";
import { ResourceService } from "./resources.js";
import { IntegrationSchemas } from "./integration-schemas.js";
import { SchemaService } from "./schema-store.js";
import { HumanIdentityVerifier, realmFromJwks } from "./identity.js";
import { CatalogService } from "./catalog.js";
import { LinkService } from "./links.js";
import { KeyRotationService } from "./key-rotations.js";
import type { VaultConfig } from "../config.js";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
/** Never opens a legacy authority or silently enables an unverified migration. */
export async function createActivatedV2App(config: VaultConfig) {
  const store = await V2MongoStore.open(config);
  try {
    const activated = await store.transaction((tx) =>
      tx.db
        .collection<any>("vault_platform_settings")
        .findOne(
          {
            _id: "v2-authority",
            enabled: true,
            verified: true,
            legacyWritersFenced: true,
            legacyReadersFenced: true,
          },
          { session: tx.session },
        ),
    );
    if (!activated) throw Error("Verified v2 maintenance cutover is required");
    const authorization = new Authorization(
        new ControlRoleAuthority(store, true),
        consentReader(store),
      ),
      schemas = new IntegrationSchemas(),
      schemaService = new SchemaService(store, authorization, schemas);
    await schemaService.load();
    const app = await createV2HttpApp({
      bootstrap: new BootstrapService(store, schemas),
      instances: new InstanceService(store),
      admin: {
        resources: new ResourceService(store, authorization, schemas),
        consents: new ConsentService(store, authorization),
        catalog: new CatalogService(store, authorization),
        links: new LinkService(store, authorization),
        schemas: schemaService,
        rotations: new KeyRotationService(store, authorization),
        grants: process.env.VAULT_DEPLOYMENT_GRANT_DIRECTORY
          ? new GrantService(store,authorization,new DeploymentGrantDelivery(store,new PrivateDirectoryGrantSink(process.env.VAULT_DEPLOYMENT_GRANT_DIRECTORY,config.baseUrl)))
          : undefined,
        verify: async (request) => {
          const scope = scopeFilter({
              environment: String(request.query.environment ?? ""),
              ownerType: request.query.ownerType as any,
              ownerId: String(request.query.ownerId ?? ""),
            }),
            header = request.headers["x-vault-provisioning"];
          if (
            typeof header !== "string" ||
            !/^Bearer [A-Za-z0-9_-]{43}$/.test(header)
          )
            throw new AccessDenied();
          const realms = await store.transaction(async (tx) => {
            const grant = await store.grants.findOne(
              {
                tokenHash: hash(header.slice(7)),
                grantClass: "interactive-provisioner",
                environment: scope.environment,
                enabled: true,
              },
              { session: tx.session },
            );
            if (!grant) throw new AccessDenied();
            if (
              !(await tx.db
                .collection("vault_grant_scopes")
                .findOne(
                  { grantId: grant._id, ...scope },
                  { session: tx.session },
                ))
            )
              throw new AccessDenied();
            return {
              grant,
              realms: await tx.db.client
                .db("control-kick-playr")
                .collection("vault_identity_realms")
                .find(
                  { environment: scope.environment, enabled: true },
                  { session: tx.session },
                )
                .limit(102)
                .toArray(),
            };
          });
          if (!realms.realms.length || realms.realms.length > 101)
            throw new AccessDenied();
          const identity = await new HumanIdentityVerifier(
            realms.realms.map((r) =>
              realmFromJwks(
                r.issuer,
                r.audience,
                r.jwksUrl,
                r.authorizedParties,
              ),
            ),
          ).verify(request.headers.authorization);
          return bindProvisioning(identity, {
            grantId: realms.grant._id,
            revision: realms.grant.revision,
            environment: scope.environment,
            tokenHash: realms.grant.tokenHash,
            capabilities: realms.grant.capabilities,
          });
        },
      },
    });
    const close = app.close.bind(app);
    app.close = async () => {
      try {
        await close();
      } finally {
        await store.close();
      }
    };
    SwaggerModule.setup(
      "docs",
      app,
      SwaggerModule.createDocument(
        app,
        new DocumentBuilder()
          .setTitle("Key Vault v2")
          .setVersion("2")
          .addBearerAuth()
          .build(),
      ),
    );
    return app;
  } catch (error) {
    await store.close();
    throw error;
  }
}
