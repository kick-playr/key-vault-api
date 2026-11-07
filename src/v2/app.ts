import type { GrantService } from "./grants.js";
import type { CatalogService } from "./catalog.js";
import type { LinkService } from "./links.js";
import type { SchemaService } from "./schema-store.js";
import type { KeyRotationService } from "./key-rotations.js";
import type { InstanceService } from "./instances.js";
import "reflect-metadata";
import {
  Body,
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Query,
  Req,
  Res,
  Module,
  Catch,
  type ExceptionFilter,
  type ArgumentsHost,
} from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { Request, Response } from "express";
import type { BootstrapService } from "./bootstrap.js";
import type { Actor } from "./authorization.js";
import type { ResourceService, ResourceInput } from "./resources.js";
import type { ConsentService } from "./consents.js";
import type { ResourceScope } from "./records.js";
import { scopeFilter } from "./mongo-store.js";
export interface V2HttpServices {
  bootstrap: Pick<BootstrapService, "snapshot">;
  instances?: InstanceService;
  admin?: {
    verify(request: Request): Promise<Actor>;
    resources: ResourceService;
    catalog?: CatalogService;
    links?: LinkService;
    schemas?: SchemaService;
    rotations?: KeyRotationService;
    grants?: Pick<GrantService, "issue" | "rotate" | "revoke">;
    consents: ConsentService;
  };
}
export async function createV2HttpApp(services: V2HttpServices) {
  const actor = async (req: Request) => {
    if (!services.admin)
      throw Object.assign(Error("Unavailable"), { status: 503 });
    return services.admin.verify(req);
  };
  const scope = (q: Record<string, string>): ResourceScope =>
    scopeFilter({
      environment: q.environment!,
      ownerType: q.ownerType as ResourceScope["ownerType"],
      ownerId: q.ownerId!,
    });
  @Catch()
  class SafeErrors implements ExceptionFilter {
    catch(error: unknown, host: ArgumentsHost) {
      const status =
        error &&
        typeof error === "object" &&
        "status" in error &&
        [400, 401, 403, 404, 409, 413, 503].includes(Number(error.status))
          ? Number(error.status)
          : 503;
      host
        .switchToHttp()
        .getResponse<Response>()
        .status(status)
        .set("cache-control", "no-store")
        .json({
          error: {
            code:
              status === 403
                ? "Forbidden"
                : status === 401
                  ? "Unauthorized"
                  : "VaultUnavailable",
          },
        });
    }
  }
  @Controller("v2")
  class V2Controller {
    @Post("instances") async register(
      @Req() req: Request,
      @Body() input: { applicationId: string; environment: string },
    ) {
      if (!services.instances) throw Object.assign(Error(), { status: 503 });
      return services.instances.register(
        req.headers.authorization,
        input.applicationId,
        input.environment,
      );
    }
    @Post("instances/acknowledge") async acknowledge(
      @Req() req: Request,
      @Body()
      input: {
        applicationId: string;
        environment: string;
        instanceId: string;
        password: string;
        rotationId: string;
        versionId: string;
      },
    ) {
      if (!services.instances) throw Object.assign(Error(), { status: 503 });
      return services.instances.acknowledge(
        req.headers.authorization,
        input.applicationId,
        input.environment,
        input,
      );
    }
    @Get("bootstrap") async bootstrap(
      @Req() req: Request,
      @Query("applicationId") app: string,
      @Query("environment") environment: string,
      @Res() res: Response,
    ) {
      const result = await services.bootstrap.snapshot(
        req.headers.authorization,
        app,
        environment,
        req.headers["if-none-match"],
        ...(services.instances
          ? [
              {
                instanceId: String(req.headers["x-vault-instance-id"] ?? ""),
                password: String(
                  req.headers["x-vault-instance-password"] ?? "",
                ),
              },
            ]
          : []),
      );
      res.set({ "cache-control": "no-store", etag: result.etag });
      if (result.status === 304) return res.status(304).end();
      return res.json(result.snapshot);
    }
    @Get("admin/catalog") async catalog(
      @Req() req: Request,
      @Query() q: Record<string, string>,
    ) {
      const identity = await actor(req);
      if (!services.admin?.catalog) throw Error();
      return services.admin.catalog.list(identity, scope(q));
    }
    @Delete("admin/applications/:id") async deleteApplication(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
      @Body() input: { revision: number; confirmation: string },
    ) {
      const identity = await actor(req);
      if (!services.admin?.catalog) throw Error();
      return services.admin.catalog.removeApplication(
        identity,
        q.environment!,
        id,
        input.revision,
        input.confirmation,
      );
    }
    @Put("admin/applications") async application(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Body() input: any,
    ) {
      const identity = await actor(req);
      if (!services.admin?.catalog) throw Error();
      return services.admin.catalog.saveApplication(
        identity,
        q.environment!,
        input,
      );
    }
    @Put("admin/assignments/:application") async assignment(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("application") application: string,
      @Body() input: { enabled: boolean; revision: number },
    ) {
      const identity = await actor(req);
      if (!services.admin?.catalog) throw Error();
      return services.admin.catalog.assign(
        identity,
        scope(q),
        application,
        input.enabled,
        input.revision,
      );
    }
    @Put("admin/enrollments/:application") async enrollment(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("application") application: string,
    ) {
      const identity = await actor(req);
      if (!services.admin?.catalog) throw Error();
      return services.admin.catalog.approveEnrollment(
        identity,
        scope(q),
        application,
      );
    }
    @Get("admin/links/:application") async links(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("application") application: string,
    ) {
      const identity = await actor(req);
      if (!services.admin?.links) throw Error();
      return services.admin.links.list(identity, scope(q), application);
    }
    @Post("admin/links/:application") async createLink(
      @Req() req:Request,@Query() q:Record<string,string>,@Param("application") applicationId:string,
      @Body() input:{resourceId:string;accessName:string;versionPolicy:string},
    ) {
      const identity=await actor(req);if(!services.admin?.links)throw Error();
      const owner=scope(q);
      return services.admin.links.create(identity,owner,{applicationId,resourceId:input.resourceId,accessName:input.accessName,versionPolicy:input.versionPolicy,...(owner.ownerType==="tenant"?{tenantId:owner.ownerId}:{})});
    }
    @Put("admin/links/:application") async saveLinks(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("application") application: string,
      @Body() input: any,
    ) {
      const identity = await actor(req);
      if (!services.admin?.links) throw Error();
      return services.admin.links.save(
        identity,
        scope(q),
        application,
        input.revision,
        input.rows,
      );
    }
    @Get("admin/schemas/:identity") async schema(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("identity") id: string,
    ) {
      const identity = await actor(req);
      await services.admin!.resources.list(identity, scope(q), { limit: 1 });
      if (!services.admin?.schemas) throw Error();
      return services.admin.schemas.get(identity, scope(q), id);
    }
    @Post("admin/schemas") async createSchema(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Body() input: any,
    ) {
      const identity = await actor(req);
      if (!services.admin?.schemas) throw Error();
      return services.admin.schemas.create(
        identity,
        scope(q),
        input.name,
        input.version,
        input.schema,
      );
    }
    @Post("admin/instances/:id/retire") async retire(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
      @Body() input: any,
    ) {
      const identity = await actor(req);
      if (!services.admin?.rotations) throw Error();
      return services.admin.rotations.retireInstance(
        identity,
        scope(q),
        id,
        input.confirmation,
        input.reason,
      );
    }
    @Put("admin/resources/:id/enabled") async enabled(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
      @Body() input: { revision: number; enabled: boolean },
    ) {
      return services.admin!.resources.setEnabled(
        await actor(req),
        scope(q),
        id,
        input.revision,
        input.enabled,
      );
    }
    @Get("admin/resources/:id/rotations") async rotations(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
    ) {
      const identity = await actor(req);
      if (!services.admin?.rotations) throw Error();
      return services.admin.rotations.status(identity, scope(q), id);
    }
    @Post("admin/resources/:id/rotations") async prepareRotation(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
      @Body() input: { revision: number },
    ) {
      const identity = await actor(req);
      if (!services.admin?.rotations) throw Error();
      return services.admin.resources.stageGeneratedKey(
        identity,
        scope(q),
        id,
        input.revision,
        services.admin.rotations,
      );
    }
    @Post("admin/rotations/:id/activate") async activateRotation(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
    ) {
      const identity = await actor(req);
      if (!services.admin?.rotations) throw Error();
      return services.admin.rotations.activate(identity, scope(q), id);
    }
    @Post("admin/applications/:application/grants") async issueGrant(
      @Req() req: Request, @Query() q: Record<string,string>, @Param("application") applicationId:string,
    ) {
      const identity=await actor(req), owner=scope(q);
      if(owner.ownerType!=="application"||owner.ownerId!==applicationId)throw Object.assign(Error(),{status:403});
      if(!services.admin?.grants)throw Error();
      return services.admin.grants.issue(identity,{applicationId,environment:owner.environment});
    }
    @Post("admin/grants/:id/rotate") async rotateGrant(
      @Req() req:Request,@Param("id") id:string,@Body() input:{revision:number},
    ) {
      const identity=await actor(req);if(!services.admin?.grants)throw Error();
      return services.admin.grants.rotate(identity,id,input.revision);
    }
    @Delete("admin/grants/:id") async revokeGrant(
      @Req() req:Request,@Param("id") id:string,@Body() input:{revision:number},
    ) {
      const identity=await actor(req);if(!services.admin?.grants)throw Error();
      await services.admin.grants.revoke(identity,id,input.revision);return {revoked:true};
    }
    @Get("admin/access") async access(
      @Req() req: Request,
      @Query() q: Record<string, string>,
    ) {
      return { ...await services.admin!.resources.access(await actor(req), scope(q)), grantDeliveryAvailable:!!services.admin?.grants };
    }
    @Get("admin/consent") async consentStatus(
      @Req() req: Request,
      @Query() q: Record<string, string>,
    ) {
      return services.admin!.consents.status(await actor(req), scope(q));
    }
    @Get("admin/resources/:id/versions") async versions(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
    ) {
      return services.admin!.resources.versions(await actor(req), scope(q), id);
    }
    @Get("admin/resources") async list(
      @Req() req: Request,
      @Query() q: Record<string, string>,
    ) {
      const identity = await actor(req);
      return services.admin!.resources.list(identity, scope(q), {
        limit: Math.min(Number(q.limit ?? 20), 100),
        after: q.after,
      });
    }
    @Post("admin/resources") async create(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Body() input: ResourceInput,
    ) {
      return services.admin!.resources.create(
        await actor(req),
        scope(q),
        input,
      );
    }
    @Put("admin/resources/:id") async update(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
      @Body() input: { revision: number; resource: ResourceInput },
    ) {
      return services.admin!.resources.update(
        await actor(req),
        scope(q),
        id,
        input.revision,
        input.resource,
      );
    }
    @Post("admin/resources/:id/reveal/:version") async reveal(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
      @Param("version") version: string,
      @Res() res: Response,
    ) {
      const value = await services.admin!.resources.reveal(
        await actor(req),
        scope(q),
        id,
        version,
      );
      try {
        return res
          .set("cache-control", "no-store")
          .type("text/plain")
          .send(value.toString("utf8"));
      } finally {
        value.fill(0);
      }
    }
    @Delete("admin/resources/:id") async remove(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Param("id") id: string,
      @Body() input: { revision: number; confirmation: string },
    ) {
      await services.admin!.resources.remove(
        await actor(req),
        scope(q),
        id,
        input.revision,
        input.confirmation,
      );
      return { deleted: true };
    }
    @Put("admin/consent") async consent(
      @Req() req: Request,
      @Query() q: Record<string, string>,
      @Body() input: { revision: number; enabled: boolean },
    ) {
      if (typeof input.enabled !== "boolean")
        throw Object.assign(Error(), { status: 400 });
      const identity = await actor(req);
      return input.enabled
        ? services.admin!.consents.approve(identity, scope(q), input.revision)
        : services.admin!.consents.revoke(identity, scope(q), input.revision);
    }
  }
  @Module({ controllers: [V2Controller] })
  class V2Module {}
  const app = await NestFactory.create(V2Module, { logger: false });
  app.useGlobalFilters(new SafeErrors());
  app.use((_req: Request, res: Response, next: () => void) => {
    res.set("cache-control", "no-store");
    next();
  });
  return app;
}
