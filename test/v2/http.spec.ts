import request from "supertest";
import { createV2HttpApp } from "../../src/v2/app.js";
it("passes only authenticated bootstrap identity, disables caching and sanitizes errors", async () => {
  const calls: unknown[] = [];
  const app = await createV2HttpApp({
    bootstrap: {
      snapshot: async (...args: unknown[]) => {
        calls.push(args);
        if (args[0] !== "Bearer allowed")
          throw Object.assign(Error("PRIVATE"), { status: 403 });
        return { status: 304 as const, etag: '"revision"' };
      },
    },
  });
  try {
    await app.init();
    await request(app.getHttpServer())
      .get("/v2/bootstrap?applicationId=club-api&environment=development")
      .set("authorization", "Bearer allowed")
      .set("if-none-match", '"old"')
      .expect(304)
      .expect("cache-control", "no-store");
    expect(calls[0]).toEqual([
      "Bearer allowed",
      "club-api",
      "development",
      '"old"',
    ]);
    const denied = await request(app.getHttpServer())
      .get("/v2/bootstrap?applicationId=club-api&environment=development")
      .expect(403);
    expect(JSON.stringify(denied.body)).not.toContain("PRIVATE");
    await request(app.getHttpServer()).get("/v2/admin/resources").expect(503);
  } finally {
    await app.close();
  }
});
it('keeps grant issuance scoped and returns only metadata through the admin route',async()=>{
 const calls:unknown[]=[];
 const app=await createV2HttpApp({bootstrap:{snapshot:async()=>({status:304 as const,etag:'"r"'})},admin:{verify:async()=>({issuer:'https://fixture',subject:'global'}),resources:{} as any,consents:{} as any,grants:{issue:async(...args:unknown[])=>{calls.push(args);return {_id:'grant-id',enabled:true}},rotate:async()=>({_id:'rotated'}),revoke:async()=>{}} as any}} as any);
 try{await app.init();
 const response=await request(app.getHttpServer()).post('/v2/admin/applications/club-api/grants?environment=development&ownerType=application&ownerId=club-api').send({applicationId:'attacker',environment:'production'}).expect(201);
 expect(response.body).toEqual({_id:'grant-id',enabled:true});expect(calls[0]).toEqual([{issuer:'https://fixture',subject:'global'},{applicationId:'club-api',environment:'development'}]);
 await request(app.getHttpServer()).post('/v2/admin/applications/other/grants?environment=development&ownerType=application&ownerId=club-api').send({}).expect(403);
 }finally{await app.close();}
});
