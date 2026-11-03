import request from'supertest';import{fixture}from'./helpers.js';import{MongoStore}from'../src/store.js';import{newSecret}from'../src/vault.js';import{vaultName}from'../src/manifest.js';import{RuntimeIdentityService}from'../src/runtime-identity.js';import{createSecretsRuntime,createApplicationRuntime}from'@kick-playr/local-key-vault/runtime-client';
it('saves a scoped configuration and hot-discovers an authorized tenant through read-only app transport',async()=>{
 const f=await fixture(),store=await MongoStore.open(f.config);const shared={environment:'dev',tenant:'_shared'},tenant={environment:'dev',tenant:'a'},operator='runtime-config-operator-aaaaaaaaaaaaaaaaaaaa';
 try{
  await f.addGrants([{...shared,token:operator,permissions:['read','write','list']},{...tenant,token:operator,permissions:['read','write','list']}]);
  const process=newSecret({value:'ordinary-mail-password',tags:{purpose:'mail',envName:'MAIL_PWD'}}),database=newSecret({value:'mongodb://fixture.invalid/tenant',tags:{purpose:'database',envName:'MONGODB_URI'}});
  await store.transaction(shared,ns=>{ns.secrets[vaultName(shared,'secret','mail')]=[process];ns.applications={'club-api':{displayName:'Club API',description:''}};ns.resourceAssociations={['secrets/'+vaultName(shared,'secret','mail')]:{envName:'MAIL_PWD',memberships:{'club-api':process.version}}};});await store.transaction(tenant,ns=>{ns.secrets[vaultName(tenant,'secret','database')]=[database];});
  const config={kind:'runtime-configuration',schemaVersion:2,id:'dev',applications:['club-api'],tenants:[] as unknown[]};
  const call=(method:'get'|'put'|'post',path:string,token=operator,scope=shared)=>request(f.app.getHttpServer())[method](path).set('Authorization','Bearer '+token).set('x-vault-environment',scope.environment).set('x-vault-tenant',scope.tenant);
  await call('put','/local/runtime-configuration').send({expectedRevision:0,configuration:config}).expect(200);
  const identity=await new RuntimeIdentityService(store).create('dev','club-api',['a']);
  await call('get','/local/runtime-access/club-api/runtime-manifests/club-api',identity.token).expect(200);
  await call('get','/local/runtime-access/club-api/runtime-manifests/app',identity.token).expect(403);
  await call('get','/secrets/'+vaultName(shared,'secret','mail')+'?api-version=2025-07-01',identity.token).expect(401);
  const environment={NODE_ENV:'test',SECRETS_KEYS_STRATEGY:'LOCAL_KEYVAULT',LOCAL_KEYVAULT_ENVIRONMENT:'dev',LOCAL_KEYVAULT_APPLICATION_TOKEN:identity.token};
  const transport:typeof fetch=async(url,options={})=>{
   const headers=new Headers(options.headers);let r=request(f.app.getHttpServer())[(options.method??'GET').toLowerCase() as 'get'|'post'](new URL(String(url)).pathname);for(const[k,v]of headers)r=r.set(k,v);if(options.body)r=r.send(JSON.parse(String(options.body)));const result=await r;return Response.json(result.body,{status:result.status});
  };
  const runtime=createSecretsRuntime({environment,fetch:transport});
  const live=createApplicationRuntime({application:'club-api',scope:shared,environment,fetch:transport,allowedMappings:['MAIL_PWD'],prepare:snapshot=>({value:snapshot.resources[0]!.value})});
  try{
   await live.start();expect(await live.withValue(value=>value)).toBe(process.value);
   expect((await runtime.refreshBindings('club-api')).tenants).toHaveLength(0);
   config.tenants=[{tenant:'a',applications:['club-api']}];
   await call('put','/local/runtime-configuration').send({expectedRevision:1,configuration:config}).expect(200);
   const bindings=await runtime.refreshBindings('club-api');expect(bindings.tenants.map(t=>t.scope.tenant)).toEqual(['a']);
   const snapshot=await runtime.loadTenant('a',bindings.tenants[0]!.request.bindingRevision);expect(snapshot.secrets[0]!.value).toBe(database.value);
   const child=createApplicationRuntime({application:'club-api',scope:tenant,environment,fetch:transport,allowedMappings:['MONGODB_URI'],prepare:snapshot=>({value:snapshot.resources[0]!.value})});try{await child.start();expect(await child.withValue(v=>v)).toBe(database.value);const updated=newSecret({value:'updated-database',tags:{purpose:'database',envName:'MONGODB_URI'}});await store.transaction(tenant,ns=>{ns.secrets[vaultName(tenant,'secret','database')]!.push(updated);ns.generation++;});await child.refresh();expect(await child.withValue(v=>v)).toBe(updated.value);}finally{child.close();}
   expect(await store.read(tenant,ns=>ns!.resourceAssociations)).toBeUndefined();
   await call('post','/local/runtime-access/club-api/oauth-credentials/begin',identity.token,tenant).send({}).expect(403);
   await call('put','/local/runtime-access-control/club-api/tenants/a').send({allow:true,oauth:true}).expect(403);
   const oauthOperator='runtime-oauth-operator-bbbbbbbbbbbbbbbbbbbb';await f.addGrants([{...shared,token:oauthOperator,permissions:['read','write','list']},{...tenant,token:oauthOperator,permissions:['read','write','list','renew']}]);
   const permission=await call('put','/local/runtime-access-control/club-api/tenants/a',oauthOperator).send({allow:true,oauth:true}).expect(200);expect(permission.body.oauthAuthorized).toBe(true);
   // Explicit broker permission does not bypass registered-provider/payload validation.
   await call('post','/local/runtime-access/club-api/oauth-credentials/begin',identity.token,tenant).send({}).expect(400);
   // A later save removing this tenant must not strand its committed namespace publication.
   config.tenants=[];await call('put','/local/runtime-configuration').send({expectedRevision:2,configuration:config}).expect(200);
   await store.transaction(tenant,ns=>{ns.audit.push({time:1,action:'after-removal',name:'metadata'});});
   expect(await store.read(tenant,ns=>ns!.resourceAssociations)).toBeUndefined();
   await call('put','/local/runtime-access-control/club-api/tenants/a').send({allow:false}).expect(200);
   expect((await call('get','/local/runtime-access-control/club-api/tenants/a').expect(200)).body.authorized).toBe(false);
   await call('put','/local/runtime-access-control/club-api/tenants/missing').send({allow:true}).expect(403);
   await call('get','/local/runtime-access/club-api/runtime-manifests/club-api',identity.token,tenant).expect(403);
  }finally{live.close();runtime.close();}
 }finally{await store.close();await f.cleanup();}
});
