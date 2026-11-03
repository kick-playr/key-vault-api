import{RuntimeIdentityService}from'../src/runtime-identity.js';import{emptyNamespace}from'../src/types.js';import type{MongoStore}from'../src/store.js';
it('binds a stable runtime identity to app/environment and separately approved assigned tenants',async()=>{
 const ns=emptyNamespace();ns.applications={'club-api':{displayName:'Club API',description:''},app:{displayName:'APP',description:''}};const store={read:async(_s:any,fn:any)=>fn(ns),transaction:async(_s:any,fn:any)=>fn(ns)};const service=new RuntimeIdentityService(store as Pick<MongoStore,'read'|'transaction'>);
 const issued=await service.create('development','club-api',['fcrww','newclub']);
 await expect(service.authorize('Bearer '+issued.token,{environment:'development',tenant:'_shared'},'club-api')).resolves.toBe(issued.id);
 await expect(service.authorize('Bearer '+issued.token,{environment:'development',tenant:'newclub'},'club-api')).rejects.toThrow();
 ns.runtimeManifests={'club-api':{currentRevision:1,versions:{'1':{tenants:[{tenant:'newclub'}]} as any}}};
 await expect(service.authorize('Bearer '+issued.token,{environment:'development',tenant:'newclub'},'club-api')).resolves.toBe(issued.id);
 await expect(service.authorize('Bearer '+issued.token,{environment:'development',tenant:'newclub'},'app')).rejects.toThrow();
 await expect(service.authorize('Bearer '+issued.token,{environment:'test',tenant:'newclub'},'club-api')).rejects.toThrow();
 await service.setTenants('development','club-api',[]);await expect(service.authorize('Bearer '+issued.token,{environment:'development',tenant:'newclub'},'club-api')).rejects.toThrow();
 expect(JSON.stringify(ns)).not.toContain(issued.token);
});
it('read identity never gains provider writes without separate explicit authorization',async()=>{
 const ns=emptyNamespace();ns.applications={'club-api':{displayName:'Club API',description:''}};ns.runtimeManifests={'club-api':{currentRevision:1,versions:{'1':{tenants:[{tenant:'a'}]} as any}}};const service=new RuntimeIdentityService({read:async(_s:any,fn:any)=>fn(ns),transaction:async(_s:any,fn:any)=>fn(ns)} as Pick<MongoStore,'read'|'transaction'>);const token=(await service.create('development','club-api',['a'])).token;const scope={environment:'development',tenant:'a'};
 await expect(service.authorizeOAuth('Bearer '+token,scope,'club-api',false)).resolves.toBeUndefined();await expect(service.authorizeOAuth('Bearer '+token,scope,'club-api',true)).rejects.toThrow('Forbidden');
 await service.allowTenant('development','club-api','a',true,true);await expect(service.authorizeOAuth('Bearer '+token,scope,'club-api',true)).resolves.toBeUndefined();await service.allowTenant('development','club-api','a',false);await expect(service.authorizeOAuth('Bearer '+token,scope,'club-api',false)).rejects.toThrow();
});
