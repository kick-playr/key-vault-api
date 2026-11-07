import {readFile,realpath} from 'node:fs/promises';
import {parseEnv} from 'node:util';
import {createHash,createHmac} from 'node:crypto';
import {scopeFilter} from './mongo-store.js';
import {applicationIdentity} from './catalog.js';
import type {LegacyItem,MigrationSource} from './migration.js';
export interface PublicEnvironmentMapping {
 envFile:string;
 /** Canonical original provenance when reading an immutable backup after cutover. */
 sourceIdentityFile?:string;
 environment:string;
 applicationId:string;
 key:'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY'|'NEXT_PUBLIC_API_ENDPOINT';
 skipIfEmpty?:boolean;
}
/** Explicit read-only public configuration seed. Private environment variables
 * are never selected, returned, copied into metadata or used as a fallback. */
export class PublicEnvironmentMigrationSource implements MigrationSource {
 constructor(private readonly mappings:readonly PublicEnvironmentMapping[]){}
 async inventory():Promise<LegacyItem[]> {
  if(this.mappings.length>1000)throw Error('Public configuration mapping exceeds limits');
  const result:LegacyItem[]=[],seen=new Set<string>();
  for(const mapping of this.mappings) {
   if(mapping.skipIfEmpty !== undefined && typeof mapping.skipIfEmpty !== "boolean")throw Error("Invalid public source policy");
   if(!['NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY','NEXT_PUBLIC_API_ENDPOINT'].includes(mapping.key))throw Error('Only public configuration may use this source');
   const applicationId=applicationIdentity(mapping.applicationId),owner=scopeFilter({environment:mapping.environment,ownerType:'application',ownerId:applicationId});
   const filename=await realpath(mapping.envFile),identityFilename=mapping.sourceIdentityFile===undefined?filename:await realpath(mapping.sourceIdentityFile),env=parseEnv(await readFile(filename,'utf8')),value=env[mapping.key];
   if((value===undefined||value==='')&&mapping.skipIfEmpty)continue;
   if(!value||value.length>4096)throw Error('Required public configuration is missing');
   const clerk=mapping.key==='NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY';
   if(clerk){if(!/^pk_(test|live)_[A-Za-z0-9+/_-]+={0,2}$/.test(value))throw Error('Invalid public Clerk configuration');}
   else{const url=new URL(value);if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.search||url.hash||url.pathname!=='/')throw Error('Invalid public API origin');}
   const sourceId=`public-environment:${owner.environment}:${applicationId}:${identityFilename}:${mapping.key}`;
   if(seen.has(sourceId))throw Error('Duplicate public configuration mapping');seen.add(sourceId);
   result.push({sourceId,revision:0,owner,name:applicationId+(clerk?'-clerk-publishable-key':'-api-public-origin'),kind:'secret',custody:'admin-managed',valueFormat:'text',versions:[{id:createHash('sha256').update(value).digest('hex'),value}]});
  }
  return result;
 }
}
export class CompositeMigrationSource implements MigrationSource {
 constructor(private readonly sources:readonly MigrationSource[]){}
 async inventory(){return(await Promise.all(this.sources.map(source=>source.inventory()))).flat();}
}
export interface ReviewedClerkEnvironmentMapping {
 envFile:string;
 /** Canonical original provenance when reading an immutable backup after cutover. */
 sourceIdentityFile?:string;
 environment:string;
 applicationId:string;
}
/** Explicit operator import of an existing working Clerk pair. Only the private
 * Clerk API credential is imported here; never root keys, grants or other ENV. */
export class ReviewedClerkEnvironmentMigrationSource implements MigrationSource {
 constructor(private readonly mappings:readonly ReviewedClerkEnvironmentMapping[],private readonly versionKey:Buffer){
  if(!Buffer.isBuffer(versionKey)||versionKey.length!==32)throw Error('Private review key required');
 }
 async inventory():Promise<LegacyItem[]> {
  if(this.mappings.length>100)throw Error('Clerk seed mapping exceeds limits');
  const result:LegacyItem[]=[];
  for(const mapping of this.mappings){
   const owner=scopeFilter({environment:mapping.environment,ownerType:'application',ownerId:applicationIdentity(mapping.applicationId)});
   const filename=await realpath(mapping.envFile),identityFilename=mapping.sourceIdentityFile===undefined?filename:await realpath(mapping.sourceIdentityFile),env=parseEnv(await readFile(filename,'utf8'));
   const value=env.CLERK_SECRET_KEY,publishable=env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
   if(!value||!/^sk_(test|live)_[A-Za-z0-9_-]+$/.test(value)||!publishable||!/^pk_(test|live)_[A-Za-z0-9+/_-]+={0,2}$/.test(publishable))throw Error('Explicit working Clerk pair required');
   const sourceId=`reviewed-clerk-environment:${owner.environment}:${owner.ownerId}:${identityFilename}:CLERK_SECRET_KEY`;
   result.push({sourceId,revision:0,owner,name:owner.ownerId+'-clerk-secret-key',kind:'secret',valueFormat:'text',custody:'workload-only',versions:[{id:createHmac('sha256',this.versionKey).update('reviewed-clerk-environment-version\0'+sourceId+'\0'+value).digest('hex'),value}]});
  }
  return result;
 }
}
