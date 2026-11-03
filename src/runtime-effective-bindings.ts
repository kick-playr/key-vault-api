import type {Namespace,Scope,ResourceAssociation} from './types.js';
import {vaultName} from './manifest.js';
import {tenantKeySet} from './tenant-key-tree.js';
import {fail} from './errors.js';

/** Join a published tenant assignment to canonical resources for the live adapter.
 * This projection is never persisted as editable application links. Shared app links
 * remain wholly authoritative; tenant key pins stay migration-owned. */
export function runtimeResourceAssociations(scope:Scope,application:string,ns:Namespace|undefined):Record<string,ResourceAssociation>{
 const associations=structuredClone(ns?.resourceAssociations??{});if(!ns||scope.tenant==='_shared')return associations;
 const selected=ns.runtimeEffectiveManifests?.[application];if(!selected)return associations;const manifest=ns.runtimeManifests?.[application]?.versions[String(selected.revision)],request=manifest?.request;if(!request||request.bindingDigest!==selected.digest||manifest.scope.environment!==scope.environment||manifest.scope.tenant!==scope.tenant||manifest.application!==application)fail(409,'RuntimeBindingMismatch');
 const add=(name:string,mapping:string,policy:string)=>{const ref='secrets/'+name,old=associations[ref];if(old&&old.envName!==mapping)fail(409,'CanonicalMappingConflict');const a=associations[ref]??={envName:mapping,memberships:{}};a.memberships[application]??=policy;};
 for(const s of request.secrets){const name=vaultName(scope,'secret',s.purpose);add(name,s.mapping,selected.policies?.[name]??s.version);}
 for(const k of request.keySets){const layout=tenantKeySet(scope,k.reference);add(layout.entries[0]!.name,k.mappings.wrapping,k.wrappingVersions.find(v=>v.keyVersion===k.currentWrappingVersion)!.vaultVersion);add(layout.entries[1]!.name,k.mappings.index,k.indexVersion);add(layout.entries[2]!.name,k.mappings.control,k.controlVersion);}
 return associations;
}
