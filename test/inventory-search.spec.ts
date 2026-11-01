import { InventoryService } from '../src/inventory.js';
import { VaultService } from '../src/vault.js';
import { emptyNamespace, type Scope, type Namespace } from '../src/types.js';
import type { MongoStore } from '../src/store.js';
const scope = { environment: 'dev', tenant: 'a' };
function fixture() {
  const ns=emptyNamespace();
  for (const [name,purpose] of [['physical-a','Database Password'],['database-b','other'],['physical-c','database backup'],['untagged',undefined],['literal','a.*b']]) {
    ns.secrets[name!]=[{version:'v1',attributes:{enabled:true,created:1,updated:1,recoveryLevel:'Purgeable'},value:'never-search-secret',...(purpose?{tags:{purpose}}:{})}];
  }
  const store={read: async (requested: Scope, project: (state:Namespace)=>unknown) => project(requested.tenant==='a'?ns:emptyNamespace())} as unknown as MongoStore;
  return {inventory:new InventoryService(new VaultService(store,'http://127.0.0.1:4000'),Buffer.alloc(32)),ns};
}
describe('literal inventory name-or-purpose search',()=>{
 it('matches name OR purpose case-insensitively before pagination without values',async()=>{
  const {inventory}=fixture();const first:any=await inventory.list(scope,'local/inventory',{kind:'secret',search:'DATABASE',maxresults:'1'});
  expect(first.value.map((x:any)=>x.name)).toEqual(['database-b']);
  const next:any=await inventory.list(scope,'local/inventory',Object.fromEntries(new URL(first.nextLink).searchParams));expect(next.value.map((x:any)=>x.name)).toEqual(['physical-a']);
  const last:any=await inventory.list(scope,'local/inventory',Object.fromEntries(new URL(next.nextLink).searchParams));expect(last.value.map((x:any)=>x.name)).toEqual(['physical-c']);expect(last.nextLink).toBeUndefined();
  expect(JSON.stringify(first)).not.toContain('never-search-secret');
  expect((await inventory.list(scope,'local/inventory',{search:'never-search-secret'}) as any).value).toEqual([]);
 });
 it('handles literal punctuation, missing tags, scope and existing AND constraints',async()=>{
  const {inventory}=fixture();expect((await inventory.list(scope,'local/inventory',{search:'.*'}) as any).value.map((x:any)=>x.name)).toEqual(['literal']);
  expect((await inventory.list(scope,'local/inventory',{search:'UNTAG'}) as any).value.map((x:any)=>x.name)).toEqual(['untagged']);
  expect((await inventory.list({...scope,tenant:'b'},'local/inventory',{search:'database'}) as any).value).toEqual([]);
  expect((await inventory.list(scope,'local/inventory',{search:'database',namePrefix:'physical-c'}) as any).value.map((x:any)=>x.name)).toEqual(['physical-c']);
 });
 it('bounds local-only search and binds signed cursors to the complete search',async()=>{
  const {inventory}=fixture();const first:any=await inventory.list(scope,'local/inventory',{search:'database',maxresults:'1'});const q=Object.fromEntries(new URL(first.nextLink).searchParams);q.search='other';expect(()=>inventory.list(scope,'local/inventory',q)).toThrow();
  for(const search of ['', 'x'.repeat(513), 'bad\nsearch']) expect(()=>inventory.list(scope,'local/inventory',{search})).toThrow();
  expect(()=>inventory.list(scope,'secrets',{search:'database'})).toThrow();
 });
});
