import type { Collection, Document } from 'mongodb';
import { MongoStore } from '../src/store.js';
import { newSecret } from '../src/vault.js';
import { fixture } from './helpers.js';
it('backfills encrypted historical versions, preserves references and is idempotent',async()=>{
  const f=await fixture();const store=await MongoStore.open(f.config,{createVerifier:false});const scope={environment:'dev',tenant:'a'};
  try{
    await store.transaction({environment:'dev',tenant:'_shared'},ns=>{ns.applications={app:{displayName:'App',description:''}};});
    await store.transaction(scope,ns=>{
      const old=newSecret({value:'aB01'.repeat(16),attributes:{enabled:false}}),current=newSecret({value:Buffer.alloc(32,5).toString('base64')});delete old.valueFormat;delete current.valueFormat;
      ns.secrets.sample=[old,current];ns.secrets.explicit=[newSecret({value:'aB01'.repeat(16),valueFormat:'text'})];
      ns.resourceAssociations={'secrets/sample':{envName:'EXAMPLE',memberships:{app:old.version}}};
    });
    const before=await store.read(scope,ns=>ns!);
    expect(await store.backfillSecretValueFormats(true)).toMatchObject({namespaces:1,versions:2});expect(await store.read(scope,ns=>ns)).toEqual(before);
    expect(await store.backfillSecretValueFormats(false)).toMatchObject({namespaces:1,versions:2});
    const after=await store.read(scope,ns=>ns!);expect(after.resourceAssociations).toEqual(before.resourceAssociations);
    expect(after.secrets.sample!.map(v=>[v.value,v.version,v.attributes])).toEqual(before.secrets.sample!.map(v=>[v.value,v.version,v.attributes]));
    expect(after.secrets.sample!.map(v=>v.valueFormat)).toEqual(['hex64','base64']);expect(after.secrets.explicit![0]!.valueFormat).toBe('text');
    expect(await store.backfillSecretValueFormats(false)).toMatchObject({namespaces:0,versions:0});
    expect(await store.read(scope,ns=>ns)).toEqual(after);
  }finally{await store.close();await f.cleanup();}
});

it('backfill preserves concurrent version creation and metadata updates from another store',async()=>{
  const f=await fixture();const one=await MongoStore.open(f.config,{createVerifier:false}),two=await MongoStore.open(f.config,{createVerifier:false});const scope={environment:'dev',tenant:'a'};
  try{
    await one.transaction(scope,ns=>{const v=newSecret({value:'aB01'.repeat(16)});delete v.valueFormat;ns.secrets.example=[v];});
    // Force the other process to commit after migration reads but before its first CAS.
    const collection=(one as unknown as {collection:Collection<Document>}).collection;
    const replace=collection.replaceOne.bind(collection);let injected=false;
    collection.replaceOne=async(...args:Parameters<typeof collection.replaceOne>)=>{
      if(!injected){injected=true;await two.transaction(scope,ns=>{ns.secrets.example![0]!.tags={owner:'concurrent-writer'};ns.secrets.example!.push(newSecret({value:'concurrent plain text'}));});}
      return replace(...args);
    };
    expect(await one.backfillSecretValueFormats(false)).toMatchObject({versions:1});expect(injected).toBe(true);
    const versions=await one.read(scope,ns=>ns!.secrets.example!);
    expect(versions).toHaveLength(2);expect(versions[0]).toMatchObject({valueFormat:'hex64',tags:{owner:'concurrent-writer'},value:'aB01'.repeat(16)});expect(versions[1]).toMatchObject({value:'concurrent plain text',valueFormat:'text'});
  }finally{await one.close();await two.close();await f.cleanup();}
});
