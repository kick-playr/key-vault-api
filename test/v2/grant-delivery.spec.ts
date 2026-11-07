import {mkdtemp,readFile,stat,rm,mkdir,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PrivateFileGrantSink} from '../../src/v2/grant-delivery.js';
it('stages bootstrap credentials only in a private new deployment file, never replaces an active file',async()=>{
 const root=await mkdtemp(join(tmpdir(),'grant-delivery-'));
 try{
  await chmod(root,0o700);
  const filename=join(root,'candidate.json');
  const sink=new PrivateFileGrantSink('deployment-a',filename,'http://127.0.0.1:4000');
  await sink.deliver({applicationId:'club-api',environment:'development',password:'a'.repeat(43)});
  expect((await stat(filename)).mode&0o777).toBe(0o600);
  expect(JSON.parse(await readFile(filename,'utf8'))).toEqual({VAULT_URL:'http://127.0.0.1:4000',VAULT_APPLICATION_ID:'club-api',VAULT_ENVIRONMENT:'development',VAULT_GRANT:'a'.repeat(43)});
  await expect(sink.deliver({applicationId:'club-api',environment:'development',password:'b'.repeat(43)})).rejects.toThrow();
  const loose=join(root,'loose');await mkdir(loose,{mode:0o755});
  await expect(new PrivateFileGrantSink('unsafe',join(loose,'candidate'),'http://127.0.0.1:4000').deliver({applicationId:'club-api',environment:'development',password:'a'.repeat(43)})).rejects.toThrow();
 }finally{await rm(root,{recursive:true,force:true});}
});
