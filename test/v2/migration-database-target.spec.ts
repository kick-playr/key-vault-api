import {rewriteReviewedDatabaseTarget} from '../../src/v2/migration-database-target.js';
it('changes only the explicitly approved database path, preserving credentials, hosts and authSource',()=>{
 const input='mongodb://user:p%40ss@host-a:27017,host-b:27017/old?authSource=admin&replicaSet=rs0';
 expect(rewriteReviewedDatabaseTarget(input,{environment:'development',ownerType:'tenant',ownerId:'fcrww'},'fcrww-kick-playr')).toBe('mongodb://user:p%40ss@host-a:27017,host-b:27017/fcrww-kick-playr?authSource=admin&replicaSet=rs0');
 expect(()=>rewriteReviewedDatabaseTarget(input,{environment:'development',ownerType:'tenant',ownerId:'fcrww'},'other-kick-playr')).toThrow();
 expect(()=>rewriteReviewedDatabaseTarget('redis://host/0',{environment:'development',ownerType:'application',ownerId:'club-api'},'control-kick-playr')).toThrow();
});
