import { runWorkloadKeyCommand } from '../../src/v2/workload-key-command.js';
it('requires an explicit permanent-stop confirmation and returns metadata only',async()=>{
 let retired=0;
 const port={prepare:async()=>({rotationId:'r',state:'prepared'}),activate:async()=>({state:'active'}),status:async()=>({rotations:[{_id:'r',state:'prepared',oldVersionId:'old',newVersionId:'new',value:'PRIVATE'}],participants:[{instanceId:'i',acknowledged:false,retired:false,password:'PRIVATE'}]}),retire:async()=>{retired++;return {retired:true}}};
 const result=await runWorkloadKeyCommand(['status','resource'],port);expect(JSON.stringify(result)).not.toContain('PRIVATE');
 await expect(runWorkloadKeyCommand(['retire','i','yes','stopped'],port)).rejects.toThrow();expect(retired).toBe(0);
 await expect(runWorkloadKeyCommand(['retire','i','PERMANENTLY STOPPED i','operator verified'],port)).resolves.toEqual({retired:true});expect(retired).toBe(1);
});
