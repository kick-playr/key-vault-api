export interface WorkloadKeyPort {
 prepare(id:string,revision:number):Promise<{rotationId:string;state:string}>;
 status(id:string):Promise<{rotations:Record<string,unknown>[];participants:Record<string,unknown>[]} >;
 activate(id:string):Promise<{state:string}>;
 retire(id:string,confirmation:string,reason:string):Promise<unknown>;
}
const pick=(row:Record<string,unknown>,fields:string[])=>Object.fromEntries(fields.filter(field=>Object.hasOwn(row,field)).map(field=>[field,row[field]]));
/** Operator CLI boundary: explicit retirement, metadata output, no key material. */
export async function runWorkloadKeyCommand(args:readonly string[],port:WorkloadKeyPort) {
 if(args[0]==='prepare' && args.length===3 && /^[1-9][0-9]*$/.test(args[2]!) && Number.isSafeInteger(Number(args[2]))) {
  const row=await port.prepare(args[1]!,Number(args[2]));return {rotationId:row.rotationId,state:row.state};
 }
 if(args[0]==='status' && args.length===2) {
  const result=await port.status(args[1]!);
  return {rotations:result.rotations.map(row=>pick(row,['_id','state','resourceId','oldVersionId','newVersionId','createdAt'])),participants:result.participants.map(row=>pick(row,['rotationId','instanceId','applicationId','acknowledged','retired','retiredAt','retirementReason']))};
 }
 if(args[0]==='activate' && args.length===2) {const row=await port.activate(args[1]!);return {state:row.state};}
 if(args[0]==='retire' && args.length===4 && args[2]==='PERMANENTLY STOPPED '+args[1] && args[3]?.trim()) {
  await port.retire(args[1]!,args[2],args[3]);return {retired:true};
 }
 throw Error('Usage: prepare <resource-id> <revision> | status <resource-id> | activate <rotation-id> | retire <instance-id> "PERMANENTLY STOPPED <instance-id>" <reason>');
}
