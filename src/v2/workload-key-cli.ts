import {loadConfig} from '../config.js';
import {V2MongoStore} from './mongo-store.js';
import {createWorkloadOperator} from './workload-operator.js';
import {ResourceService} from './resources.js';
import {KeyRotationService} from './key-rotations.js';
import {IntegrationSchemas} from './integration-schemas.js';
import {runWorkloadKeyCommand} from './workload-key-command.js';
async function main(){
 const password=process.env.VAULT_OPERATOR_GRANT,environment=process.env.VAULT_ENVIRONMENT,ownerId=process.env.VAULT_APPLICATION_ID;
 if(!password||!environment||!ownerId)throw Error();
 const config=loadConfig(process.env);let store:V2MongoStore|undefined;
 try{
  store=await V2MongoStore.open(config);
  const scope={environment,ownerType:'application' as const,ownerId};
  const {actor,authorization}=await createWorkloadOperator(store,'Bearer '+password,scope);
  const resources=new ResourceService(store,authorization,new IntegrationSchemas()),rotations=new KeyRotationService(store,authorization);
  const result=await runWorkloadKeyCommand(process.argv.slice(2),{prepare:(id,revision)=>resources.stageGeneratedKey(actor,scope,id,revision,rotations),status:id=>rotations.status(actor,scope,id),activate:id=>rotations.activate(actor,scope,id),retire:(id,confirmation,reason)=>rotations.retireInstance(actor,scope,id,confirmation,reason)});
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
 }finally{await store?.close();config.masterKey.fill(0);}
}
void main().catch(()=>{process.stderr.write('Operator key command failed. Check scope, permissions, revision, instance acknowledgements and verified migration evidence. No key values are printed.\n');process.exitCode=1;});
