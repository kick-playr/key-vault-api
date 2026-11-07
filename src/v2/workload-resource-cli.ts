import { loadConfig } from "../config.js";
import { V2MongoStore } from "./mongo-store.js";
import { createWorkloadOperator } from "./workload-operator.js";
import { ResourceService } from "./resources.js";
import { IntegrationSchemas } from "./integration-schemas.js";
import { runWorkloadResourceCommand } from "./workload-resource-command.js";
async function main() {
  const password = process.env.VAULT_OPERATOR_GRANT;
  const environment = process.env.VAULT_ENVIRONMENT,
    applicationId = process.env.VAULT_APPLICATION_ID;
  if (!password || !environment || !applicationId)
    throw Error("Operator bootstrap required");
  const config = loadConfig(process.env);
  let store: V2MongoStore | undefined;
  try {
    store = await V2MongoStore.open(config);
    const scope = {
      environment,
      ownerType: "application" as const,
      ownerId: applicationId,
    };
    const operator = await createWorkloadOperator(
      store,
      "Bearer " + password,
      scope,
    );
    const schemas = new IntegrationSchemas();
    const resources = new ResourceService(
      store,
      operator.authorization,
      schemas,
    );
    await runWorkloadResourceCommand(process.argv.slice(2), {
      create: (input) => resources.create(operator.actor, scope, input),
      update: (id, revision, input) =>
        resources.update(operator.actor, scope, id, revision, input),
      reveal: (id, version) =>
        resources.reveal(operator.actor, scope, id, version),
    });
    process.stdout.write(
      "Operator resource command completed. Values are never printed.\n",
    );
  } finally {
    await store?.close();
    config.masterKey.fill(0);
  }
}
void main().catch(() => {
  process.stderr.write(
    "Operator resource command failed. Check the explicit application scope, operator grant permissions, revision and private file paths. No credentials are printed.\n",
  );
  process.exitCode = 1;
});
