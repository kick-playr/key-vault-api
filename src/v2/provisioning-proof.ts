import type { Actor, AdminAction } from "./authorization.js";
import type { GrantCapability } from "./records.js";
export interface ProvisioningProof {
  grantId: string;
  revision: number;
  environment: string;
  tokenHash: string;
  capabilities: readonly GrantCapability[];
}
const proofs = new WeakMap<Actor, ProvisioningProof>();
export function bindProvisioning(
  actor: Actor,
  proof: ProvisioningProof,
): Actor {
  const identity = { issuer: actor.issuer, subject: actor.subject };
  proofs.set(
    identity,
    Object.freeze({
      ...proof,
      capabilities: Object.freeze([...proof.capabilities]),
    }),
  );
  return identity;
}
export function provisioningProof(actor: Actor) {
  return proofs.get(actor);
}
export function copyActor(actor: Actor): Actor {
  const proof = proofs.get(actor);
  return proof
    ? bindProvisioning(actor, proof)
    : { issuer: actor.issuer, subject: actor.subject };
}
export function provisioningAllows(actor: Actor, action: AdminAction) {
  const proof = proofs.get(actor);
  if (!proof) return true;
  const capability: Record<AdminAction, GrantCapability> = {
    "metadata:list": "metadata:list",
    "values:read": "secrets:read",
    "keys:export": "keys:export",
    "resources:write": "resources:write",
    "links:write": "assignments:write",
    "grants:admin": "grants:admin",
    "rotations:admin": "rotations:admin",
    "consent:write": "resources:write",
  };
  return proof.capabilities.includes(capability[action]);
}
