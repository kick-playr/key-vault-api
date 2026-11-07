# Local startup: Vault, Explorer and Club

Verified against the six repositories' startup scripts on 7 November 2026.
This guide describes the current local `development` environment for FCRWW.

## Prerequisites

- Use Node.js 24.x and npm. In a shell with nvm: `nvm use 24`.
- Install each repository's dependencies with `npm ci` when first setting it up or after dependency changes.
- Keep the configured MongoDB deployment reachable. Start Redis too if the runtime's configuration enables it.
- Use the existing private `.env` / `.env.local` files listed below. Application grants and the Vault root key are credentials; keep these files out of Git.
- Start each component in its own terminal. The APP and API commands are independent.

## Components and commands

Run each command **from the corresponding repository directory**.

| Component | Repository directory | Development command | Port | Browser / API URL |
| --- | --- | --- | --- | --- |
| Vault API | `/Users/Lolo/git/key-vault-api` | `npm run start:dev` | 4000 | `http://127.0.0.1:4000/docs` — Swagger |
| Vault APP | `/Users/Lolo/git/key-vault-app` | `npm run dev` | 4001 | `http://localhost:4001/` |
| Explorer API | `/Users/Lolo/git/kick-playr-tenant-explorer-api` | `npm run dev` | 3003 | `http://127.0.0.1:3003/docs` — Swagger |
| Explorer APP | `/Users/Lolo/git/kick-playr-tenant-explorer` | `npm run dev` | 3002 | `http://localhost:3002/` — global administration |
| Club API | `/Users/Lolo/git/fcrww-api-kick-playr-ch` | `npm run start:tenant-local` | 4312 | `http://127.0.0.1:4312/swagger-api` — Swagger |
| Club APP | `/Users/Lolo/git/fcrww-app-kick-playr-ch` | `npm run start:tenant-local` | 4311 | `http://fcrww.localhost:4311/` |

Club API also opens **4313**, its internal authenticated ingress used by Club APP. It starts with Club API; do not start a separate process for it or use it as the browser URL.

The Club API command starts only the API. `start:tenant-local:combined` is the optional combined launcher; use the two separate commands above when controlling APP and API independently. Generic Club `npm start` / `npm run dev` commands use a different launch path and are not the commands for this tenant-local stack.

## Startup order

1. Make MongoDB and any configured Redis service available.
2. Start **Vault API**. Wait for `Local vault ready`.
3. Start **Explorer API** and **Club API**. Wait for successful startup; Club API prints `"state":"ready"`.
4. Start **Vault APP**, **Explorer APP** and **Club APP**.

Consumers load their explicitly linked application and tenant secrets from Vault during bootstrap. Required secrets must be available before readiness. Background refresh checks for changes; requests use secrets already held in memory.

For normal shutdown, press `Ctrl+C` in each component's terminal. Stop the APPs first, then the consumer APIs, and Vault API last.

## Which URL to open

| Purpose | URL | Port |
| --- | --- | --- |
| Vault administration | `http://localhost:4001/` | 4001 |
| Explorer global administration | `http://localhost:3002/` | 3002 |
| FCRWW tenant / club administration | `http://fcrww.explorer.localhost:3002/` | 3002 |
| FCRWW Club APP | `http://fcrww.localhost:4311/` | 4311 |
| FCRWW Club API | `http://fcrww.localhost:4312/` | 4312 |
| Club API Swagger | `http://127.0.0.1:4312/swagger-api` | 4312 |
| Explorer API health | `http://127.0.0.1:3003/healthcheck` | 3003 |
| Explorer API Swagger | `http://127.0.0.1:3003/docs` | 3003 |
| Vault API Swagger | `http://127.0.0.1:4000/docs` | 4000 |

Tenant administration and club administration are sections of Explorer APP, not additional processes. Use the FCRWW Explorer hostname for the FCRWW Clerk login. The global Explorer hostname uses the platform login.

The Club API root URL is an API origin, not an application homepage. Protected endpoints require authentication. For example, the Club APP calls `/api/contacts/me` through its own origin on port 4311; direct API requests use port 4312 and must supply the required authentication.

## Run an existing build

For Vault API, Vault APP, Explorer API and Explorer APP, the alternative is:

```sh
npm run build
npm start
```

Run this in each relevant repository. Rebuild and restart that component after source changes when using `npm start`. Keep the tenant-local commands for Club API and Club APP shown above.

## Environment files

| Component | File | Vault application ID |
| --- | --- | --- |
| Vault API | `/Users/Lolo/git/key-vault-api/.env` | Root service; `VAULT_STORAGE_AUTHORITY=v2` |
| Vault APP | `/Users/Lolo/git/key-vault-app/.env` | `vault-app` |
| Explorer API | `/Users/Lolo/git/kick-playr-tenant-explorer-api/.env` | `explorer-api` |
| Explorer APP | `/Users/Lolo/git/kick-playr-tenant-explorer/.env.local` | `explorer-app` |
| Club API | `/Users/Lolo/git/fcrww-api-kick-playr-ch/.env` | `club-api` |
| Club APP | `/Users/Lolo/git/fcrww-app-kick-playr-ch/.env` | `club-app` |

All five consumers use `VAULT_URL=http://127.0.0.1:4000`, `VAULT_ENVIRONMENT=development`, their own `VAULT_APPLICATION_ID` and a private `VAULT_GRANT`. Vault APP and Explorer APP also hold separate private provisioning grants for administration. Vault API keeps its master key and MongoDB connection outside Vault so it can bootstrap independently.

## Bexio development callback

Register this exact URL in the Bexio developer console:

```text
http://fcrww.localhost:4311/bexio/oauth/callback
```

For a reconnect initiated in Explorer, Club APP relays the callback to the same tenant's Explorer session. Keep Vault API, Explorer API, Explorer APP, Club API and Club APP running during reconnect. The callback remains bound to the initiating tenant and session and cannot be replayed.

## Quick checks

- **Port occupied:** check `lsof -nP -iTCP:PORT -sTCP:LISTEN` before starting another instance. Identify the existing process before stopping it.
- **Vault unavailable / bootstrap waiting:** check Vault API, MongoDB connectivity, the consumer's bootstrap grant and its explicit secret links.
- **Club APP cannot reach its API:** check Club API's ready message and ports 4312 and 4313.
- **Wrong tenant login:** use `fcrww.explorer.localhost:3002` for FCRWW administration and `fcrww.localhost:4311` for Club APP.
- **Changes do not appear under `npm start`:** rebuild and restart the affected component. Development commands watch source changes; bootstrap env changes may still require a restart.
