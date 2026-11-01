# Node 24 dependency update

User requested current packages while retaining Node 24. Preserve the existing package updates already in the working tree.

- Upgrade NestJS to 12.3.2 and MongoDB driver to 7.8.0; both declare Node versions including 24.
- Adopt native ESM (`type: module`, NodeNext TypeScript resolution, explicit relative `.js` imports). Configure Jest/ts-jest for ESM with Node's VM-modules flag, so ESM dependencies are loaded in the same test realm.
- Upgrade TypeScript to 6.0.3, the latest release inside ts-jest's declared `>=4.3 <7` peer range. TypeScript 7 is deliberately excluded; keep Node types on 24, not latest 26.
- Set the supported runtime to Node 24.x and add `.nvmrc`; keep all scripts executable on Node 24. Replace ts-node with compilation followed by native Node for the development start script.
- Remove the multer override once Nest 12 brings the patched version directly. Inspect remaining audit findings without forcing incompatible dependency downgrades.
- Verify clean install, build, typecheck, all real-MongoDB tests, production/development startup and production audit on Node 24.22.0. No application behavior or API security policy changes are intended.
