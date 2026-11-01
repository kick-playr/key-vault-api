// Pure HTTP/in-memory and runtime/config contracts: no disposable mongod setup.
module.exports = {
  ...require('./jest.config.cjs'),
  setupFilesAfterEnv: [],
  testMatch: ['**/test/audit.spec.ts', '**/test/config.spec.ts', '**/test/runtime-client.spec.ts', '**/test/runtime-snapshot.spec.ts'],
};
