const base = require('./jest.config.cjs');
module.exports = { ...base, setupFilesAfterEnv: [], testMatch: ['**/test/runtime-snapshot.spec.ts', '**/test/runtime-client.spec.ts'] };
