module.exports = { ...require('./jest.config.cjs'), setupFilesAfterEnv: [], testMatch: ['**/test/v2/**/*.spec.ts'], testPathIgnorePatterns: ['/node_modules/', '/test/v2/mongo-store.spec.ts'] };
