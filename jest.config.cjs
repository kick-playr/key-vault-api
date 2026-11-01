module.exports = { preset: 'ts-jest', testEnvironment: 'node', setupFilesAfterEnv: ['<rootDir>/test/mongo.ts'], testMatch: ['**/test/**/*.spec.ts'], testTimeout: 20000 };
