module.exports = {
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  transform: { '^.+\\.tsx?$': ['ts-jest', { useESM: true }] },
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  setupFilesAfterEnv: ['<rootDir>/test/mongo.ts'],
  testMatch: ['**/test/**/*.spec.ts'],
  testTimeout: 20000,
};
