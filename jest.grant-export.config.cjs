module.exports = {
  ...require('./jest.config.cjs'),
  setupFilesAfterEnv: [],
  testMatch: ['**/test/create-key-vault-grants.spec.ts'],
};
