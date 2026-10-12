module.exports = {
    transform: {
      '^.+\\.ts$': [ 'ts-jest', {
        tsconfig: 'tsconfig.json',
      }],
      '^.+\\.m?js$': 'babel-jest',   // turns ESM JS from node_modules into CommonJS
    },
    transformIgnorePatterns: [],
    // Only run tests in the unit and integration folders.
    // All test files need to have the suffix `.test.ts`.
    testRegex: '/test/(unit|integration)/.*\\.test\\.ts$',
    moduleFileExtensions: [
      'ts',
      'js',
    ],
    testEnvironment: 'node',
    collectCoverage: true,
    coverageReporters: [ 'text', 'lcov' ],
    coveragePathIgnorePatterns: [
      '/dist/',
      '/node_modules/',
      '/test/',
    ],
    testTimeout: 90000,
  };