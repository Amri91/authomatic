'use strict';

module.exports = {
  collectCoverageFrom: [
    'index.js',
    '!**/node_modules/**',
    '!**/vendor/**',
    '!examples/**'
  ],
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100
    }
  }
};
