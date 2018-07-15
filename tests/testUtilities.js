'use strict';

exports.fakeStore = {
  // Signature: (userId, refreshTokenJTI)
  remove: jest.fn(() => true),
  // Signature: (userId)
  removeAll: jest.fn(() => true),
  // Signature: (userId, refreshTokenJTI, accessTokenJTI, ttl)
  add: jest.fn(() => true),
};
