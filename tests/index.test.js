'use strict';

const JWTPlus = require('../index');
const {omit, merge} = require('ramda');
const ms = require('ms');

const customAlgorithm = 'HS256';

const acceptableVerifyOptions = {
  algorithm: customAlgorithm
};

const expiresIn = 1800;
const acceptableSignOptions = {
  algorithm: customAlgorithm
};

describe('jwtPlus', () => {
  let jwtPlus, fakeStore, fakeJWT;
  const userId = '123', token = '789', refreshToken = '456', secret = 'asdfasdfasdfasdf1234';
  beforeEach(() => {
    fakeStore = {
      // Signature: (userId, refreshToken)
      remove: jest.fn(() => 1),
      // Signature: (userId)
      removeAll: jest.fn(() => 1),
      // Signature: (userId, refreshToken)
      getAccessToken: jest.fn(() => token),
      // Signature: (userId, refreshToken, accessToken, ttl)
      registerTokens: jest.fn(() => 1),
    };
    fakeJWT = {
      verify: jest.fn(token => token),
      sign: jest.fn(() => 'I am a token'),
      decode: jest.fn(() => ({payload: {exp: expiresIn, rme: true, pld: {userId: 123}}}))
    };
    jwtPlus = new JWTPlus({store: fakeStore, algorithm: customAlgorithm, jwt: fakeJWT});
  });

  describe('#constructor', () => {
    it('should not allow incomplete store object', () => {
      // Store missing the remove function
      expect(() => new JWTPlus({store: omit(['remove'], fakeStore)})).toThrow();
    });
    it('should not allow the none algorithm', () => {
      expect(() => new JWTPlus({algorithm: 'none'})).toThrow();
    });
    it('should not accept values greater than an hour', () => {
      expect(() => new JWTPlus({expiresIn: 60 * 60 * 12})).toThrow();
    });
  });
  describe('#invalidateRefreshToken', () => {
    it('should instruct the store to remove the refresh token', () => {
      jwtPlus.invalidateRefreshToken(userId, refreshToken);
      expect(fakeStore.remove.mock.calls[0][0]).toBe(userId);
      expect(fakeStore.remove.mock.calls[0][1]).toBe(refreshToken);
    });
    it('Should be truthy on success', () => {
      expect(jwtPlus.invalidateRefreshToken(userId, refreshToken)).toBeTruthy();
    });
    it('Should be falsey if token was not found', () => {
      // Make remove unsuccessful
      jwtPlus = new JWTPlus({store: merge(fakeStore, {remove: jest.fn(() => 0)})});
      expect(jwtPlus.invalidateRefreshToken(userId, refreshToken)).toBeFalsy();
    });
  });
  describe('#invalidateAllRefreshTokens', () => {
    it('should instruct the store to remove all refresh tokens', () => {
      jwtPlus.invalidateAllRefreshTokens(userId);
      expect(fakeStore.removeAll.mock.calls[0][0]).toBe(userId);
    });
    it('Should be truthy on success', () => {
      expect(jwtPlus.invalidateAllRefreshTokens(userId)).toBeTruthy();
    });
    it('Should be falsey if no tokens were found', () => {
      // make removeAll unsuccessful
      jwtPlus = new JWTPlus({store: merge(fakeStore, {removeAll: jest.fn(() => 0)})});
      expect(jwtPlus.invalidateAllRefreshTokens(userId)).toBeFalsy();
    });
  });
  describe('#verify', () => {
    it('should instruct jwt to verify the token', async () => {
      await jwtPlus.verify(token, secret);
      expect(fakeJWT.verify.mock.calls[0][0]).toBe(token);
      expect(fakeJWT.verify.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.verify.mock.calls[0][2]).toEqual(acceptableVerifyOptions);
    });
    it('should return jwt.verify results', async () => {
      expect(await jwtPlus.verify(token, secret)).toBeTruthy();
    });
  });
  describe('#refresh', () => {
    it('should instruct sign to refresh token with correct arguments', async () => {
      const trustedToken = '123';
      jwtPlus = new JWTPlus({
        // Make store returns expected token
        jwt: fakeJWT, store: merge(fakeStore, {getAccessToken: jest.fn(() => trustedToken)})
      });
      // Stub out sign
      jwtPlus.sign = jest.fn();
      await jwtPlus.refresh(refreshToken, trustedToken, secret);
      expect(jwtPlus.sign.mock.calls[0][1]).toBe(secret);
      expect(jwtPlus.sign.mock.calls[0][2]).toBeTruthy();
    });
    it('should throw an error if the tokens mismatch', async () => {
      const trustedToken = '123', oldToken = '1234';
      expect.assertions(1);
      jwtPlus = new JWTPlus({
        // Make store return expected token
        store: merge(fakeStore, {getAccessToken: jest.fn(() => trustedToken)}), jwt: fakeJWT
      });
      try {
        await jwtPlus.refresh(refreshToken, oldToken, secret);
      } catch(e) {
        expect(e.name).toBe('InvalidAccessToken');
      }
    });
    it('should throw an error if the refresh token expired', async () => {
      expect.assertions(1);
      jwtPlus = new JWTPlus({
        // Make remove operation unsuccessful
        store: merge(fakeStore, {remove: jest.fn(() => 0)}), jwt: fakeJWT
      });
      try {
        await jwtPlus.refresh(refreshToken, token, secret);
      } catch(e) {
        expect(e.name).toBe('RefreshTokenExpiredError');
      }
    });
  });
  describe('#signIn', () => {
    it('should instruct jwt.sign to sign a token with correct arguments', async () => {
      const content = {userId: '123'};
      await jwtPlus.sign(content, secret);
      expect(fakeJWT.sign.mock.calls[0][0].pld).toEqual(content);
      expect(fakeJWT.sign.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.sign.mock.calls[0][2]).toEqual(acceptableSignOptions);
    });
    it('should return correct object', async () => {
      const content = {userId: '123'};
      const object = await jwtPlus.sign(content, secret);
      expect(object).toEqual(expect.objectContaining({
        accessToken: expect.any(String),
        accessTokenExpiresIn: expect.any(Number),
        refreshToken: expect.any(String),
        refreshTokenExpiresIn: expect.any(Number)
      }));
    });
    it('should change refreshToken life when using rememberMe option', async () => {
      const content = {userId: '123'};
      const object = await jwtPlus.sign(content, secret, true);
      expect(object.refreshTokenExpiresIn).toBe(ms('7d'));
    });
  });
});
