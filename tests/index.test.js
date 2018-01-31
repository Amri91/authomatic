'use strict';

const Authomatic = require('../index');
const {omit, merge} = require('ramda');

const customAlgorithm = 'HS256';

const acceptableVerifyOptions = {
  algorithm: customAlgorithm
};

const acceptableSignOptions = {
  algorithm: customAlgorithm
};

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

describe('authomatic', () => {
  let authomatic, fakeStore, fakeJWT;
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
      decode: jest.fn(() => ({exp: 123, rme: true, pld: {userId: 123}}))
    };
    authomatic = new Authomatic({store: fakeStore, algorithm: customAlgorithm, jwt: fakeJWT});
  });

  describe('#constructor', () => {
    it('should not allow incomplete store object', () => {
      // Store missing the remove function
      expect(() => new Authomatic({store: omit(['remove'], fakeStore)})).toThrow();
    });
    it('should not allow the none algorithm', () => {
      expect(() => new Authomatic({algorithm: 'none'})).toThrow();
    });
    it('should not accept values greater than an hour', () => {
      expect(() => new Authomatic({expiresIn: 60 * 60 * 12})).toThrow();
    });
  });
  describe('#invalidateRefreshToken', () => {
    it('should instruct the store to remove the refresh token', () => {
      authomatic.invalidateRefreshToken(userId, refreshToken);
      expect(fakeStore.remove.mock.calls[0][0]).toBe(userId);
      expect(fakeStore.remove.mock.calls[0][1]).toBe(refreshToken);
    });
    it('Should be truthy on success', () => {
      expect(authomatic.invalidateRefreshToken(userId, refreshToken)).toBeTruthy();
    });
    it('Should be falsey if token was not found', () => {
      // Make remove unsuccessful
      authomatic = new Authomatic({store: merge(fakeStore, {remove: jest.fn(() => 0)})});
      expect(authomatic.invalidateRefreshToken(userId, refreshToken)).toBeFalsy();
    });
  });
  describe('#invalidateAllRefreshTokens', () => {
    it('should instruct the store to remove all refresh tokens', () => {
      authomatic.invalidateAllRefreshTokens(userId);
      expect(fakeStore.removeAll.mock.calls[0][0]).toBe(userId);
    });
    it('Should be truthy on success', () => {
      expect(authomatic.invalidateAllRefreshTokens(userId)).toBeTruthy();
    });
    it('Should be falsey if no tokens were found', () => {
      // make removeAll unsuccessful
      authomatic = new Authomatic({store: merge(fakeStore, {removeAll: jest.fn(() => 0)})});
      expect(authomatic.invalidateAllRefreshTokens(userId)).toBeFalsy();
    });
  });
  describe('#verify', () => {
    it('should instruct jwt to verify the token', async () => {
      await authomatic.verify(token, secret);
      expect(fakeJWT.verify.mock.calls[0][0]).toBe(token);
      expect(fakeJWT.verify.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.verify.mock.calls[0][2]).toEqual(acceptableVerifyOptions);
    });
    it('should return jwt.verify results', async () => {
      expect(await authomatic.verify(token, secret)).toBeTruthy();
    });
  });
  describe('#refresh', () => {
    it('should instruct sign to refresh token with correct arguments', async () => {
      const trustedToken = '123';
      authomatic = new Authomatic({
        // Make store returns expected token
        jwt: fakeJWT, store: merge(fakeStore, {getAccessToken: jest.fn(() => trustedToken)})
      });
      // Stub out sign
      authomatic.sign = jest.fn();
      await authomatic.refresh(refreshToken, trustedToken, secret);
      expect(authomatic.sign.mock.calls[0][1]).toBe(secret);
      expect(authomatic.sign.mock.calls[0][2]).toBeTruthy();
    });
    it('should throw an error if the tokens mismatch', async () => {
      const trustedToken = '123', oldToken = '1234';
      expect.assertions(1);
      authomatic = new Authomatic({
        // Make store return expected token
        store: merge(fakeStore, {getAccessToken: jest.fn(() => trustedToken)}), jwt: fakeJWT
      });
      try {
        await authomatic.refresh(refreshToken, oldToken, secret);
      } catch(e) {
        expect(e.name).toBe('InvalidAccessToken');
      }
    });
    it('should throw an error if the refresh token expired', async () => {
      expect.assertions(1);
      authomatic = new Authomatic({
        // Make remove operation unsuccessful
        store: merge(fakeStore, {remove: jest.fn(() => 0)}), jwt: fakeJWT
      });
      try {
        await authomatic.refresh(refreshToken, token, secret);
      } catch(e) {
        expect(e.name).toBe('RefreshTokenExpiredOrNotFound');
      }
    });
  });
  describe('#sign', () => {
    it('should instruct jwt.sign to sign a token with correct arguments', async () => {
      const content = {userId: '123'};
      await authomatic.sign(content, secret);
      expect(fakeJWT.sign.mock.calls[0][0].pld).toEqual(content);
      expect(fakeJWT.sign.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.sign.mock.calls[0][2]).toEqual(acceptableSignOptions);
    });
    it('should allow payload to contain unstrictly defined properties', async () => {
      const content = {userId: '123', someProp: '123'};
      await authomatic.sign(content, secret);
      expect(fakeJWT.sign.mock.calls[0][0].pld).toEqual(content);
      expect(fakeJWT.sign.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.sign.mock.calls[0][2]).toEqual(acceptableSignOptions);
    });
    it('should return correct object', async () => {
      const content = {userId: '123'};
      const object = await authomatic.sign(content, secret);
      expect(object).toEqual(expect.objectContaining({
        accessToken: expect.any(String),
        accessTokenExpiresAt: expect.any(Number),
        refreshToken: expect.any(String),
        refreshTokenExpiresAt: expect.any(Number)
      }));
    });
    it('should prolong the refreshToken ttl when rememberMe is true', async () => {
      const content = {userId: '123'};
      const {refreshTokenExpiresAt: longTTL} = await authomatic.sign(content, secret, true);
      const {refreshTokenExpiresAt: shortTTL} = await authomatic.sign(content, secret);
      expect(longTTL > shortTTL).toBeTruthy();
    });
    it('should recalculate current time every time a new pair of tokens are created. Issue #21',
      async () => {
        const content = {userId: '123'};
        const {accessTokenExpiresAt: firstAT, refreshTokenExpiresAt: firstRT} =
          await authomatic.sign(content, secret);
        await sleep(2000);
        const {accessTokenExpiresAt: secondAT, refreshTokenExpiresAt: secondRT} =
          await authomatic.sign(content, secret);
        expect(firstAT < secondAT).toBeTruthy();
        expect(firstRT < secondRT).toBeTruthy();
      }
    );
  });
});
