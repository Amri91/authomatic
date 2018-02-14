'use strict';

const util = require('util');
const crypto = require('crypto');
const {omit, merge} = require('ramda');

const Authomatic = require('../index');

const customAlgorithm = 'HS256';

const acceptableVerifyOptions = {
  algorithm: customAlgorithm
};

const acceptableSignOptions = {
  algorithm: customAlgorithm
};

const randomBytes = util.promisify(crypto.randomBytes);

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

describe('authomatic', () => {
  let authomatic, fakeStore, fakeJWT;
  const userId = '123', token = '789', secret = 'asdfasdfasdfasdf1234';

  let refreshToken;

  beforeAll(async () => {
    refreshToken = Buffer.concat([
      await randomBytes(128), new Buffer('123', 'utf8')
    ]).toString('base64');
  });

  beforeEach(() => {
    fakeStore = {
      // Signature: (userId, refreshToken)
      remove: jest.fn(() => true),
      // Signature: (userId)
      removeAll: jest.fn(() => true),
      // Signature: (userId, refreshToken)
      getAccessToken: jest.fn(() => token),
      // Signature: (userId, refreshToken, accessToken, ttl)
      registerTokens: jest.fn(() => true),
    };
    fakeJWT = {
      verify: jest.fn(token => token),
      sign: jest.fn(() => 'I am a token'),
      decode: jest.fn(() => ({uid: 123, exp: 123, rme: true, pld: {}}))
    };
    authomatic = Authomatic({store: fakeStore, algorithm: customAlgorithm, jwt: fakeJWT});
  });

  describe('#constructor', () => {
    it('should not allow incomplete store object', () => {
      // Store missing the remove function
      expect(() => Authomatic({store: omit(['remove'], fakeStore)})).toThrow();
    });
    it('should not allow the none algorithm', () => {
      expect(() => Authomatic({algorithm: 'none'})).toThrow();
    });
    it('should not accept values greater than an hour', () => {
      expect(() => Authomatic({expiresIn: 60 * 60 * 12})).toThrow();
    });
  });
  describe('#invalidateRefreshToken', () => {
    it('should instruct the store to remove the refresh token', () => {
      authomatic.invalidateRefreshToken(refreshToken);
      expect(fakeStore.remove.mock.calls[0][0]).toBe(userId);
      expect(fakeStore.remove.mock.calls[0][1]).toBe(refreshToken);
    });
    it('Should be true on success', () => {
      expect(authomatic.invalidateRefreshToken(refreshToken)).toBe(true);
    });
    it('Should be false if token was not found', () => {
      // Make remove unsuccessful
      authomatic = Authomatic({store: merge(fakeStore, {remove: jest.fn(() => false)})});
      expect(authomatic.invalidateRefreshToken(refreshToken)).toBe(false);
    });
  });
  describe('#invalidateAllRefreshTokens', () => {
    it('should instruct the store to remove all refresh tokens', () => {
      authomatic.invalidateAllRefreshTokens(userId);
      expect(fakeStore.removeAll.mock.calls[0][0]).toBe(userId);
    });
    it('Should be truthy on success', () => {
      expect(authomatic.invalidateAllRefreshTokens(userId)).toBe(true);
    });
    it('Should be falsey if no tokens were found', () => {
      // make removeAll unsuccessful
      authomatic = Authomatic({store: merge(fakeStore, {removeAll: jest.fn(() => false)})});
      expect(authomatic.invalidateAllRefreshTokens(userId)).toBe(false);
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
    it('should throw an error if the tokens mismatch', async () => {
      const trustedToken = '123', oldToken = '1234';
      expect.assertions(1);
      authomatic = Authomatic({
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
      authomatic = Authomatic({
        // Make remove operation unsuccessful
        store: merge(fakeStore, {remove: jest.fn(() => false)}), jwt: fakeJWT
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
      await authomatic.sign('123', secret);
      const {exp, jti, ...payload} = fakeJWT.sign.mock.calls[0][0];
      expect(exp).toBeTruthy();
      expect(jti).toBeTruthy();
      expect(payload).toEqual({pld: {}, rme: false, uid: '123'});
      expect(fakeJWT.sign.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.sign.mock.calls[0][2]).toEqual(acceptableSignOptions);
    });
    it('should allow payload to contain unstrictly defined properties', async () => {
      const content = {someProp: '123'};
      await authomatic.sign('123', secret, content);
      const {exp, jti, ...payload} = fakeJWT.sign.mock.calls[0][0];
      expect(exp).toBeTruthy();
      expect(jti).toBeTruthy();
      expect(payload).toEqual({pld: content, rme: false, uid: '123'});
      expect(fakeJWT.sign.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.sign.mock.calls[0][2]).toEqual(acceptableSignOptions);
    });
    it('should return correct object', async () => {
      const object = await authomatic.sign('123', secret);
      expect(object).toEqual(expect.objectContaining({
        accessToken: expect.any(String),
        accessTokenExpiresAt: expect.any(Number),
        refreshToken: expect.any(String),
        refreshTokenExpiresAt: expect.any(Number)
      }));
    });
    it('should prolong the refreshToken ttl when rememberMe is true', async () => {
      const {refreshTokenExpiresAt: longTTL} = await authomatic.sign('123', secret, {}, true);
      const {refreshTokenExpiresAt: shortTTL} = await authomatic.sign('123', secret);
      expect(longTTL > shortTTL).toBeTruthy();
    });
    it('should recalculate current time every time a new pair of tokens are created. Issue #21',
      async () => {
        const {accessTokenExpiresAt: firstAT, refreshTokenExpiresAt: firstRT} =
          await authomatic.sign('123', secret);
        await sleep(2000);
        const {accessTokenExpiresAt: secondAT, refreshTokenExpiresAt: secondRT} =
          await authomatic.sign('123', secret);
        expect(firstAT < secondAT).toBeTruthy();
        expect(firstRT < secondRT).toBeTruthy();
      }
    );
  });
});
