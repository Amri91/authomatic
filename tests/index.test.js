'use strict';

const {omit, merge} = require('ramda');

const testUtilities = require('./testUtilities');

const Authomatic = require('../index');

const customAlgorithm = 'HS256';

const acceptableSignOptions = {
  algorithm: customAlgorithm
};

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

describe('authomatic', () => {
  let authomatic, fakeStore, fakeJWT;
  const userId = '123', secret = 'asdfasdfasdfasdf1234', refreshToken = {
    aud: ['Authomatic'], iss: 'Authomatic',
    uid: userId, jti: 'rtJTI', accessTokenJTI: 'atJTI',
    exp: 123, t: 'Authomatic-RT'
  };

  beforeEach(() => {
    fakeStore = testUtilities.fakeStore;
    fakeJWT = {
      verify: jest.fn(t => t),
      sign: jest.fn(t => t),
      decode: jest.fn(t => t)
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
    it('Should be true on success', () => {
      expect(authomatic.invalidateRefreshToken(refreshToken, secret)).toBe(true);
    });
    it('Should be false if token was not found', () => {
      // Make remove unsuccessful
      authomatic = Authomatic(
        {store: merge(fakeStore, {remove: jest.fn(() => false)}), jwt: fakeJWT}
      );
      expect(authomatic.invalidateRefreshToken(refreshToken, secret)).toBe(false);
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
  describe('#sign', () => {
    it('should instruct jwt.sign to sign a token with correct arguments', async () => {
      await authomatic.sign('123', secret);
      const {exp, jti, ...payload} = fakeJWT.sign.mock.calls[0][0];
      expect(exp).toBeTruthy();
      expect(jti).toBeTruthy();
      expect(payload).toEqual({pld: {}, rme: false, uid: '123', t: 'Authomatic-AT'});
      expect(fakeJWT.sign.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.sign.mock.calls[0][2]).toEqual(acceptableSignOptions);
    });
    it('should allow payload to contain unstrictly defined properties', async () => {
      const content = {someProp: '123'};
      await authomatic.sign('123', secret, content);
      const {exp, jti, ...payload} = fakeJWT.sign.mock.calls[0][0];
      expect(exp).toBeTruthy();
      expect(jti).toBeTruthy();
      expect(payload.pld).toEqual(content);
      expect(fakeJWT.sign.mock.calls[0][1]).toBe(secret);
      expect(fakeJWT.sign.mock.calls[0][2]).toEqual(acceptableSignOptions);
    });
    it('should return correct object', async () => {
      const object = await authomatic.sign('123', secret);
      expect(object).toEqual(expect.objectContaining({
        accessToken: expect.anything(),
        accessTokenExpiresAt: expect.any(Number),
        refreshToken: expect.anything(),
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
