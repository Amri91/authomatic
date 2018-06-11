'use strict';

const jwt = require('jsonwebtoken');

const Authomatic = require('../index');
const testUtilities = require('./testUtilities');

const algorithm = 'HS256';

const userId = '123';
const secret = 'asdfasdfasdfasdf1234';
const computeExpiryDate = seconds => Math.floor(Date.now() / 1000) + seconds;

const createFakeAccessToken = (jti, exp, alg) =>
  jwt.sign(
    {
      pld: {}, uid: userId, jti: jti || 'atJTI',
      exp: exp || computeExpiryDate(10), t: 'Authomatic-AT'
    },
    secret, {algorithm: alg || algorithm}
  );

const createFakeRefreshToken = (jti, atJTI, exp) =>
  jwt.sign(
    {
      aud: ['Authomatic'], iss: 'Authomatic',
      uid: userId, jti: jti || 'rtJTI', accessTokenJTI: atJTI || 'atJTI',
      exp: exp || computeExpiryDate(100), t: 'Authomatic-RT'
    },
    secret, {algorithm}
  );

const accessToken = createFakeAccessToken();
const refreshToken = createFakeRefreshToken();

describe('authomatic', () => {
  let authomatic, fakeStore;

  beforeEach(() => {
    fakeStore = testUtilities.fakeStore;
    authomatic = Authomatic({store: fakeStore, algorithm, jwt});
  });

  describe('#verify', () => {
    it('Should verify and decode tokens', async () => {
      const exp = computeExpiryDate(10);
      expect(await authomatic.verify(createFakeAccessToken('jti', exp), secret))
      .toEqual({
        pld: {}, uid: userId, jti: 'jti',
        exp, iat: exp - 10, t: 'Authomatic-AT'
      });
    });
    it('Should fail if the algorithm mismatch', async () => {
      expect.assertions(1);
      try {
        await authomatic.verify(createFakeAccessToken(null, null, 'RS256'), secret);
      } catch (e) {
        expect(e).toBeTruthy();
      }
    });
    it('Should fail when trying to verify refresh tokens instead of access tokens', async () => {
      expect.assertions(1);
      try {
        await authomatic.verify(createFakeRefreshToken(), secret);
      } catch (e) {
        expect(e.name).toBe('InvalidToken');
      }
    });
  });
  describe('#refresh', () => {
    it('Should return a new pair of valid tokens', async () => {
      const results =
        await authomatic.refresh(refreshToken, accessToken, secret, {});
      expect(authomatic.verify(results.accessToken, secret)).toBeTruthy();
      expect(
        authomatic.refresh(results.refreshToken, results.accessToken, secret, {})
      ).toBeTruthy();
    });
    it('Should not refresh mismatching tokens', async () => {
      expect.assertions(1);
      const mismatchingAccessToken =
        jwt.sign(
          {pld: {}, uid: userId, jti: 'mismatchingJTI', t: 'Authomatic-AT'}, secret, {algorithm}
        );
      try {
        await authomatic.refresh(refreshToken, mismatchingAccessToken, secret, {});
      } catch(e) {
        expect(e.name).toBe('TokensMismatch');
      }
    });
    it('Should throw an error if the refresh token expired', async () => {
      expect.assertions(1);
      try {
        await authomatic.refresh(
          createFakeRefreshToken(0, 0, computeExpiryDate(-10)), null, secret, {}
        );
      } catch(e) {
        expect(e.name).toBe('TokenExpiredError');
      }
    });
    it('Should throw an error if refresh token and access tokens were swaped', async () => {
      expect.assertions(1);
      try {
        await authomatic.refresh(createFakeAccessToken(), createFakeRefreshToken(), secret, {}
        );
      } catch(e) {
        expect(e.name).toBe('InvalidToken');
      }
    });
    it('Should accept expired access tokens', async () => {
      expect(await authomatic.refresh(
        createFakeRefreshToken(0, 0, computeExpiryDate()),
        createFakeAccessToken(0, computeExpiryDate(-10)), secret, {}
      )).toBeTruthy();
    });
  });
});
