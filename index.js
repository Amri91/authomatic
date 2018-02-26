'use strict';

const crypto = require('crypto');
const util = require('util');
const jsonwebtoken = require('jsonwebtoken');
const t = require('tcomb');
const StandardError = require('standard-error');

const Store = t.interface({
  // Signature: (userId, refreshToken)
  remove: t.Function,
  // Signature: (userId)
  removeAll: t.Function,
  // Signature: (userId, refreshToken)
  getAccessToken: t.Function,
  // Signature: (userId, refreshToken, accessToken, ttl)
  registerTokens: t.Function
}, 'Stores');

const JWT = t.interface({
  // Signature: (payload, secret, {algorithm: String})
  sign: t.Function,
  // Signature: (payload, secret, {algorithm: String, otherVerifyOptions})
  verify: t.Function,
  // Signature: (payload)
  decode: t.Function,
}, 'JWT');

/**
 * @type {String}
 * @typedef Secret
 * @description a string greater than 20 characters
 */
const Secret = secret => {
  t.String(secret);
  t.assert(secret.length >= 20, 'The secret must be greater than or equal 20 characters');
  return secret;
};

const ExpiresAt = t.Integer;
const Algorithm = t.enums.of(['HS256', 'HS384', 'HS512', 'RS256'], 'Algorithm');
const UserId = t.Any;
const RefreshToken = t.String;
const Token = t.String;
const Prolong = t.Boolean;

/**
 * Access token
 * @typedef AccessToken
 * @type {String}
 * @description Regular JWT token.
 * Its payload looks like this:
 ```js
{
  "uid": "userId",
  "exp": "someNumber",
  "jti": "randomBytes",
  ...otherClaims,
  "pld": {
    ...otherUserContent
  }
}
 ```
 */

/**
 * Refresh token
 * @typedef RefreshToken
 * @type {String}
 * @description A base64 encoded string.
 */

/**
 * Token pairs
 * @typedef Tokens
 * @type {Object}
 * @property {AccessToken} accessToken
 * @property {Number} accessTokenExpiresAt epoch
 * @property {RefreshToken} refreshToken
 * @property {Number} refreshTokenExpiresAt epoch
 */

/**
 * Verify options to be used when verifying tokens
 * @typedef VerifyOptions
 * @type {Object}
 * @property {String|Array|Object} [audience] checks the aud field
 * @property {String|Array} [issuer] checks the iss field
 * @property {Boolean} [ignoreExpiration] if true, ignores the expiration check of access tokens
 * @property {Boolean} [ignoreNotBefore] if true, ignores the not before check of access tokens
 * @property {String} [subject] checks the sub field
 * @property {Number|String} [clockTolerance]
 * @property {String|Number} [maxAge]
 * @property {Number} [clockTimestamp] overrides the clock for the verification process
 */
const VerifyOptions = t.interface({
  audience: t.maybe(t.union([t.String, t.Array, t.Object])),
  issuer: t.maybe(t.union([t.String, t.Array])),
  ignoreExpiration: t.maybe(t.Boolean),
  ignoreNotBefore: t.maybe(t.Boolean),
  subject: t.maybe(t.String),
  clockTolerance: t.maybe(t.union([t.Number, t.String])),
  maxAge: t.maybe(t.union([t.String, t.Number])),
  clockTimestamp: t.maybe(t.Number)
}, {name: 'VerifyOptions', strict: true});

/**
 * The allowed user options to for signing tokens
 * @typedef SignOptions
 * @type {Object}
 * @property {Number} [nbf]
 * @property {String} [aud]
 * @property {String} [iss]
 * @property {String} [sub]
 */
const SignOptions = t.interface({
  nbf: t.maybe(t.Number),
  aud: t.maybe(t.String),
  iss: t.maybe(t.String),
  sub: t.maybe(t.String),
}, {name: 'SignOptions', strict: true});

const Payload = SignOptions.extend(t.interface({
  uid: UserId,
  pld: t.Any,
  exp: ExpiresAt,
  rme: t.Boolean
}, {name: 'Payload', strict: true}));

/**
 * The refresh token has expired or was not found
 * @type {StandardError}
 * @typedef RefreshTokenExpiredOrNotFound
 * @property {String} [name='RefreshTokenExpiredOrNotFound']
 */
const refreshTokenExpiredOrNotFound = new StandardError(
  'The refresh token has expired or was not found',
  {name: 'RefreshTokenExpiredOrNotFound'}
);

/**
 * The access token provided is invalid
 * @type {StandardError}
 * @typedef InvalidAccessToken
 * @property {String} [name='InvalidAccessToken']
 */
const invalidAccessToken = new StandardError(
  'The access token provided is invalid',
  {name: 'InvalidAccessToken'}
);

// 15 minutes
const regularAccessTTL = 60 * 15;
// 1 hour
const prolongedAccessTTL = 60 * 60;
// 25 minutes
const regularRefreshTTL = 60 * 25;
// 7 days
const prolongedRefreshTTL = 60 * 60 * 24 * 7;

// Seconds -> Seconds Since the Epoch
const computeExpiryDate = seconds => Math.floor(Date.now() / 1000) + seconds;

const randomBytes = util.promisify(crypto.randomBytes);

const generateTokenId = () => randomBytes(32).then(x => x.toString('base64'));

const generateRefreshToken = async userId =>
  Buffer.concat([await randomBytes(128), new Buffer(userId, 'utf8')]).toString('base64');

const getUserId = refreshToken => {
  const buf = new Buffer(refreshToken, 'base64');
  return buf.slice(128).toString('utf8');
};

/**
 * Authomatic
 * @param {Object} store one of authomatic stores
 * @param {String} [algorithm=HS256] Can be one of these ['HS256', 'HS384', 'HS512', 'RS256']
 * @param {SignOptions} [defaultSignOptions]
 * @param {VerifyOptions} [defaultVerifyOptions]
 */
module.exports = function Authomatic({
  store, algorithm = 'HS256',
  jwt = jsonwebtoken, defaultSignOptions = {}, defaultVerifyOptions = {}
}) {

  Store(store);
  Algorithm(algorithm);
  JWT(jwt);
  SignOptions(defaultSignOptions);
  VerifyOptions(defaultVerifyOptions);

  const sign = async (userId, secret, content = {}, prolong = false, signOptions = {}) => {
    UserId(userId);
    Prolong(prolong);

    const accessExp = computeExpiryDate(prolong ? prolongedAccessTTL : regularAccessTTL);
    const refreshTTL = prolong ? prolongedRefreshTTL : regularRefreshTTL;
    // Order of spreading is important!
    const payload = Payload({
      ...defaultSignOptions,
      ...SignOptions(signOptions),
      pld: content,
      uid: userId,
      exp: accessExp,
      rme: prolong,
      jti: await generateTokenId()
    });

    const refreshToken = await generateRefreshToken(userId);
    const accessToken = jwt.sign(payload, Secret(secret), {algorithm});

    await store.registerTokens(userId, refreshToken, accessToken, refreshTTL * 1000);

    return {
      accessToken,
      accessTokenExpiresAt: accessExp,
      refreshToken,
      refreshTokenExpiresAt: computeExpiryDate(refreshTTL)
    };

  };

  const verify = (token, secret, verifyOptions = {}) =>
    jwt.verify(Token(token), Secret(secret), {
      ...defaultVerifyOptions,
      ...VerifyOptions(verifyOptions),
      algorithm: algorithm
    });

  const refresh = async (refreshToken, accessToken, secret) => {
    RefreshToken(refreshToken);
    Token(accessToken);

    const userId = getUserId(refreshToken);
    const storedToken = await store.getAccessToken(userId, refreshToken);

    // Remove the refresh token even if the following operations were not successful.
    // RefreshTokens are one time use only
    if(!await store.remove(userId, refreshToken)) {
      throw refreshTokenExpiredOrNotFound;
    }

    // RefreshTokens works with only one AccessToken
    if (storedToken !== accessToken) {throw invalidAccessToken;}

    // Token is safe since it is stored by us
    // eslint-disable-next-line no-unused-vars
    const {exp, iat, jti, uid, pld: payload, rme: prolong, ...jwtOptions} = jwt.decode(storedToken);

    // Finally, sign new tokens for the user
    return sign(uid, Secret(secret), payload, prolong, jwtOptions);
  };

  const invalidateRefreshToken = refreshToken => {
    RefreshToken(refreshToken);
    return store.remove(getUserId(refreshToken), refreshToken);
  };

  const invalidateAllRefreshTokens = userId => store.removeAll(UserId(userId));

  return {
    /**
     * Returns access and refresh tokens
     * @param {String} userId
     * @param {Secret} secret
     * @param {Object} [content] user defined properties
     * @param {Boolean} [prolong] if true, the refreshToken will last 4 days and accessToken 1 hour,
     * otherwise the refresh token will last 25 minutes and the accessToken 15 minutes.
     * @param {SignOptions} [signOptions] Options to be passed to jwt.sign
     * @returns {Promise<Tokens>}
     */
    sign,
    /**
     * Verifies token, might throw jwt.verify errors
     * @param {String} token
     * @param {Secret} secret
     * @param {VerifyOptions} [verifyOptions] Options to pass to jwt.verify.
     * @returns {String} decoded token
     * @throws JsonWebTokenError
     * @throws TokenExpiredError
     * Error info at {@link https://www.npmjs.com/package/jsonwebtoken#errors--codes}
     */
    verify,
    /**
     * Issues a new access token using a refresh token and an old token.
     * There is no need to verify the old token provided because this method uses the stored one.
     * @param {String} refreshToken
     * @param {String} accessToken
     * @param {Secret} secret
     * @param {SignOptions} [signOptions] Options passed to jwt.sign
     * @returns {Promise<Tokens>}
     * @throws {RefreshTokenExpiredOrNotFound} refreshTokenExpiredOrNotFound
     * @throws {InvalidAccessToken} invalidAccessToken
     */
    refresh,
    /**
     * Invalidates refresh token
     * @param {String} refreshToken
     * @returns {Promise<Boolean>} true if successful, false otherwise.
     */
    invalidateRefreshToken,
    /**
     * Invalidates all refresh tokens
     * @param {String|Number} userId
     * @returns {Promise<Boolean>} true if successful, false otherwise.
     */
    invalidateAllRefreshTokens
  };
};
