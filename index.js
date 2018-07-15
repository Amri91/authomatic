'use strict';

const crypto = require('crypto');
const util = require('util');
const jsonwebtoken = require('jsonwebtoken');
const t = require('tcomb');
const StandardError = require('standard-error');

const arrayOfStrings = t.refinement(t.Array, n => n.every(t.String), 'Array<String>');

const Store = t.interface({
  // Signature: (userId, refreshToken)
  remove: t.Function,
  // Signature: (userId)
  removeAll: t.Function,
  // Signature: (userId, refreshToken)
  add: t.Function
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
const UserId = t.String;
const Prolong = t.Boolean;
const accessTokenType = 'Authomatic-AT';
const refreshTokenType = 'Authomatic-RT';
// Does not add extra functionality to the token, merely makes it look complete and professional
const refreshTokenSignOptions = {
  aud: ['Authomatic'],
  iss: 'Authomatic'
};
const refreshTokenVerifyOptions = {
  audience: ['Authomatic'],
  issuer: 'Authomatic'
};

/**
 * Access token
 * @typedef AccessToken
 * @type {String}
 * @description Regular JWT token.
 * Its payload looks like this:
 ```js
{
  "t": "Authomatic-AT",
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
 * @description regular JWT token.
 * Its payload looks like this:
 ```js
 {
   "t": "Authomatic-RT",
   "iss": "Authomatic",
   "aud": ["Authomatic"]
   "uid": "userId",
   "exp": "someNumber",
   "jti": "randomBytes",
   "accessTokenJTI": "randomBytes"
 }
 ```
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
 * @property {Array|String} [audience] checks the aud field
 * @property {String|Array} [issuer] checks the iss field
 * @property {Boolean} [ignoreExpiration] if true, ignores the expiration check of access tokens
 * @property {Boolean} [ignoreNotBefore] if true, ignores the not before check of access tokens
 * @property {String} [subject] checks the sub field
 * @property {Number|String} [clockTolerance]
 * @property {String|Number} [maxAge]
 * @property {Number} [clockTimestamp] overrides the clock for the verification process
 */
const VerifyOptions = t.interface({
  audience: t.maybe(t.union([arrayOfStrings, t.String])),
  issuer: t.maybe(t.union([t.String, arrayOfStrings])),
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
 * @property {Array|String} [aud]
 * @property {String} [iss]
 * @property {String} [sub]
 */
const SignOptions = t.interface({
  nbf: t.maybe(t.Number),
  aud: t.maybe(t.union([arrayOfStrings, t.String])),
  iss: t.maybe(t.String),
  sub: t.maybe(t.String),
}, {name: 'SignOptions', strict: true});

const getTypeRefinement = tokenType =>
  t.refinement(
    t.String,
    n => n === tokenType,
    `Token type: ${tokenType}`
  );

const internalSignOptions = SignOptions.extend(t.interface({
  uid: UserId,
  jti: t.String,
  exp: ExpiresAt
}, {name: 'InternalSignOptions', strict: true}));

const Payload = internalSignOptions.extend(t.interface({
  pld: t.Any,
  rme: t.Boolean,
  t: getTypeRefinement(accessTokenType)
}, {name: 'Payload', strict: true}));

const RefreshPayload = internalSignOptions.extend(t.interface({
  accessTokenJTI: t.String,
  t: getTypeRefinement(refreshTokenType)
}, {name: 'RefreshPayload', strict: true}));

/**
 * The refresh token was not found.
 * @type {StandardError}
 * @typedef RefreshTokenNotFound
 * @property {String} [name='RefreshTokenNotFound']
 */
const refreshTokenNotFound = new StandardError(
  'The refresh token was not found',
  {name: 'RefreshTokenNotFound'}
);

/**
 * The tokens provided do not match
 * @type {StandardError}
 * @typedef TokensMismatch
 * @property {String} [name='TokensMismatch']
 */
const tokensMismatch = new StandardError(
  'The tokens provided do not match',
  {name: 'TokensMismatch'}
);

/**
 * The provided input is not a valid token.
 * @type {StandardError}
 * @typedef InvalidToken
 * @property {String} [name='InvalidToken']
 */
const invalidToken = new StandardError(
  'The provided input is not a valid token',
  {name: 'InvalidToken'}
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

  const checkToken = type => token => {
    const decodedATContent = jwt.decode(token);
    if(decodedATContent && decodedATContent.t === type) {
      return token;
    }
    throw invalidToken;
  };

  const AccessToken = checkToken(accessTokenType);
  const RefreshToken = checkToken(refreshTokenType);

  const sign = async (userId, secret, content = {}, prolong = false, signOptions = {}) => {
    UserId(userId);
    Prolong(prolong);
    Secret(secret);

    const accessExp = computeExpiryDate(prolong ? prolongedAccessTTL : regularAccessTTL);
    const refreshTTL = prolong ? prolongedRefreshTTL : regularRefreshTTL;
    const refreshExp = computeExpiryDate(refreshTTL);

    // Order of spreading is important!
    const accessPayload = Payload({
      ...defaultSignOptions,
      ...SignOptions(signOptions),
      pld: content, uid: userId, exp: accessExp, rme: prolong,
      jti: await generateTokenId(), t: accessTokenType
    });

    const refreshPayload = RefreshPayload({
      ...refreshTokenSignOptions, uid: userId,
      accessTokenJTI: accessPayload.jti, exp: refreshExp,
      jti: await generateTokenId(), t: refreshTokenType
    });

    const accessToken = jwt.sign(accessPayload, secret, {algorithm});
    const refreshToken = jwt.sign(refreshPayload, secret, {algorithm});

    await store.add(userId, refreshPayload.jti, accessPayload.jti, refreshTTL * 1000);

    return {
      accessToken, accessTokenExpiresAt: accessExp, refreshToken, refreshTokenExpiresAt: refreshExp
    };
  };

  const verifyRefreshToken = (refreshToken, secret) =>
    jwt.verify(RefreshToken(refreshToken), Secret(secret), {
      ...refreshTokenVerifyOptions,
      algorithm
    });

  const verifyAccessToken = (token, secret, verifyOptions = {}) =>
    jwt.verify(AccessToken(token), Secret(secret), {
      ...defaultVerifyOptions,
      ...VerifyOptions(verifyOptions),
      algorithm
    });

  const refresh = async (refreshToken, accessToken, secret, verifyOptions) => {
    RefreshToken(refreshToken);
    // It is required to pass verifyOptions during refresh because the old function didn't have it
    VerifyOptions(verifyOptions);
    Secret(secret);

    const verifiedRTContent = verifyRefreshToken(refreshToken, secret);

    const {uid: userId, jti: refreshTokenJTI} = verifiedRTContent;

    // Eagerly invalidates refresh token
    if(!await store.remove(userId, refreshTokenJTI)) {
      throw refreshTokenNotFound;
    }

    AccessToken(accessToken);

    const verifiedATContent =
      verifyAccessToken(accessToken, secret, {...verifyOptions, ignoreExpiration: true});

    // RefreshTokens works with only one AccessToken
    if (verifiedATContent.jti !== verifiedRTContent.accessTokenJTI) {
      throw tokensMismatch;
    }

    // eslint-disable-next-line no-unused-vars
    const {exp, iat, jti, uid, t, pld: payload, rme, ...jwtOptions} = verifiedATContent;

    // Finally, sign new tokens for the user
    return sign(userId, secret, payload, rme, jwtOptions);
  };

  const invalidateRefreshToken = (refreshToken, secret) => {
    const {uid, jti} = verifyRefreshToken(refreshToken, secret);
    return store.remove(uid, jti);
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
     * @throws {TypeError} typeError if any param was not sent exactly as specified
     */
    sign,
    /**
     * Verifies token, might throw jwt.verify errors
     * @param {String} token
     * @param {Secret} secret
     * @param {VerifyOptions} [verifyOptions] Options to pass to jwt.verify.
     * @returns {String} decoded token
     * @throws {InvalidToken} invalidToken
     * @throws {TypeError} typeError if any param was not sent exactly as specified
     * @throws JsonWebTokenError
     * @throws TokenExpiredError
     * Error info at {@link https://www.npmjs.com/package/jsonwebtoken#errors--codes}
     */
    verify: verifyAccessToken,
    /**
     * Issues a new access token using a refresh token and an old token (can be expired).
     * @param {String} refreshToken
     * @param {String} accessToken
     * @param {Secret} secret
     * @param {SignOptions} signOptions Options passed to jwt.sign,
     * ignoreExpiration will be set to true
     * @returns {Promise<Tokens>}
     * @throws {RefreshTokenNotFound} refreshTokenNotFound
     * @throws {TokensMismatch} tokensMismatch
     * @throws {TypeError} typeError if any param was not sent exactly as specified
     * @throws JsonWebTokenError
     * @throws TokenExpiredError
     * Error info at {@link https://www.npmjs.com/package/jsonwebtoken#errors--codes}
     */
    refresh,
    /**
     * Invalidates refresh token
     * @param {String} refreshToken
     * @returns {Promise<Boolean>} true if successful, false otherwise.
     * @throws {TypeError} typeError if any param was not sent exactly as specified
     * @throws {InvalidToken} invalidToken
     * @throws JsonWebTokenError
     * @throws TokenExpiredError
     * Error info at {@link https://www.npmjs.com/package/jsonwebtoken#errors--codes}
     */
    invalidateRefreshToken,
    /**
     * Invalidates all refresh tokens
     * @param {String} userId
     * @returns {Promise<Boolean>} true if successful, false otherwise.
     * @throws {TypeError} typeError if any param was not sent exactly as specified
     */
    invalidateAllRefreshTokens
  };
};
