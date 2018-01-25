'use strict';

const jsonwebtoken = require('jsonwebtoken');
const randToken = require('rand-token');
const generator = randToken.generator({source: 'crypto'});
const t = require('tcomb');
const {mergeAll, omit} = require('ramda');
const StandardError = require('standard-error');

const RefreshTokenExpiredOrNotFound =
  new StandardError(
    'The refresh token has expired or was not found',
    {name: 'RefreshTokenExpiredOrNotFound'}
  );
const InvalidAccessToken =
  new StandardError('The access token provided is invalid', {name: 'InvalidAccessToken'});

// Seconds -> Seconds Since the Epoch
const _expiresInToEpoch = seconds => Math.floor(Date.now() / 1000) + seconds;

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

// 30 minutes
const regularTokenLifeInSeconds = 60 * 30;
// 1 hour
const tokenLifeUpperLimitInSeconds = 60 * 60;
// 1 day
const regularRefreshTokenLifeInMS = 1000 * 60 * 60 * 24;
// 7 days
const prolongedRefreshTokenLifeInMS = 1000 * 60 * 60 * 24 * 7;

const Secret = secret => {
  t.String(secret);
  t.assert(secret.length >= 20, 'The secret must be greater than or equal 20 characters');
  return secret;
};
const ExpiresIn = t.refinement(t.Integer, e => e <= tokenLifeUpperLimitInSeconds, 'ExpiresIn');
const ExpiresAt = t.Integer;
const Algorithm = t.enums.of(['HS256', 'HS384', 'HS512', 'RS256'], 'Algorithm');
const UserId = t.Any;
const RefreshToken = t.String;
const Token = t.String;
const RememberMe = t.Boolean;

const pld = t.interface({
  userId: UserId
}, {name: 'Payload', strict: false});

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

const UserSignOptions = t.interface({
  nbf: t.maybe(t.Number),
  aud: t.maybe(t.String),
  iss: t.maybe(t.String),
  jti: t.maybe(t.String),
  sub: t.maybe(t.String),
}, {name: 'UserSignOption', strict: true});

const Payload = UserSignOptions.extend(t.interface({
  pld: pld,
  exp: ExpiresAt,
  rme: t.Boolean
}, {name: 'Payload', strict: true}));

const _getTTL = rememberMe =>
  rememberMe ? prolongedRefreshTokenLifeInMS : regularRefreshTokenLifeInMS;

const _getTokensObj = (accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt) => ({
  accessToken,
  accessTokenExpiresAt,
  refreshToken,
  refreshTokenExpiresAt
});

module.exports = class JWTPlus {
  /**
   * Constructor
   * @param {Object} store
   * @param {string} [algorithm='HS256] algorithm cannot be 'none'
   * @param {Number} [expiresIn=60 * 30] expiration time in seconds.
   * @param {Object} [jwt] jsonwebtoken instance, by default it uses require('jsonwebtoken')
   * @param {Object} [defaultSignInOptions]
   * @param {Object} [defaultVerifyOptions]
   */
  constructor({
    store, algorithm = 'HS256', expiresIn = regularTokenLifeInSeconds, jwt = jsonwebtoken,
    defaultSignInOptions = {}, defaultVerifyOptions = {}
  }) {
    this._store = Store(store);
    this._defaultSignInOptions = UserSignOptions(defaultSignInOptions);
    this._defaultVerifyOptions = VerifyOptions(defaultVerifyOptions);
    this._algorithm = Algorithm(algorithm);
    this._expiresIn = ExpiresIn(expiresIn);
    this._jwt = JWT(jwt);
  }

  /**
   * @private
   * A private function that creates a refresh token
   * @param {String|Number} userId
   * @param {String} accessToken
   * @param {Number} ttl time to live in milliseconds
   * @returns {Promise}
   */
  async _createRefreshToken(userId, accessToken, ttl) {
    const refreshToken = generator.generate(256);
    await this._store.registerTokens(userId, refreshToken, accessToken, ttl);
    return refreshToken;
  }

  /**
   * Returns access and refresh tokens
   * @param {Object} content token's payload
   * @param secret
   * @param {Boolean} rememberMe if true, the token will last 7 days instead of 1.
   * @param {Object} [signOptions] Options to be passed to jwt.sign
   * @returns {Promise<{
   * token: *, tokenTTL: Number, refreshToken: *, refreshTokenTTL: Number
   * }>}
   */
  async sign(content, secret, rememberMe = false, signOptions = {}) {
    const exp = _expiresInToEpoch(this._expiresIn);
    RememberMe(rememberMe);
    const token = this._jwt.sign(
      // Payload
      Payload({pld: content,
        ...mergeAll([
          this._defaultSignInOptions, UserSignOptions(signOptions),
          {exp, rme: rememberMe}
        ])}),
      // Secret
      Secret(secret),
      // Options
      {algorithm: this._algorithm});
    const ttl = _getTTL(rememberMe);
    return _getTokensObj(token,
      exp,
      await this._createRefreshToken(content.userId, token, ttl),
      _expiresInToEpoch(ttl / 1000)
    );
  }

  /**
   * Verifies token, might throw jwt.verify errors
   * @param {String} token
   * @param secret
   * @param {Object} [verifyOptions] Options to pass to jwt.verify.
   * @returns {Promise<*>}
   */
  verify(token, secret, verifyOptions = {}) {
    return this._jwt.verify(Token(token), Secret(secret),
      mergeAll([this._defaultVerifyOptions, VerifyOptions(verifyOptions),
        {algorithm: this._algorithm}]));
  }

  /**
   * Issues a new access token using a refresh token and an old token.
   * There is no need to verify the old token provided because this method uses the stored one.
   * @param {String} refreshToken
   * @param {String} oldToken
   * @param secret
   * @param {Object} [signOptions] Options passed to jwt.sign
   * @returns {Promise<*>}
   */
  async refresh(refreshToken, oldToken, secret, signOptions) {
    RefreshToken(refreshToken);
    Token(oldToken);
    const untrustedPayload = Payload(this._jwt.decode(oldToken));
    const trustedToken =
      await this._store.getAccessToken(untrustedPayload.pld.userId, refreshToken);
    // Remove the refresh token even if the following operations were not successful.
    // RefreshTokens are one time use only
    if(!await this._store.remove(untrustedPayload.pld.userId, refreshToken)) {
      throw RefreshTokenExpiredOrNotFound;
    }
    // RefreshTokens works with only one AccessToken
    if (trustedToken !== oldToken) {throw InvalidAccessToken;}

    // Token is safe since it is stored by us
    const {pld: payload, rme: rememberMe, ...jwtOptions} =
      this._jwt.decode(trustedToken);

    // Finally, sign new tokens for the user
    return this.sign(
      payload,
      Secret(secret),
      rememberMe,
      // Ignoring exp
      UserSignOptions({...omit(['exp', 'iat'], jwtOptions), ...signOptions})
    );
  }

  /**
   * Invalidates refresh token
   * @param {String|Number} userId
   * @param {String} refreshToken
   * @returns {Promise}
   */
  invalidateRefreshToken(userId, refreshToken) {
    return this._store.remove(UserId(userId), RefreshToken(refreshToken));
  }

  /**
   * Invalidates all refresh tokens
   * @param {String|Number} userId
   * @returns {Promise}
   */
  invalidateAllRefreshTokens(userId) {return this._store.removeAll(UserId(userId));}
};
