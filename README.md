# authomatic
[![Build Status](https://travis-ci.org/wearereasonablepeople/authomatic.svg?branch=master)](https://travis-ci.org/wearereasonablepeople/authomatic)
[![Maintainability](https://api.codeclimate.com/v1/badges/314b595549aca68c5c6c/maintainability)](https://codeclimate.com/github/wearereasonablepeople/authomatic/maintainability)
[![Coverage Status](https://coveralls.io/repos/github/wearereasonablepeople/authomatic/badge.svg?branch=master)](https://coveralls.io/github/wearereasonablepeople/authomatic?branch=master)
[![dependencies Status](https://david-dm.org/wearereasonablepeople/authomatic/status.svg)](https://david-dm.org/wearereasonablepeople/authomatic)
[![devDependencies Status](https://david-dm.org/awearereasonablepeople/authomatic/dev-status.svg)](https://david-dm.org/wearereasonablepeople/authomatic?type=dev)
[![Greenkeeper badge](https://badges.greenkeeper.io/wearereasonablepeople/authomatic.svg)](https://greenkeeper.io/)

## Description
An authentication library that uses JWT for access and refresh tokens with sensible defaults.

## Install
```
npm install authomatic
```

## Available stores
[Redis](https://github.com/wearereasonablepeople/authomatic-redis)

Please create an issue if you need another store.

## Examples
[Koa Example](/examples/koa.js)

## Quickstart
```javascript
const Store = require('authomatic-redis');
const Authomatic = require('authomatic');
const store = Store();
const authomatic = new Authomatic({store});

// Use authomatic functions
```

## Test
```
npm test
```

## Notes about migrating from version 0.0.1 to 1
1. Access and refresh tokens from those old versions will not work with the new ones. If you just upgraded, users will be required to relog.
If that is undesirable, and you want a seamless transition use two instances of Authomatic, but do not sign new tokens (or refresh) with the old instance.
1. The refresh method now accepts a 4th argument, verify options.
1. The invalidate refresh token method now requires a secret.
1. aud in sign options and audience in verify options are now strictly an array.
1. RefreshTokenExpiredOrNotFound became RefreshTokenNotFound, the expiration error is throw by the 'jsonwebtoken' library.
1. InvalidAccessToken became InvalidToken, it is for both refresh and access tokens.
1. TokensMismatch error is thrown if refresh and access token do not match.

The example has been updated to reflect all the new changes.

# Documentation

## Members

<dl>
<dt><a href="#sign">sign</a> ⇒ <code><a href="#Tokens">Promise.&lt;Tokens&gt;</a></code></dt>
<dd><p>Returns access and refresh tokens</p>
</dd>
<dt><a href="#verify">verify</a> ⇒ <code>String</code></dt>
<dd><p>Verifies token, might throw jwt.verify errors</p>
</dd>
<dt><a href="#refresh">refresh</a> ⇒ <code><a href="#Tokens">Promise.&lt;Tokens&gt;</a></code></dt>
<dd><p>Issues a new access token using a refresh token and an old token (can be expired).</p>
</dd>
<dt><a href="#invalidateRefreshToken">invalidateRefreshToken</a> ⇒ <code>Promise.&lt;Boolean&gt;</code></dt>
<dd><p>Invalidates refresh token</p>
</dd>
<dt><a href="#invalidateAllRefreshTokens">invalidateAllRefreshTokens</a> ⇒ <code>Promise.&lt;Boolean&gt;</code></dt>
<dd><p>Invalidates all refresh tokens</p>
</dd>
</dl>

## Typedefs

<dl>
<dt><a href="#Secret">Secret</a> : <code>String</code></dt>
<dd><p>a string greater than 20 characters</p>
</dd>
<dt><a href="#AccessToken">AccessToken</a> : <code>String</code></dt>
<dd><p>Regular JWT token.
Its payload looks like this:</p>
<pre><code class="language-javascript">{
  &quot;t&quot;: &quot;Authomatic-AT&quot;,
  &quot;uid&quot;: &quot;userId&quot;,
  &quot;exp&quot;: &quot;someNumber&quot;,
  &quot;jti&quot;: &quot;randomBytes&quot;,
  ...otherClaims,
  &quot;pld&quot;: {
    ...otherUserContent
  }
}
</code></pre>
</dd>
<dt><a href="#RefreshToken">RefreshToken</a> : <code>String</code></dt>
<dd><p>regular JWT token.
Its payload looks like this:</p>
<pre><code class="language-javascript"> {
   &quot;t&quot;: &quot;Authomatic-RT&quot;,
   &quot;iss&quot;: &quot;Authomatic&quot;,
   &quot;aud&quot;: [&quot;Authomatic&quot;]
   &quot;uid&quot;: &quot;userId&quot;,
   &quot;exp&quot;: &quot;someNumber&quot;,
   &quot;jti&quot;: &quot;randomBytes&quot;,
   &quot;accessTokenJTI&quot;: &quot;randomBytes&quot;
 }
</code></pre>
</dd>
<dt><a href="#Tokens">Tokens</a> : <code>Object</code></dt>
<dd><p>Token pairs</p>
</dd>
<dt><a href="#VerifyOptions">VerifyOptions</a> : <code>Object</code></dt>
<dd><p>Verify options to be used when verifying tokens</p>
</dd>
<dt><a href="#SignOptions">SignOptions</a> : <code>Object</code></dt>
<dd><p>The allowed user options to for signing tokens</p>
</dd>
<dt><a href="#RefreshTokenNotFound">RefreshTokenNotFound</a> : <code>StandardError</code></dt>
<dd><p>The refresh token was not found.</p>
</dd>
<dt><a href="#TokensMismatch">TokensMismatch</a> : <code>StandardError</code></dt>
<dd><p>The tokens provided do not match</p>
</dd>
<dt><a href="#InvalidToken">InvalidToken</a> : <code>StandardError</code></dt>
<dd><p>The provided input is not a valid token.</p>
</dd>
</dl>

<a name="sign"></a>

## sign ⇒ [<code>Promise.&lt;Tokens&gt;</code>](#Tokens)
Returns access and refresh tokens

**Kind**: global variable  
**Throws**:

- <code>TypeError</code> typeError if any param was not sent exactly as specified


| Param | Type | Description |
| --- | --- | --- |
| userId | <code>String</code> |  |
| secret | [<code>Secret</code>](#Secret) |  |
| [content] | <code>Object</code> | user defined properties |
| [prolong] | <code>Boolean</code> | if true, the refreshToken will last 4 days and accessToken 1 hour, otherwise the refresh token will last 25 minutes and the accessToken 15 minutes. |
| [signOptions] | [<code>SignOptions</code>](#SignOptions) | Options to be passed to jwt.sign |

<a name="verify"></a>

## verify ⇒ <code>String</code>
Verifies token, might throw jwt.verify errors

**Kind**: global variable  
**Returns**: <code>String</code> - decoded token  
**Throws**:

- [<code>InvalidToken</code>](#InvalidToken) invalidToken
- <code>TypeError</code> typeError if any param was not sent exactly as specified
- JsonWebTokenError
- TokenExpiredError
Error info at [https://www.npmjs.com/package/jsonwebtoken#errors--codes](https://www.npmjs.com/package/jsonwebtoken#errors--codes)


| Param | Type | Description |
| --- | --- | --- |
| token | <code>String</code> |  |
| secret | [<code>Secret</code>](#Secret) |  |
| [verifyOptions] | [<code>VerifyOptions</code>](#VerifyOptions) | Options to pass to jwt.verify. |

<a name="refresh"></a>

## refresh ⇒ [<code>Promise.&lt;Tokens&gt;</code>](#Tokens)
Issues a new access token using a refresh token and an old token (can be expired).

**Kind**: global variable  
**Throws**:

- [<code>RefreshTokenNotFound</code>](#RefreshTokenNotFound) refreshTokenNotFound
- [<code>TokensMismatch</code>](#TokensMismatch) tokensMismatch
- <code>TypeError</code> typeError if any param was not sent exactly as specified
- JsonWebTokenError
- TokenExpiredError
Error info at [https://www.npmjs.com/package/jsonwebtoken#errors--codes](https://www.npmjs.com/package/jsonwebtoken#errors--codes)


| Param | Type | Description |
| --- | --- | --- |
| refreshToken | <code>String</code> |  |
| accessToken | <code>String</code> |  |
| secret | [<code>Secret</code>](#Secret) |  |
| signOptions | [<code>SignOptions</code>](#SignOptions) | Options passed to jwt.sign, ignoreExpiration will be set to true |

<a name="invalidateRefreshToken"></a>

## invalidateRefreshToken ⇒ <code>Promise.&lt;Boolean&gt;</code>
Invalidates refresh token

**Kind**: global variable  
**Returns**: <code>Promise.&lt;Boolean&gt;</code> - true if successful, false otherwise.  
**Throws**:

- <code>TypeError</code> typeError if any param was not sent exactly as specified
- [<code>InvalidToken</code>](#InvalidToken) invalidToken
- JsonWebTokenError
- TokenExpiredError
Error info at [https://www.npmjs.com/package/jsonwebtoken#errors--codes](https://www.npmjs.com/package/jsonwebtoken#errors--codes)


| Param | Type |
| --- | --- |
| refreshToken | <code>String</code> | 

<a name="invalidateAllRefreshTokens"></a>

## invalidateAllRefreshTokens ⇒ <code>Promise.&lt;Boolean&gt;</code>
Invalidates all refresh tokens

**Kind**: global variable  
**Returns**: <code>Promise.&lt;Boolean&gt;</code> - true if successful, false otherwise.  
**Throws**:

- <code>TypeError</code> typeError if any param was not sent exactly as specified


| Param | Type |
| --- | --- |
| userId | <code>String</code> | 

<a name="Secret"></a>

## Secret : <code>String</code>
a string greater than 20 characters

**Kind**: global typedef  
<a name="AccessToken"></a>

## AccessToken : <code>String</code>
Regular JWT token.
Its payload looks like this:
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

**Kind**: global typedef  
<a name="RefreshToken"></a>

## RefreshToken : <code>String</code>
regular JWT token.
Its payload looks like this:
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

**Kind**: global typedef  
<a name="Tokens"></a>

## Tokens : <code>Object</code>
Token pairs

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| accessToken | [<code>AccessToken</code>](#AccessToken) |  |
| accessTokenExpiresAt | <code>Number</code> | epoch |
| refreshToken | [<code>RefreshToken</code>](#RefreshToken) |  |
| refreshTokenExpiresAt | <code>Number</code> | epoch |

<a name="VerifyOptions"></a>

## VerifyOptions : <code>Object</code>
Verify options to be used when verifying tokens

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| [audience] | <code>Array</code> \| <code>String</code> | checks the aud field |
| [issuer] | <code>String</code> \| <code>Array</code> | checks the iss field |
| [ignoreExpiration] | <code>Boolean</code> | if true, ignores the expiration check of access tokens |
| [ignoreNotBefore] | <code>Boolean</code> | if true, ignores the not before check of access tokens |
| [subject] | <code>String</code> | checks the sub field |
| [clockTolerance] | <code>Number</code> \| <code>String</code> |  |
| [maxAge] | <code>String</code> \| <code>Number</code> |  |
| [clockTimestamp] | <code>Number</code> | overrides the clock for the verification process |

<a name="SignOptions"></a>

## SignOptions : <code>Object</code>
The allowed user options to for signing tokens

**Kind**: global typedef  
**Properties**

| Name | Type |
| --- | --- |
| [nbf] | <code>Number</code> | 
| [aud] | <code>Array</code> \| <code>String</code> | 
| [iss] | <code>String</code> | 
| [sub] | <code>String</code> | 

<a name="RefreshTokenNotFound"></a>

## RefreshTokenNotFound : <code>StandardError</code>
The refresh token was not found.

**Kind**: global typedef  
**Properties**

| Name | Type | Default |
| --- | --- | --- |
| [name] | <code>String</code> | <code>&#x27;RefreshTokenNotFound&#x27;</code> | 

<a name="TokensMismatch"></a>

## TokensMismatch : <code>StandardError</code>
The tokens provided do not match

**Kind**: global typedef  
**Properties**

| Name | Type | Default |
| --- | --- | --- |
| [name] | <code>String</code> | <code>&#x27;TokensMismatch&#x27;</code> | 

<a name="InvalidToken"></a>

## InvalidToken : <code>StandardError</code>
The provided input is not a valid token.

**Kind**: global typedef  
**Properties**

| Name | Type | Default |
| --- | --- | --- |
| [name] | <code>String</code> | <code>&#x27;InvalidToken&#x27;</code> | 


# Creating a store
If you want to create a new store you need to expose the following functions:

1. add

```js
/**
* Register token and refresh token to the user
* @param {String} userId
* @param {String} refreshTokenJTI
* @param {String} accessTokenJTI
* @param {Number} ttl time to live in ms
* @returns {Promise<Boolean>} returns true when created.
*/
function add(userId, refreshTokenJTI, accessTokenJTI, ttl){...}
```

2. remove
```js
/**
* Remove a single refresh token from the user
* @param userId
* @param refreshTokenJTI
* @returns {Promise<Boolean>} true if found and deleted, otherwise false.
*/
function remove(userId, refreshTokenJTI) {...}
```

3. removeAll
```js
/**
* Removes all tokens for a particular user
* @param userId
* @returns {Promise<Boolean>} true if any were found and delete, false otherwise
*/
function removeAll(userId) {...}
```
You may need to expose a reference to the store if the user may need to handle connections during testing for example.
