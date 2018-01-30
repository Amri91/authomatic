# authomatic
[![Build Status](https://travis-ci.com/wearereasonablepeople/authomatic.svg?token=yQTBKvDF8NXw5WvCpzqf&branch=master)](https://travis-ci.com/wearereasonablepeople/authomatic)
[![codecov](https://codecov.io/gh/wearereasonablepeople/authomatic/branch/master/graph/badge.svg?token=tHRvIF5F3v)](https://codecov.io/gh/wearereasonablepeople/authomatic)


## Description
An opinionated JWT library with sensible defaults that supports refresh and access tokens.

## Install
```
npm install authomatic
```

## Test
```
npm test
```

## Documentation

## Classes

<dl>
<dt><a href="#Authomatic">Authomatic</a></dt>
<dd></dd>
</dl>

## Constants

<dl>
<dt><a href="#RefreshTokenExpiredOrNotFound">RefreshTokenExpiredOrNotFound</a> : <code>StandardError</code></dt>
<dd><p>The refresh token has expired or was not found</p>
</dd>
<dt><a href="#InvalidAccessToken">InvalidAccessToken</a> : <code>StandardError</code></dt>
<dd><p>The access token provided is invalid</p>
</dd>
</dl>

## Typedefs

<dl>
<dt><a href="#VerifyOptions">VerifyOptions</a> : <code>Object</code></dt>
<dd><p>Verify options to be used when verifying tokens</p>
</dd>
<dt><a href="#UserSignOptions">UserSignOptions</a> : <code>Object</code></dt>
<dd><p>The allowed user options to for signing tokens</p>
</dd>
<dt><a href="#Tokens">Tokens</a> : <code>Object</code></dt>
<dd><p>Token pairs</p>
</dd>
</dl>

<a name="Authomatic"></a>

## Authomatic
**Kind**: global class  

* [Authomatic](#Authomatic)
    * [new Authomatic(store, [algorithm], [expiresIn], [jwt], [defaultSignInOptions], [defaultVerifyOptions])](#new_Authomatic_new)
    * [.sign(content, secret, rememberMe, [signOptions])](#Authomatic+sign) ⇒ [<code>Promise.&lt;Tokens&gt;</code>](#Tokens)
    * [.verify(token, secret, [verifyOptions])](#Authomatic+verify) ⇒ <code>Promise.&lt;String&gt;</code>
    * [.refresh(refreshToken, oldToken, secret, [signOptions])](#Authomatic+refresh) ⇒ [<code>Promise.&lt;Tokens&gt;</code>](#Tokens)
    * [.invalidateRefreshToken(userId, refreshToken)](#Authomatic+invalidateRefreshToken) ⇒ <code>Promise.&lt;Number&gt;</code>
    * [.invalidateAllRefreshTokens(userId)](#Authomatic+invalidateAllRefreshTokens) ⇒ <code>Promise.&lt;Number&gt;</code>

<a name="new_Authomatic_new"></a>

### new Authomatic(store, [algorithm], [expiresIn], [jwt], [defaultSignInOptions], [defaultVerifyOptions])
Constructor


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| store | <code>Object</code> |  |  |
| [algorithm] | <code>string</code> | <code>&quot;HS256&quot;</code> | algorithm cannot be 'none' |
| [expiresIn] | <code>Number</code> | <code>60 * 30</code> | expiration time in seconds. |
| [jwt] | <code>Object</code> |  | jsonwebtoken instance, by default it uses require('jsonwebtoken') |
| [defaultSignInOptions] | [<code>UserSignOptions</code>](#UserSignOptions) |  |  |
| [defaultVerifyOptions] | [<code>VerifyOptions</code>](#VerifyOptions) |  |  |

<a name="Authomatic+sign"></a>

### authomatic.sign(content, secret, rememberMe, [signOptions]) ⇒ [<code>Promise.&lt;Tokens&gt;</code>](#Tokens)
Returns access and refresh tokens

**Kind**: instance method of [<code>Authomatic</code>](#Authomatic)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| content | <code>Object</code> |  | token's payload |
| secret |  |  |  |
| rememberMe | <code>Boolean</code> | <code>false</code> | if true, the token will last 7 days instead of 1. |
| [signOptions] | [<code>UserSignOptions</code>](#UserSignOptions) |  | Options to be passed to jwt.sign |

<a name="Authomatic+verify"></a>

### authomatic.verify(token, secret, [verifyOptions]) ⇒ <code>Promise.&lt;String&gt;</code>
Verifies token, might throw jwt.verify errors

**Kind**: instance method of [<code>Authomatic</code>](#Authomatic)  
**Returns**: <code>Promise.&lt;String&gt;</code> - decoded token  
**Throws**:

- JsonWebTokenError
- TokenExpiredError
Error info at [https://www.npmjs.com/package/jsonwebtoken#errors--codes](https://www.npmjs.com/package/jsonwebtoken#errors--codes)


| Param | Type | Description |
| --- | --- | --- |
| token | <code>String</code> |  |
| secret |  |  |
| [verifyOptions] | [<code>VerifyOptions</code>](#VerifyOptions) | Options to pass to jwt.verify. |

<a name="Authomatic+refresh"></a>

### authomatic.refresh(refreshToken, oldToken, secret, [signOptions]) ⇒ [<code>Promise.&lt;Tokens&gt;</code>](#Tokens)
Issues a new access token using a refresh token and an old token.
There is no need to verify the old token provided because this method uses the stored one.

**Kind**: instance method of [<code>Authomatic</code>](#Authomatic)  
**Throws**:

- [<code>RefreshTokenExpiredOrNotFound</code>](#RefreshTokenExpiredOrNotFound) RefreshTokenExpiredOrNotFound
- [<code>InvalidAccessToken</code>](#InvalidAccessToken) InvalidAccessToken


| Param | Type | Description |
| --- | --- | --- |
| refreshToken | <code>String</code> |  |
| oldToken | <code>String</code> |  |
| secret |  |  |
| [signOptions] | [<code>UserSignOptions</code>](#UserSignOptions) | Options passed to jwt.sign |

<a name="Authomatic+invalidateRefreshToken"></a>

### authomatic.invalidateRefreshToken(userId, refreshToken) ⇒ <code>Promise.&lt;Number&gt;</code>
Invalidates refresh token

**Kind**: instance method of [<code>Authomatic</code>](#Authomatic)  
**Returns**: <code>Promise.&lt;Number&gt;</code> - 1 if successful, 0 otherwise.  

| Param | Type |
| --- | --- |
| userId | <code>String</code> \| <code>Number</code> | 
| refreshToken | <code>String</code> | 

<a name="Authomatic+invalidateAllRefreshTokens"></a>

### authomatic.invalidateAllRefreshTokens(userId) ⇒ <code>Promise.&lt;Number&gt;</code>
Invalidates all refresh tokens

**Kind**: instance method of [<code>Authomatic</code>](#Authomatic)  
**Returns**: <code>Promise.&lt;Number&gt;</code> - 1 if successful, 0 otherwise.  

| Param | Type |
| --- | --- |
| userId | <code>String</code> \| <code>Number</code> | 

<a name="RefreshTokenExpiredOrNotFound"></a>

## RefreshTokenExpiredOrNotFound : <code>StandardError</code>
The refresh token has expired or was not found

**Kind**: global constant  
**Properties**

| Name | Type | Default |
| --- | --- | --- |
| [name] | <code>String</code> | <code>&#x27;RefreshTokenExpiredOrNotFound&#x27;</code> | 

<a name="InvalidAccessToken"></a>

## InvalidAccessToken : <code>StandardError</code>
The access token provided is invalid

**Kind**: global constant  
**Properties**

| Name | Type | Default |
| --- | --- | --- |
| [name] | <code>String</code> | <code>&#x27;InvalidAccessToken&#x27;</code> | 

<a name="VerifyOptions"></a>

## VerifyOptions : <code>Object</code>
Verify options to be used when verifying tokens

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| [audience] | <code>String</code> \| <code>Array</code> \| <code>Object</code> | checks the aud field |
| [issuer] | <code>String</code> \| <code>Array</code> | checks the iss field |
| [ignoreExpiration] | <code>Boolean</code> | if true, ignores the expiration check of access tokens |
| [ignoreNotBefore] | <code>Boolean</code> | if true, ignores the not before check of access tokens |
| [subject] | <code>String</code> | checks the sub field |
| [clockTolerance] | <code>Number</code> \| <code>String</code> |  |
| [maxAge] | <code>String</code> \| <code>Number</code> |  |
| [clockTimestamp] | <code>Number</code> | overrides the clock for the verification process |

<a name="UserSignOptions"></a>

## UserSignOptions : <code>Object</code>
The allowed user options to for signing tokens

**Kind**: global typedef  
**Properties**

| Name | Type |
| --- | --- |
| [nbf] | <code>Number</code> | 
| [aud] | <code>String</code> | 
| [iss] | <code>String</code> | 
| [jti] | <code>String</code> | 
| [sub] | <code>String</code> | 

<a name="Tokens"></a>

## Tokens : <code>Object</code>
Token pairs

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| accessToken | <code>String</code> |  |
| accessTokenExpiresAt | <code>Number</code> | epoch |
| refreshToken | <code>String</code> |  |
| refreshTokenExpiresAt | <code>Number</code> | epoch |

