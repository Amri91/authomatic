# authomatic
[![Build Status](https://travis-ci.org/wearereasonablepeople/authomatic.svg?branch=master)](https://travis-ci.org/wearereasonablepeople/authomatic)
[![Maintainability](https://api.codeclimate.com/v1/badges/314b595549aca68c5c6c/maintainability)](https://codeclimate.com/github/wearereasonablepeople/authomatic/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/314b595549aca68c5c6c/test_coverage)](https://codeclimate.com/github/wearereasonablepeople/authomatic/test_coverage)
[![dependencies Status](https://david-dm.org/wearereasonablepeople/authomatic/status.svg)](https://david-dm.org/wearereasonablepeople/authomatic)
[![devDependencies Status](https://david-dm.org/awearereasonablepeople/authomatic/dev-status.svg)](https://david-dm.org/wearereasonablepeople/authomatic?type=dev)

## Description
An opinionated JWT library with sensible defaults that supports refresh and access tokens.

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

## Documentation

## Typedefs

<dl>
<dt><a href="#Secret">Secret</a> : <code>String</code></dt>
<dd><p>a string greater than 20 characters</p>
</dd>
<dt><a href="#AccessToken">AccessToken</a> : <code>String</code></dt>
<dd><p>Regular JWT token.
Its payload looks like this:</p>
<pre><code class="language-javascript">{
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
<dd><p>A base64 encoded string.</p>
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
<dt><a href="#RefreshTokenExpiredOrNotFound">RefreshTokenExpiredOrNotFound</a> : <code>StandardError</code></dt>
<dd><p>The refresh token has expired or was not found</p>
</dd>
<dt><a href="#InvalidAccessToken">InvalidAccessToken</a> : <code>StandardError</code></dt>
<dd><p>The access token provided is invalid</p>
</dd>
</dl>

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
A base64 encoded string.

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
| [audience] | <code>String</code> \| <code>Array</code> \| <code>Object</code> | checks the aud field |
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
| [aud] | <code>String</code> | 
| [iss] | <code>String</code> | 
| [sub] | <code>String</code> | 

<a name="RefreshTokenExpiredOrNotFound"></a>

## RefreshTokenExpiredOrNotFound : <code>StandardError</code>
The refresh token has expired or was not found

**Kind**: global typedef  
**Properties**

| Name | Type | Default |
| --- | --- | --- |
| [name] | <code>String</code> | <code>&#x27;RefreshTokenExpiredOrNotFound&#x27;</code> | 

<a name="InvalidAccessToken"></a>

## InvalidAccessToken : <code>StandardError</code>
The access token provided is invalid

**Kind**: global typedef  
**Properties**

| Name | Type | Default |
| --- | --- | --- |
| [name] | <code>String</code> | <code>&#x27;InvalidAccessToken&#x27;</code> | 

