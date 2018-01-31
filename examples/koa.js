'use strict';

const secret = 'thisIsAVeryBadSecret';
const scope = 'Admin';

const Koa = require('koa');
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router');

const Store = require('authomatic-redis');
const Authomatic = require('../index');

const store = Store();
const authomatic = new Authomatic({
  store,
  defaultSignOptions: {
    // Set iss property to A for all signed tokens
    iss: 'A'
  },
  defaultVerifyOptions: {
    // Accept tokens issued by A and B
    issuer: ['A', 'B']
  }
});

const getBearer = ({request: {headers}}) => {
  if(headers.authorization) {
    return headers.authorization.replace('Bearer ', '');
  }
  return '';
};

const verify = (ctx, next) => {
  const accessToken = getBearer(ctx);
  if(!accessToken) {
    return ctx.throw(400, 'missing authorization header');
  }
  try {
    // Returns decoded token
    authomatic.verify(accessToken, secret);
    return next();
  } catch (e) {
    return ctx.throw(
      ['JsonWebTokenError', 'TokenExpiredError'].includes(e.name) ? 401 : 500,
      e.message
    );
  }
};

const router = new Router({
  prefix: `/tokens`
});

router
.post('/login', async ctx => {
  const {rememberMe} = ctx.request.body;
  // Add verify credentials logic
  ctx.body = await authomatic.sign(
    '123',
    secret,
    {/*Put any extra static content*/scopes: [scope]},
    rememberMe
  );
  ctx.status = 201;
})
.post('/refresh', async ctx => {
  const {accessToken, refreshToken} = ctx.request.body;

  try {
    ctx.body = await authomatic.refresh(refreshToken, accessToken, secret);
  } catch (e) {
    ctx.throw(
      ['RefreshTokenExpiredOrNotFound', 'InvalidAccessToken'].includes(e.name) ? 400 : 500,
      e.message
    );
  }
})
.delete('/refreshTokens/:refreshToken', async ctx => {
  const {refreshToken} = ctx.params;

  if(await authomatic.invalidateRefreshToken(decodeURIComponent(refreshToken))) {
    ctx.status = 204;
  } else {
    ctx.status = 404;
  }
})
.use(verify)
// All private routes under this point
.delete('/refreshTokens', async ctx => {
  const {userId} = ctx.request.body;
  // You need to check if the user is authorized to
  // delete all refresh tokens for the provided user id
  if(await authomatic.invalidateAllRefreshTokens(userId)) {
    ctx.status = 204;
  } else {
    ctx.status = 404;
  }
});

exports.app = new Koa();
exports.app
.use(bodyParser())
.use(router.allowedMethods({throw: true}))
.use(router.routes());

exports.authomatic = authomatic;
exports.store = store;
