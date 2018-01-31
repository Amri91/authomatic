'use strict';

const util = require('util');
const request = require('supertest');
const crypto = require('crypto');
const secret = 'thisIsAVeryBadSecret';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const {app, authomatic, store} = require('../examples/koa');

const randomBytes = util.promisify(crypto.randomBytes);

const getToken = () => authomatic.sign('111', secret);

describe('Authomatic', () => {
  let staticRefreshToken;

  beforeAll(async () => {
    staticRefreshToken = Buffer.concat([
      await randomBytes(128), new Buffer('123', 'utf8')
    ]).toString('base64');
  });

  beforeEach(done => {
    store.client.flushall(err => {
      done(err);
    });
  });

  afterAll(done => {
    store.client.quit(err => {
      done(err);
    });
  });

  describe('#revokeRefreshToken', () => {
    it('should return 404 if refresh token is not found', async () => {
      await request(app.callback())
      .delete(`/tokens/refreshTokens/${staticRefreshToken}`)
      .expect(404);
    });
    it('should revoke the refreshToken if found', async () => {
      const {refreshToken} = await getToken();
      await request(app.callback())
      .delete(`/tokens/refreshTokens/${encodeURIComponent(refreshToken)}`)
      .expect(204);
      await request(app.callback())
      .delete(`/tokens/refreshTokens/${encodeURIComponent(refreshToken)}`)
      .expect(404);
    });
  });

  describe('#login', () => {
    it('should return token pairs when logging in', async () => {
      const {body} = await request(app.callback())
      .post(`/tokens/login`)
      .send({rememberMe: false})
      .expect(201);
      expect(body.accessToken && body.refreshToken).toBeTruthy();
    });
  });

  describe('#verify', () => {
    it('should not allow unauthenticated users to access private routes', async () => {
      await request(app.callback())
      .delete(`/tokens/refreshTokens`)
      .set('Authorization', 'Bearer 123')
      .send({userId: '123'})
      .expect(401);
    });
    it('should not allow users without accessTokens', async () => {
      await request(app.callback())
      .delete(`/tokens/refreshTokens`)
      .send({userId: '123'})
      .expect(400);
    });
  });

  describe('#revokeAllTokens', () => {
    it('should revokeAllTokens for the provided userId', async () => {
      const {accessToken} = await getToken();
      await request(app.callback())
      .delete(`/tokens/refreshTokens`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({userId: '111'})
      .expect(204);

      await request(app.callback())
      .delete(`/tokens/refreshTokens`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({userId: '111'})
      .expect(404);
    });
  });

  describe('#refresh', () => {
    it('should generate a new pair of tokens and remove the old refresh token', async () => {
      const {accessToken, refreshToken} = await getToken();
      await request(app.callback())
      .post(`/tokens/refresh`)
      .send({accessToken, refreshToken})
      .expect(200);

      await request(app.callback())
      .post(`/tokens/refresh`)
      .send({accessToken, refreshToken})
      .expect(400);
    });

    it('should generate handle bad refresh tokens', async () => {
      const {accessToken} = await getToken();
      await request(app.callback())
      .post(`/tokens/refresh`)
      .send({accessToken, refreshToken: ''})
      .expect(400);
    });

    it('should not allow mismatching token pairs', async () => {
      const {accessToken: oldToken, refreshToken} = await getToken();
      await sleep(2000);
      const {accessToken} = await getToken();
      expect(oldToken !== accessToken).toBeTruthy();
      await request(app.callback())
      .post(`/tokens/refresh`)
      .send({accessToken, refreshToken})
      .expect(400);
    });
  });
});
