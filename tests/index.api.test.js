'use strict';

const request = require('supertest');
const secret = 'thisIsAVeryBadSecret';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const {app, authomatic, store} = require('../examples/koa');

const getTokens = () => authomatic.sign('111', secret);

describe('Authomatic', () => {

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
    it('should revoke the refreshToken if found and return 404 afterwards', async () => {
      const {refreshToken} = await getTokens();
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
    it('should return 400 if the authorization header was not set', async () => {
      await request(app.callback())
      .delete(`/tokens/refreshTokens`)
      .send({userId: '123'})
      .expect(400);
    });
  });

  describe('#revokeAllTokens', () => {
    it('should revokeAllTokens for the provided userId', async () => {
      const {accessToken} = await getTokens();
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
      const {accessToken, refreshToken} = await getTokens();
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
      const {accessToken} = await getTokens();
      await request(app.callback())
      .post(`/tokens/refresh`)
      .send({accessToken, refreshToken: ''})
      .expect(400);
    });

    it('should not allow mismatching token pairs', async () => {
      const {accessToken: oldToken, refreshToken} = await getTokens();
      await sleep(2000);
      const {accessToken} = await getTokens();
      expect(oldToken !== accessToken).toBeTruthy();
      await request(app.callback())
      .post(`/tokens/refresh`)
      .send({accessToken, refreshToken})
      .expect(400);
    });
  });
});
