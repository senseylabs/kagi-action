import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness, jsonResponse, stubFetch, withOidcEnv } from './helpers.js';
import { mintIdToken } from '../src/oidc.js';
import { ActionError } from '../src/core.js';

let harness;
afterEach(() => harness?.restore());

describe('OIDC token request', () => {
  test('requests the audience against the runner token service with the runner bearer', async () => {
    harness = createHarness();
    withOidcEnv();
    const calls = stubFetch({ oidc: jsonResponse(200, { value: 'header.payload.signature' }) });

    const token = await mintIdToken('api.kagi.pw', 5000);

    assert.equal(token, 'header.payload.signature');
    assert.equal(calls.length, 1);
    // The runner URL already carries a query string, so the audience must be appended with &.
    assert.equal(
      calls[0].url,
      'https://token-service.example/token?api-version=2.0&audience=api.kagi.pw'
    );
    assert.equal(calls[0].options.headers.authorization, 'Bearer runner-bearer');
  });

  test('a custom audience is URL-encoded', async () => {
    harness = createHarness();
    withOidcEnv();
    const calls = stubFetch({ oidc: jsonResponse(200, { value: 'jwt' }) });

    await mintIdToken('https://kagi.example/api', 5000);

    assert.ok(calls[0].url.endsWith('&audience=https%3A%2F%2Fkagi.example%2Fapi'));
  });

  test('a job without id-token permission fails with the fix, not a stack trace', async () => {
    harness = createHarness();
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;

    await assert.rejects(mintIdToken('api.kagi.pw', 5000), (error) => {
      assert.ok(error instanceof ActionError);
      assert.match(error.message, /id-token: write/);
      return true;
    });
  });

  test('a 403 from the token service is reported as the missing permission, not as transient', async () => {
    harness = createHarness();
    withOidcEnv();
    stubFetch({ oidc: jsonResponse(403, { message: 'forbidden' }) });

    await assert.rejects(mintIdToken('api.kagi.pw', 5000), (error) => {
      assert.match(error.message, /id-token: write/);
      assert.equal(error.transient, false);
      return true;
    });
  });

  test('a 500 from the token service is transient', async () => {
    harness = createHarness();
    withOidcEnv();
    stubFetch({ oidc: jsonResponse(500, 'boom', { contentType: 'text/plain' }) });

    await assert.rejects(mintIdToken('api.kagi.pw', 5000), (error) => {
      assert.equal(error.transient, true);
      return true;
    });
  });

  test('a network failure is transient and names the cause', async () => {
    harness = createHarness();
    withOidcEnv();
    globalThis.fetch = async () => {
      throw Object.assign(new Error('connect ECONNREFUSED'), { name: 'TypeError' });
    };

    await assert.rejects(mintIdToken('api.kagi.pw', 5000), (error) => {
      assert.equal(error.transient, true);
      assert.match(error.message, /ECONNREFUSED/);
      return true;
    });
  });

  test('a token service response with no value fails and never echoes the body', async () => {
    harness = createHarness();
    withOidcEnv();
    stubFetch({ oidc: jsonResponse(200, { unexpected: 'super-secret-jwt' }) });

    await assert.rejects(mintIdToken('api.kagi.pw', 5000), (error) => {
      assert.doesNotMatch(error.message, /super-secret-jwt/);
      return true;
    });
  });
});
