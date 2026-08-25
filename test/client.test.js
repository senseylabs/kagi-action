import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness, jsonResponse, stubFetch } from './helpers.js';
import { fetchSecrets, readEnvelope } from '../src/client.js';
import { ActionError } from '../src/core.js';

let harness;
afterEach(() => harness?.restore());

const OK_BODY = {
  success: true,
  message: 'Secrets fetched successfully',
  data: {
    scopes: [
      {
        appId: '11111111-1111-1111-1111-111111111111',
        appPath: '/clients/acme/api',
        environmentSlug: 'production',
        secrets: { DATABASE_URL: 'postgres://u:p@h/db', STRIPE_KEY: 'sk_live_x' },
      },
    ],
    dotenv: null,
  },
  pagination: null,
  error: null,
};

const args = (overrides = {}) => ({
  apiUrl: 'https://api.kagi.pw',
  identityPublicId: '3fa2c1e0-0000-4000-8000-000000000000',
  token: 'the.id.token',
  wantDotenv: false,
  timeoutMs: 5000,
  ...overrides,
});

describe('request shape', () => {
  test('POSTs the exact KagiCiSecretFetchRequest record shape', async () => {
    harness = createHarness();
    const calls = stubFetch({ kagi: jsonResponse(200, OK_BODY) });

    await fetchSecrets(args());

    assert.equal(calls[0].url, 'https://api.kagi.pw/kagi/auth/ci/fetch');
    assert.equal(calls[0].options.method, 'POST');
    assert.deepEqual(JSON.parse(calls[0].options.body), {
      provider: 'GITHUB_ACTIONS',
      identity: '3fa2c1e0-0000-4000-8000-000000000000',
      token: 'the.id.token',
    });
  });

  test('asks for DOTENV only when a .env file was requested', async () => {
    harness = createHarness();
    const calls = stubFetch({
      kagi: jsonResponse(200, { ...OK_BODY, data: { ...OK_BODY.data, dotenv: 'A="b"\n' } }),
    });

    await fetchSecrets(args({ wantDotenv: true }));

    assert.equal(JSON.parse(calls[0].options.body).format, 'DOTENV');
  });

  test('a trailing slash on api-url does not produce a double slash', async () => {
    harness = createHarness();
    const calls = stubFetch({ kagi: jsonResponse(200, OK_BODY) });

    await fetchSecrets(args({ apiUrl: 'https://api.kagi.pw/' }));

    assert.equal(calls[0].url, 'https://api.kagi.pw/kagi/auth/ci/fetch');
  });
});

describe('successful response', () => {
  test('unwraps the CustomResponse envelope into scopes and dotenv', async () => {
    harness = createHarness();
    stubFetch({ kagi: jsonResponse(200, OK_BODY) });

    const result = await fetchSecrets(args());

    assert.equal(result.scopes.length, 1);
    assert.equal(result.scopes[0].appPath, '/clients/acme/api');
    assert.deepEqual(result.scopes[0].secrets, [
      ['DATABASE_URL', 'postgres://u:p@h/db'],
      ['STRIPE_KEY', 'sk_live_x'],
    ]);
    assert.equal(result.dotenv, null);
  });

  test('an empty grant is returned as zero scopes, not as an error', () => {
    const result = readEnvelope({ success: true, data: { scopes: [], dotenv: null } });
    assert.deepEqual(result, { scopes: [], dotenv: null });
  });
});

describe('malformed responses fail loudly', () => {
  const cases = [
    ['no envelope', 'not-an-object'],
    ['no data', { success: true, data: null }],
    ['scopes not a list', { success: true, data: { scopes: {} } }],
    ['scope not an object', { success: true, data: { scopes: ['nope'] } }],
    ['secrets not a map', { success: true, data: { scopes: [{ secrets: 'nope' }] } }],
    ['non-string value', { success: true, data: { scopes: [{ secrets: { A: 42 } }] } }],
    ['dotenv not a string', { success: true, data: { scopes: [], dotenv: 7 } }],
    ['success false', { success: false, error: { code: 'KGI_X', message: 'nope' } }],
  ];

  for (const [name, body] of cases) {
    test(name, () => {
      assert.throws(() => readEnvelope(body), ActionError);
    });
  }

  test('a 200 with a non-JSON body never echoes the body, which may hold secrets', async () => {
    harness = createHarness();
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async json() {
        throw new Error('Unexpected token');
      },
      async text() {
        return 'DATABASE_URL=postgres://leak';
      },
    });

    await assert.rejects(fetchSecrets(args()), (error) => {
      assert.doesNotMatch(error.message, /postgres:\/\/leak/);
      assert.match(error.message, /not JSON/);
      return true;
    });
  });
});

describe('HTTP failures', () => {
  test('401 explains the opaque denial and lists what to check', async () => {
    harness = createHarness();
    stubFetch({
      kagi: jsonResponse(401, {
        success: false,
        error: { code: 'KGI_AUT_CI_EXCHANGE_DENIED', message: 'Fetch denied' },
      }),
    });

    await assert.rejects(fetchSecrets(args()), (error) => {
      assert.match(error.message, /KGI_AUT_CI_EXCHANGE_DENIED/);
      assert.match(error.message, /audience/);
      assert.match(error.message, /VERIFIED/);
      assert.equal(error.transient, false);
      return true;
    });
  });

  test('403 is reported as a plan or subscription problem, not a workflow problem', async () => {
    harness = createHarness();
    stubFetch({
      kagi: jsonResponse(403, { success: false, error: { code: 'KGI_SEC_005', message: 'Locked' } }),
    });

    await assert.rejects(fetchSecrets(args()), (error) => {
      assert.match(error.message, /plan or subscription/);
      assert.equal(error.transient, false);
      return true;
    });
  });

  test('400 points at identity-public-id', async () => {
    harness = createHarness();
    stubFetch({ kagi: jsonResponse(400, { success: false, error: { code: 'KGI_VAL_001' } }) });

    await assert.rejects(fetchSecrets(args()), (error) => {
      assert.match(error.message, /identity-public-id/);
      return true;
    });
  });

  test('404 points at api-url', async () => {
    harness = createHarness();
    stubFetch({ kagi: jsonResponse(404, '<html>not found</html>', { contentType: 'text/html' }) });

    await assert.rejects(fetchSecrets(args()), (error) => {
      assert.match(error.message, /api-url/);
      return true;
    });
  });

  test('429 and 5xx are transient; 4xx is not', async () => {
    harness = createHarness();
    for (const [status, expected] of [
      [429, true],
      [500, true],
      [503, true],
      [418, false],
    ]) {
      stubFetch({ kagi: jsonResponse(status, { success: false }) });
      await assert.rejects(fetchSecrets(args()), (error) => {
        assert.equal(error.transient, expected, `status ${status}`);
        return true;
      });
    }
  });

  test('a network failure is transient and names the endpoint', async () => {
    harness = createHarness();
    globalThis.fetch = async () => {
      throw new Error('socket hang up');
    };

    await assert.rejects(fetchSecrets(args()), (error) => {
      assert.equal(error.transient, true);
      assert.match(error.message, /api\.kagi\.pw\/kagi\/auth\/ci\/fetch/);
      return true;
    });
  });
});
