/**
 * End-to-end tests of run(): inputs in, workflow commands and runner-file writes out.
 *
 * KAGI_ACTION_TEST is set before the dynamic import so importing main.js does not execute the
 * action as a side effect.
 */

import { test, describe, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness, jsonResponse, setInput, stubFetch, withOidcEnv } from './helpers.js';

process.env.KAGI_ACTION_TEST = '1';

let run;
before(async () => {
  ({ run } = await import('../src/main.js'));
});

let harness;
afterEach(() => harness?.restore());

const BINDING_ID = '3fa2c1e0-0000-4000-8000-000000000000';

const body = (overrides = {}) => ({
  success: true,
  message: 'Secrets fetched successfully',
  data: {
    scopes: [
      {
        appId: '11111111-1111-1111-1111-111111111111',
        appPath: '/clients/acme/api',
        environmentSlug: 'production',
        secrets: { DATABASE_URL: 'postgres://u:p@h/db' },
      },
    ],
    dotenv: null,
    ...overrides,
  },
  pagination: null,
  error: null,
});

describe('happy path', () => {
  test('mints a token at the default audience, exchanges it, masks, then exports', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID });
    withOidcEnv();
    const calls = stubFetch({
      oidc: jsonResponse(200, { value: 'id.token.value' }),
      kagi: jsonResponse(200, body()),
    });

    await run();

    // Default audience mirrors KagiCiExchangeConstant.DEFAULT_EXPECTED_AUDIENCE.
    assert.ok(calls[0].url.endsWith('&audience=api.kagi.pw'));
    assert.equal(calls[1].url, 'https://api.kagi.pw/kagi/auth/ci/fetch');

    // The id-token is a credential too, and is masked the moment it arrives.
    assert.ok(harness.masks().includes('id.token.value'));

    const maskIndex = harness.indexOfMask('postgres://u:p@h/db');
    const writeIndex = harness.indexOfWriteContaining('postgres://u:p@h/db');
    assert.ok(maskIndex >= 0, 'the value was never masked');
    assert.ok(maskIndex < writeIndex, 'the value reached GITHUB_ENV before it was masked');

    assert.match(harness.envWrites().join(''), /^DATABASE_URL<</);
    assert.match(harness.outputWrites().join(''), /secret-count<<[^\n]*\n1\n/);
    assert.equal(process.exitCode, 0);
  });

  test('a custom audience is honoured', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID, audience: 'kagi.example' });
    withOidcEnv();
    const calls = stubFetch({
      oidc: jsonResponse(200, { value: 'jwt' }),
      kagi: jsonResponse(200, body()),
    });

    await run();

    assert.ok(calls[0].url.endsWith('&audience=kagi.example'));
  });

  test('env-file-path asks for DOTENV and writes the server-rendered document', async () => {
    harness = createHarness({
      'binding-id': BINDING_ID,
      'export-env': 'false',
    });
    setInput('env-file-path', harness.path('out/.env'));
    withOidcEnv();
    const calls = stubFetch({
      oidc: jsonResponse(200, { value: 'jwt' }),
      kagi: jsonResponse(200, body({ dotenv: 'DATABASE_URL="postgres://u:p@h/db"\n' })),
    });

    await run();

    assert.equal(JSON.parse(calls[1].options.body).format, 'DOTENV');
    assert.equal(harness.envWrites().length, 0, 'export-env: false must not touch GITHUB_ENV');
    assert.equal(harness.readFile(harness.path('out/.env')), 'DATABASE_URL="postgres://u:p@h/db"\n');
  });
});

describe('input validation', () => {
  test('a missing binding-id fails', async () => {
    harness = createHarness();
    withOidcEnv();
    await assert.rejects(run(), /binding-id/);
  });

  test('a non-UUID binding-id fails before any network call', async () => {
    harness = createHarness({ 'binding-id': 'my-binding' });
    withOidcEnv();
    const calls = stubFetch({ oidc: jsonResponse(200, { value: 'jwt' }), kagi: jsonResponse(200, body()) });

    await assert.rejects(run(), /routing UUID/);
    assert.equal(calls.length, 0);
  });

  test('export-env false with no env-file-path fails instead of quietly doing nothing', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID, 'export-env': 'false' });
    withOidcEnv();
    await assert.rejects(run(), /Nothing to do/);
  });

  test('mask: false warns that it is ignored and still masks', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID, mask: 'false' });
    withOidcEnv();
    stubFetch({ oidc: jsonResponse(200, { value: 'jwt' }), kagi: jsonResponse(200, body()) });

    await run();

    assert.ok(harness.warnings().some((w) => /always masked/.test(w)));
    assert.ok(harness.masks().includes('postgres://u:p@h/db'));
  });
});

describe('failure paths never continue silently', () => {
  test('a 401 rejects and writes nothing to GITHUB_ENV', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID });
    withOidcEnv();
    stubFetch({
      oidc: jsonResponse(200, { value: 'jwt' }),
      kagi: jsonResponse(401, { success: false, error: { code: 'KGI_AUT_CI_EXCHANGE_DENIED' } }),
    });

    await assert.rejects(run(), /KGI_AUT_CI_EXCHANGE_DENIED/);
    assert.equal(harness.envWrites().length, 0);
  });

  test('a missing id-token permission rejects before the exchange', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID });
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    const calls = stubFetch({ oidc: jsonResponse(200, {}), kagi: jsonResponse(200, body()) });

    await assert.rejects(run(), /id-token: write/);
    assert.equal(calls.length, 0);
  });

  test('an unexportable key fails the step rather than corrupting GITHUB_ENV', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID });
    withOidcEnv();
    stubFetch({
      oidc: jsonResponse(200, { value: 'jwt' }),
      kagi: jsonResponse(
        200,
        body({ scopes: [{ appPath: '/a', environmentSlug: 'p', secrets: { 'BAD=KEY': 'v' } }] })
      ),
    });

    await assert.rejects(run(), /not a valid environment variable name/);
  });
});

describe('retry', () => {
  test('a transient failure is retried with a FRESHLY minted token, never the spent one', async () => {
    harness = createHarness({
      'binding-id': BINDING_ID,
      'request-timeout-seconds': '5',
    });
    withOidcEnv();

    let minted = 0;
    let attempted = 0;
    globalThis.fetch = async (url, options) => {
      if (String(url).includes('token-service')) {
        minted += 1;
        return jsonResponse(200, { value: `jwt-${minted}` });
      }
      attempted += 1;
      if (attempted === 1) {
        return jsonResponse(503, { success: false, message: 'upstream' });
      }
      assert.equal(JSON.parse(options.body).token, 'jwt-2', 'the spent token was resent');
      return jsonResponse(200, body());
    };

    await run();

    assert.equal(minted, 2);
    assert.equal(attempted, 2);
    assert.ok(harness.warnings().some((w) => /freshly minted/.test(w)));
  });

  test('a non-transient failure is not retried', async () => {
    harness = createHarness({ 'binding-id': BINDING_ID });
    withOidcEnv();
    let attempted = 0;
    globalThis.fetch = async (url) => {
      if (String(url).includes('token-service')) return jsonResponse(200, { value: 'jwt' });
      attempted += 1;
      return jsonResponse(401, { success: false, error: { code: 'KGI_AUT_CI_EXCHANGE_DENIED' } });
    };

    await assert.rejects(run());
    assert.equal(attempted, 1);
  });
});
