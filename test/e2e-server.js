/**
 * A stand-in for the GitHub OIDC token service and the Kagi API, used by the CI smoke test.
 *
 * The smoke test runs the real action end to end on a real runner -- real INPUT_* wiring, real
 * $GITHUB_ENV, real node24 runtime -- which is the part unit tests cannot cover. It deliberately
 * does NOT declare `permissions: id-token: write`, so the only ACTIONS_ID_TOKEN_REQUEST_* variables
 * in play are the ones the workflow points at this server.
 *
 * Serves:
 *   GET  /token?api-version=2.0&audience=...  -> { value: "<fake jwt>" }
 *   POST /kagi/auth/ci/fetch                  -> CustomResponse<KagiCiSecretFetchResponse>
 */

import { createServer } from 'node:http';
import { writeFileSync } from 'node:fs';

const EXPECTED_AUDIENCE = process.env.E2E_EXPECTED_AUDIENCE ?? 'api.kagi.pw';
const SECRET_VALUE = 'e2e-secret-value';
const DENIED_IDENTITY = '00000000-0000-4000-8000-000000000000';

const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');

  if (request.method === 'GET' && url.pathname === '/token') {
    if (request.headers.authorization !== 'Bearer e2e-runner-bearer') {
      return json(response, 401, { message: 'wrong runner bearer' });
    }
    if (url.searchParams.get('audience') !== EXPECTED_AUDIENCE) {
      return json(response, 400, { message: `wrong audience: ${url.searchParams.get('audience')}` });
    }
    return json(response, 200, { value: 'header.payload.signature' });
  }

  if (request.method === 'POST' && url.pathname === '/kagi/auth/ci/fetch') {
    let raw = '';
    request.on('data', (chunk) => {
      raw += chunk;
    });
    request.on('end', () => {
      const body = JSON.parse(raw);
      // Reserved routing id the smoke test uses to exercise the opaque-denial path.
      if (body.identity === DENIED_IDENTITY) {
        return json(response, 401, { success: false, error: { code: 'KGI_AUT_CI_EXCHANGE_DENIED' } });
      }
      if (body.provider !== 'GITHUB_ACTIONS' || body.token !== 'header.payload.signature') {
        return json(response, 401, { success: false, error: { code: 'KGI_AUT_CI_EXCHANGE_DENIED' } });
      }
      const secrets = { E2E_SECRET: SECRET_VALUE, E2E_MULTILINE: 'first-line\nsecond-line' };
      const dotenv =
        `E2E_SECRET="${SECRET_VALUE}"\n` + 'E2E_MULTILINE="first-line\\nsecond-line"\n';
      return json(response, 200, {
        success: true,
        message: 'Secrets fetched successfully',
        data: {
          scopes: [
            {
              appId: '11111111-1111-1111-1111-111111111111',
              appPath: '/e2e/app',
              environmentSlug: 'production',
              secrets,
            },
          ],
          dotenv: body.format === 'DOTENV' ? dotenv : null,
        },
        pagination: null,
        error: null,
      });
    });
    request.on('error', (error) => {
      json(response, 500, { message: error.message });
    });
    return undefined;
  }

  return json(response, 404, { message: 'no route' });
});

function json(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(body);
}

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  // The workflow reads these back to build the step env; writing them out avoids parsing logs.
  writeFileSync(
    process.env.E2E_ENDPOINT_FILE ?? 'e2e-endpoints.env',
    `E2E_TOKEN_URL=${base}/token?api-version=2.0\nE2E_API_URL=${base}\nE2E_SECRET_VALUE=${SECRET_VALUE}\n`
  );
  process.stdout.write(`e2e server listening on ${base}\n`);
});
