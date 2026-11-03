import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeHar, sanitizeHttp } from '../src/sanitize.mjs';

const CANARY = 'CANARY_PRIVATE_79af94ef';
const ENCODED = encodeURIComponent(`${CANARY}/email@example.test`);

function fixture() {
  return { secret: CANARY, log: { version: CANARY, creator: { name: CANARY },
    comment: CANARY, pages: [{ title: CANARY }], entries: [{
      startedDateTime: '2026-11-03T10:20:30.100Z', time: 42,
      serverIPAddress: CANARY, connection: CANARY, _custom: { password: CANARY },
      request: {
        method: 'GET', url: `https://${CANARY}:${CANARY}@${CANARY}.example.test/private/${ENCODED}?${ENCODED}=${ENCODED}&token=${CANARY}#${CANARY}`,
        httpVersion: 'HTTP/2',
        headers: [
          { name: 'Authorization', value: `Bearer ${CANARY}`, comment: CANARY },
          { name: 'Cookie', value: `sid=${CANARY}` },
          { name: 'Content-Type', value: `Application/JSON; boundary=${CANARY}; charset=utf-8` },
          { name: `x-${CANARY}`, value: CANARY },
          { name: 'X-Request-ID', value: CANARY },
        ],
        cookies: [{ name: CANARY, value: CANARY, domain: CANARY, path: CANARY }],
        queryString: [{ name: CANARY, value: CANARY, comment: CANARY }],
        postData: { mimeType: CANARY, text: CANARY, params: [{ name: CANARY, value: CANARY }] },
        body: CANARY,
      },
      response: {
        status: 200, statusText: CANARY, httpVersion: 'HTTP/2', redirectURL: `https://${CANARY}.test`,
        cookies: [{ name: CANARY, value: CANARY }],
        headers: [{ name: 'Set-Cookie', value: `${CANARY}=${CANARY}` }, { name: 'Location', value: CANARY }],
        content: { size: 100, mimeType: `text/html; charset=${CANARY}`, text: CANARY, encoding: CANARY, comment: CANARY },
        _custom: CANARY,
      },
      cache: { beforeRequest: { comment: CANARY } },
      timings: { send: 1, wait: 40, receive: 1, _custom: CANARY },
    }] } };
}

function noCanary(value) {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  assert.ok(!serialized.includes(CANARY), 'raw canary leaked');
  assert.ok(!serialized.includes(ENCODED), 'encoded canary leaked');
}

test('HAR rebuilds only allowed fields and removes canaries in every supported surface', () => {
  const { har, stats } = sanitizeHar(fixture());
  noCanary({ har, stats });
  assert.equal(har.log.version, '1.2');
  assert.deepEqual(har.log.creator, { name: 'evidence-scrub', version: '0.1.0' });
  const item = har.log.entries[0];
  assert.equal(item.startedDateTime, '2026-11-03T10:20:30.100Z');
  assert.equal(item.request.url, 'https://redacted.invalid/[REDACTED_PATH]?param1=[REDACTED]&param2=[REDACTED]');
  assert.deepEqual(item.request.cookies, []);
  assert.equal(item.request.postData, undefined);
  assert.equal(item.response.content.text, undefined);
  assert.equal(item.response.statusText, '');
  assert.deepEqual(item.request.headers.find((h) => h.name === 'content-type'), { name: 'content-type', value: 'application/json' });
  assert.equal(item.response.content.mimeType, 'text/html');
  assert.equal(item.serverIPAddress, undefined);
  assert.deepEqual(item.cache, {});
  assert.deepEqual(stats, { entries: 1, urls: 1, queryValues: 3, headersRedacted: 5,
    headersRemoved: 1, cookiesRemoved: 4, bodiesRemoved: 2, pathsRedacted: 1 });
});

test('HAR does not mutate input, including frozen objects', () => {
  const input = fixture();
  const before = structuredClone(input);
  function freeze(value) {
    if (value && typeof value === 'object') {
      Object.freeze(value);
      for (const child of Object.values(value)) freeze(child);
    }
    return value;
  }
  const cleaned = sanitizeHar(freeze(input));
  assert.deepEqual(input, before);
  assert.notEqual(cleaned.har.log.entries, input.log.entries);
});

test('keepPaths opts into pathname retention while still removing origin, userinfo, query and fragment', () => {
  const input = fixture();
  input.log.entries[0].request.url = `https://${CANARY}:${CANARY}@${CANARY}.test/api/v1/items?token=${CANARY}#${CANARY}`;
  const { har, stats } = sanitizeHar(input, { keepPaths: true });
  assert.equal(har.log.entries[0].request.url, 'https://redacted.invalid/api/v1/items?param1=[REDACTED]');
  assert.equal(stats.pathsRedacted, 0);
  noCanary({ har, stats });
});

test('root paths and controlled scalar metadata survive; arbitrary strings and invalid numbers do not', () => {
  const input = fixture();
  const item = input.log.entries[0];
  item.request.url = 'https://example.test/';
  item.request.method = CANARY;
  item.request.httpVersion = CANARY;
  item.time = Infinity;
  item.response.status = CANARY;
  item.response.content.mimeType = CANARY;
  item.timings = { send: NaN, wait: Infinity, receive: CANARY, ssl: -900 };
  const output = sanitizeHar(input);
  const clean = output.har.log.entries[0];
  noCanary(output);
  assert.equal(clean.request.url, 'https://redacted.invalid/');
  assert.equal(clean.request.method, 'OTHER');
  assert.equal(clean.request.httpVersion, '');
  assert.equal(clean.startedDateTime, '2026-11-03T10:20:30.100Z');
  assert.equal(clean.time, 0);
  assert.equal(clean.response.status, 0);
  assert.equal(clean.response.content.mimeType, 'application/octet-stream');
  assert.deepEqual(clean.timings, { blocked: -1, dns: -1, connect: -1, send: 0, wait: 0, receive: 0, ssl: -1 });
});

test('raw HTTP request removes encoded values, folded lines, unknown header names and the entire body', () => {
  const raw = `POST https://${CANARY}:${CANARY}@${CANARY}.test/${ENCODED}?access_token=${ENCODED}#${CANARY} HTTP/1.1\r\nAuthorization: Bearer ${CANARY}\r\nCookie: sid=${CANARY}\r\nContent-Type: application/json; boundary=${CANARY}\r\nx-${CANARY}: ${CANARY}\r\n ${CANARY}\r\n\r\n{"secret":"${CANARY}"}`;
  const output = sanitizeHttp(raw);
  noCanary(output);
  assert.equal(output.text, 'POST https://redacted.invalid/[REDACTED_PATH]?param1=[REDACTED] HTTP/1.1\r\nauthorization: [REDACTED]\r\ncookie: [REDACTED]\r\ncontent-type: application/json\r\n\r\n');
  assert.equal(output.stats.bodiesRemoved, 1);
  assert.equal(output.stats.headersRemoved, 2);
});

test('raw HTTP supports relative targets, root paths, explicit keepPaths and response status lines', () => {
  assert.equal(sanitizeHttp(`GET /secret/${CANARY}?q=${CANARY} HTTP/2\nHost: ${CANARY}\n\n`).text,
    'GET /[REDACTED_PATH]?param1=[REDACTED] HTTP/2\r\nhost: [REDACTED]\r\n\r\n');
  assert.equal(sanitizeHttp('GET / HTTP/1.1\n\n').text, 'GET / HTTP/1.1\r\n\r\n');
  assert.equal(sanitizeHttp(`GET /api/items?q=${CANARY} HTTP/1.1\n\n`, { keepPaths: true }).text,
    'GET /api/items?param1=[REDACTED] HTTP/1.1\r\n\r\n');
  const response = sanitizeHttp(`HTTP/1.1 403 ${CANARY}\r\nSet-Cookie: session=${CANARY}\r\nX-Request-ID: ${CANARY}\r\n\r\n${CANARY}`);
  noCanary(response);
  assert.match(response.text, /^HTTP\/1\.1 403 \[REDACTED\]/);
  assert.equal(response.stats.bodiesRemoved, 1);
});

test('raw HTTP handles CONNECT and OPTIONS without retaining authorities', () => {
  noCanary(sanitizeHttp(`CONNECT ${CANARY}.test:443 HTTP/1.1\r\nHost: ${CANARY}\r\n\r\n`));
  assert.equal(sanitizeHttp('OPTIONS * HTTP/1.1\r\n\r\n').text, 'OPTIONS * HTTP/1.1\r\n\r\n');
});

test('invalid HAR inputs throw only a generic message, including hostile accessors', () => {
  const invalid = [null, CANARY, [], {}, { log: {} }, { log: { entries: CANARY } },
    { log: { entries: Array(10_001).fill(null) } }, { log: { entries: [null] } },
    { log: { entries: [{ request: {}, response: {} }] } }];
  for (const input of invalid) {
    assert.throws(() => sanitizeHar(input), { message: 'Invalid HAR input.' });
  }
  const hostile = { get log() { throw new Error(CANARY); } };
  assert.throws(() => sanitizeHar(hostile), (error) => {
    noCanary(error.message);
    return error.message === 'Invalid HAR input.';
  });
  const input = fixture();
  input.log.entries[0].request.url = `javascript:${CANARY}`;
  assert.throws(() => sanitizeHar(input), { message: 'Invalid HAR input.' });
  assert.throws(() => sanitizeHar(fixture(), { keepPaths: CANARY }), { message: 'Invalid HAR input.' });
});

test('invalid raw HTTP input and oversized strings never appear in errors', () => {
  for (const input of [null, 42, CANARY, `GET ${CANARY} HTTP/1.1\n\n`, 'x'.repeat(2 * 1024 * 1024 + 1)]) {
    assert.throws(() => sanitizeHttp(input), (error) => {
      noCanary(error.message);
      return error.message === 'Invalid HTTP input.';
    });
  }
  assert.throws(() => sanitizeHttp('GET / HTTP/1.1\rBROKEN'), { message: 'Invalid HTTP input.' });
});

test('sparse arrays, collection caps, oversized URLs and hostile nested values fail closed', () => {
  assert.deepEqual(sanitizeHar({ log: { entries: [] } }).har.log.entries, []);
  assert.throws(() => sanitizeHar({ log: { entries: Array(1) } }), { message: 'Invalid HAR input.' });
  const oversizedUrl = fixture();
  oversizedUrl.log.entries[0].request.url = `https://example.test/${'x'.repeat(16_384)}`;
  assert.throws(() => sanitizeHar(oversizedUrl), { message: 'Invalid HAR input.' });
  const tooManyHeaders = fixture();
  tooManyHeaders.log.entries[0].request.headers = Array.from({ length: 201 }, () => ({ name: 'Host', value: CANARY }));
  assert.throws(() => sanitizeHar(tooManyHeaders), { message: 'Invalid HAR input.' });
  const hostileHeader = fixture();
  hostileHeader.log.entries[0].request.headers = [{ name: 'Authorization', get value() { throw new Error(CANARY); } }];
  assert.throws(() => sanitizeHar(hostileHeader), (error) => {
    noCanary(error.message);
    return error.message === 'Invalid HAR input.';
  });
});

test('timestamps preserve normalized valid times and reject missing or impossible dates without inventing evidence', () => {
  for (const value of [undefined, null, CANARY, '2026-02-30T12:00:00Z', '2026-11-03T24:00:00Z', '2026-11-03T12:00:99Z']) {
    const input = fixture();
    input.log.entries[0].startedDateTime = value;
    assert.throws(() => sanitizeHar(input), (error) => {
      noCanary(error.message);
      return error.message === 'Invalid HAR input.';
    });
  }
  const input = fixture();
  input.log.entries[0].startedDateTime = '2026-11-03T07:20:30.1-03:00';
  assert.equal(sanitizeHar(input).har.log.entries[0].startedDateTime, '2026-11-03T10:20:30.100Z');
  input.log.entries[0].startedDateTime = '2024-02-29T12:00:00Z';
  assert.equal(sanitizeHar(input).har.log.entries[0].startedDateTime, '2024-02-29T12:00:00.000Z');
});

test('URL removal does not depend on detecting or decoding the secret spelling', () => {
  const fullyEncoded = Array.from(Buffer.from(CANARY), (byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
  const doubleEncoded = encodeURIComponent(fullyEncoded);
  const input = fixture();
  input.log.entries[0].request.url = `https://example.test/${fullyEncoded}?${fullyEncoded}=${doubleEncoded}#${fullyEncoded}`;
  for (const output of [sanitizeHar(input), sanitizeHttp(`GET /${fullyEncoded}?${fullyEncoded}=${doubleEncoded} HTTP/1.1\r\n\r\n`)]) {
    const serialized = JSON.stringify(output);
    noCanary(output);
    assert.ok(!serialized.toLowerCase().includes(fullyEncoded.toLowerCase()));
    assert.ok(!serialized.toLowerCase().includes(doubleEncoded.toLowerCase()));
  }
});
