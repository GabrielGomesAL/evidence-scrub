/**
 * Conservative evidence projection, not a universal secret detector.
 * keepPaths explicitly retains URL pathnames, which can contain sensitive data.
 */
const REDACTED = '[REDACTED]';
const REDACTED_PATH = '/[REDACTED_PATH]';
const REDACTED_ORIGIN = 'https://redacted.invalid';
const MAX_ENTRIES = 10_000;
const MAX_HEADERS = 200;
const MAX_COOKIES = 500;
const MAX_QUERY = 1_000;
const MAX_URL = 16_384;
const MAX_HEADER_VALUE = 65_536;
const MAX_HTTP = 2 * 1024 * 1024;
const MAX_DURATION = 86_400_000;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE']);
const VERSIONS = new Set(['HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/2.0', 'HTTP/3', 'HTTP/3.0']);
const MIMES = new Set([
  'application/json', 'application/problem+json', 'application/xml',
  'application/javascript', 'application/octet-stream', 'application/pdf',
  'application/zip', 'application/x-www-form-urlencoded', 'multipart/form-data',
  'text/plain', 'text/html', 'text/css', 'text/javascript', 'text/xml',
  'text/csv', 'text/event-stream', 'image/png', 'image/jpeg', 'image/gif',
  'image/webp', 'image/svg+xml', 'audio/mpeg', 'video/mp4',
]);
const HEADER_NAMES = new Set([
  'accept', 'accept-charset', 'accept-encoding', 'accept-language',
  'access-control-allow-origin', 'access-control-allow-credentials',
  'access-control-allow-headers', 'access-control-allow-methods',
  'access-control-expose-headers', 'access-control-max-age',
  'access-control-request-headers', 'access-control-request-method',
  'age', 'allow', 'authorization', 'cache-control', 'connection',
  'content-disposition', 'content-encoding', 'content-language',
  'content-length', 'content-location', 'content-range', 'content-security-policy',
  'content-security-policy-report-only', 'content-type', 'cookie', 'date',
  'etag', 'expect', 'expires', 'forwarded', 'host', 'if-match',
  'if-modified-since', 'if-none-match', 'if-range', 'if-unmodified-since',
  'last-modified', 'location', 'origin', 'pragma', 'proxy-authenticate',
  'proxy-authorization', 'range', 'referer', 'referrer-policy', 'retry-after',
  'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
  'sec-websocket-accept', 'sec-websocket-key', 'sec-websocket-protocol',
  'sec-websocket-version', 'server', 'set-cookie', 'strict-transport-security',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'user-agent', 'vary',
  'via', 'warning', 'www-authenticate', 'x-api-key', 'x-auth-token',
  'x-content-type-options', 'x-correlation-id', 'x-csrf-token',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'x-frame-options', 'x-request-id', 'x-xsrf-token',
]);

function newStats() {
  return { entries: 0, urls: 0, queryValues: 0, headersRedacted: 0,
    headersRemoved: 0, cookiesRemoved: 0, bodiesRemoved: 0, pathsRedacted: 0 };
}

function record(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function optionsFor(options) {
  if (!record(options) || (options.keepPaths !== undefined && typeof options.keepPaths !== 'boolean')) throw new Error();
  return { keepPaths: options.keepPaths === true };
}

function list(value, max) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > max) throw new Error();
  return value;
}

function boundedString(value, max) {
  if (typeof value !== 'string' || value.length > max) throw new Error();
  return value;
}

function mime(value, fallback = 'application/octet-stream') {
  if (typeof value !== 'string' || value.length > MAX_HEADER_VALUE) return fallback;
  const normalized = value.split(';', 1)[0].trim().toLowerCase();
  return MIMES.has(normalized) ? normalized : fallback;
}

function method(value) {
  if (typeof value !== 'string' || value.length > 32) return 'OTHER';
  return METHODS.has(value) ? value : 'OTHER';
}

function version(value) {
  return typeof value === 'string' && VERSIONS.has(value) ? value : '';
}

function duration(value, fallback = 0) {
  return typeof value === 'number' && Number.isFinite(value) && value >= -1 && value <= MAX_DURATION ? value : fallback;
}

function timestamp(value) {
  if (typeof value !== 'string' || value.length > 35) throw new Error();
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!parts) throw new Error();
  const [, year, month, day, hour, minute, second] = parts.map(Number);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) throw new Error();
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error();
  return date.toISOString();
}

function sanitizeUrl(value, options, stats, allowRelative = false) {
  boundedString(value, MAX_URL);
  if (allowRelative && !value.startsWith('/') && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value)) throw new Error();
  const parsed = allowRelative ? new URL(value, REDACTED_ORIGIN) : new URL(value);
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) throw new Error();
  const pathname = parsed.pathname || '/';
  const path = options.keepPaths || pathname === '/' ? pathname : REDACTED_PATH;
  if (!options.keepPaths && pathname !== '/') stats.pathsRedacted++;
  let count = 0;
  for (const _ of parsed.searchParams) {
    if (++count > MAX_QUERY) throw new Error();
  }
  stats.urls++;
  stats.queryValues += count;
  const query = Array.from({ length: count }, (_, index) => `param${index + 1}=${REDACTED}`).join('&');
  const origin = allowRelative && value.startsWith('/') ? '' : REDACTED_ORIGIN;
  return `${origin}${path}${query ? `?${query}` : ''}`;
}

function sanitizeHeader(name, value, stats) {
  boundedString(name, 256);
  boundedString(value, MAX_HEADER_VALUE);
  const normalized = name.toLowerCase();
  if (!HEADER_NAMES.has(normalized)) {
    stats.headersRemoved++;
    return null;
  }
  if (normalized === 'cookie' || normalized === 'set-cookie') stats.cookiesRemoved++;
  if (normalized === 'content-type') {
    const normalizedMime = mime(value, null);
    if (normalizedMime !== null) return { name: normalized, value: normalizedMime };
  }
  stats.headersRedacted++;
  return { name: normalized, value: REDACTED };
}

function headers(value, stats) {
  const result = [];
  for (const header of list(value, MAX_HEADERS)) {
    if (!record(header)) throw new Error();
    const cleaned = sanitizeHeader(header.name, header.value, stats);
    if (cleaned) result.push(cleaned);
  }
  return result;
}

function cookies(value, stats) {
  stats.cookiesRemoved += list(value, MAX_COOKIES).length;
  return [];
}

function queryString(value, stats) {
  const source = list(value, MAX_QUERY);
  stats.queryValues += source.length;
  return Array.from(source, (item, index) => {
    if (!record(item)) throw new Error();
    return { name: `param${index + 1}`, value: REDACTED };
  });
}

function entry(value, options, stats) {
  if (!record(value) || !record(value.request) || !record(value.response)) throw new Error();
  const request = value.request;
  const response = value.response;
  if (Object.hasOwn(request, 'postData')) stats.bodiesRemoved++;
  const content = record(response.content) ? response.content : {};
  if (Object.hasOwn(content, 'text')) stats.bodiesRemoved++;
  const sourceTimings = record(value.timings) ? value.timings : {};
  const timings = {};
  for (const name of ['blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl']) {
    timings[name] = duration(sourceTimings[name], ['send', 'wait', 'receive'].includes(name) ? 0 : -1);
  }
  stats.entries++;
  return {
    startedDateTime: timestamp(value.startedDateTime),
    time: Math.max(0, duration(value.time)),
    request: {
      method: method(request.method),
      url: sanitizeUrl(request.url, options, stats),
      httpVersion: version(request.httpVersion),
      cookies: cookies(request.cookies, stats),
      headers: headers(request.headers, stats),
      queryString: queryString(request.queryString, stats),
      headersSize: -1,
      bodySize: 0,
    },
    response: {
      status: Number.isInteger(response.status) && response.status >= 100 && response.status <= 599 ? response.status : 0,
      statusText: '',
      httpVersion: version(response.httpVersion),
      cookies: cookies(response.cookies, stats),
      headers: headers(response.headers, stats),
      content: { size: 0, mimeType: mime(content.mimeType) },
      redirectURL: '',
      headersSize: -1,
      bodySize: 0,
    },
    cache: {},
    timings,
  };
}

/**
 * Build a new HAR 1.2 document from explicitly selected fields.
 * Counters describe removed/sanitized occurrences, including duplicated URL and
 * queryString representations. Unknown/custom fields are omitted, not inspected.
 */
export function sanitizeHar(input, options = {}) {
  try {
    const cleanOptions = optionsFor(options);
    if (!record(input) || !record(input.log) || !Array.isArray(input.log.entries) || input.log.entries.length > MAX_ENTRIES) throw new Error();
    const stats = newStats();
    const har = { log: { version: '1.2', creator: { name: 'evidence-scrub', version: '0.1.0' },
      entries: Array.from(input.log.entries, (item) => entry(item, cleanOptions, stats)) } };
    return { har, stats };
  } catch {
    throw new Error('Invalid HAR input.');
  }
}

/** Sanitize one raw HTTP request or response; all body content is discarded. */
export function sanitizeHttp(text, options = {}) {
  try {
    const cleanOptions = optionsFor(options);
    boundedString(text, MAX_HTTP);
    if (new TextEncoder().encode(text).length > MAX_HTTP) throw new Error();
    const stats = newStats();
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const start = lines.shift();
    if (!start || start.length > MAX_URL + 64 || start.includes('\r')) throw new Error();
    let cleanStart;
    const response = /^(HTTP\/(?:1\.0|1\.1|2(?:\.0)?|3(?:\.0)?))[ \t]+([1-5]\d{2})(?:[ \t]+.*)?$/.exec(start);
    if (response) {
      cleanStart = `${response[1]} ${response[2]} ${REDACTED}`;
    } else {
      const request = /^(\S{1,32})[ \t]+(\S{1,16384})[ \t]+(HTTP\/(?:1\.0|1\.1|2(?:\.0)?|3(?:\.0)?))$/.exec(start);
      if (!request) throw new Error();
      const cleanMethod = method(request[1]);
      let target;
      if (request[1] === 'CONNECT') {
        target = '[REDACTED_AUTHORITY]';
        stats.urls++;
      } else if (request[2] === '*') {
        target = '*';
      } else {
        target = sanitizeUrl(request[2], cleanOptions, stats, true);
      }
      cleanStart = `${cleanMethod} ${target} ${request[3]}`;
    }
    const cleaned = [];
    let headerCount = 0;
    let bodyIndex = lines.length;
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index];
      if (line === '') {
        bodyIndex = index + 1;
        break;
      }
      if (++headerCount > MAX_HEADERS || line.length > MAX_HEADER_VALUE + 257 || line.includes('\r')) throw new Error();
      const colon = line.indexOf(':');
      if (colon < 1 || /^[ \t]/.test(line)) {
        stats.headersRemoved++;
        continue;
      }
      const clean = sanitizeHeader(line.slice(0, colon), line.slice(colon + 1).trim(), stats);
      if (clean) cleaned.push(`${clean.name}: ${clean.value}`);
    }
    if (lines.slice(bodyIndex).some((line) => line.length > 0)) stats.bodiesRemoved++;
    stats.entries = 1;
    return { text: `${[cleanStart, ...cleaned].join('\r\n')}\r\n\r\n`, stats };
  } catch {
    throw new Error('Invalid HTTP input.');
  }
}
