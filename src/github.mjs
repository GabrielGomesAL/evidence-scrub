const API_ORIGIN = 'https://api.github.com';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_FAILED = 'Unable to fetch public GitHub metadata.';
const REQUEST_TIMED_OUT = 'GitHub metadata request timed out.';

function repositoryParts(repository) {
  if (typeof repository !== 'string') {
    throw new TypeError('Repository must use the owner/repo format.');
  }

  const parts = repository.split('/');
  const [owner, name] = parts;
  const validOwner = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
  const validName = /^[A-Za-z0-9._-]{1,100}$/;
  if (parts.length !== 2 || !validOwner.test(owner) || owner.includes('--')
      || !validName.test(name) || name === '.' || name === '..') {
    throw new TypeError('Repository must use the owner/repo format.');
  }

  return parts;
}

async function boundedJson(response, signal) {
  const body = response.body;
  const length = response.headers?.get('content-length');
  if (!body || (length && /^\d+$/.test(length) && Number(length) > MAX_RESPONSE_BYTES)) {
    if (body) void body.cancel().catch(() => {});
    throw new Error(REQUEST_FAILED);
  }

  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    if (signal.aborted) throw new Error(REQUEST_FAILED);
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        cancel();
        throw new Error(REQUEST_FAILED);
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function licenseId(license) {
  const id = record(license) ? license.spdx_id : null;
  return typeof id === 'string' && /^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$/.test(id)
    && id !== 'NOASSERTION' ? id : null;
}

/**
 * Read public repository metadata only. No capture, credentials, token, or
 * caller-supplied headers are accepted or sent by this integration.
 */
export async function fetchGitHubMetadata(
  repository,
  { fetchImpl = globalThis.fetch, timeoutMs = 10_000 } = {},
) {
  const [owner, name] = repositoryParts(repository);
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('GitHub metadata fetch is unavailable.');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new TypeError('GitHub metadata timeout must be between 1 and 60000 milliseconds.');
  }

  const path = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
  const controller = new AbortController();
  let timedOut = false;
  let timer;

  const request = async (url) => {
    const response = await fetchImpl(url, {
      method: 'GET',
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10',
        'User-Agent': 'evidence-scrub',
      },
      credentials: 'omit',
      redirect: 'error',
      signal: controller.signal,
    });
    if (response.status !== 200 || response.redirected
        || (response.url && response.url !== url)) {
      if (response.body) void response.body.cancel().catch(() => {});
      throw new Error(REQUEST_FAILED);
    }
    return boundedJson(response, controller.signal);
  };

  const operation = async () => {
    const repo = await request(`${API_ORIGIN}${path}`);
    if (!record(repo) || repo.private === true || (repo.visibility && repo.visibility !== 'public')
        || typeof repo.default_branch !== 'string' || repo.default_branch.length === 0
        || repo.default_branch === '.' || repo.default_branch === '..'
        || repo.default_branch.length > 1024 || /[\u0000-\u001f\u007f]/.test(repo.default_branch)
        || !Number.isSafeInteger(repo.stargazers_count) || repo.stargazers_count < 0) {
      throw new Error(REQUEST_FAILED);
    }
    const commit = await request(`${API_ORIGIN}${path}/commits/${encodeURIComponent(repo.default_branch)}`);
    if (!record(commit) || typeof commit.sha !== 'string'
        || !/^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(commit.sha)) {
      throw new Error(REQUEST_FAILED);
    }
    return {
      repository,
      url: `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`,
      defaultBranch: repo.default_branch,
      commitSha: commit.sha.toLowerCase(),
      license: licenseId(repo.license),
      stars: repo.stargazers_count,
    };
  };

  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(new Error(REQUEST_TIMED_OUT));
    }, timeoutMs);
  });

  try {
    return await Promise.race([operation(), deadline]);
  } catch {
    throw new Error(timedOut ? REQUEST_TIMED_OUT : REQUEST_FAILED);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}
