const assert = require('assert/strict');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { Readable, Writable } = require('stream');

const {
  buildSummary,
  compareSemver,
  parseGithubRepo,
  requestHandler,
  scanDependencies,
  scanRepository,
  scanSecrets,
} = require('./server');

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

test('accepts only exact public GitHub repository URLs', () => {
  assert.deepEqual(parseGithubRepo('https://github.com/openai/codex'), { owner: 'openai', repo: 'codex' });
  assert.deepEqual(parseGithubRepo('https://github.com/openai/codex.git'), { owner: 'openai', repo: 'codex' });
  assert.equal(parseGithubRepo('http://github.com/openai/codex'), null);
  assert.equal(parseGithubRepo('https://notgithub.com/openai/codex'), null);
  assert.equal(parseGithubRepo('https://github.com/openai'), null);
  assert.equal(parseGithubRepo('https://github.com/openai/codex/issues'), null);
  assert.equal(parseGithubRepo('not a url'), null);
});

test('detects common leaked secrets and reports source lines', () => {
  const findings = scanSecrets([
    'const key = "AKIAABCDEFGHIJKLMNOP";',
    'password = "super-secret-password"',
    '-----BEGIN OPENSSH PRIVATE KEY-----'
  ].join('\n'), 'src/config.js');

  assert.equal(findings.filter(f => f.category === 'secret').length, 3);
  assert(findings.some(f => f.title.includes('AWS access key') && f.file === 'src/config.js:1'));
  assert(findings.some(f => f.title.includes('password') && f.file === 'src/config.js:2'));
  assert(findings.some(f => f.title.includes('Private key') && f.file === 'src/config.js:3'));
});

test('detects vulnerable npm dependencies and ignores fixed versions', () => {
  const vulnerable = scanDependencies(JSON.stringify({
    dependencies: { lodash: '4.17.15', express: '^4.17.1' },
    devDependencies: { minimist: '1.2.8' }
  }), 'package.json');

  assert(vulnerable.some(f => f.title.includes('lodash')));
  assert(vulnerable.some(f => f.title.includes('express')));
  assert(!vulnerable.some(f => f.title.includes('minimist')));
});

test('detects vulnerable Python requirements', () => {
  const findings = scanDependencies('requests==2.19.0\nflask==3.0.0\npyyaml==5.3.1\n', 'requirements.txt');
  assert(findings.some(f => f.title.includes('requests') && f.file === 'requirements.txt:1'));
  assert(findings.some(f => f.title.includes('PyYAML') || f.title.includes('PyYAML'.toLowerCase())));
  assert(!findings.some(f => f.title.includes('Flask')));
});

test('handles invalid dependency files without crashing', () => {
  assert.deepEqual(scanDependencies('{ this is not json', 'package.json'), []);
  assert.deepEqual(scanDependencies('requests>=2.19.0', 'requirements.txt'), []);
});

test('sorts and deduplicates full repository findings', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'repoguard-test-'));
  try {
    await fs.mkdir(path.join(dir, 'src'), { recursive: true });
    await fs.writeFile(path.join(dir, 'src', 'config.js'), 'const token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";\n');
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { lodash: '4.17.15' } }));
    await fs.writeFile(path.join(dir, 'requirements.txt'), 'requests==2.19.0\n');
    await fs.mkdir(path.join(dir, 'node_modules'), { recursive: true });
    await fs.writeFile(path.join(dir, 'node_modules', 'ignored.js'), 'password = "should-not-be-scanned"\n');

    const findings = await scanRepository(dir);
    assert.equal(findings[0].severity, 'high');
    assert(findings.some(f => f.category === 'secret'));
    assert(findings.some(f => f.category === 'dependency' && f.file === 'package.json'));
    assert(findings.some(f => f.category === 'dependency' && f.file === 'requirements.txt:1'));
    assert(!findings.some(f => f.file.includes('node_modules')));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('produces useful clean and finding summaries', () => {
  assert(buildSummary([], 'owner/repo').includes('did not find obvious leaked secrets'));
  assert(buildSummary([{ severity: 'high', category: 'secret' }], 'owner/repo').includes('Fix high-severity'));
});

test('compares semantic versions across missing patch numbers', () => {
  assert(compareSemver('4.17.15', '4.17.21') < 0);
  assert(compareSemver('4.18', '4.18.0') === 0);
  assert(compareSemver('5.0.0', '4.17.21') > 0);
});

test('serves frontend and validates scan endpoint requests', async () => {
  const home = await dispatch({ method: 'GET', url: '/' });
  assert.equal(home.status, 200);
  assert(home.body.includes('RepoGuard'));

  const head = await dispatch({ method: 'HEAD', url: '/' });
  assert.equal(head.status, 200);
  assert.equal(head.body, '');

  const missing = await dispatch({ method: 'GET', url: '/missing.js' });
  assert.equal(missing.status, 404);

  const invalid = await dispatch({
    method: 'POST',
    url: '/scan',
    body: JSON.stringify({ repo_url: 'https://github.com/openai/codex/issues' })
  });
  assert.equal(invalid.status, 400);
  assert(JSON.parse(invalid.body).error.includes('GitHub repository URL'));

  const malformed = await dispatch({ method: 'POST', url: '/scan', body: '{nope' });
  assert.equal(malformed.status, 400);
});

test('inline frontend scripts parse', async () => {
  const html = await fs.readFile(path.join(__dirname, 'index.html'), 'utf8');
  for (const match of html.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g)) {
    new Function(match[1]);
  }
});

async function dispatch({ method, url, body = '' }) {
  const req = Readable.from(body ? [body] : []);
  req.method = method;
  req.url = url;

  const chunks = [];
  const res = new Writable({
    write(chunk, encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    }
  });
  res.statusCode = 200;
  res.headers = {};
  res.writeHead = (status, headers) => {
    res.statusCode = status;
    res.headers = headers;
  };
  const finished = new Promise(resolve => {
    res.end = chunk => {
      if (chunk) chunks.push(Buffer.from(chunk));
      resolve();
    };
  });

  await requestHandler(req, res);
  await finished;
  return {
    status: res.statusCode,
    headers: res.headers,
    body: Buffer.concat(chunks).toString('utf8')
  };
}

(async () => {
  let failures = 0;
  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`PASS ${name}`);
    } catch (err) {
      failures++;
      console.error(`FAIL ${name}`);
      console.error(err);
    }
  }
  if (failures) process.exit(1);
})();
