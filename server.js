const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');

const PORT = Number(process.env.PORT || 5001);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES = 3500;

const SECRET_PATTERNS = [
  {
    title: 'AWS access key committed to source',
    severity: 'high',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    fix: 'Revoke the AWS key, rotate any related credentials, move secrets into environment variables or a secret manager, and check cloud access logs.'
  },
  {
    title: 'Google API key committed to source',
    severity: 'high',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    fix: 'Restrict and rotate the Google API key, then load it from a secret manager or deployment environment.'
  },
  {
    title: 'GitHub token committed to source',
    severity: 'high',
    regex: /\bgh[pousr]_[0-9A-Za-z_]{36,255}\b/g,
    fix: 'Revoke the GitHub token immediately, create a least-privilege replacement, and remove it from git history.'
  },
  {
    title: 'Private key material committed to source',
    severity: 'high',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    fix: 'Treat the key as compromised, revoke or replace it, and store the replacement outside the repository.'
  },
  {
    title: 'Slack token committed to source',
    severity: 'high',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/g,
    fix: 'Revoke the Slack token, rotate app credentials, and move it into a managed secret store.'
  },
  {
    title: 'Stripe secret key committed to source',
    severity: 'high',
    regex: /\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b/g,
    fix: 'Rotate the Stripe key in the dashboard and use environment variables for runtime access.'
  },
  {
    title: 'Possible hard-coded password',
    severity: 'medium',
    regex: /\b(?:password|passwd|pwd)\b\s*[:=]\s*["']?[^"'\s]{8,}/gi,
    fix: 'Verify whether the value is real. If it is, rotate it and load it from an environment variable or secret manager.'
  },
  {
    title: 'Possible hard-coded API key or token',
    severity: 'medium',
    regex: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret)\b\s*[:=]\s*["']?[A-Za-z0-9_.\-]{16,}/gi,
    fix: 'Confirm whether the value is a live secret. Rotate live credentials and replace committed values with configuration references.'
  }
];

const VULN_DB = [
  { ecosystem: 'npm', name: 'lodash', below: '4.17.21', title: 'lodash before 4.17.21 has known prototype pollution vulnerabilities', severity: 'medium', fix: 'Upgrade lodash to 4.17.21 or later.' },
  { ecosystem: 'npm', name: 'minimist', below: '1.2.6', title: 'minimist before 1.2.6 is vulnerable to prototype pollution', severity: 'medium', fix: 'Upgrade minimist to 1.2.6 or later.' },
  { ecosystem: 'npm', name: 'axios', below: '0.21.2', title: 'axios before 0.21.2 has known SSRF and credential exposure issues', severity: 'medium', fix: 'Upgrade axios to a current maintained version.' },
  { ecosystem: 'npm', name: 'express', below: '4.18.2', title: 'express before 4.18.2 depends on packages with known CVEs', severity: 'low', fix: 'Upgrade express to 4.18.2 or later.' },
  { ecosystem: 'pip', name: 'django', below: '3.2.25', title: 'older Django versions contain multiple security fixes', severity: 'medium', fix: 'Upgrade Django to a supported LTS or current stable release.' },
  { ecosystem: 'pip', name: 'flask', below: '2.2.5', title: 'older Flask versions contain security fixes in Flask and its dependencies', severity: 'low', fix: 'Upgrade Flask to a current stable release.' },
  { ecosystem: 'pip', name: 'requests', below: '2.20.0', title: 'requests before 2.20.0 can leak credentials on redirect', severity: 'medium', fix: 'Upgrade requests to 2.20.0 or later.' },
  { ecosystem: 'pip', name: 'pyyaml', below: '5.4', title: 'older PyYAML versions can allow unsafe deserialization patterns', severity: 'medium', fix: 'Upgrade PyYAML and avoid unsafe loaders.' }
];

const server = http.createServer(requestHandler);

async function requestHandler(req, res) {
  try {
    if (req.method === 'OPTIONS') return sendEmpty(res, 204);
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res);
    if (req.method === 'POST' && req.url === '/scan') return handleScan(req, res);
    sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { error: 'Unexpected server error.' });
  }
}

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`RepoGuard running at http://${HOST}:${PORT}`);
  });
}

async function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, `http://${HOST}:${PORT}`).pathname);
  const safePath = path.normalize(urlPath === '/' ? '/index.html' : urlPath).replace(/^(\.\.[/\\])+/, '');
  const filePath = path.join(ROOT, safePath);
  if (!filePath.startsWith(ROOT)) return sendJson(res, 403, { error: 'Forbidden' });

  try {
    const body = await fs.readFile(filePath);
    const ext = path.extname(filePath);
    const type = ext === '.html' ? 'text/html; charset=utf-8' : ext === '.js' ? 'text/javascript; charset=utf-8' : 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch {
    sendJson(res, 404, { error: 'Not found' });
  }
}

async function handleScan(req, res) {
  const body = await readBody(req);
  let repoUrl;
  try {
    repoUrl = JSON.parse(body).repo_url;
  } catch {
    return sendJson(res, 400, { error: 'Request body must be JSON.' });
  }

  const parsed = parseGithubRepo(repoUrl);
  if (!parsed) return sendJson(res, 400, { error: 'Use a public GitHub repository URL like https://github.com/owner/repo.' });

  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'repoguard-'));
  const repoDir = path.join(tmp, 'repo');
  const gitUrl = `https://github.com/${parsed.owner}/${parsed.repo}.git`;

  try {
    await execFileAsync('git', ['clone', '--depth', '1', '--filter=blob:limit=1m', gitUrl, repoDir], { timeout: 60000 });
    const findings = await scanRepository(repoDir);
    const summary = buildSummary(findings, `${parsed.owner}/${parsed.repo}`);
    sendJson(res, 200, { summary, findings });
  } catch (err) {
    const message = err.code === 'ENOENT'
      ? 'Git is required to clone public repositories. Install Git, then try again.'
      : `Could not scan this repository. Make sure it is public and reachable. ${err.message || ''}`.trim();
    sendJson(res, 502, { error: message });
  } finally {
    fs.rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}

async function scanRepository(repoDir) {
  const files = [];
  await collectFiles(repoDir, files);

  const findings = [];
  for (const file of files) {
    const rel = path.relative(repoDir, file).split(path.sep).join('/');
    const stat = await fs.stat(file);
    if (stat.size > MAX_FILE_BYTES) continue;

    const text = await fs.readFile(file, 'utf8').catch(() => null);
    if (!text || isMostlyBinary(text)) continue;

    findings.push(...scanSecrets(text, rel));
    findings.push(...scanDependencies(text, rel));
  }

  return dedupeFindings(findings).slice(0, 80);
}

async function collectFiles(dir, out) {
  if (out.length >= MAX_FILES) return;
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (out.length >= MAX_FILES) break;
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'vendor' || entry.name === 'dist' || entry.name === 'build') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await collectFiles(full, out);
    else if (entry.isFile()) out.push(full);
  }
}

function scanSecrets(text, rel) {
  const findings = [];
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(text))) {
      const line = lineNumberAt(text, match.index);
      findings.push({
        severity: pattern.severity,
        category: 'secret',
        title: pattern.title,
        file: `${rel}:${line}`,
        explanation: 'A credential-like value was found in repository contents. Even if this is old or accidentally committed, exposed secrets should be treated as compromised.',
        fix: pattern.fix
      });
      if (findings.length >= 5) break;
    }
  }
  return findings;
}

function scanDependencies(text, rel) {
  if (rel.endsWith('package.json')) return scanPackageJson(text, rel);
  if (rel.endsWith('requirements.txt')) return scanRequirements(text, rel);
  return [];
}

function scanPackageJson(text, rel) {
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    return [];
  }
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  return Object.entries(deps).flatMap(([name, version]) => dependencyFindings('npm', name, version, rel));
}

function scanRequirements(text, rel) {
  return text.split(/\r?\n/).flatMap((line, index) => {
    const match = line.trim().match(/^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.-]+)/);
    if (!match) return [];
    return dependencyFindings('pip', match[1], match[2], `${rel}:${index + 1}`);
  });
}

function dependencyFindings(ecosystem, rawName, rawVersion, file) {
  const name = rawName.toLowerCase();
  const version = cleanVersion(rawVersion);
  if (!version) return [];

  return VULN_DB
    .filter(v => v.ecosystem === ecosystem && v.name === name && compareSemver(version, v.below) < 0)
    .map(v => ({
      severity: v.severity,
      category: 'dependency',
      title: v.title,
      file,
      explanation: `${rawName} is pinned at ${rawVersion}, which is below the safer baseline ${v.below}. This prototype uses a small built-in advisory set for hackathon demos; run a full audit tool before production use.`,
      fix: v.fix
    }));
}

function buildSummary(findings, repoName) {
  if (!findings.length) {
    return `Scan complete for ${repoName}. RepoGuard did not find obvious leaked secrets or dependency versions from its built-in advisory set. This is a static prototype scan, not a full security audit.`;
  }

  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const low = findings.filter(f => f.severity === 'low').length;
  const secrets = findings.filter(f => f.category === 'secret').length;
  const deps = findings.filter(f => f.category === 'dependency').length;
  const first = high ? 'Fix high-severity exposed credentials first.' : medium ? 'Review medium-severity findings first.' : 'Review the low-severity cleanup items.';
  return `Scan complete for ${repoName}. Found ${findings.length} issue${findings.length === 1 ? '' : 's'}: ${high} high, ${medium} medium, and ${low} low. ${secrets} secret-related finding${secrets === 1 ? '' : 's'} and ${deps} dependency finding${deps === 1 ? '' : 's'} were detected. ${first}`;
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.category}|${f.title}|${f.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
  });
}

function parseGithubRepo(raw) {
  try {
    const url = new URL(raw);
    const parts = url.pathname.split('/').filter(Boolean);
    if (url.protocol !== 'https:' || url.hostname !== 'github.com' || parts.length !== 2) return null;
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/, '');
    if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) return null;
    return { owner, repo };
  } catch {
    return null;
  }
}

function execFileAsync(command, args, options) {
  return new Promise((resolve, reject) => {
    execFile(command, args, options, (error, stdout, stderr) => {
      if (error) {
        error.message = stderr || error.message;
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error('Request body too large.'));
      }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    ...corsHeaders()
  });
  res.end(JSON.stringify(payload));
}

function sendEmpty(res, status) {
  res.writeHead(status, corsHeaders());
  res.end();
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}

function lineNumberAt(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function isMostlyBinary(text) {
  const sample = text.slice(0, 2048);
  let suspicious = 0;
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (code === 0 || (code < 7 && code !== 9 && code !== 10 && code !== 13)) suspicious++;
  }
  return suspicious > sample.length * 0.05;
}

function cleanVersion(version) {
  const match = String(version).match(/\d+(?:\.\d+){0,2}/);
  return match ? match[0] : null;
}

function compareSemver(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff) return diff;
  }
  return 0;
}

module.exports = {
  buildSummary,
  compareSemver,
  dependencyFindings,
  parseGithubRepo,
  requestHandler,
  scanDependencies,
  scanPackageJson,
  scanRepository,
  scanRequirements,
  scanSecrets,
  server
};
