# RepoGuard

Hackathon prototype for scanning public GitHub repositories for leaked secrets, hard-coded passwords, API keys, and risky dependency versions.

## Run it

```bash
npm start
```

Then open:

```text
http://localhost:5001
```

Paste a public GitHub repository URL like:

```text
https://github.com/owner/repo
```

## What works

- Serves the existing RepoGuard frontend.
- Clones public GitHub repositories with a shallow, read-only `git clone`.
- Scans text files for common leaked credential patterns.
- Checks `package.json` and `requirements.txt` against a small built-in vulnerability baseline.
- Returns prioritized findings to the frontend.
- Includes a clearly labelled sample report for demos without network access.

## Prototype limits

This is a hackathon-grade static scanner, not a professional audit. Before production, replace the built-in dependency checks with tools such as `npm audit`, `pip-audit`, OSV, or GitHub Advisory Database, and replace the regex secret scanner with a production scanner such as Gitleaks.

## Test it

```bash
npm test
```

The test suite covers URL validation, common secret patterns, npm and Python dependency findings, malformed dependency files, clean summaries, finding summaries, ignored directories, frontend script parsing, and scan endpoint validation.

## Deploy it

For a fully working hosted demo, deploy the backend separately from the Vercel frontend. The backend clones public GitHub repositories, which is not a great fit for a static-only Vercel deployment.

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial RepoGuard prototype"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### 2. Deploy the backend

Use Render, Railway, Fly, or another Node host.

Recommended settings:

- Build command: leave blank or use `npm install`
- Start command: `npm start`
- Environment variable: `HOST=0.0.0.0`
- Environment variable: `PORT` should be supplied by the host if required

After deploy, copy the backend URL, for example:

```text
https://repoguard-api.onrender.com
```

### 3. Point the frontend at the hosted backend

In `index.html`, set:

```js
const HOSTED_API = "https://repoguard-api.onrender.com/scan";
```

Commit and push that change.

### 4. Deploy frontend on Vercel

Import the GitHub repo into Vercel.

Recommended settings:

- Framework preset: Other
- Build command: leave blank
- Output directory: `.`

Open the Vercel URL and run a scan.
