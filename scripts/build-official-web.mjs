import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dest = join(root, 'official-web', 'dist');
const source = join(root, '.tmp', 'official-web-source');
const release = 'web-v2026.9.0';
const revision = '7ecf0d710cf39db40aa4db1c611417af2a0f44e0';
const patch = join(root, 'official-web', 'patches', 'organization-create.patch');
const clientsRepo = process.env.BITWARDEN_CLIENTS || '/home/steve/git/github.com/bitwarden/clients';

mkdirSync(dirname(source), { recursive: true });
if (!existsSync(join(source, '.git'))) {
  if (existsSync(join(clientsRepo, '.git'))) {
    execFileSync('git', ['-C', clientsRepo, 'worktree', 'add', '--detach', source, revision], { stdio: 'inherit' });
  } else {
    execFileSync('git', ['clone', '--depth', '1', '--branch', release, 'https://github.com/bitwarden/clients.git', source], { stdio: 'inherit' });
  }
}
const actualRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' }).trim();
if (actualRevision !== revision) throw new Error(`Official web source must be ${release} (${revision}), found ${actualRevision}`);

// Fail if an upstream change invalidates the patch; never silently ship the license-only form.
if (spawnSync('git', ['apply', '--reverse', '--check', patch], { cwd: source, stdio: 'ignore' }).status !== 0) {
  execFileSync('git', ['apply', '--check', patch], { cwd: source, stdio: 'inherit' });
  execFileSync('git', ['apply', patch], { cwd: source, stdio: 'inherit' });
}
if (!existsSync(join(source, 'node_modules'))) {
  execFileSync('npm', ['ci', '--no-audit', '--no-fund'], {
    cwd: source, stdio: 'inherit',
    env: { ...process.env, HUSKY: '0', ELECTRON_SKIP_BINARY_DOWNLOAD: '1', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1' },
  });
}

// The full self-hosted entry point includes /sm; the OSS entry point only has its landing page.
execFileSync('npm', ['run', 'build:bit:selfhost:prod', '--workspace=@bitwarden/web-vault'], {
  cwd: source, stdio: 'inherit',
  env: { ...process.env, NODE_OPTIONS: process.env.NODE_OPTIONS || '--max-old-space-size=8192' },
});
const buildDir = join(source, 'apps', 'web', 'build');
if (!existsSync(join(buildDir, 'index.html'))) throw new Error(`Official web build did not produce ${buildDir}/index.html`);
rmSync(dest, { recursive: true, force: true });
cpSync(buildDir, dest, { recursive: true, filter: path => !path.endsWith('.map') });
for (const license of ['LICENSE.txt', 'LICENSE_GPL.txt', 'LICENSE_BITWARDEN.txt']) {
  cpSync(join(source, license), join(dest, license));
}
writeFileSync(join(dest, '_redirects'), '/* /index.html 200\n');
writeFileSync(join(dest, '_headers'), `/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
/index.html
  Cache-Control: no-cache
`);
console.log(`Built NodeWarden official web from ${release} with name-based organization creation.`);
