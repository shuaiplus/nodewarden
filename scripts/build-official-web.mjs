import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dest = join(root, 'official-web', 'dist');
const clientsDir = process.env.BITWARDEN_CLIENTS || '/home/steve/git/github.com/bitwarden/clients';
const image = process.env.OFFICIAL_WEB_IMAGE || 'ghcr.io/bitwarden/web:latest';

function writeSpaFallback() {
  writeFileSync(join(dest, '_redirects'), '/* /index.html 200\n');
  writeFileSync(join(dest, '_headers'), `/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
`);
}

function extractFromDocker() {
  const inspect = spawnSync('docker', ['image', 'inspect', image], { encoding: 'utf8' });
  if (inspect.status !== 0) {
    execFileSync('docker', ['pull', image], { stdio: 'inherit' });
  }

  const container = `nw-official-web-${Date.now()}`;
  execFileSync('docker', ['create', '--name', container, image], { stdio: 'inherit' });
  try {
    const candidates = [
      '/app',
      '/usr/share/nginx/html',
      '/bitwarden/web',
      '/etc/bitwarden/web',
    ];
    for (const candidate of candidates) {
      const extracted = spawnSync('docker', ['cp', `${container}:${candidate}/.`, dest], { encoding: 'utf8' });
      if (extracted.status === 0 && existsSync(join(dest, 'index.html'))) {
        console.log(`Extracted official web from ${image}:${candidate}`);
        return true;
      }
    }
  } finally {
    spawnSync('docker', ['rm', container], { stdio: 'ignore' });
  }
  return false;
}

function buildFromClients() {
  const webPkg = join(clientsDir, 'apps', 'web', 'package.json');
  if (!existsSync(webPkg)) {
    throw new Error(`Bitwarden clients checkout not found at ${clientsDir}`);
  }
  if (!existsSync(join(clientsDir, 'node_modules'))) {
    execFileSync('npm', ['ci'], { cwd: clientsDir, stdio: 'inherit' });
  }
  execFileSync('npm', ['run', 'build:oss:selfhost:prod', '--workspace=@bitwarden/web-vault'], {
    cwd: clientsDir,
    stdio: 'inherit',
    env: { ...process.env, ENV: 'selfhosted', NODE_ENV: 'production' },
  });
  const buildDir = join(clientsDir, 'apps', 'web', 'build');
  if (!existsSync(join(buildDir, 'index.html'))) {
    throw new Error(`Official web build did not produce ${buildDir}/index.html`);
  }
  cpSync(buildDir, dest, { recursive: true });
  console.log(`Copied official web from ${buildDir}`);
}

mkdirSync(dest, { recursive: true });
rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });

const preferSource = String(process.env.OFFICIAL_WEB_SOURCE || '').trim() === '1';
if (!preferSource) {
  try {
    if (extractFromDocker()) {
      writeSpaFallback();
      process.exit(0);
    }
  } catch (error) {
    console.warn(`Docker extract failed (${error instanceof Error ? error.message : error}); falling back to source build`);
  }
}

buildFromClients();
writeSpaFallback();
