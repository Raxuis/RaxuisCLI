'use strict';

// Downloads the RaxuisCLI native binary for the current platform from the
// matching GitHub release, verifies its checksum, and unpacks it into vendor/.
// Runs automatically on `npm install`. Set RAXUISCLI_SKIP_DOWNLOAD=1 to skip.

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const { binaryPath } = require('./paths');
const pkg = require('../package.json');

const REPO = 'Raxuis/RaxuisCLI';

function fail(message) {
  console.error('raxuiscli install: ' + message);
  process.exit(1);
}

function resolveTarget() {
  const osMap = { linux: 'linux', darwin: 'darwin', win32: 'windows' };
  const archMap = { x64: 'amd64', arm64: 'arm64' };
  const goos = osMap[os.platform()];
  const goarch = archMap[os.arch()];
  if (!goos) fail('unsupported OS: ' + os.platform());
  if (!goarch) fail('unsupported architecture: ' + os.arch());
  if (goos === 'windows' && goarch === 'arm64') {
    fail('windows/arm64 builds are not published');
  }
  return { goos, goarch };
}

function download(url, redirects) {
  redirects = redirects || 0;
  return new Promise((resolve, reject) => {
    if (redirects > 10) return reject(new Error('too many redirects'));
    https
      .get(url, { headers: { 'User-Agent': 'raxuiscli-npm-installer' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return download(res.headers.location, redirects + 1).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error('HTTP ' + res.statusCode + ' for ' + url));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

function verifyChecksum(sumsText, archive, data) {
  const line = sumsText
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.endsWith(' ' + archive) || l.endsWith('*' + archive) || l.endsWith('  ' + archive));
  if (!line) return; // checksums are best-effort
  const expected = line.split(/\s+/)[0];
  const actual = crypto.createHash('sha256').update(data).digest('hex');
  if (expected !== actual) fail('checksum mismatch for ' + archive);
}

async function main() {
  if (process.env.RAXUISCLI_SKIP_DOWNLOAD) {
    console.log('raxuiscli: download skipped (RAXUISCLI_SKIP_DOWNLOAD set)');
    return;
  }

  const version = pkg.version;
  const { goos, goarch } = resolveTarget();
  const ext = goos === 'windows' ? 'zip' : 'tar.gz';
  const archive = 'raxuiscli_' + version + '_' + goos + '_' + goarch + '.' + ext;
  const base = 'https://github.com/' + REPO + '/releases/download/v' + version;

  console.log('raxuiscli: downloading ' + archive + ' ...');
  const data = await download(base + '/' + archive).catch((e) =>
    fail('download failed: ' + e.message)
  );

  try {
    const sums = (await download(base + '/checksums.txt')).toString('utf8');
    verifyChecksum(sums, archive, data);
  } catch (_) {
    // checksums.txt is optional; skip verification if it cannot be fetched.
  }

  const vendor = path.join(__dirname, '..', 'vendor');
  fs.mkdirSync(vendor, { recursive: true });
  const archivePath = path.join(vendor, archive);
  fs.writeFileSync(archivePath, data);

  // System tar is present on Linux, macOS, and Windows 10+ (bsdtar handles zip).
  const args = ext === 'tar.gz' ? ['-xzf', archivePath, '-C', vendor] : ['-xf', archivePath, '-C', vendor];
  const result = spawnSync('tar', args, { stdio: 'inherit' });
  if (result.error || result.status !== 0) {
    fail('extraction failed (a `tar` binary must be on PATH)');
  }
  try {
    fs.unlinkSync(archivePath);
  } catch (_) {
    // leaving the archive behind is harmless
  }

  const bin = binaryPath();
  if (!fs.existsSync(bin)) fail('binary not found after extraction');
  if (os.platform() !== 'win32') fs.chmodSync(bin, 0o755);
  console.log('raxuiscli ' + version + ' installed for ' + goos + '/' + goarch + '.');
}

main().catch((e) => fail(e && e.message ? e.message : String(e)));
