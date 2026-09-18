#!/usr/bin/env node
'use strict';

// Thin launcher: forwards args and stdio to the native binary unpacked by the
// postinstall script, and mirrors its exit code.

const fs = require('fs');
const { spawnSync } = require('child_process');
const { binaryPath } = require('../scripts/paths');

const bin = binaryPath();

if (!fs.existsSync(bin)) {
  console.error('raxuiscli: native binary not found.');
  console.error('The download may have failed. Reinstall with: npm install -g raxuiscli');
  process.exit(1);
}

const result = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });

if (result.error) {
  console.error('raxuiscli: failed to launch binary:', result.error.message);
  process.exit(1);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
}
process.exit(result.status === null ? 1 : result.status);
