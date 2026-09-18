'use strict';

const path = require('path');
const os = require('os');

function binaryName() {
  return os.platform() === 'win32' ? 'raxuiscli.exe' : 'raxuiscli';
}

// The native binary is unpacked into vendor/ by the postinstall script.
function binaryPath() {
  return path.join(__dirname, '..', 'vendor', binaryName());
}

module.exports = { binaryName, binaryPath };
