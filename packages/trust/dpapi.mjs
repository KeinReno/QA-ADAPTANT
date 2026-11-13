import { spawn } from 'node:child_process';

const script = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$line = [Console]::In.ReadToEnd().Trim()
$bytes = [Convert]::FromBase64String($line)
$entropy = [Text.Encoding]::UTF8.GetBytes('KAIDEN-QA-ADAPTANT-0.2')
$scope = [Security.Cryptography.DataProtectionScope]::CurrentUser
if ($env:QA_DPAPI_MODE -eq 'unprotect') {
  $result = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, $scope)
} else {
  $result = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, $scope)
}
[Console]::Out.Write([Convert]::ToBase64String($result))
`;

function dpapi(mode, bytes) {
  if (process.platform !== 'win32') throw Object.assign(new Error('DPAPI доступен только на Windows'), { code: 'UNSUPPORTED' });
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
      windowsHide: true,
      env: { ...process.env, QA_DPAPI_MODE: mode }
    });
    const out = [];
    const err = [];
    child.stdout.on('data', chunk => out.push(chunk));
    child.stderr.on('data', chunk => err.push(chunk));
    child.on('error', reject);
    child.on('close', code => {
      const failure = Buffer.concat(err).toString('utf8').trim();
      if (code !== 0) reject(Object.assign(new Error(failure || 'DPAPI недоступен'), { code: 'TRUST_STORE_UNAVAILABLE' }));
      else resolve(Buffer.from(Buffer.concat(out).toString('utf8').replace(/^\uFEFF/, '').trim(), 'base64'));
    });
    child.stdin.end(Buffer.from(bytes).toString('base64'));
  });
}

export function protect(bytes) {
  return dpapi('protect', bytes);
}

export function unprotect(bytes) {
  return dpapi('unprotect', bytes);
}
