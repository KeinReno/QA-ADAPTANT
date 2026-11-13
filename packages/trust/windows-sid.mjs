import { execFileSync } from 'node:child_process';

const sidPattern = /^S-\d-\d+(?:-\d+)+$/;

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

export function isValidSid(value) {
  return typeof value === 'string' && sidPattern.test(value);
}

// SID читается у токена текущего процесса средствами Windows, а не из аргументов вызывающего.
export function currentUserSid() {
  if (process.platform !== 'win32') fail('CALLER_UNAUTHENTICATED', 'Доверенный вход 0.2 определён только для Windows');
  try {
    const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8', windowsHide: true, timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    const sid = String(out).trim();
    if (isValidSid(sid)) return sid;
  } catch { /* переход к резервному источнику того же токена */ }
  try {
    const out = execFileSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true, timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    const match = String(out).match(/"(S-\d-\d+(?:-\d+)+)"/);
    if (match && isValidSid(match[1])) return match[1];
  } catch { /* ниже fail-closed */ }
  fail('CALLER_UNAUTHENTICATED', 'SID вызывающего не получен из Windows-токена');
}

export function assertCallerSid(principal, sid) {
  if (!principal || !principal.windowsSid) fail('PRINCIPAL_UNKNOWN', 'У субъекта нет windowsSid');
  if (!isValidSid(sid) || principal.windowsSid !== sid) fail('CALLER_UNAUTHENTICATED', 'SID вызывающего не совпал с карточкой субъекта');
  return true;
}
