import { execFileSync } from 'node:child_process';
import { currentUserSid } from '../trust/windows-sid.mjs';

function run(exe, args) {
  return execFileSync(exe, args, { encoding: 'utf8', windowsHide: true, timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}

function currentAccountName() {
  const csv = run('whoami.exe', ['/user', '/fo', 'csv', '/nh']);
  const values = csv.match(/^"([^"]+)","(S-[^"]+)"$/);
  if (!values || values[2] !== currentUserSid()) throw Object.assign(new Error('Не удалось определить principal Planner store'), { code: 'ARTIFACT_ACCESS_UNVERIFIED' });
  return values[1].toLowerCase();
}

function accessEntries(output) {
  return output.split(/\r?\n/).filter(line => line.includes(':(')).map(line => {
    const aceStart = line.indexOf(':(');
    const principalStart = line.lastIndexOf(' ', aceStart);
    return line.slice(principalStart < 0 ? 0 : principalStart + 1).trim();
  });
}

export function restrictPlannerStoreToCurrentUser(root) {
  if (process.platform !== 'win32') throw Object.assign(new Error('Ограничение Planner store ACL поддерживается только на Windows'), { code: 'ARTIFACT_ACCESS_UNVERIFIED' });
  const sid = currentUserSid();
  run('icacls.exe', [root, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`]);
  if (!inspectPlannerStoreAcl(root)) throw Object.assign(new Error('Не удалось ограничить Planner store текущей identity'), { code: 'ARTIFACT_ACCESS_UNVERIFIED' });
  return true;
}

export function inspectPlannerStoreAcl(root) {
  if (process.platform !== 'win32') return false;
  try {
    const sid = currentUserSid();
    const account = currentAccountName();
    const output = run('icacls.exe', [root]);
    const lines = accessEntries(output);
    if (lines.length !== 1) return false;
    const ace = lines[0];
    const principal = ace.slice(0, ace.indexOf(':')).toLowerCase();
    const rights = ace.slice(ace.indexOf(':') + 1);
    if (principal !== account || !rights.includes('(F)') || rights.includes('(I)')) return false;
    return sid === currentUserSid();
  } catch { return false; }
}


export function createPlannerStoreAclGuard(root) {
  return () => inspectPlannerStoreAcl(root);
}
