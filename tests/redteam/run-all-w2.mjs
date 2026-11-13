// run-all-w2.mjs — прогнать все воспроизводимые скрипты волны 2 (tests/redteam/rt2-*.mjs) против
// переданной ветки (--target=..., по умолчанию integration) и собрать сводку.
// Запуск: node tests/redteam/run-all-w2.mjs [--target=<путь>]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import { createHash } from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const targetArg = process.argv.find(item => item.startsWith('--target=')) || null;
const liveDir = path.resolve(targetArg ? targetArg.slice('--target='.length) : 'C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\integration');
function liveState() {
  const head = spawnSync('git', ['-C', liveDir, 'rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true }).stdout.trim();
  const diff = spawnSync('git', ['-C', liveDir, 'diff'], { encoding: 'utf8', windowsHide: true }).stdout || '';
  const status = spawnSync('git', ['-C', liveDir, 'status', '--porcelain'], { encoding: 'utf8', windowsHide: true }).stdout || '';
  return { head: head || 'UNKNOWN', dirty: status.trim() !== '', diffHash: createHash('sha256').update(diff, 'utf8').digest('hex') };
}
function pin() {
  for (let attempt = 0; attempt < 3; attempt++) {
    const before = liveState();
    const key = createHash('sha256').update(before.head + '\n' + before.diffHash).digest('hex').slice(0, 16);
    const dir = path.join(os.tmpdir(), 'qa-rt-w2-pin-' + key);
    if (!fs.existsSync(path.join(dir, 'package.json'))) {
      try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* кэш */ }
      fs.cpSync(liveDir, dir, { recursive: true, force: true, filter: source => !['node_modules', '.git'].includes(path.basename(source)) });
      const liveModules = path.join(liveDir, 'node_modules');
      if (fs.existsSync(liveModules)) fs.symlinkSync(liveModules, path.join(dir, 'node_modules'), 'junction');
    }
    const after = liveState();
    if (before.head === after.head && before.diffHash === after.diffHash) return { dir, ...before };
  }
  return { dir: null, head: 'UNKNOWN', dirty: false, diffHash: '' };
}
const PIN = pin();
const target = PIN.dir;
const scripts = fs.readdirSync(here).filter(name => /^rt2-[a-z].*\.mjs$/.test(name)).sort();
const results = [];
for (const name of scripts) {
  const args = [path.join(here, name)];
  if (target) args.push('--target=' + target, '--pinned', '--sha=' + PIN.head);
  const started = Date.now();
  const child = spawnSync(process.execPath, args, { cwd: path.resolve(here, '..', '..'), encoding: 'utf8', windowsHide: true, timeout: 300000 });
  const stdout = child.stdout || '';
  let parsed = null;
  try { const start = stdout.indexOf('{'); parsed = start === -1 ? null : JSON.parse(stdout.slice(start)); } catch { parsed = null; }
  results.push({
    script: name,
    ms: Date.now() - started,
    exitCode: child.status,
    id: parsed?.id || name,
    verdict: parsed?.verdict || (child.status === 0 ? 'PASS' : child.status === 3 ? 'INCONCLUSIVE' : 'FAIL'),
    targetHead: parsed?.target?.head || PIN.head,
    failedChecks: parsed ? parsed.checks.filter(check => !check.ok).map(check => check.name) : [],
    stderr: parsed ? null : String(child.stderr || '').slice(0, 300)
  });
}
const summary = {
  tool: 'REDTEAM-W2-ALL',
  target: target || 'по умолчанию integration',
  targetHead: PIN.head,
  pinnedSnapshot: PIN.dir,
  targetDirty: PIN.dirty,
  total: results.length,
  pass: results.filter(result => result.verdict === 'PASS').length,
  fail: results.filter(result => result.verdict === 'FAIL').length,
  inconclusive: results.filter(result => result.verdict === 'INCONCLUSIVE').length,
  verdict: results.some(result => result.verdict === 'FAIL') ? 'FAIL' : results.some(result => result.verdict === 'INCONCLUSIVE') ? 'INCONCLUSIVE' : 'PASS',
  results
};
process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
process.exitCode = summary.verdict === 'FAIL' ? 1 : 0;