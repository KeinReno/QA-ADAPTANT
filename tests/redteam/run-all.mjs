// run-all.mjs — прогнать все атаки Red Team волны 1 и собрать один сводный JSON.
// Запуск: node tests/redteam/run-all.mjs [--json]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { revision } from './_lib.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const scripts = fs.readdirSync(here).filter(name => /^rt-\d+.*\.mjs$/.test(name)).sort();
const results = [];
for (const name of scripts) {
  const started = Date.now();
  const run = spawnSync(process.execPath, [path.join(here, name)], { cwd: path.resolve(here, '..', '..'), encoding: 'utf8', windowsHide: true, timeout: 180_000 });
  const stdout = run.stdout || '';
  let parsed = null;
  try {
    const start = stdout.indexOf('{');
    parsed = start === -1 ? null : JSON.parse(stdout.slice(start));
  } catch { parsed = null; }
  results.push({
    script: name,
    exitCode: run.status,
    ms: Date.now() - started,
    id: parsed?.id || 'UNKNOWN',
    title: parsed?.title || '',
    verdict: parsed?.verdict || (run.status === 0 ? 'PASS' : run.status === 3 ? 'INCONCLUSIVE' : 'FAIL'),
    failedChecks: parsed ? parsed.checks.filter(check => !check.ok).map(check => check.name) : [],
    note: parsed ? (parsed.notes || []) : [String(run.stderr || '').slice(0, 400)]
  });
}
const failed = results.filter(result => result.verdict === 'FAIL');
const inconclusive = results.filter(result => result.verdict === 'INCONCLUSIVE');
const summary = {
  tool: 'REDTEAM-MATRIX',
  revision: revision(),
  total: results.length,
  pass: results.filter(result => result.verdict === 'PASS').length,
  fail: failed.length,
  inconclusive: inconclusive.length,
  verdict: failed.length ? 'FAIL' : inconclusive.length ? 'INCONCLUSIVE' : 'PASS',
  results
};
process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
process.exitCode = failed.length ? 1 : 0;
