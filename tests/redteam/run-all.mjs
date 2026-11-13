// run-all.mjs — прогнать все атаки Red Team волны 1 и собрать один сводный JSON.
// Запуск: node tests/redteam/run-all.mjs [--json] [--artifacts=<каталог>]
// FAIL-CLOSED (F-WP08-04): exit 0 без распознанного JSON-вердикта РАВЕН FAIL, а не PASS.
// Полный JSON каждого скрипта (или сырой вывод при ошибке разбора) сохраняется в артефакт.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { revision } from './_lib.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const artifactsArg = process.argv.find(item => item.startsWith('--artifacts='));
const artifactsDir = path.resolve(artifactsArg ? artifactsArg.slice('--artifacts='.length)
  : path.join(os.tmpdir(), 'qa-redteam-artifacts-' + Date.now() + '-' + process.pid));
fs.mkdirSync(artifactsDir, { recursive: true });
const verdicts = new Set(['PASS', 'FAIL', 'INCONCLUSIVE']);
const scripts = fs.readdirSync(here).filter(name => /^rt-\d+.*\.mjs$/.test(name)).sort();
const results = [];
for (const name of scripts) {
  const started = Date.now();
  const run = spawnSync(process.execPath, [path.join(here, name)], { cwd: path.resolve(here, '..', '..'), encoding: 'utf8', windowsHide: true, timeout: 180_000 });
  const stdout = run.stdout || '';
  const stderr = run.stderr || '';
  let parsed = null;
  try {
    const start = stdout.indexOf('{');
    parsed = start === -1 ? null : JSON.parse(stdout.slice(start));
  } catch { parsed = null; }
  const parsedVerdict = parsed && verdicts.has(parsed.verdict) ? parsed.verdict : null;
  // Нераспознанный вывод или расхождение вердикта с exit code не может стать PASS.
  const consistent = parsedVerdict === null ? false
    : parsedVerdict === 'PASS' ? run.status === 0
      : parsedVerdict === 'INCONCLUSIVE' ? run.status === 3
        : run.status === 1;
  const verdict = parsedVerdict === null ? 'INVALID' : (consistent ? parsedVerdict : 'INVALID');
  const checks = parsed && Array.isArray(parsed.checks) ? parsed.checks : [];
  const artifactFile = path.join(artifactsDir, name.replace(/\.mjs$/, '.json'));
  fs.writeFileSync(artifactFile, JSON.stringify(
    parsedVerdict === null
      ? { script: name, exitCode: run.status, unparsed: true, stdout: stdout.slice(0, 200_000), stderr: stderr.slice(0, 20_000) }
      : parsed,
    null,
    2
  ) + '\n');
  results.push({
    script: name,
    exitCode: run.status,
    ms: Date.now() - started,
    id: parsed?.id || 'UNKNOWN',
    title: parsed?.title || '',
    verdict,
    artifact: artifactFile,
    failedChecks: checks.filter(check => !check.ok).map(check => check.name),
    note: parsedVerdict === null ? ['нераспознанный JSON-вердикт: результат считается INVALID'] : (parsed.notes || [])
  });
}
const failed = results.filter(result => result.verdict === 'FAIL' || result.verdict === 'INVALID');
const inconclusive = results.filter(result => result.verdict === 'INCONCLUSIVE');
const summary = {
  tool: 'REDTEAM-MATRIX',
  revision: revision(),
  artifactsDir,
  total: results.length,
  pass: results.filter(result => result.verdict === 'PASS').length,
  fail: results.filter(result => result.verdict === 'FAIL').length,
  invalid: results.filter(result => result.verdict === 'INVALID').length,
  inconclusive: inconclusive.length,
  verdict: failed.length ? 'FAIL' : inconclusive.length ? 'INCONCLUSIVE' : 'PASS',
  results
};
fs.writeFileSync(path.join(artifactsDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
process.exitCode = failed.length ? 1 : 0;
