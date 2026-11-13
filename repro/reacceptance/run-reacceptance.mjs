// Агрегатор ре-приёмочных проверок R5–R8 (WP08-QWEN-F1, SHA исправления).
// Запускает сценарии последовательно, собирает единый JSON. exit 0 = все проверки выполнены
// (исходы фиксируются, не оцениваются); exit 1 = есть инфраструктурные ошибки.
// Запуск: node repro/reacceptance/run-reacceptance.mjs
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gitSha } from '../neg/_world.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../..');
const scripts = [
  'r5-dpapi-sid-pin-forge.mjs',
  'r6-pin-cache-mtime.mjs',
  'r7-config-new-root.mjs',
  'r8-reseal-sid.mjs'
];
const { head, productTree, productSha } = gitSha();
const results = [];
for (const script of scripts) {
  process.stderr.write(`[reaccept] ${script} ...\n`);
  const run = spawnSync(process.execPath, [path.join(here, script)], { cwd: repoRoot, encoding: 'utf8', timeout: 300000 });
  let parsed = null;
  try { parsed = JSON.parse(run.stdout); } catch { /* сырой вывод сохраняем */ }
  if (parsed) results.push(parsed);
  else results.push({ attack: script, outcome: 'INFRA_ERROR', infraError: { code: 'PARSE', message: 'не разобран JSON вывода', exitCode: run.status, stderr: String(run.stderr || '').slice(-2000), stdout: String(run.stdout || '').slice(-2000) } });
  const last = results[results.length - 1];
  process.stderr.write(`[reaccept] ${script} → ${last.outcome}${last.falseTrustedPass ? ' (falseTrustedPass=true)' : ''}\n`);
}
const summary = {
  total: results.length,
  reachedTrustedPass: results.filter(r => r.falseTrustedPass).map(r => r.attack),
  noTrustedPass: results.filter(r => !r.falseTrustedPass && r.outcome !== 'INFRA_ERROR').map(r => r.attack),
  infraErrors: results.filter(r => r.outcome === 'INFRA_ERROR').map(r => r.attack)
};
console.log(JSON.stringify({ suite: 'WP08-QWEN-F1-REACCEPTANCE', head, productTree, productSha, summary, results }, null, 2));
process.exitCode = summary.infraErrors.length > 0 ? 1 : 0;