// Агрегатор негативного набора WP08-QWEN (F1). Запускает N01–N12 и P01 последовательно,
// собирает единый JSON. exit 0 = все проверки выполнены (исходы фиксируются, не оцениваются);
// exit 1 = есть инфраструктурные ошибки. Оценка ACCEPT/REJECT — за ревьюером по матрице.
// Запуск: node repro/neg/run-all.mjs > repro/logs/neg-<ревизия>.log
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gitSha } from './_world.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../..');
const scripts = [
  'n01-owner-pub-only.mjs', 'n02-anchor-pub-only.mjs', 'n03-ready-json-only.mjs',
  'n04-coordinated-all-three.mjs', 'n05-before-load.mjs', 'n06-between-load-and-start.mjs',
  'n07-during-recovery.mjs', 'n08-foreign-approval.mjs', 'n09-foreign-anchor.mjs',
  'n10-expected-key-config.mjs', 'n11-unauthorized-rotation.mjs', 'n12-corrupt-pinning.mjs',
  'p01-positive-control.mjs'
];
const { head, productTree, productSha } = gitSha();
const results = [];
for (const script of scripts) {
  process.stderr.write(`[neg] ${script} ...\n`);
  const run = spawnSync(process.execPath, [path.join(here, script)], { cwd: repoRoot, encoding: 'utf8', timeout: 300000 });
  let parsed = null;
  try { parsed = JSON.parse(run.stdout); } catch { /* сырой вывод сохраняем */ }
  if (parsed) results.push(parsed);
  else results.push({ attack: script, outcome: 'INFRA_ERROR', infraError: { code: 'PARSE', message: 'не разобран JSON вывода', exitCode: run.status, stderr: String(run.stderr || '').slice(-2000), stdout: String(run.stdout || '').slice(-2000) } });
  const last = results[results.length - 1];
  process.stderr.write(`[neg] ${script} → ${last.outcome}${last.falseTrustedPass ? ' (falseTrustedPass=true)' : ''}\n`);
}
const attacks = results.filter(r => r.attack !== 'P01');
const positive = results.find(r => r.attack === 'P01') || null;
const summary = {
  total: results.length,
  attacksReachedTrustedPass: attacks.filter(r => r.falseTrustedPass).map(r => r.attack),
  noTrustedPass: attacks.filter(r => !r.falseTrustedPass && r.outcome !== 'INFRA_ERROR').map(r => r.attack),
  infraErrors: results.filter(r => r.outcome === 'INFRA_ERROR').map(r => r.attack),
  positiveControl: positive ? { legitPass: positive.details?.legitPass === true, reconcileIdempotent: positive.details?.reconcileIdempotent === true, repeatedMutation: positive.mutations?.repeatedMutation === true } : null
};
console.log(JSON.stringify({ suite: 'WP08-QWEN-F1-NEG', head, productTree, productSha, summary, results }, null, 2));
process.exitCode = summary.infraErrors.length > 0 ? 1 : 0;