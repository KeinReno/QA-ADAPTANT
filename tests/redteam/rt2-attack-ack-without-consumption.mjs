// Атака WP-06: ACK без расхода approval (T-B). Остаточный guard lock блокирует расход;
// Control обязан отказать до ACK и не отправлять POST.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { caseMain, makeWorld, check, waitFile, sleep, checkNoMutation } from './_w2.mjs';

await caseMain({ id: 'WP06-ACK', title: 'ACK без расхода approval', async body({ modules, cleanup, target, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-ack' });
  const approval = world.approvalFor({ bundle, contract });
  const expected = modules.facts.expectedFromFrozen({ manifest: bundle.manifest, operation: bundle.operation, scenario: bundle.scenario, fixture: bundle.fixture, manifestSha256: modules.digest(bundle.manifest) });
  const readyFile = path.join(world.base, 'guard-ready.json');
  const errorFile = path.join(world.base, 'guard-error.json');
  const requestFile = path.join(world.base, 'guard-request.json');
  fs.writeFileSync(requestFile, JSON.stringify({
    targetDir: target.dir, trustRoot: world.trustRoot, approval, issuer: world.cards.owner,
    subject: world.cards.operator, windowsSid: world.sid, expected, runId: bundle.manifest.runId, decisionId: 'decision-ack', readyFile, errorFile
  }));
  const victimScript = path.join(path.dirname(fileURLToPath(import.meta.url)), '_w2-guard-victim.mjs');
  const child = spawn(process.execPath, [victimScript, requestFile], { stdio: 'ignore', windowsHide: true });
  const exitPromise = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  await waitFile(readyFile, 20000);
  const ready = JSON.parse(fs.readFileSync(readyFile, 'utf8'));
  process.kill(ready.pid, 'SIGKILL');
  await Promise.race([exitPromise, sleep(15000)]);
  const guardFile = path.join(world.trustRoot, 'guards', approval.approvalId + '.lock');
  check(checks, 'остаточный lock на месте', fs.existsSync(guardFile));
  const started = Date.now();
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  const elapsed = Date.now() - started;
  check(checks, 'T-B отказал: нет ACK и POST без расхода', result.verdict.verdict === 'BLOCKED', { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode });
  check(checks, 'ожидание отказа ~5 с (guard timeout)', elapsed >= 4500, { elapsedMs: elapsed });
  checkNoMutation(checks, world, 0);
  const consumption = path.join(world.trustRoot, 'consumption', approval.approvalId + '.json');
  check(checks, 'файл расхода не создан', !fs.existsSync(consumption));
  let items = [];
  try { items = new modules.store.RunStore(world.root).readEvidence(new modules.store.RunStore(world.root).runPath(bundle.manifest.runId)); } catch { items = []; }
  check(checks, 'mutation-intent не записан (ACK не выдан)', items.filter(item => item.envelope.kind === 'mutation-intent').length === 0, { kinds: items.map(item => item.envelope.kind) });
  return { checks };
} });
