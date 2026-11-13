// R-01 на целевой ветке: остаточный guards/<approvalId>.lock после SIGKILL внутри withGuard.
// Ожидание: fail-closed; revoke/consume падают через ~5 с, второго ACK/расхода/отзыва нет.
// Восстановление нельзя делать удалением lock вслепую: файл пуст, владелец неизвестен.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { caseMain, makeWorld, check, expectCode, waitFile, sleep } from './_w2.mjs';

await caseMain({ id: 'R-01', title: 'Остаточный guard lock после аварийного завершения', risk: 'R-01', async body({ modules, cleanup, target, checks }) {
  const world = await makeWorld(modules, { withSigner: false });
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-r01' });
  const approval = world.approvalFor({ bundle, contract });
  const expected = modules.facts.expectedFromFrozen({
    manifest: bundle.manifest, operation: bundle.operation, scenario: bundle.scenario,
    fixture: bundle.fixture, manifestSha256: modules.digest(bundle.manifest)
  });
  const readyFile = path.join(world.base, 'guard-ready.json');
  const errorFile = path.join(world.base, 'guard-error.json');
  const requestFile = path.join(world.base, 'guard-request.json');
  fs.writeFileSync(requestFile, JSON.stringify({
    targetDir: target.dir, trustRoot: world.trustRoot, approval, issuer: world.cards.owner,
    subject: world.cards.operator, windowsSid: world.sid, expected,
    runId: bundle.manifest.runId, decisionId: 'decision-r01', readyFile, errorFile
  }));
  const victimScript = path.join(path.dirname(fileURLToPath(import.meta.url)), '_w2-guard-victim.mjs');
  const child = spawn(process.execPath, [victimScript, requestFile], { stdio: 'ignore', windowsHide: true });
  const exitPromise = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  await waitFile(readyFile, 20000);
  const ready = JSON.parse(fs.readFileSync(readyFile, 'utf8'));
  const guardFile = path.join(world.trustRoot, 'guards', approval.approvalId + '.lock');
  check(checks, 'lock создан реальным withGuard', fs.existsSync(guardFile), { pid: ready.pid });
  check(checks, 'lock пуст (нет pid/времени/владельца)', fs.statSync(guardFile).size === 0);
  process.kill(ready.pid, 'SIGKILL');
  await Promise.race([exitPromise, sleep(15000)]);
  check(checks, 'lock остался после SIGKILL', fs.existsSync(guardFile));
  const tRevoke = Date.now();
  await expectCode(checks, 'revoke падает через ~5 с (CONSUMPTION_INCOMPLETE)', () => modules.approval.revokeApproval(world.ownerKey, world.trustRoot, {
    approvalId: approval.approvalId, reason: 'owner-revoked', revokedAt: new Date().toISOString(), keyId: world.created.ownerKeyId
  }), 'CONSUMPTION_INCOMPLETE');
  const revokeMs = Date.now() - tRevoke;
  check(checks, 'пауза отказа не меньше 4.5 с', revokeMs >= 4500 && revokeMs <= 9000, { elapsedMs: revokeMs });
  check(checks, 'файл отзыва не создан', !fs.existsSync(path.join(world.trustRoot, 'revocations', approval.approvalId + '.json')));
  const tConsume = Date.now();
  await expectCode(checks, 'consume падает через ~5 с (CONSUMPTION_INCOMPLETE)', () => modules.approval.consumeDispatch({
    trust: world.trust, trustRoot: world.trustRoot, approval, issuer: world.cards.owner, subject: world.cards.operator,
    windowsSid: world.sid, expected, runId: bundle.manifest.runId, decisionId: 'decision-r01'
  }), 'CONSUMPTION_INCOMPLETE');
  const consumeMs = Date.now() - tConsume;
  check(checks, 'пауза отказа consume не меньше 4.5 с', consumeMs >= 4500 && consumeMs <= 9000, { elapsedMs: consumeMs });
  check(checks, 'второго ACK нет и расход не создан', !fs.existsSync(path.join(world.trustRoot, 'consumption', approval.approvalId + '.json')));
  const source = fs.readFileSync(path.join(target.dir, 'packages', 'trust', 'approval.mjs'), 'utf8');
  check(checks, 'модуль по-прежнему не содержит владельца lock (слепое удаление небезопасно)', source.includes("openSync(guardFile, 'wx')") && !/guardOwner/.test(source));
  return { checks };
} });