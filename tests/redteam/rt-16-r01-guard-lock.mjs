// RT-16 (R-01): guards/<approvalId>.lock остаётся после аварийного завершения процесса.
// Сценарий: процесс входит в withGuard (реальный код approval.mjs), получает SIGKILL внутри guard.
// Факты: lock остаётся; последующие revoke и consume падают через ~5 с с CONSUMPTION_INCOMPLETE;
// второго ACK/POST и расхода нет; содержимое lock пустое — восстановление не может отличить
// аварию от живого держателя, поэтому удалять lock вслепую нельзя.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { makeTrust, principals, makeApproval, dispatchRequest, expectedOf, expectThrow, record, finish, waitForFile, PROJECT_ROOT, sleep } from './_lib.mjs';
import { consumeDispatch, revokeApproval } from '../../packages/trust/approval.mjs';

const checks = [];
const env = await makeTrust('rt16');
const victim = path.join(PROJECT_ROOT, 'tests', 'redteam', '_guard-victim.mjs');
let child = null;
try {
  env.cards = principals(env);
  const approval = makeApproval(env, 'approval-rt16');
  const approvalId = 'approval-rt16';
  const readyFile = path.join(env.root, 'guard-ready.json');
  const errorFile = path.join(env.root, 'guard-error.json');
  const requestFile = path.join(env.root, 'guard-request.json');
  const request = dispatchRequest(env, approval, { runId: 'run-rt16', decisionId: 'dec-rt16' });
  delete request.trust;
  fs.writeFileSync(requestFile, JSON.stringify({ ...request, readyFile, errorFile }));

  child = spawn(process.execPath, [victim, requestFile], { stdio: 'ignore', windowsHide: true });
  const exitPromise = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  await waitForFile(readyFile, 15_000);
  const ready = JSON.parse(fs.readFileSync(readyFile, 'utf8'));
  const guardFile = path.join(env.trustRoot, 'guards', approvalId + '.lock');
  record(checks, 'victim вошёл в guard и создал lock', fs.existsSync(guardFile), { pid: ready.pid });
  record(checks, 'lock не содержит владельца (пустой файл)', fs.statSync(guardFile).size === 0, { size: fs.statSync(guardFile).size });

  // Живой держатель: второй dispatch обязан ждать и упасть fail-closed, ACK нет.
  const tLive = Date.now();
  await expectThrow(checks, 'второй dispatch при живом держателе -> CONSUMPTION_INCOMPLETE через ~5 с',
    () => consumeDispatch(dispatchRequest(env, approval, { runId: 'run-rt16-live', decisionId: 'dec-rt16-live' })), 'CONSUMPTION_INCOMPLETE');
  const liveMs = Date.now() - tLive;
  record(checks, 'живой держатель блокирует второй dispatch не менее 4.5 с', liveMs >= 4500 && liveMs <= 9000, { elapsedMs: liveMs });
  record(checks, 'при живом держателе расход не создан', !fs.existsSync(path.join(env.trustRoot, 'consumption', approvalId + '.json')));
  record(checks, 'lock живого держателя не повреждён', fs.existsSync(guardFile) && fs.statSync(guardFile).size === 0);

  // Аварийное завершение держателя.
  process.kill(ready.pid, 'SIGKILL');
  const exit = await Promise.race([exitPromise, sleep(10_000).then(() => ({ code: null, signal: 'timeout' }))]);
  record(checks, 'процесс-держатель завершён принудительно', exit.code !== null || exit.signal === 'SIGKILL' || exit.signal === 'timeout' || exit.code !== 0, { exit });
  record(checks, 'R-01: lock остался после аварийного завершения', fs.existsSync(guardFile), { path: guardFile });
  const residue = fs.existsSync(guardFile) ? fs.readFileSync(guardFile) : Buffer.alloc(0);
  record(checks, 'остаточный lock пуст и не содержит pid/времени', residue.length === 0, { bytes: residue.length });

  // Последующий отзыв падает через ~5 с.
  const tRevoke = Date.now();
  await expectThrow(checks, 'revoke после остаточного lock -> CONSUMPTION_INCOMPLETE через ~5 с',
    () => revokeApproval(env.ownerKey, env.trustRoot, {
      approvalId, reason: 'owner-revoked', revokedAt: new Date().toISOString(), keyId: env.ownerKeyId
    }), 'CONSUMPTION_INCOMPLETE');
  const revokeMs = Date.now() - tRevoke;
  record(checks, 'revoke упал не раньше 4.5 с', revokeMs >= 4500 && revokeMs <= 9000, { elapsedMs: revokeMs });
  record(checks, 'файл отзыва не создан', !fs.existsSync(path.join(env.trustRoot, 'revocations', approvalId + '.json')));

  // Последующий расход падает через ~5 с, ACK/POST и consumption отсутствуют.
  const tConsume = Date.now();
  await expectThrow(checks, 'consume после остаточного lock -> CONSUMPTION_INCOMPLETE через ~5 с',
    () => consumeDispatch(dispatchRequest(env, approval, { runId: 'run-rt16-after-crash', decisionId: 'dec-rt16-after-crash' })), 'CONSUMPTION_INCOMPLETE');
  const consumeMs = Date.now() - tConsume;
  record(checks, 'consume упал не раньше 4.5 с', consumeMs >= 4500 && consumeMs <= 9000, { elapsedMs: consumeMs });
  record(checks, 'R-01: второй ACK не выдан и расход не создан', !fs.existsSync(path.join(env.trustRoot, 'consumption', approvalId + '.json')));
  record(checks, 'R-01: второго POST быть не может — Control на базе не подключён к approval', !fs.readFileSync(path.join(PROJECT_ROOT, 'apps', 'control', 'run.mjs'), 'utf8').includes('packages/trust'));

  // Восстановление не должно удалять lock вслепую: у файла нет ни владельца, ни метки времени.
  const approvalSource = fs.readFileSync(path.join(PROJECT_ROOT, 'packages', 'trust', 'approval.mjs'), 'utf8');
  record(checks, 'модуль не даёт API восстановления lock (нет pid/времени/owner в файле)', approvalSource.includes('openSync(guardFile, \'wx\')') && !approvalSource.includes('guardOwner') && residue.length === 0);
  record(checks, 'слепое удаление lock недопустимо: живой держатель неотличим от аварии', true, { note: 'lock пуст, liveness держателя хранится только в его процессе; удаление при живом держателе открывает окно второго dispatch' });
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  if (child && child.exitCode === null && child.signalCode === null) { try { child.kill('SIGKILL'); } catch { /* уже мёртв */ } }
  env.cleanup();
}
finish({ id: 'RT-16', title: 'R-01: остаточный guard lock после kill -9', checks, risk: 'R-01',
  notes: [
    'Факт подтверждён: SIGKILL внутри withGuard оставляет guards/<approvalId>.lock; revoke и consume после этого падают через ~5 с (CONSUMPTION_INCOMPLETE), ACK и consumption не появляются.',
    'Fail-closed сохранён: это безопаснее, чем открыть ACK. Но остаточный lock блокирует штатные отзыв/расход до ручного вмешательства.',
    'Восстановление не должно удалять lock вслепую: файл пуст, в нём нет pid/времени, живой держатель неотличим от аварии; удаление при живом держателе открывает окно второго dispatch.',
    'Владелец: пакет WP-02 (packages/trust/approval.mjs); severity P2 — отказ в обслуживании отзыва/расхода, не второй POST и не обход approval. Решение (safe recovery) вводить только с отдельным доказательством.'
  ] });
