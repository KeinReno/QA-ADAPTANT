// WP-08 independent audit (WP-06): L-02 (CANCEL до INTENT), L-04 (падение после POST),
// L-05 (повторный reconcile терминального), B-02 (повторный fixture), чужой SID.
// Запуск: node wp08-audit/tests/wp06-lifecycle.mjs ; exit 0 = PASS, 1 = FAIL.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { digest } from '../../packages/core/canonical.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import { localBundle } from '../../adapters/local/bundle.mjs';
import { verifyAnchorStatement, readTerminalChoice, readCandidate } from '../../packages/trust/anchor.mjs';
import { observeTrustedVerdict } from '../../packages/trust/anchor.mjs';
import {
  makeWorld, writeWorldRequest, waitFor, readEvents, sleep, trusted
} from './wp06-world.mjs';

const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (detail === null ? '' : ' :: ' + JSON.stringify(detail)));
  return Boolean(ok);
}
function runChild(requestFile, timeoutMs = 90000) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [new URL('./wp06-child.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), requestFile], { windowsHide: true });
    const out = [], err = [];
    child.stdout.on('data', chunk => out.push(chunk));
    child.stderr.on('data', chunk => err.push(chunk));
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, timeoutMs);
    child.on('error', error => { clearTimeout(timer); resolve({ code: -1, out: '', err: String(error.message) }); });
    child.on('exit', (code, signal) => { clearTimeout(timer); resolve({ code, signal, out: Buffer.concat(out).toString('utf8'), err: Buffer.concat(err).toString('utf8') }); });
  });
}
function readObject(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } }
function evidence(store, runDir) { return store.readEvidence(runDir); }
function kinds(items, kind) { return items.filter(item => item.envelope.kind === kind); }
function closeEnough(a, b) { return digest(a) === digest(b); }

const startedAt = new Date().toISOString();
const world = await makeWorld();
const store = new RunStore(world.root);
try {
  // ---------------------------------------------------------------- L-02 CANCEL до INTENT
  {
    const first = world.prepare({ runId: 'wp06-l02' });
    const approval = world.approvalFor(first);
    const runDir = world.runDir('wp06-l02');
    const pending = trusted.startTrusted(first.bundle, world.trustedOptions(approval, { fault: 'pauseBeforeIntent' }));
    // Browser запущен, форма заполнена, но INTENT ещё не отправлен (fault pauseBeforeIntent = 1500 мс).
    await waitFor(() => {
      const events = readEvents(runDir);
      return events.some(event => event.type === 'READY') &&
        events.some(event => event.type === 'STEP' && event.payload?.stepId === 'marker' && event.payload?.status === 'PASS');
    }, 30000);
    check('L-02: Browser жив и дошёл до формы, INTENT ещё не отправлен',
      !readEvents(runDir).some(event => event.type === 'INTENT_DURABLE'), { events: readEvents(runDir).map(e => e.type) });
    const cancellation = await trusted.cancelTrusted({
      root: world.root, trustRoot: world.trustRoot, runId: 'wp06-l02', subject: world.cards.operator
    });
    check('L-02: cancelTrusted вернул CANCEL_REQUESTED', cancellation?.state === 'CANCEL_REQUESTED', { state: cancellation?.state });
    const result = await pending;
    const items = evidence(store, runDir);
    check('L-02: итог BLOCKED/CANCELED', result?.verdict?.verdict === 'BLOCKED' && result?.verdict?.reasonCode === 'CANCELED',
      { verdict: result?.verdict?.verdict, reasonCode: result?.verdict?.reasonCode });
    check('L-02: POST = 0', world.stand.mutationCount === 0, { mutationCount: world.stand.mutationCount });
    check('L-02: нет mutation-intent/request', kinds(items, 'mutation-intent').length === 0 && kinds(items, 'request').length === 0,
      { intent: kinds(items, 'mutation-intent').length, request: kinds(items, 'request').length });
    check('L-02: расход approval не создан',
      !fs.existsSync(path.join(world.trustRoot, 'consumption', approval.approvalId + '.json')));
    check('L-02: approval остаётся закреплённым документом',
      fs.existsSync(path.join(world.trustRoot, 'approvals', approval.approvalId + '.json')));
    const observed = await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: 'wp06-l02' });
    checks.push({ name: 'L-02 (наблюдение): observeTrusted на BLOCKED-прогоне', ok: true,
      detail: { trusted: observed.trusted, passed: observed.passed, publication: observed.publication, reasonCode: observed.reasonCode } });
    console.log('INFO  L-02 observeTrusted: trusted=' + observed.trusted + ' passed=' + observed.passed +
      ' publication=' + observed.publication + ' reasonCode=' + observed.reasonCode);
  }

  // -------------------------------------------------- чужой SID не является аутентификацией (A-11)
  {
    const foreign = world.prepare({ runId: 'wp06-foreign-sid' });
    const approval = world.approvalFor(foreign);
    const { signTrustedDocument } = await import('../../packages/trust/identity.mjs');
    const foreignCard = signTrustedDocument(world.ownerKey, {
      schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator',
      roles: ['operator'], keyId: world.created.ownerKeyId, windowsSid: 'S-1-5-21-9999999999-1-1-1', status: 'active'
    });
    const result = await trusted.startTrusted(foreign.bundle, world.trustedOptions(approval, { subject: foreignCard }));
    check('A-11: подпись SID чужого пользователя не даёт доверенный старт',
      result?.verdict?.verdict === 'BLOCKED' && result?.verdict?.reasonCode === 'AUTH_UNAVAILABLE',
      { verdict: result?.verdict?.verdict, reasonCode: result?.verdict?.reasonCode });
    check('A-11: POST = 0', world.stand.mutationCount === 0, { mutationCount: world.stand.mutationCount });
    check('A-11: расход не создан', !fs.existsSync(path.join(world.trustRoot, 'consumption', approval.approvalId + '.json')));
  }

  // ---------------------------------------------------------------- L-04 падение после POST
  let crashRun = null;
  {
    const first = world.prepare({ runId: 'wp06-l04' });
    const approval = world.approvalFor(first);
    const request = writeWorldRequest(world, { bundle: first.bundle, approval, mode: 'crash-after-post', runId: first.runId });
    const child = await runChild(request.requestFile);
    check('L-04: процесс Control погиб после POST', child.code !== 0,
      { exitCode: child.code, signal: child.signal || null, stderr: child.err.slice(-400) });
    check('L-04: ровно один POST до аварии', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    const runDir = world.runDir(first.runId);
    const items = evidence(store, runDir);
    check('L-04: durable intent/request/response есть, verdict нет',
      kinds(items, 'mutation-intent').length === 1 && kinds(items, 'request').length === 1 &&
      kinds(items, 'response').length === 1 && kinds(items, 'verdict').length === 0,
      { kinds: items.map(item => item.envelope.kind) });
    const reconciled = await trusted.reconcileTrusted({
      root: world.root, trustRoot: world.trustRoot, approvalId: approval.approvalId, approval,
      issuer: world.cards.owner, subject: world.cards.operator, signerPipe: world.signer.pipePath,
      standPublicKey: world.stand.standPublicKey, runId: first.runId
    });
    check('L-04: reconcile восстановил терминальный INCONCLUSIVE', reconciled?.verdict?.verdict === 'INCONCLUSIVE',
      { verdict: reconciled?.verdict?.verdict, reasonCode: reconciled?.verdict?.reasonCode });
    check('L-04: второго POST нет', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    const after = evidence(store, runDir);
    check('L-04: request evidence ровно один', kinds(after, 'request').length === 1, { request: kinds(after, 'request').length });
    check('L-04: verdict ровно один', kinds(after, 'verdict').length === 1, { verdict: kinds(after, 'verdict').length });
    const choice = readTerminalChoice(runDir);
    check('L-04: выбор исхода зафиксирован без анкера', Boolean(choice) && choice.outcome === 'inconclusive-without-anchor',
      { outcome: choice?.outcome || null });
    const observed = await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: first.runId });
    check('L-04: observeTrusted не показывает PASS', observed.passed === false, { passed: observed.passed, trusted: observed.trusted, state: observed.publication });
    crashRun = { first, approval, runDir };
  }

  // ---------------------------------------------------------------- L-05 повторный reconcile терминального
  {
    const { first, approval, runDir } = crashRun;
    const beforeItems = evidence(store, runDir);
    const firstVerdict = readObject(path.join(runDir, 'evidence', beforeItems.at(-1).envelope.artifact.path)) || null;
    const second = await trusted.reconcileTrusted({
      root: world.root, trustRoot: world.trustRoot, approvalId: approval.approvalId, approval,
      issuer: world.cards.owner, subject: world.cards.operator, signerPipe: world.signer.pipePath,
      standPublicKey: world.stand.standPublicKey, runId: first.runId
    });
    const third = await trusted.reconcileTrusted({
      root: world.root, trustRoot: world.trustRoot, approvalId: approval.approvalId, approval,
      issuer: world.cards.owner, subject: world.cards.operator, signerPipe: world.signer.pipePath,
      standPublicKey: world.stand.standPublicKey, runId: first.runId
    });
    const afterItems = evidence(store, runDir);
    check('L-05: повторный reconcile возвращает тот же verdict',
      second?.verdict?.verdict === 'INCONCLUSIVE' && third?.verdict?.verdict === 'INCONCLUSIVE' &&
      closeEnough(second.verdict, third.verdict) && closeEnough(second.verdict, firstVerdict),
      { second: second?.verdict?.verdict, third: third?.verdict?.verdict });
    check('L-05: evidence не изменился', afterItems.length === beforeItems.length && JSON.stringify(afterItems.map(i => i.envelope.evidenceId)) === JSON.stringify(beforeItems.map(i => i.envelope.evidenceId)),
      { before: beforeItems.length, after: afterItems.length });
    check('L-05: verdict по-прежнему один', kinds(afterItems, 'verdict').length === 1, { verdict: kinds(afterItems, 'verdict').length });
    check('L-05: второго POST нет', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    const repeatedStart = await trusted.startTrusted(first.bundle, world.trustedOptions(approval));
    check('L-05: повторный startTrusted возвращает тот же терминальный verdict',
      repeatedStart?.verdict?.verdict === 'INCONCLUSIVE' && closeEnough(repeatedStart.verdict, firstVerdict),
      { verdict: repeatedStart?.verdict?.verdict });
    check('L-05: повторный startTrusted не добавил evidence', evidence(store, runDir).length === beforeItems.length);
    check('L-05: повторный startTrusted не сделал POST', world.stand.mutationCount === 1);
    let secondVerdictBlocked = false;
    try {
      store.appendEvidence(runDir, {
        runId: first.runId, manifestSha256: first.bundle.manifest ? digest(first.bundle.manifest) : 'a'.repeat(64),
        fixtureId: first.contract.fixtureId, stepId: first.bundle.scenario.nodes.at(-1).id,
        producer: 'verification', kind: 'verdict', artifact: firstVerdict
      });
    } catch (error) { secondVerdictBlocked = String(error.message || '').includes('INTEGRITY_ERROR'); }
    check('L-05: второй terminal verdict отвергнут журналом', secondVerdictBlocked);
  }

  // ---------------------------------------------------------------- B-02 повторный fixture
  {
    const { first, runDir: firstRunDir } = crashRun;
    const runId2 = 'wp06-b02-second';
    const sharedFixtureId = first.contract.fixtureId;
    const contract2 = { ...first.contract, runId: runId2 };
    world.stand.fixtureId = contract2.fixtureId;
    const bundle2 = localBundle(world.stand, { runId: runId2 });
    bundle2.fixture = contract2;
    bundle2.manifest.fixtureSha256 = digest(contract2);
    bundle2.manifest.budget.deadlineMs = 60000;
    const approval2 = world.approvalFor({ bundle: bundle2, contract: contract2 });
    const beforeFirst = evidence(store, firstRunDir).length;
    const result = await trusted.startTrusted(bundle2, world.trustedOptions(approval2));
    const runDir2 = world.runDir(runId2);
    const items2 = evidence(store, runDir2);
    check('B-02: второй старт с тем же fixtureId отвергнут привязкой fixture',
      result?.verdict?.verdict === 'BLOCKED' && result?.verdict?.reasonCode === 'CONTRACT_INVALID',
      { verdict: result?.verdict?.verdict, reasonCode: result?.verdict?.reasonCode });
    check('B-02: нового POST нет (суммарно 1)', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    check('B-02: второй approval не израсходован',
      !fs.existsSync(path.join(world.trustRoot, 'consumption', approval2.approvalId + '.json')));
    check('B-02: в новом прогоне нет request/mutation-intent',
      kinds(items2, 'request').length === 0 && kinds(items2, 'mutation-intent').length === 0,
      { kinds: items2.map(item => item.envelope.kind) });
    const bind = (() => {
      const dir = path.join(world.root, 'fixtures', digest({ environmentId: world.stand.environmentId, fixtureId: sharedFixtureId }));
      try { return JSON.parse(fs.readFileSync(path.join(dir, 'bind.json'), 'utf8')); } catch { return null; }
    })();
    check('B-02: привязка fixture осталась за первым прогоном', bind?.runId === first.runId, { bind });
    check('B-02: первый прогон не изменён', evidence(store, firstRunDir).length === beforeFirst);
  }
} catch (error) {
  check('скрипт завершился без аварии', false, { code: error.code || null, message: String(error.message || error), stack: String(error.stack || '').split('\n').slice(0, 6).join(' | ') });
} finally {
  await world.cleanup();
}
const failed = checks.filter(item => !item.ok);
const summary = { tool: 'WP08-AUDIT', part: 'WP-06', file: 'wp06-lifecycle.mjs', startedAt, finishedAt: new Date().toISOString(), total: checks.length, failed: failed.length, verdict: failed.length ? 'FAIL' : 'PASS', checks };
console.log('\n' + JSON.stringify(summary, null, 2));
process.exitCode = failed.length ? 1 : 0;
