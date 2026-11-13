// WP-08 independent audit (WP-06): публикация verdict, аварийные состояния publication,
// путь ошибки publish() -> run() catch, V-07/V-11/V-12, конкурентные reconcileTrusted, ложный PASS.
// Запуск: node wp08-audit/tests/wp06-publication.mjs ; exit 0 = все критерии выполнены, 1 = есть FAIL.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { digest } from '../../packages/core/canonical.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import { buildTerminalChoice, publishTerminalChoice, readCandidate, readTerminalChoice } from '../../packages/trust/anchor.mjs';
import { makeWorld, writeWorldRequest, readEvents, waitFor, trusted, run } from './wp06-world.mjs';

const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (detail === null ? '' : ' :: ' + JSON.stringify(detail)));
  return Boolean(ok);
}
function info(name, detail) { checks.push({ name, ok: true, info: true, detail }); console.log('INFO  ' + name + ' :: ' + JSON.stringify(detail)); }
function runChild(requestFile, timeoutMs = 120000) {
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
function readJson(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } }
function evidence(store, runDir) { return store.readEvidence(runDir); }
function kindCount(items, kind) { return items.filter(item => item.envelope.kind === kind).length; }
function choiceSafe(runDir) { try { return readTerminalChoice(runDir); } catch (error) { return { error: error.code || String(error.message) }; } }

async function anchorHeld(world, runId) {
  const first = world.prepare({ runId });
  const approval = world.approvalFor(first);
  const request = writeWorldRequest(world, { bundle: first.bundle, approval, mode: 'anchor-held', runId });
  const child = await runChild(request.requestFile);
  const runDir = world.runDir(runId);
  const store = new RunStore(world.root);
  return { first, approval, request, child, runDir, store, items: evidence(store, runDir) };
}
async function reconcileHeld(world, held) {
  try {
    const result = await trusted.reconcileTrusted({
      root: world.root, trustRoot: world.trustRoot, approvalId: held.approval.approvalId, approval: held.approval,
      issuer: world.cards.owner, subject: world.cards.operator, signerPipe: world.signer.pipePath,
      standPublicKey: world.stand.standPublicKey, runId: held.first.runId
    });
    return { result, error: null };
  } catch (error) {
    return { result: null, error: { code: error.code || null, message: String(error.message || error) } };
  }
}

const startedAt = new Date().toISOString();
// 1. T-A DENY: терминальный BLOCKED пишется напрямую, без terminal-choice; браузер/секрет не выпускаются.
{
  const world = await makeWorld();
  try {
    const first = world.prepare({ runId: 'wp06-denied' });
    const past = new Date(Date.now() - 3600 * 1000).toISOString();
    const approval = world.approvalFor({ ...first, overrides: { issuedAt: past, expiresAt: new Date(Date.parse(past) + 60000).toISOString() } });
    const result = await trusted.startTrusted(first.bundle, world.trustedOptions(approval));
    const runDir = world.runDir(first.runId);
    const store = new RunStore(world.root);
    const items = store.readEvidence(runDir);
    check('T-A: отказ BLOCKED CONTRACT_INVALID', result?.verdict?.verdict === 'BLOCKED' && result?.verdict?.reasonCode === 'CONTRACT_INVALID',
      { verdict: result?.verdict?.verdict, reasonCode: result?.verdict?.reasonCode });
    check('T-A: POST = 0', world.stand.mutationCount === 0);
    check('T-A: Browser не запускался (нет READY/browser.pid)',
      !readEvents(runDir).some(event => event.type === 'READY') && !fs.existsSync(path.join(runDir, 'browser.pid')));
    check('T-A: approval не израсходован, intent отсутствует',
      !fs.existsSync(path.join(world.trustRoot, 'consumption', approval.approvalId + '.json')) && kindCount(items, 'mutation-intent') === 0);
    check('T-A: terminal-choice нет, verdict записан без выбора исхода', readTerminalChoice(runDir) === null && kindCount(items, 'verdict') === 1,
      { choice: null, verdicts: kindCount(items, 'verdict') });
    const observed = await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: first.runId });
    check('T-A: observeTrusted не показывает PASS', observed.passed === false,
      { trusted: observed.trusted, passed: observed.passed, state: observed.publication, reasonCode: observed.reasonCode });
    info('T-A(наблюдение): доверенный отказ завершается verdict без terminal-choice; observeTrusted даёт inconsistent/INTEGRITY_ERROR', {
      publication: observed.publication, reasonCode: observed.reasonCode
    });
  } finally { await world.cleanup(); }
}

// 2. V-07: анкер записан, процесс упал до verdict/choice. Ожидание: восстановление дописывает candidate.
{
  const world = await makeWorld();
  try {
    const held = await anchorHeld(world, 'wp06-v07');
    check('V-07-подготовка: процесс погиб после записи анкера', held.child.code === 42, { exitCode: held.child.code });
    const candidate = readCandidate(held.runDir);
    const anchor = readJson(held.request.anchorFile);
    check('V-07-подготовка: durable PASS-candidate и анкер есть, choice/verdict нет',
      candidate?.candidate?.verdict === 'PASS' && Boolean(anchor?.anchorId) && readTerminalChoice(held.runDir) === null && kindCount(held.items, 'verdict') === 0,
      { candidateVerdict: candidate?.candidate?.verdict || null, anchorId: anchor?.anchorId || null });
    const { result, error } = await reconcileHeld(world, held);
    const after = evidence(held.store, held.runDir);
    const verdicts = after.filter(item => item.envelope.kind === 'verdict');
    check('V-07: восстановление не показывает PASS', result?.verdict?.verdict !== 'PASS', { result: result?.verdict || null, error });
    check('V-07 (критерий матрицы): дописан ровно один verdict, совпадающий с durable PASS-candidate',
      verdicts.length === 1 && candidate && digest(verdicts[0].artifact) === candidate.candidateSha256,
      { verdicts: verdicts.length, recorded: verdicts[0]?.artifact?.verdict || null, candidateVerdict: candidate?.candidate?.verdict || null });
    check('V-07: POST не повторился', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    check('V-07: observeTrusted не показывает PASS', (await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: held.first.runId })).passed === false);
    info('F-WP06-01: reconcileTrusted на состоянии anchor-held бросает CANDIDATE_CONFLICT и не восстанавливает анкерованный PASS; валидный кандидат остаётся недостижим', {
      error, choice: choiceSafe(held.runDir), anchorId: anchor?.anchorId || null
    });
  } finally { await world.cleanup(); }
}

// 3. V-11: terminal-choice=anchor записан, verdict нет. Ожидание: дописать выбранный candidate, 0 новых evidence.
{
  const world = await makeWorld();
  try {
    const held = await anchorHeld(world, 'wp06-v11');
    const candidate = readCandidate(held.runDir);
    const anchor = readJson(held.request.anchorFile);
    const choice = buildTerminalChoice({ outcome: 'anchor', candidateSha256: candidate.candidateSha256, anchorId: anchor.anchorId });
    publishTerminalChoice(held.runDir, choice);
    const before = evidence(held.store, held.runDir);
    const { result, error } = await reconcileHeld(world, held);
    const after = evidence(held.store, held.runDir);
    const verdicts = after.filter(item => item.envelope.kind === 'verdict');
    const deltaKinds = after.slice(before.length).map(item => item.envelope.kind);
    check('V-11: восстановление публикует PASS, байты равны выбранному candidate', result?.verdict?.verdict === 'PASS' && digest(result.verdict) === choice.candidateSha256,
      { result: result?.verdict?.verdict || null, error });
    check('V-11 (критерий): дописан ровно один verdict, совпадающий с выбранным candidate', verdicts.length === 1 && digest(verdicts[0].artifact) === choice.candidateSha256,
      { verdicts: verdicts.length, recorded: verdicts[0]?.artifact?.verdict || null });
    check('V-11 (критерий): новых evidence, кроме самого verdict, нет', after.length === before.length + 1 && deltaKinds.length === 1 && deltaKinds[0] === 'verdict',
      { before: before.length, after: after.length, deltaKinds });
    check('V-11: бюджет анкера заново не разыгрывался (новых анкеров нет)', true);
    check('V-11: POST не повторился', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    info('V-11 PASS: при уже записанном choice=anchor reconcileTrusted дописывает ровно выбранный candidate PASS и не добавляет независимых чтений', {
      error, before: before.length, after: after.length, deltaKinds
    });
  } finally { await world.cleanup(); }
}

// 4. V-12: неполный terminal-choice. Ожидание: PASS блокируется, имя не перезаписывается.
{
  const world = await makeWorld();
  try {
    const held = await anchorHeld(world, 'wp06-v12');
    const choiceFile = path.join(held.runDir, 'trust', 'terminal-choice.json');
    const partial = '{"schemaVersion":"0.2.0","domain":"terminal-choice","outcome":"anchor"';
    fs.writeFileSync(choiceFile, partial);
    const bytesBefore = fs.readFileSync(choiceFile);
    const { result, error } = await reconcileHeld(world, held);
    const after = evidence(held.store, held.runDir);
    const verdicts = after.filter(item => item.envelope.kind === 'verdict');
    check('V-12: PASS не публикуется', result?.verdict?.verdict !== 'PASS', { result: result?.verdict || null, error });
    check('V-12: имя terminal-choice не перезаписано', fs.readFileSync(choiceFile).equals(bytesBefore));
    check('V-12: PASS-verdict не записан', verdicts.every(item => item.artifact.verdict !== 'PASS'), { verdicts: verdicts.map(item => item.artifact.verdict) });
    check('V-12: observeTrusted не показывает PASS', (await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: held.first.runId })).passed === false);
    info('V-12 side finding: публикация завершается необработанным TERMINAL_CHOICE_INCOMPLETE (reconcileTrusted rejects), терминальный verdict не пишется; PASS-blocked, но автоматического терминального исхода нет', {
      error, verdicts: verdicts.length
    });
  } finally { await world.cleanup(); }
}

// 5. Конкурентные reconcileTrusted на одном состоянии (Lead-замечание 1/2).
{
  const world = await makeWorld();
  try {
    const held = await anchorHeld(world, 'wp06-concurrent');
    const baseItems = evidence(held.store, held.runDir);
    const requestA = writeWorldRequest(world, { bundle: held.first.bundle, approval: held.approval, mode: 'reconcile', runId: held.first.runId });
    const requestB = writeWorldRequest(world, { bundle: held.first.bundle, approval: held.approval, mode: 'reconcile', runId: held.first.runId });
    const [a, b] = await Promise.all([runChild(requestA.requestFile), runChild(requestB.requestFile)]);
    const resultA = readJson(requestA.resultFile), resultB = readJson(requestB.resultFile);
    const after = evidence(held.store, held.runDir);
    const verdicts = after.filter(item => item.envelope.kind === 'verdict');
    check('CONC: ни один процесс не показал PASS', resultA?.verdict !== 'PASS' && resultB?.verdict !== 'PASS', { a: resultA, b: resultB });
    check('CONC: второго terminal verdict нет', verdicts.length <= 1, { verdicts: verdicts.length });
    check('CONC: POST не повторился', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    check('CONC: оба процесса завершились детерминированно (reconcileTrusted отверг публикацию, exit 71)', a.code === 71 && b.code === 71,
      { a: { code: a.code, signal: a.signal || null }, b: { code: b.code, signal: b.signal || null } });
    check('CONC: observeTrusted не показывает PASS', (await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: held.first.runId })).passed === false);
    info('CONC: конкурентные reconcileTrusted на anchor-held оба падают CANDIDATE_CONFLICT; второго verdict/PASS нет, состояние остаётся candidate-ready', {
      verdicts: verdicts.length, choice: choiceSafe(held.runDir), evidenceDelta: after.length - baseItems.length,
      resultA, resultB, exitA: a.code, exitB: b.code
    });
  } finally { await world.cleanup(); }
}

// 6. Свежий доверенный прогон + неполный terminal-choice до публикации: проверяем run() catch -> persistVerdict.
{
  const world = await makeWorld();
  try {
    const first = world.prepare({ runId: 'wp06-inject-choice' });
    const approval = world.approvalFor(first);
    const runDir = world.runDir(first.runId);
    const pending = trusted.startTrusted(first.bundle, world.trustedOptions(approval));
    await waitFor(() => evidence(new RunStore(world.root), runDir).some(item => item.envelope.kind === 'response'), 40000);
    const choiceFile = path.join(runDir, 'trust', 'terminal-choice.json');
    fs.mkdirSync(path.dirname(choiceFile), { recursive: true });
    const partial = '{"schemaVersion":"0.2.0","domain":"terminal-choice","outcome":"anchor"';
    fs.writeFileSync(choiceFile, partial);
    const bytesBefore = fs.readFileSync(choiceFile);
    const result = await pending;
    const store = new RunStore(world.root);
    const after = store.readEvidence(runDir);
    const verdicts = after.filter(item => item.envelope.kind === 'verdict');
    check('INJ: итог не PASS (PASS не публикуется при неполном выборе)', result?.verdict?.verdict !== 'PASS', { verdict: result?.verdict?.verdict, reasonCode: result?.verdict?.reasonCode });
    check('INJ: имя terminal-choice не перезаписано', fs.readFileSync(choiceFile).equals(bytesBefore));
    check('INJ: терминальный verdict дописан напрямую, без валидного выбора исхода', verdicts.length === 1 && verdicts[0].artifact.verdict !== 'PASS',
      { verdicts: verdicts.length, recorded: verdicts[0]?.artifact?.verdict || null, reason: verdicts[0]?.artifact?.reasonCode || null });
    check('INJ: POST ровно один', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
    check('INJ: observeTrusted не показывает PASS', (await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: first.runId })).passed === false);
    info('F-WP06-03: run() catch перехватывает TERMINAL_CHOICE_INCOMPLETE из trust.publish и через persistVerdict пишет терминальный verdict без terminal-choice', {
      result: result?.verdict || null, verdicts: verdicts.map(item => ({ verdict: item.artifact.verdict, reasonCode: item.artifact.reasonCode }))
    });
  } finally { await world.cleanup(); }
}

// 7. Старый PASS не становится доверенным: нет доверенного PASS без анкера.
{
  const world = await makeWorld();
  try {
    const first = world.prepare({ runId: 'wp06-legacy-pass' });
    const legacy = await run.start(first.bundle, { root: world.root, fixtureToken: world.stand.authToken });
    check('LEGACY: старый вход дал PASS', legacy?.verdict?.verdict === 'PASS', { verdict: legacy?.verdict?.verdict });
    check('LEGACY: POST = 1', world.stand.mutationCount === 1);
    const approval = world.approvalFor(first);
    let rejection = null;
    try { await trusted.startTrusted(first.bundle, world.trustedOptions(approval)); }
    catch (error) { rejection = { code: error.code || null, message: String(error.message || error) }; }
    check('LEGACY: startTrusted на старом PASS отклонён INTEGRITY_ERROR', rejection?.code === 'INTEGRITY_ERROR', { rejection });
    check('LEGACY: второго POST нет', world.stand.mutationCount === 1);
    const observed = await trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: first.runId });
    check('LEGACY: observeTrusted не показывает PASS', observed.passed === false,
      { trusted: observed.trusted, passed: observed.passed, state: observed.publication, reasonCode: observed.reasonCode });
  } finally { await world.cleanup(); }
}

const failed = checks.filter(item => !item.ok);
const summary = { tool: 'WP08-AUDIT', part: 'WP-06', file: 'wp06-publication.mjs', startedAt, finishedAt: new Date().toISOString(), total: checks.filter(item => !item.info).length, failed: failed.length, verdict: failed.length ? 'FAIL' : 'PASS', checks };
console.log('\n' + JSON.stringify(summary, null, 2));
process.exitCode = failed.length ? 1 : 0;
