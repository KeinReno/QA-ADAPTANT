// WP-08 независимый аудит WP-05 (Anchor). Не меняет продуктивный код.
// Покрытие TODO матрицы V-05, V-10, V-12 и части V-06 + R-05/R-06/R-07.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { canonical, digest, scenarioApprovalHash } from '../../packages/core/canonical.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { localBundle, localFixtureContract } from '../../adapters/local/bundle.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../../packages/trust/identity.mjs';
import { consumeDispatch, signApproval } from '../../packages/trust/approval.mjs';
import {
  anchorWithinBudget, buildCandidate, buildTerminalChoice, loadAnchor, loadAnchorBudgetMs,
  observeTrustedVerdict, publishBudgetInconclusiveOutcome, publishCandidate, publishTerminalChoice,
  publishTerminalVerdict, readCandidate, readTerminalChoice, verifyAnchorStatement
} from '../../packages/trust/anchor.mjs';
import { connectAnchorSigner, startAnchorSigner } from '../../packages/trust/anchor-signer.mjs';
import { createTrustContext } from '../../apps/control/trusted.mjs';

const REPO = path.resolve('.');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'wp08-wp05-'));
const secretsDir = path.join(work, 'secrets');
const trustRoot = path.join(work, 'trust-root');
const created = await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const store = new RunStore(path.join(work, 'store'));
const signer = startAnchorSigner({ trustRoot, secretsDir });
await signer.ready;
const client = connectAnchorSigner(signer.pipePath);
after(async () => { await client.close(); await signer.close(); });

const finding = (id, text) => console.log('[FINDING] ' + id + ' ' + text);
const issuedAt = new Date(Date.now() - 60000).toISOString();
const expiresAt = new Date(Date.now() + 10 * 60000).toISOString();
const issuer = signTrustedDocument(ownerKey, {
  schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner', 'operator'],
  keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-owner', status: 'active'
});
const subject = signTrustedDocument(ownerKey, {
  schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'],
  keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-operator', status: 'active'
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let counter = 0;
const nextId = prefix => prefix + '-' + String(++counter).padStart(4, '0');

function makeRun(tag) {
  const runId = nextId('run-' + tag);
  const descriptor = { environmentId: 'local-stand', baseUrl: 'http://127.0.0.1:9/', fingerprint: 'fp-local', fixtureId: 'fixture-' + runId };
  const fixture = localFixtureContract(descriptor, runId);
  const bundle = localBundle({ ...descriptor, fixtureId: fixture.fixtureId }, { runId });
  bundle.fixture = fixture;
  bundle.manifest.fixtureSha256 = digest(fixture);
  const runDir = store.snapshot(bundle, null);
  return { runId, runDir, frozen: verifyFrozenBundle(store, runDir) };
}

function appendChain(run, { withRead = true } = {}) {
  const { runId, runDir, frozen } = run;
  const operation = frozen.operation;
  const fixture = frozen.fixture;
  const requestId = nextId('req');
  const intent = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: 'create',
    producer: 'control', kind: 'mutation-intent',
    artifact: { intentId: runId + ':create', stepId: 'create', operationId: operation.id, mutationName: operation.mutation.name, inputsSha256: digest(operation.inputs), fixtureId: fixture.fixtureId },
    parentEvidenceIds: []
  });
  const request = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: 'create',
    producer: 'browser', kind: 'request', requestId,
    artifact: { requestId, intentId: runId + ':create', operationId: operation.id, method: 'POST', path: '/records', fixtureId: fixture.fixtureId, fields: { ...operation.inputs, fixtureId: fixture.fixtureId } },
    parentEvidenceIds: [intent.evidenceId]
  });
  const entity = { kind: 'local-record', id: nextId('record') };
  const response = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: 'create',
    producer: 'browser', kind: 'response', requestId, entity,
    artifact: { requestId, intentId: runId + ':create', operationId: operation.id, fixtureId: fixture.fixtureId, status: 201, entity },
    parentEvidenceIds: [request.evidenceId]
  });
  let read = null;
  if (withRead) {
    read = store.appendEvidence(runDir, {
      runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: frozen.scenario.nodes.at(-1).id,
      producer: 'verification', kind: 'independent-read', requestId, entity, checkIds: ['title-saved'],
      artifact: { method: 'GET', path: '/records', fixtureId: fixture.fixtureId, entity, fields: { ...operation.inputs, fixtureId: fixture.fixtureId }, environmentFingerprint: frozen.manifest.environment.fingerprint, requestId, httpStatus: 200, observedAt: new Date().toISOString() },
      parentEvidenceIds: [response.evidenceId]
    });
  }
  return { intent, request, response, read };
}

function makeApproval(frozen, overrides = {}) {
  const approvalId = nextId('approval');
  const fields = {
    approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: frozen.operation.id, operationVersion: frozen.operation.version,
    scenarioContentSha256: scenarioApprovalHash(frozen.scenario),
    operationSha256: digest(frozen.operation),
    approvedInputsHash: digest(frozen.operation.inputs),
    fixtureId: frozen.fixture.fixtureId,
    targetEnvironmentId: frozen.manifest.environment.id,
    environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: frozen.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt, expiresAt, approvalNonce: randomBytes(32).toString('hex'), keyId: created.ownerKeyId,
    ...overrides
  };
  return signApproval(ownerKey, fields, trust, trustRoot);
}

function consume(approval, frozen, runId, overrides = {}) {
  return consumeDispatch({
    trust, trustRoot, approval, issuer, subject, windowsSid: 'S-1-5-21-operator', runId,
    decisionId: nextId('decision'),
    expected: {
      operation: frozen.operation, inputs: frozen.operation.inputs,
      effects: frozen.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
      scenarioContentSha256: scenarioApprovalHash(frozen.scenario),
      fixtureId: frozen.fixture.fixtureId,
      environmentId: frozen.manifest.environment.id,
      environmentGeneration: 1,
      ...overrides
    }
  });
}

function passCandidate(frozen, evidenceIds = [], override = {}) {
  return buildCandidate({
    frozen, verdict: 'PASS', reasonCode: 'NONE', message: 'Проверка пройдена',
    checks: frozen.operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds })),
    ...override
  });
}

function trustedEnv(tag) {
  const run = makeRun(tag);
  const chain = appendChain(run);
  const approval = makeApproval(run.frozen);
  consume(approval, run.frozen, run.runId);
  const candidate = passCandidate(run.frozen, [chain.read?.evidenceId || chain.response.evidenceId]);
  const published = publishCandidate(run.runDir, candidate);
  return { ...run, chain, approval, candidate, candidateSha256: published.candidateSha256 };
}

const verdictItems = runDir => store.readEvidence(runDir).filter(item => item.envelope.kind === 'verdict');
const anchorFiles = () => fs.existsSync(path.join(trustRoot, 'anchors')) ? fs.readdirSync(path.join(trustRoot, 'anchors')).filter(name => name.endsWith('.json')) : [];
const observe = env => observeTrustedVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });

async function waitFor(check, timeoutMs = 15000, stepMs = 10) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) { if (check()) return true; await sleep(stepMs); }
  return false;
}

// ---------------------------------------------------------------------------
// V-05: идемпотентная повторная публикация тех же байт анкера.
// ---------------------------------------------------------------------------
test('V-05: повторная подпись того же anchorId идемпотентна, другой anchorId на тот же runId — ANCHOR_CONFLICT', async () => {
  const env = trustedEnv('v05');
  const anchorId = nextId('anchor-v05');
  const first = await client.sign({ runDir: env.runDir, approvalId: env.approval.approvalId, anchorId });
  const file = path.join(trustRoot, 'anchors', anchorId + '.json');
  const bytes = fs.readFileSync(file);
  const second = await client.sign({ runDir: env.runDir, approvalId: env.approval.approvalId, anchorId });
  assert.deepEqual(second, first, 'повтор тех же смысловых полей вернул другое заявление');
  assert.deepEqual(fs.readFileSync(file), bytes, 'файл анкера перезаписан при идемпотентном повторе');
  assert.equal(anchorFiles().filter(name => name.startsWith(anchorId)).length, 1);
  await assert.rejects(
    client.sign({ runDir: env.runDir, approvalId: env.approval.approvalId, anchorId: nextId('anchor-v05-second') }),
    error => error.code === 'ANCHOR_CONFLICT'
  );
  // Повторная публикация того же terminal verdict не создаёт второй записи.
  publishTerminalChoice(env.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId }));
  const published = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  const again = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  assert.equal(published.created, true);
  assert.equal(again.created, false);
  assert.equal(verdictItems(env.runDir).length, 1);
  console.log('[V-05] PASS: один анкер, повтор идемпотентен, второй anchorId отклонён, verdict один');
});

// ---------------------------------------------------------------------------
// V-12: CREATE_NEW terminal-choice, падение до полного тела (0 байт и обрыв JSON).
// ---------------------------------------------------------------------------
test('V-12: нулевой/оборванный terminal-choice блокирует PASS, не заменяется, анкер не выпускается', async () => {
  for (const [label, body] of [['zero-byte', ''], ['torn-json', '{"schemaVersion":"0.2.0","domain":"terminal-choice"']]) {
    const env = trustedEnv('v12-' + label);
    const anchorId = nextId('anchor-v12');
    const statement = await client.sign({ runDir: env.runDir, approvalId: env.approval.approvalId, anchorId });
    const choiceFile = path.join(env.runDir, 'trust', 'terminal-choice.json');
    fs.writeFileSync(choiceFile, body, 'utf8');
    const kept = fs.readFileSync(choiceFile);
    assert.throws(() => readTerminalChoice(env.runDir), error => error.code === 'TERMINAL_CHOICE_INCOMPLETE');
    assert.throws(() => publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }), error => error.code === 'TERMINAL_CHOICE_INCOMPLETE');
    assert.throws(() => publishTerminalChoice(env.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId })), error => error.code === 'TERMINAL_CHOICE_INCOMPLETE');
    assert.deepEqual(fs.readFileSync(choiceFile), kept, 'имя terminal-choice заменено');
    assert.equal(verdictItems(env.runDir).length, 0, 'verdict записан поверх неполного choice');
    const observed = observe(env);
    assert.equal(observed.passed, false);
    assert.equal(observed.state, 'inconsistent');
    await assert.rejects(client.sign({ runDir: env.runDir, approvalId: env.approval.approvalId, anchorId: nextId('anchor-v12-after') }), error => error.code === 'ANCHOR_BINDING_REJECTED');
    assert.equal(verifyAnchorStatement(trust, statement).candidateSha256, env.candidateSha256);
    console.log('[V-12] PASS (' + label + '): PASS не публикуется, файл не заменяется, подписант отказывает');
  }
});

// ---------------------------------------------------------------------------
// V-10: подложный PASS-candidate. Часть 1 — связка не подтверждается.
// ---------------------------------------------------------------------------
test('V-10: подложный PASS без approval / с чужим consumption / с подменёнными входами — ANCHOR_BINDING_REJECTED, анкера нет', async () => {
  const before = anchorFiles().length;
  const noApproval = makeRun('v10-no-approval');
  const chainA = appendChain(noApproval);
  publishCandidate(noApproval.runDir, passCandidate(noApproval.frozen, [chainA.response.evidenceId]));
  const fakeA = nextId('anchor-v10-a');
  await assert.rejects(client.sign({ runDir: noApproval.runDir, approvalId: 'approval-absent', anchorId: fakeA }), error => error.code === 'ANCHOR_BINDING_REJECTED');
  assert.equal(fs.existsSync(path.join(trustRoot, 'anchors', fakeA + '.json')), false);

  const foreign = makeRun('v10-foreign-consumption');
  const chainB = appendChain(foreign);
  publishCandidate(foreign.runDir, passCandidate(foreign.frozen, [chainB.response.evidenceId]));
  const approvalB = makeApproval(foreign.frozen);
  consume(approvalB, foreign.frozen, nextId('run-foreign'));
  const fakeB = nextId('anchor-v10-b');
  await assert.rejects(client.sign({ runDir: foreign.runDir, approvalId: approvalB.approvalId, anchorId: fakeB }), error => error.code === 'ANCHOR_BINDING_REJECTED');
  assert.equal(fs.existsSync(path.join(trustRoot, 'anchors', fakeB + '.json')), false);

  const inputs = makeRun('v10-inputs');
  const chainC = appendChain(inputs);
  publishCandidate(inputs.runDir, passCandidate(inputs.frozen, [chainC.response.evidenceId]));
  const approvalC = makeApproval(inputs.frozen, { approvedInputsHash: digest({ forged: true }) });
  consume(approvalC, inputs.frozen, inputs.runId, { inputs: { forged: true } });
  const fakeC = nextId('anchor-v10-c');
  await assert.rejects(client.sign({ runDir: inputs.runDir, approvalId: approvalC.approvalId, anchorId: fakeC }), error => error.code === 'ANCHOR_BINDING_REJECTED');
  assert.equal(fs.existsSync(path.join(trustRoot, 'anchors', fakeC + '.json')), false);
  assert.equal(anchorFiles().length, before, 'подложные запросы создали файлы анкеров');
  console.log('[V-10] PASS: связка approval/consumption обязательна, хеш от вызывающего не принимается');
});

// ---------------------------------------------------------------------------
// V-10 / R-05 / R-06 / R-07: подложный PASS с ВАЛИДНОЙ связкой получает подпись,
// а observeTrustedVerdict показывает его как доверенный PASS без пересчёта покрытия.
// ---------------------------------------------------------------------------
test('R-07/V-10: подложный PASS-candidate при валидном approval/consumption подписывается и наблюдается как trusted PASS', async () => {
  const run = makeRun('r07-fake-pass');
  // Цепочка без independent-read: бизнес-проверок в журнале нет вообще.
  const chain = appendChain(run, { withRead: false });
  const approval = makeApproval(run.frozen);
  consume(approval, run.frozen, run.runId);
  // Атакующий того же SID с правами на runDir пишет candidate напрямую, минуя Verification Worker.
  const forged = passCandidate(run.frozen, [chain.response.evidenceId], { completedAt: new Date().toISOString() });
  const published = publishCandidate(run.runDir, forged);
  const anchorId = nextId('anchor-r07');
  const statement = await client.sign({ runDir: run.runDir, approvalId: approval.approvalId, anchorId });
  publishTerminalChoice(run.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: published.candidateSha256, anchorId }));
  const verdict = publishTerminalVerdict({ store, runDir: run.runDir, frozen: run.frozen, trust, trustRoot });
  assert.equal(verdict.verdict.verdict, 'PASS');
  assert.equal(verifyAnchorStatement(trust, statement).candidateSha256, published.candidateSha256);
  const reads = store.readEvidence(run.runDir).filter(item => item.envelope.kind === 'independent-read');
  assert.equal(reads.length, 0, 'в журнале появился independent-read');
  const observed = observe({ runDir: run.runDir, frozen: run.frozen });
  assert.equal(observed.trusted, true);
  assert.equal(observed.passed, true);
  assert.equal(observed.verdict.verdict, 'PASS');
  finding('F-WP05-01', 'подложный candidate с валидной связкой подписан (R-07 подтверждён); observeTrustedVerdict.passed=true при нуле independent-read — покрытие verdict не перепроверяется');
  console.log('[R-07] CONFIRMED: trusted PASS без единого independent-read; исходная формулировка WP-00 «процесс с правами на runDir не получает годный анкер для подложного PASS» неверна');
});

// ---------------------------------------------------------------------------
// V-07 (интеграционный путь Control publish): crash после записи анкера и до terminal-choice.
// Согласно матрице V-07 восстановление должно дописать выбранный candidate (PASS).
// ---------------------------------------------------------------------------
test('V-07-Control: crash после анкера до terminal-choice — восстановление даёт INCONCLUSIVE, а не PASS (расхождение с матрицей)', async () => {
  const run = makeRun('v07-crash');
  appendChain(run);
  const approval = makeApproval(run.frozen);
  consume(approval, run.frozen, run.runId);
  const candidate = passCandidate(run.frozen, [store.readEvidence(run.runDir).find(item => item.envelope.kind === 'independent-read').envelope.evidenceId]);
  assert.equal(readTerminalChoice(run.runDir), null);

  const readyFile = path.join(work, 'v07-ready-' + randomUUID() + '.json');
  const workerFile = path.join(work, 'v07-crash-worker.mjs');
  fs.writeFileSync(workerFile, String.raw`
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const [repo, runDir, trustRoot, approvalId, verdictJson, readyFile, pipePath] = process.argv.slice(2);
const imp = rel => import(pathToFileURL(path.join(repo, rel)).href);
const { createTrustContext } = await imp('apps/control/trusted.mjs');
const { RunStore } = await imp('packages/core/store.mjs');
const { verifyFrozenBundle } = await imp('packages/core/bundle.mjs');
const { loadTrustRoot } = await imp('packages/trust/identity.mjs');
const { connectAnchorSigner } = await imp('packages/trust/anchor-signer.mjs');
const store = new RunStore(path.dirname(path.dirname(runDir)));
const frozen = verifyFrozenBundle(store, runDir);
const client = connectAnchorSigner(pipePath);
const trust = loadTrustRoot(trustRoot);
const signer = { async sign(request) { const statement = await client.sign(request); fs.writeFileSync(readyFile, JSON.stringify(statement)); await new Promise(() => {}); } };
const context = createTrustContext({ trust, trustRoot, approvalId, issuer: { domain: 'principal' }, subject: { domain: 'principal' }, sid: 'S-1-5-21-operator', signer });
await context.publish({ store, runDir, frozen, verdict: JSON.parse(verdictJson) });
`);
  const child = spawn(process.execPath, [workerFile, REPO, run.runDir, trustRoot, approval.approvalId, JSON.stringify(candidate), readyFile, signer.pipePath], { stdio: 'ignore', windowsHide: true });
  const wrote = await waitFor(() => fs.existsSync(readyFile));
  assert.equal(wrote, true, 'дочерний процесс не дошёл до записи анкера');
  const lateStatement = JSON.parse(fs.readFileSync(readyFile, 'utf8'));
  child.kill('SIGKILL');
  await new Promise(resolve => child.once('exit', resolve));
  assert.equal(readTerminalChoice(run.runDir), null, 'choice записан до аварии — сценарий не воспроизведён');
  const anchorFile = path.join(trustRoot, 'anchors', lateStatement.anchorId + '.json');
  assert.equal(fs.existsSync(anchorFile), true, 'анкер не успел записаться до аварии');

  // Новый процесс: восстановление через тот же публикационный путь Control.
  const context = createTrustContext({ trust, trustRoot, approvalId: approval.approvalId, issuer, subject, sid: 'S-1-5-21-operator', signer: client });
  const recovered = await context.publish({ store, runDir: run.runDir, frozen: run.frozen, verdict: candidate });
  const observed = observe({ runDir: run.runDir, frozen: run.frozen });
  assert.equal(verdictItems(run.runDir).length, 1);
  assert.equal(observed.passed, false);
  console.log('[V-07-Control] expected(PASS по матрице V-07)=' + 'PASS' + ' actual=' + recovered.verdict.verdict + ' outcome=' + observed.outcome + ' anchorStatus=' + observed.anchorStatus + ' unlinked=' + observed.unlinkedAnchorId);
  assert.equal(recovered.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(observed.anchorStatus, 'ANCHOR_UNLINKED');
  finding('F-WP05-02', 'восстановление после crash между анкером и terminal-choice выбирает новый random anchorId, получает ANCHOR_CONFLICT и публикует INCONCLUSIVE; уже подписанный анкер PASS остаётся ANCHOR_UNLINKED. Матрица V-07 ожидает дописывание выбранного candidate');
});

// ---------------------------------------------------------------------------
// V-06 (частично): crash до анкера → INCONCLUSIVE; повторная публикация не превращает в PASS.
// ---------------------------------------------------------------------------
test('V-06: без анкера публикуется один INCONCLUSIVE, повторная публикация и наблюдение не дают PASS', async () => {
  const run = makeRun('v06');
  appendChain(run);
  const approval = makeApproval(run.frozen);
  consume(approval, run.frozen, run.runId);
  const candidate = passCandidate(run.frozen, [store.readEvidence(run.runDir).find(item => item.envelope.kind === 'independent-read').envelope.evidenceId]);
  const context = createTrustContext({ trust, trustRoot, approvalId: approval.approvalId, issuer, subject, sid: 'S-1-5-21-operator', signer: null });
  const first = await context.publish({ store, runDir: run.runDir, frozen: run.frozen, verdict: candidate });
  assert.equal(first.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(first.verdict.reasonCode, 'EVIDENCE_MISSING');
  assert.equal(verdictItems(run.runDir).length, 1);
  const second = await context.publish({ store, runDir: run.runDir, frozen: run.frozen, verdict: candidate });
  assert.equal(second.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(verdictItems(run.runDir).length, 1);
  const observed = observe({ runDir: run.runDir, frozen: run.frozen });
  assert.equal(observed.passed, false);
  assert.equal(observed.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(observed.trusted, true);
  console.log('[V-06] PARTIAL PASS (module/publication): один терминальный INCONCLUSIVE, PASS не появляется. Не покрыт реальный reconcileTrusted после POST');
});

// ---------------------------------------------------------------------------
// Поздний анкер: подписант успел записать анкер, бюджет истёк — ANCHOR_UNLINKED, не PASS.
// ---------------------------------------------------------------------------
test('Поздний анкер: контроль выбирает INCONCLUSIVE, годный анкер PASS остаётся ANCHOR_UNLINKED', async () => {
  const run = makeRun('late-anchor');
  appendChain(run);
  const approval = makeApproval(run.frozen);
  consume(approval, run.frozen, run.runId);
  const candidate = passCandidate(run.frozen, [store.readEvidence(run.runDir).find(item => item.envelope.kind === 'independent-read').envelope.evidenceId]);
  const profileFile = path.join(trustRoot, 'profile.json');
  fs.writeFileSync(profileFile, JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-profile', anchorBudgetMs: 30 }) + '\n');
  try {
    assert.equal(loadAnchorBudgetMs(trustRoot), 30);
    const delayed = { async sign(request) { const statement = await client.sign(request); await sleep(200); return statement; } };
    const context = createTrustContext({ trust, trustRoot, approvalId: approval.approvalId, issuer, subject, sid: 'S-1-5-21-operator', signer: delayed });
    const published = await context.publish({ store, runDir: run.runDir, frozen: run.frozen, verdict: candidate });
    assert.equal(published.verdict.verdict, 'INCONCLUSIVE');
    const observed = observe({ runDir: run.runDir, frozen: run.frozen });
    assert.equal(observed.passed, false);
    assert.equal(observed.anchorStatus, 'ANCHOR_UNLINKED');
    assert.notEqual(observed.unlinkedAnchorId, null);
    assert.equal(verdictItems(run.runDir).length, 1);
    console.log('[V-09/late] PASS: INCONCLUSIVE единственный, поздний анкер ' + observed.unlinkedAnchorId + ' не создаёт PASS/конфликт');
  } finally {
    fs.rmSync(profileFile, { force: true });
  }
});

// ---------------------------------------------------------------------------
// R-05: профиль бюджета не подписан; подмена меняет длительность, но не даёт PASS.
// ---------------------------------------------------------------------------
test('R-05: profile.json не подписан, anchorBudgetMs подменяем; вызывающий бюджет не переопределяет', async () => {
  const profileFile = path.join(trustRoot, 'profile.json');
  fs.writeFileSync(profileFile, JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-profile', anchorBudgetMs: 1 }) + '\n');
  try {
    const raw = JSON.parse(fs.readFileSync(profileFile, 'utf8'));
    assert.equal(Object.hasOwn(raw, 'signature'), false);
    assert.equal(loadAnchorBudgetMs(trustRoot), 1);
    const run = makeRun('r05');
    appendChain(run);
    const approval = makeApproval(run.frozen);
    consume(approval, run.frozen, run.runId);
    const slow = { async sign(request) { await sleep(80); return client.sign(request); } };
    const outcome = await anchorWithinBudget({ signer: slow, trustRoot, runDir: run.runDir, approvalId: approval.approvalId, anchorId: nextId('anchor-r05'), budgetMs: 60000 });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.code, 'ANCHOR_TIMEOUT');
    assert.equal(outcome.budgetMs, 1, 'вызывающий переопределил бюджет');
    finding('F-WP05-03', 'R-05 подтверждён: неподписанный trust-root/profile.json принимается, диапазон 1…60000; подмена даёт DoS/задержку, но не PASS (fail-closed)');
    console.log('[R-05] CONFIRMED: бюджет берётся из неподписанного профиля, параметр вызывающего игнорируется');
  } finally {
    fs.rmSync(profileFile, { force: true });
  }
});

// ---------------------------------------------------------------------------
// Поддельный анкер: (a) подпись owner, (b) анкер чужого прогона, (c) удаление анкера после PASS.
// ---------------------------------------------------------------------------
test('Подделка анкера: owner-подпись, чужой runId и удаление после PASS не дают доверенный PASS', async () => {
  // (a) owner подписывает тело анкера как owner-ключом.
  const envA = trustedEnv('forged-owner');
  const anchorIdA = nextId('anchor-forged');
  const valid = await client.sign({ runDir: envA.runDir, approvalId: envA.approval.approvalId, anchorId: anchorIdA });
  const { signature, signatureAlgorithm, ...bodyA } = valid;
  const forged = signTrustedDocument(ownerKey, { ...bodyA, keyId: created.ownerKeyId });
  const forgedPath = path.join(trustRoot, 'anchors', anchorIdA + '.json');
  const kept = fs.readFileSync(forgedPath);
  fs.writeFileSync(forgedPath, JSON.stringify(forged) + '\n');
  assert.throws(() => verifyAnchorStatement(trust, forged), error => error.code === 'ANCHOR_SIGNATURE_INVALID');
  publishTerminalChoice(envA.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: envA.candidateSha256, anchorId: anchorIdA }));
  assert.throws(() => publishTerminalVerdict({ store, runDir: envA.runDir, frozen: envA.frozen, trust, trustRoot }), error => error.code === 'ANCHOR_SIGNATURE_INVALID');
  assert.equal(verdictItems(envA.runDir).length, 0);
  assert.equal(observe(envA).passed, false);
  fs.writeFileSync(forgedPath, kept);

  // (b) анкер другого прогона подставлен в choice этого прогона.
  const envB = trustedEnv('anchor-cross');
  const other = trustedEnv('anchor-cross-other');
  const otherAnchor = nextId('anchor-other');
  await client.sign({ runDir: other.runDir, approvalId: other.approval.approvalId, anchorId: otherAnchor });
  publishTerminalChoice(envB.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: envB.candidateSha256, anchorId: otherAnchor }));
  assert.throws(() => publishTerminalVerdict({ store, runDir: envB.runDir, frozen: envB.frozen, trust, trustRoot }), error => ['ANCHOR_CONFLICT', 'ANCHOR_SIGNATURE_INVALID'].includes(error.code));
  assert.equal(observe(envB).passed, false);

  // (c) удаление анкера после PASS закрывает доверенный PASS.
  const envC = trustedEnv('anchor-delete');
  const anchorC = nextId('anchor-delete');
  await client.sign({ runDir: envC.runDir, approvalId: envC.approval.approvalId, anchorId: anchorC });
  publishTerminalChoice(envC.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: envC.candidateSha256, anchorId: anchorC }));
  publishTerminalVerdict({ store, runDir: envC.runDir, frozen: envC.frozen, trust, trustRoot });
  assert.equal(observe(envC).passed, true);
  fs.rmSync(path.join(trustRoot, 'anchors', anchorC + '.json'));
  assert.equal(observe(envC).passed, false);
  assert.equal(observe(envC).reasonCode, 'ANCHOR_MISSING');
  console.log('[V-01/V-02/V-08] PASS: owner-подпись, чужой runId и удаление анкера не дают доверенный PASS');
});

// ---------------------------------------------------------------------------
// Единственность terminal-choice: второй писатель с другим исходом не заменяет первый
// (наблюдение: конфликт исхода молча не сообщается).
// ---------------------------------------------------------------------------
test('terminal-choice единственность: второй различный выбор не заменяет первый (молчаливый возврат существующего)', async () => {
  const env = trustedEnv('choice-unique');
  const first = buildTerminalChoice({ outcome: 'inconclusive-without-anchor', candidateSha256: env.candidateSha256 });
  const created = publishTerminalChoice(env.runDir, first);
  assert.equal(created.created, true);
  const second = buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId: nextId('anchor-choice-second') });
  const replaced = publishTerminalChoice(env.runDir, second);
  assert.equal(replaced.created, false);
  assert.equal(replaced.choice.outcome, 'inconclusive-without-anchor');
  assert.deepEqual(readTerminalChoice(env.runDir), first);
  finding('F-WP05-04', 'P3: publishTerminalChoice при существующем файле молча возвращает первый выбор вместо явного конфликта; второй исход не заменяет первый, но расхождение не сигнализируется');
  console.log('[terminal-choice] PASS: файл единственный и не заменён');
});
