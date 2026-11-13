import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { canonical, digest, scenarioApprovalHash } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { verifyFrozenBundle } from '../packages/core/bundle.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { consumeDispatch, signApproval } from '../packages/trust/approval.mjs';
import {
  DEFAULT_ANCHOR_BUDGET_MS, INCONCLUSIVE_MESSAGE, anchorWithinBudget, buildBudgetInconclusiveChoice, buildCandidate,
  buildInconclusiveCandidate, buildTerminalChoice, evidenceChainHead, loadAnchor, loadAnchorBudgetMs,
  observeTrustedVerdict, publicationState, publishBudgetInconclusiveOutcome, publishCandidate, publishCandidateBody,
  publishTerminalChoice, publishTerminalVerdict, readCandidate, readCandidateBody, readTerminalChoice, verifyAnchorStatement
} from '../packages/trust/anchor.mjs';
import { connectAnchorSigner, spawnAnchorSigner, startAnchorSigner } from '../packages/trust/anchor-signer.mjs';
import { verifyWithTrustedWorker } from '../apps/control/trusted.mjs';

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-anchor-'));
const secretsDir = path.join(work, 'secrets');
const trustRoot = path.join(work, 'trust-root');
const created = await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const store = new RunStore(path.join(work, 'store'));
// Реальный локальный стенд R-B: ответы /records подписаны ключом стенда, доверенный
// Worker принимает только валидную подпись. Запись среды закрепляется в trust root.
const stand = await serveLocalFixture({ generation: 1 });
const environmentId = stand.environmentId;
const fingerprint = stand.fingerprint;
const standBaseUrl = stand.baseUrl;
await commitEnvironmentRecord(trust, trustRoot, signEnvironmentRecord(ownerKey, {
  environmentId, generation: stand.generation, kind: 'local-stand', status: 'active',
  origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: 'local:fixture-token'
}));
// Подписант — дочерний процесс Control (тестовый harness) с приватным fork IPC.
const signer = spawnAnchorSigner({ trustRoot, anchorKeyPath: path.join(secretsDir, 'anchor.key') });
const client = signer;
const openWorkers = [];
after(async () => {
  for (const worker of openWorkers) { try { await worker.close(); } catch { /* уже закрыт */ } }
  await signer.close();
  await stand.close();
  fs.rmSync(work, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
});

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
const candidateKeys = [
  'checks', 'completedAt', 'integrityVerified', 'manifestSha256', 'message', 'ownershipVerified',
  'reasonCode', 'runId', 'schemaVersion', 'verdict'
];
let counter = 0;
const nextId = prefix => prefix + '-' + String(++counter).padStart(4, '0');

function makeRun(tag) {
  const runId = nextId('run-' + tag);
  const descriptor = { environmentId, baseUrl: standBaseUrl, fingerprint, fixtureId: 'fixture-' + runId };
  const fixture = localFixtureContract(descriptor, runId);
  const bundle = localBundle({ ...descriptor, fixtureId: fixture.fixtureId }, { runId });
  bundle.fixture = fixture;
  bundle.manifest.fixtureSha256 = digest(fixture);
  const runDir = store.snapshot(bundle, null);
  const frozen = verifyFrozenBundle(store, runDir);
  return { runId, runDir, frozen, bundle, fixture };
}

async function appendChain(run) {
  const { runId, runDir, frozen } = run;
  const operation = frozen.operation;
  const fixture = frozen.fixture;
  const mutationStep = 'create';
  const verifyStep = frozen.scenario.nodes.at(-1).id;
  const requestId = nextId('req');
  // Реальная мутация на стенде: независимое чтение Worker должно подтвердить фактические поля.
  const response = await fetch(new URL('/records', stand.baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + stand.authToken },
    body: JSON.stringify({ ...operation.inputs, fixtureId: fixture.fixtureId })
  });
  if (response.status !== 201) throw new Error('POST на локальный стенд не удался: ' + response.status);
  const posted = await response.json();
  const intent = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep,
    producer: 'control', kind: 'mutation-intent',
    artifact: { intentId: runId + ':' + mutationStep, stepId: mutationStep, operationId: operation.id, mutationName: operation.mutation.name, inputsSha256: digest(operation.inputs), fixtureId: fixture.fixtureId },
    parentEvidenceIds: []
  });
  const request = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep,
    producer: 'browser', kind: 'request', requestId,
    artifact: { requestId, intentId: runId + ':' + mutationStep, operationId: operation.id, method: 'POST', path: '/records', fixtureId: fixture.fixtureId, fields: { ...operation.inputs, fixtureId: fixture.fixtureId } },
    parentEvidenceIds: [intent.evidenceId]
  });
  const entity = { kind: operation.entityKind, id: posted.id };
  const responseEvidence = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep,
    producer: 'browser', kind: 'response', requestId, entity,
    artifact: { requestId, intentId: runId + ':' + mutationStep, operationId: operation.id, fixtureId: fixture.fixtureId, status: 201, entity },
    parentEvidenceIds: [request.evidenceId]
  });
  const read = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: verifyStep,
    producer: 'verification', kind: 'independent-read', requestId, entity, checkIds: operation.effects.map(effect => effect.id),
    artifact: { method: 'GET', path: '/records', fixtureId: fixture.fixtureId, entity, fields: { ...operation.inputs, fixtureId: fixture.fixtureId }, environmentFingerprint: frozen.manifest.environment.fingerprint, requestId, httpStatus: 200, observedAt: new Date().toISOString() },
    parentEvidenceIds: [responseEvidence.evidenceId]
  });
  return { intent, request, response: responseEvidence, read };
}

function unknownChecks(frozen) {
  return frozen.operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] }));
}

function passCandidate(frozen, readId) {
  return buildCandidate({
    frozen, verdict: 'PASS', reasonCode: 'NONE', message: 'Проверка пройдена',
    checks: frozen.operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds: [readId] }))
  });
}

function businessCandidate(frozen, readId, verdict, reasonCode) {
  const status = verdict === 'FAIL' ? 'VIOLATED' : 'UNKNOWN';
  const checks = frozen.operation.effects.map(effect => ({ id: effect.id, status, evidenceIds: status === 'UNKNOWN' ? [] : [readId] }));
  return buildCandidate({ frozen, verdict, reasonCode, message: 'Бизнес-результат ' + verdict, checks });
}

function makeApproval(frozen, overrides = {}) {
  const approvalId = nextId('approval');
  const fields = {
    approvalId,
    issuerPrincipalId: 'local-owner',
    subjectPrincipalId: 'local-operator',
    operationId: frozen.operation.id,
    operationVersion: frozen.operation.version,
    scenarioContentSha256: scenarioApprovalHash(frozen.scenario),
    operationSha256: digest(frozen.operation),
    approvedInputsHash: digest(frozen.operation.inputs),
    fixtureId: frozen.fixture.fixtureId,
    targetEnvironmentId: frozen.manifest.environment.id,
    environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: frozen.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt,
    expiresAt,
    approvalNonce: randomBytes(32).toString('hex'),
    keyId: created.ownerKeyId,
    ...overrides
  };
  const approval = signApproval(ownerKey, fields, trust, trustRoot);
  return { approvalId, approval };
}

function consume(approval, frozen, runId, expectedOverrides = {}) {
  return consumeDispatch({
    trust, trustRoot, approval, issuer, subject, windowsSid: 'S-1-5-21-operator', runId,
    decisionId: nextId('decision'),
    expected: {
      operation: frozen.operation,
      inputs: frozen.operation.inputs,
      effects: frozen.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
      scenarioContentSha256: scenarioApprovalHash(frozen.scenario),
      fixtureId: frozen.fixture.fixtureId,
      environmentId: frozen.manifest.environment.id,
      environmentGeneration: 1,
      ...expectedOverrides
    }
  });
}

async function trustedRun(tag) {
  const run = makeRun(tag);
  const chain = await appendChain(run);
  const { approvalId, approval } = makeApproval(run.frozen);
  consume(approval, run.frozen, run.runId);
  // Кандидат PASS и аттестацию выдаёт только доверенный Verification Worker.
  const worker = await verifyWithTrustedWorker({ runDir: run.runDir, frozen: run.frozen, trustRoot, approvalId, fixtureToken: stand.authToken, standPublicKey: stand.standPublicKey });
  openWorkers.push(worker);
  const candidate = worker.payload.verdict;
  const published = publishCandidate(run.runDir, candidate);
  return { ...run, chain, candidate, candidateSha256: published.candidateSha256, approvalId, approval, anchorIds: [], worker };
}

function anchorIdFor(env, suffix) {
  const id = nextId('anchor-' + suffix);
  env.anchorIds.push(id);
  return id;
}

async function signFor(env, suffix) {
  const anchorId = anchorIdFor(env, suffix);
  await client.registerVerificationKey(env.runId, env.worker.verificationPublicKey, env.worker.verificationPid, env.worker.sessionNonce);
  const statement = await client.sign({ runDir: env.runDir, approvalId: env.approvalId, anchorId, attestation: env.worker.payload.attestation });
  return { anchorId, statement };
}

function publishAnchorChoice(env, anchorId) {
  return publishTerminalChoice(env.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId }));
}

function observe(env) {
  return observeTrustedVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
}

function stateOf(env) {
  return publicationState({ store, runDir: env.runDir, trust, trustRoot });
}

function verdictItems(runDir) {
  return store.readEvidence(runDir).filter(item => item.envelope.kind === 'verdict');
}

function anchorFile(anchorId) {
  return path.join(trustRoot, 'anchors', anchorId + '.json');
}

test('candidate — ровно объект VerdictPolicy 0.1, durable через CREATE_NEW и body под хешем', async () => {
  const env = await trustedRun('candidate');
  assert.deepEqual(Object.keys(env.candidate).sort(), candidateKeys.slice().sort());
  assert.equal(Object.hasOwn(env.candidate, 'anchorId'), false);
  assert.equal(Object.hasOwn(env.candidate, 'approvalId'), false);
  assert.equal(env.candidateSha256, digest(env.candidate));
  const candidateFile = path.join(env.runDir, 'trust', 'candidate.json');
  const raw = fs.readFileSync(candidateFile);
  assert.equal(raw.toString('utf8'), canonical(env.candidate) + '\n');
  const body = readCandidateBody(env.runDir, env.candidateSha256);
  assert.deepEqual(body.candidate, env.candidate);
  assert.equal(fs.readFileSync(path.join(env.runDir, 'trust', 'candidates', env.candidateSha256 + '.json')).toString('utf8'), raw.toString('utf8'));
  const repeat = publishCandidate(env.runDir, env.candidate);
  assert.equal(repeat.created, false);
  assert.equal(repeat.candidateSha256, env.candidateSha256);
  assert.deepEqual(fs.readFileSync(candidateFile), raw);
  const replacement = businessCandidate(env.frozen, env.chain.read.evidenceId, 'FAIL', 'BUSINESS_INVARIANT_VIOLATED');
  assert.throws(() => publishCandidate(env.runDir, replacement), error => error.code === 'CANDIDATE_CONFLICT');
  assert.deepEqual(fs.readFileSync(candidateFile), raw);
  const other = makeRun('candidate-foreign');
  assert.throws(() => publishCandidate(other.runDir, env.candidate), error => error.code === 'CONTRACT_INVALID');
  assert.throws(() => buildCandidate({ frozen: env.frozen, verdict: 'PASS', reasonCode: 'NONE', message: 'x', checks: [], anchorId: 'a' }), error => error.code === 'CONTRACT_INVALID');
  assert.equal(readCandidate(other.runDir), null);
  assert.equal(readTerminalChoice(env.runDir), null);
});

test('collecting → candidate-ready: без выбора исхода verdict не пишется', async () => {
  const run = makeRun('collecting');
  assert.equal(stateOf({ runDir: run.runDir, frozen: run.frozen }), 'collecting');
  const chain = await appendChain(run);
  const candidate = passCandidate(run.frozen, chain.read.evidenceId);
  publishCandidate(run.runDir, candidate);
  const env = { ...run, candidateSha256: digest(candidate) };
  assert.equal(stateOf(env), 'candidate-ready');
  assert.throws(() => publishTerminalVerdict({ store, runDir: run.runDir, frozen: run.frozen, trust, trustRoot }), error => error.code === 'PUBLICATION_PENDING');
  assert.equal(verdictItems(run.runDir).length, 0);
  const observed = observe(env);
  assert.equal(observed.passed, false);
  assert.equal(observed.state, 'candidate-ready');
  assert.equal(observed.verdict, null);
  assert.equal(observed.reasonCode, 'PUBLICATION_PENDING');
});

test('доверенный PASS: полная связка approval/consumption/снапшоты/цепочка/candidate', async () => {
  const env = await trustedRun('trusted-pass');
  const { anchorId, statement } = await signFor(env, 'trusted');
  const body = verifyAnchorStatement(trust, statement);
  assert.equal(body.domain, 'anchor-statement');
  assert.equal(body.candidateSha256, env.candidateSha256);
  assert.equal(body.runId, env.runId);
  assert.equal(body.manifestSha256, env.frozen.manifestSha256);
  assert.equal(body.approvalId, env.approvalId);
  assert.equal(body.verdict, 'PASS');
  assert.equal(body.reasonCode, 'NONE');
  const head = evidenceChainHead(store, env.runDir);
  assert.deepEqual(body.chainHead, head);
  assert.equal(body.keyId, trust['anchor-signer'].keyId);
  assert.equal(fs.existsSync(anchorFile(anchorId)), true);
  assert.equal(stateOf(env), 'candidate-ready');
  publishAnchorChoice(env, anchorId);
  assert.equal(stateOf(env), 'anchor-held');
  const before = observe(env);
  assert.equal(before.passed, false);
  assert.equal(before.state, 'anchor-held');
  assert.equal(before.reasonCode, 'PUBLICATION_PENDING');
  const published = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  assert.equal(published.created, true);
  const items = verdictItems(env.runDir);
  assert.equal(items.length, 1);
  assert.deepEqual(items[0].artifact, env.candidate);
  assert.equal(Object.hasOwn(items[0].artifact, 'anchorId'), false);
  assert.equal(fs.readFileSync(path.join(env.runDir, 'evidence', items[0].envelope.artifact.path)).toString('utf8'), canonical(env.candidate) + '\n');
  const observed = observe(env);
  assert.equal(observed.state, 'terminal');
  assert.equal(observed.trusted, true);
  assert.equal(observed.passed, true);
  assert.equal(observed.verdict.verdict, 'PASS');
  assert.equal(observed.anchorStatus, 'ANCHOR_OK');
  assert.equal(observed.anchorId, anchorId);
  assert.equal(stateOf(env), 'terminal');
  const repeat = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  assert.equal(repeat.created, false);
  assert.equal(verdictItems(env.runDir).length, 1);
  assert.throws(() => store.appendEvidence(env.runDir, {
    runId: env.runId, manifestSha256: env.frozen.manifestSha256, fixtureId: env.frozen.fixture.fixtureId,
    stepId: env.frozen.scenario.nodes.at(-1).id, producer: 'verification', kind: 'verdict', artifact: env.candidate,
    parentEvidenceIds: [], checkIds: []
  }), error => String(error.message).includes('INTEGRITY_ERROR'));
});

test('V-10: подложный PASS без связки approval/consumption получает ANCHOR_BINDING_REJECTED', async () => {
  const run = makeRun('fake-pass');
  const chain = await appendChain(run);
  const candidate = passCandidate(run.frozen, chain.read.evidenceId);
  publishCandidate(run.runDir, candidate);
  const fakeAnchor = nextId('anchor-fake');
  await assert.rejects(client.sign({ runDir: run.runDir, approvalId: 'approval-does-not-exist', anchorId: fakeAnchor, attestation: {} }), error => error.code === 'ANCHOR_BINDING_REJECTED');
  assert.equal(fs.existsSync(anchorFile(fakeAnchor)), false);
  const mismatched = makeRun('fake-inputs');
  const chainB = await appendChain(mismatched);
  publishCandidate(mismatched.runDir, passCandidate(mismatched.frozen, chainB.read.evidenceId));
  const { approval } = makeApproval(mismatched.frozen, { approvedInputsHash: digest({ forged: true }) });
  consume(approval, mismatched.frozen, mismatched.runId, { inputs: { forged: true } });
  const fakeAnchorB = nextId('anchor-fake');
  await assert.rejects(client.sign({ runDir: mismatched.runDir, approvalId: approval.approvalId, anchorId: fakeAnchorB, attestation: {} }), error => error.code === 'ANCHOR_BINDING_REJECTED');
  assert.equal(fs.existsSync(anchorFile(fakeAnchorB)), false);
  const otherRun = makeRun('fake-consumption');
  const chainC = await appendChain(otherRun);
  publishCandidate(otherRun.runDir, passCandidate(otherRun.frozen, chainC.read.evidenceId));
  const approvalC = makeApproval(otherRun.frozen);
  consume(approvalC.approval, otherRun.frozen, nextId('run-other'));
  const fakeAnchorC = nextId('anchor-fake');
  await assert.rejects(client.sign({ runDir: otherRun.runDir, approvalId: approvalC.approvalId, anchorId: fakeAnchorC, attestation: {} }), error => error.code === 'ANCHOR_BINDING_REJECTED');
  assert.equal(fs.existsSync(anchorFile(fakeAnchorC)), false);
});

test('хеш candidate от вызывающего не принимается: протокол отвергает поле, подписант читает файл сам', async () => {
  const env = await trustedRun('caller-hash');
  const anchorId = nextId('anchor-caller');
  assert.throws(() => client.sign({ runDir: env.runDir, approvalId: env.approvalId, anchorId, candidateSha256: 'ab'.repeat(32), attestation: env.worker.payload.attestation }), error => error.code === 'CONTRACT_INVALID');
  assert.equal(fs.existsSync(anchorFile(anchorId)), false);
  await client.registerVerificationKey(env.runId, env.worker.verificationPublicKey, env.worker.verificationPid, env.worker.sessionNonce);
  // Сырой кадр протокола по legacy named pipe: служебный id не обязателен, field candidateSha256 отвергается.
  const legacy = startAnchorSigner({ trustRoot, secretsDir });
  await legacy.ready;
  const legacyClient = connectAnchorSigner(legacy.pipePath);
  try {
    await legacyClient.registerVerificationKey(env.runId, env.worker.verificationPublicKey, env.worker.verificationPid, env.worker.sessionNonce);
    const socketRequest = request => new Promise((resolve, reject) => {
      const socket = net.connect(legacy.pipePath);
      let buffer = '';
      socket.setEncoding('utf8');
      socket.on('connect', () => socket.write(JSON.stringify(request) + '\n'));
      socket.on('data', chunk => {
        buffer += chunk;
        const index = buffer.indexOf('\n');
        if (index === -1) return;
        socket.destroy();
        try { resolve(JSON.parse(buffer.slice(0, index))); } catch (error) { reject(error); }
      });
      socket.on('error', reject);
    });
    const rejected = await socketRequest({ type: 'sign', runDir: env.runDir, approvalId: env.approvalId, anchorId, candidateSha256: 'ab'.repeat(32), attestation: env.worker.payload.attestation });
    assert.equal(rejected.ok, false);
    assert.equal(rejected.code, 'CONTRACT_INVALID');
    const noId = await socketRequest({ type: 'sign', runDir: env.runDir, approvalId: env.approvalId, anchorId, attestation: env.worker.payload.attestation });
    assert.equal(noId.ok, true);
    const body = verifyAnchorStatement(trust, noId.statement);
    assert.equal(body.candidateSha256, env.candidateSha256);
    assert.equal(body.anchorId, anchorId);
  } finally {
    await legacyClient.close();
    await legacy.close();
  }
});

test('V-08: ключ owner не создаёт годный анкер', async () => {
  const env = await trustedRun('owner-key');
  const { statement } = await signFor(env, 'owner');
  const { signature, signatureAlgorithm, ...body } = statement;
  const forged = signTrustedDocument(ownerKey, { ...body, keyId: created.ownerKeyId });
  assert.throws(() => verifyAnchorStatement(trust, forged), error => error.code === 'ANCHOR_SIGNATURE_INVALID');
  assert.equal(verifyAnchorStatement(trust, statement).candidateSha256, env.candidateSha256);
  assert.throws(() => verifyAnchorStatement({ owner: trust.owner, 'anchor-signer': trust['anchor-signer'] }, forged), error => error.code === 'ANCHOR_SIGNATURE_INVALID');
});

test('V-04/V-05: второе отличное заявление на runId — ANCHOR_CONFLICT, повтор тех же байт идемпотентен', async () => {
  const env = await trustedRun('anchor-twice');
  const first = await signFor(env, 'first');
  await assert.rejects(client.sign({ runDir: env.runDir, approvalId: env.approvalId, anchorId: nextId('anchor-second'), attestation: env.worker.payload.attestation }), error => error.code === 'ANCHOR_CONFLICT');
  const again = await client.sign({ runDir: env.runDir, approvalId: env.approvalId, anchorId: first.anchorId, attestation: env.worker.payload.attestation });
  assert.deepEqual(again, first.statement);
  assert.equal(fs.existsSync(anchorFile(first.anchorId)), true);
});

test('V-07/V-11: выбор anchor переживает падение до verdict; бюджет заново не разыгрывается', async () => {
  const env = await trustedRun('crash-after-anchor');
  const { anchorId } = await signFor(env, 'crash');
  publishAnchorChoice(env, anchorId);
  assert.equal(stateOf(env), 'anchor-held');
  assert.equal(verdictItems(env.runDir).length, 0);
  const before = fs.readdirSync(path.join(trustRoot, 'anchors')).length;
  const published = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  assert.equal(published.created, true);
  assert.deepEqual(published.verdict, env.candidate);
  assert.equal(verdictItems(env.runDir).length, 1);
  assert.equal(fs.readdirSync(path.join(trustRoot, 'anchors')).length, before);
  assert.equal(observe(env).passed, true);
  assert.equal(publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }).created, false);
});

test('V-12: частично записанный terminal-choice блокирует PASS и не заменяется', async () => {
  const env = await trustedRun('torn-choice');
  const { anchorId } = await signFor(env, 'torn');
  const choiceFile = path.join(env.runDir, 'trust', 'terminal-choice.json');
  fs.writeFileSync(choiceFile, '{"schemaVersion":"0.2.0","domain":"terminal-choice"');
  const torn = fs.readFileSync(choiceFile);
  assert.throws(() => readTerminalChoice(env.runDir), error => error.code === 'TERMINAL_CHOICE_INCOMPLETE');
  assert.throws(() => publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }), error => error.code === 'TERMINAL_CHOICE_INCOMPLETE');
  assert.equal(verdictItems(env.runDir).length, 0);
  assert.deepEqual(fs.readFileSync(choiceFile), torn);
  assert.throws(() => publishTerminalChoice(env.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId })), error => error.code === 'TERMINAL_CHOICE_INCOMPLETE');
  assert.deepEqual(fs.readFileSync(choiceFile), torn);
  const observed = observe(env);
  assert.equal(observed.passed, false);
  assert.equal(observed.state, 'inconsistent');
  assert.equal(stateOf(env), 'inconsistent');
  await assert.rejects(client.sign({ runDir: env.runDir, approvalId: env.approvalId, anchorId: nextId('anchor-after-torn'), attestation: env.worker.payload.attestation }), error => error.code === 'ANCHOR_BINDING_REJECTED');
});

test('D-01: исход anchor без подписанного анкера не пишет PASS', async () => {
  const env = await trustedRun('d01-anchor-missing');
  const anchorId = nextId('anchor-never-signed');
  publishTerminalChoice(env.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId }));
  assert.throws(() => publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }), error => error.code === 'ANCHOR_MISSING');
  assert.equal(verdictItems(env.runDir).length, 0);
  const observed = observe(env);
  assert.equal(observed.passed, false);
  assert.equal(observed.verdict, null);
  assert.equal(observed.reasonCode, 'ANCHOR_MISSING');
  // Без trust/trustRoot исход anchor тоже fail-closed, а не публикует PASS.
  assert.throws(() => publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen }), error => error.code === 'ANCHOR_MISSING');
  assert.equal(verdictItems(env.runDir).length, 0);
});

test('D-01: удалённый анкер не превращает повторную публикацию в PASS', async () => {
  const env = await trustedRun('d01-anchor-removed');
  const { anchorId } = await signFor(env, 'removed');
  publishAnchorChoice(env, anchorId);
  const published = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  assert.equal(published.verdict.verdict, 'PASS');
  assert.equal(verdictItems(env.runDir).length, 1);
  fs.rmSync(anchorFile(anchorId));
  assert.throws(() => publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }), error => error.code === 'ANCHOR_MISSING');
  const items = verdictItems(env.runDir);
  assert.equal(items.length, 1);
  assert.equal(items[0].artifact.verdict, 'PASS');
  const observed = observe(env);
  assert.equal(observed.passed, false);
  assert.equal(observed.reasonCode, 'ANCHOR_MISSING');
});

test('D-01: подмена outcome в ветке существующего verdict не возвращает PASS', async () => {
  const env = await trustedRun('d01-outcome-swap');
  const { anchorId } = await signFor(env, 'swap');
  publishAnchorChoice(env, anchorId);
  publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  const choiceFile = path.join(env.runDir, 'trust', 'terminal-choice.json');
  const saved = readTerminalChoice(env.runDir);
  fs.writeFileSync(choiceFile, canonical({ ...saved, outcome: 'inconclusive-without-anchor', anchorId: null, discardedCandidateSha256: null }) + '\n');
  assert.throws(() => publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }), error => error.code === 'INTEGRITY_ERROR');
  assert.equal(verdictItems(env.runDir).length, 1);
});

test('два одновременных publishTerminalChoice: один CREATE_NEW, второй читает первый выбор', async () => {
  const env = await trustedRun('choice-race');
  const choices = [
    buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId: nextId('anchor-race-a') }),
    buildTerminalChoice({ outcome: 'anchor', candidateSha256: env.candidateSha256, anchorId: nextId('anchor-race-b') })
  ];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-choice-race-'));
  const worker = path.join(directory, 'choice-worker.mjs');
  fs.writeFileSync(worker, [
    'import fs from "node:fs";',
    'const [moduleUrl, runDir, choiceJson, readyFile, goFile, resultFile] = process.argv.slice(2);',
    'const { publishTerminalChoice } = await import(moduleUrl);',
    'fs.writeFileSync(readyFile, "1");',
    'while (!fs.existsSync(goFile)) await new Promise(resolve => setTimeout(resolve, 5));',
    'let result;',
    'try { const published = publishTerminalChoice(runDir, JSON.parse(choiceJson)); result = { ok: true, created: published.created, choice: published.choice }; }',
    'catch (error) { result = { ok: false, code: error.code, message: error.message }; }',
    'fs.writeFileSync(resultFile, JSON.stringify(result));',
    ''
  ].join('\n'));
  const moduleUrl = pathToFileURL(path.resolve('packages/trust/anchor.mjs')).href;
  const goFile = path.join(directory, 'go');
  const children = choices.map((choice, index) => {
    const readyFile = path.join(directory, 'ready-' + index);
    const resultFile = path.join(directory, 'result-' + index + '.json');
    const child = spawn(process.execPath, [worker, moduleUrl, env.runDir, JSON.stringify(choice), readyFile, goFile, resultFile], { stdio: 'ignore' });
    return { readyFile, resultFile, child };
  });
  await waitForFiles(children.map(item => item.readyFile));
  fs.writeFileSync(goFile, 'go');
  await Promise.all(children.map(item => exitOf(item.child)));
  const results = children.map(item => JSON.parse(fs.readFileSync(item.resultFile, 'utf8')));
  assert.equal(results.every(item => item.ok), true);
  assert.equal(results.filter(item => item.created).length, 1);
  assert.deepEqual(results[0].choice, results[1].choice);
  const saved = JSON.parse(fs.readFileSync(path.join(env.runDir, 'trust', 'terminal-choice.json'), 'utf8'));
  assert.deepEqual(saved, results[0].choice);
  assert.deepEqual(saved, choices.find(choice => choice.anchorId === saved.anchorId));
});

test('подмена candidate после анкера не даёт PASS и не перезаписывается', async () => {
  const env = await trustedRun('candidate-tamper');
  const { anchorId } = await signFor(env, 'tamper');
  publishAnchorChoice(env, anchorId);
  const candidateFile = path.join(env.runDir, 'trust', 'candidate.json');
  const kept = fs.readFileSync(candidateFile);
  const replacement = businessCandidate(env.frozen, env.chain.read.evidenceId, 'FAIL', 'BUSINESS_INVARIANT_VIOLATED');
  fs.writeFileSync(candidateFile, canonical(replacement) + '\n');
  const observed = observe(env);
  assert.equal(observed.passed, false);
  assert.notEqual(observed.state, 'terminal');
  assert.equal(stateOf(env), 'inconsistent');
  assert.throws(() => publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }), error => ['INTEGRITY_ERROR', 'EVIDENCE_MISSING', 'ANCHOR_CONFLICT'].includes(error.code));
  assert.equal(verdictItems(env.runDir).length, 0);
  assert.equal(fs.readFileSync(candidateFile).equals(kept), false);
  await assert.rejects(client.sign({ runDir: env.runDir, approvalId: env.approvalId, anchorId: nextId('anchor-after-candidate'), attestation: env.worker.payload.attestation }), error => error.code === 'ANCHOR_BINDING_REJECTED' || error.code === 'ANCHOR_CONFLICT');
});

test('подмена evidence chain ломает терминальный PASS', async () => {
  const env = await trustedRun('chain-tamper');
  const { anchorId } = await signFor(env, 'chain');
  publishAnchorChoice(env, anchorId);
  publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  assert.equal(observe(env).passed, true);
  const readItem = store.readEvidence(env.runDir).find(item => item.envelope.kind === 'independent-read');
  const artifactFile = path.join(env.runDir, 'evidence', readItem.envelope.artifact.path);
  fs.writeFileSync(artifactFile, canonical({ tampered: true }) + '\n');
  assert.throws(() => store.readEvidence(env.runDir), error => String(error.message).includes('INTEGRITY_ERROR'));
  const observed = observe(env);
  assert.equal(observed.passed, false);
  assert.equal(observed.state, 'inconsistent');
  assert.equal(stateOf(env), 'inconsistent');
});

test('подмена финального verdict после публикации не показывается как PASS', async () => {
  const env = await trustedRun('verdict-tamper');
  const { anchorId } = await signFor(env, 'verdict');
  publishAnchorChoice(env, anchorId);
  publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  const item = verdictItems(env.runDir)[0];
  const artifactFile = path.join(env.runDir, 'evidence', item.envelope.artifact.path);
  fs.writeFileSync(artifactFile, canonical({ ...env.candidate, verdict: 'FAIL', reasonCode: 'BUSINESS_INVARIANT_VIOLATED' }) + '\n');
  assert.throws(() => store.readEvidence(env.runDir), error => String(error.message).includes('INTEGRITY_ERROR'));
  const observed = observe(env);
  assert.equal(observed.passed, false);
  assert.equal(observed.verdict, null);
  assert.equal(stateOf(env), 'inconsistent');
});

test('чужой runId: candidate и анкер не переносятся между прогонами', async () => {
  const first = await trustedRun('run-a');
  const second = makeRun('run-b');
  await appendChain(second);
  assert.throws(() => publishCandidate(second.runDir, first.candidate), error => error.code === 'CONTRACT_INVALID');
  const { anchorId, statement } = await signFor(first, 'foreign');
  publishAnchorChoice(first, anchorId);
  publishTerminalVerdict({ store, runDir: first.runDir, frozen: first.frozen, trust, trustRoot });
  const secondTrust = path.join(second.runDir, 'trust');
  fs.mkdirSync(secondTrust, { recursive: true });
  fs.copyFileSync(path.join(first.runDir, 'trust', 'candidate.json'), path.join(secondTrust, 'candidate.json'));
  fs.mkdirSync(path.join(secondTrust, 'candidates'), { recursive: true });
  fs.copyFileSync(path.join(first.runDir, 'trust', 'candidates', first.candidateSha256 + '.json'), path.join(secondTrust, 'candidates', first.candidateSha256 + '.json'));
  const observed = observe({ runDir: second.runDir, frozen: second.frozen });
  assert.equal(observed.passed, false);
  assert.equal(observed.state, 'candidate-ready');
  const body = verifyAnchorStatement(trust, statement);
  assert.equal(body.runId, first.runId);
  assert.notEqual(body.runId, second.runId);
});

test('V-09: гонка бюджета и позднего анкера — один INCONCLUSIVE, анкер ANCHOR_UNLINKED', async () => {
  const env = await trustedRun('budget-race');
  const profileFile = path.join(trustRoot, 'profile.json');
  fs.writeFileSync(profileFile, JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-profile', anchorBudgetMs: 120 }) + '\n');
  try {
    assert.equal(loadAnchorBudgetMs(trustRoot), 120);
    const anchorId = nextId('anchor-late');
    let resolveLate;
    let rejectLate;
    const latePromise = new Promise((resolve, reject) => { resolveLate = resolve; rejectLate = reject; });
    const delayed = {
      sign(request) {
        setTimeout(() => { client.sign({ ...request, attestation: env.worker.payload.attestation }).then(resolveLate, rejectLate); }, 250);
        return latePromise;
      }
    };
    await client.registerVerificationKey(env.runId, env.worker.verificationPublicKey, env.worker.verificationPid, env.worker.sessionNonce);
    const outcome = await anchorWithinBudget({ signer: delayed, trustRoot, runDir: env.runDir, approvalId: env.approvalId, anchorId, attestation: env.worker.payload.attestation, budgetMs: 1 });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.code, 'ANCHOR_TIMEOUT');
    assert.equal(outcome.budgetMs, 120);
    const lateStatement = await latePromise;
    assert.equal(lateStatement.candidateSha256, env.candidateSha256);
    assert.equal(fs.existsSync(anchorFile(anchorId)), true);
    const published = publishBudgetInconclusiveOutcome({ runDir: env.runDir, frozen: env.frozen });
    assert.equal(published.created, true);
    assert.equal(published.choice.outcome, 'budget-inconclusive');
    assert.equal(published.choice.discardedCandidateSha256, env.candidateSha256);
    assert.equal(published.choice.anchorId, null);
    const verdict = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
    assert.equal(verdict.verdict.verdict, 'INCONCLUSIVE');
    assert.equal(verdict.verdict.reasonCode, 'EVIDENCE_MISSING');
    assert.equal(verdict.verdict.message, INCONCLUSIVE_MESSAGE);
    assert.equal(verdictItems(env.runDir).length, 1);
    const observed = observe(env);
    assert.equal(observed.state, 'terminal');
    assert.equal(observed.passed, false);
    assert.equal(observed.verdict.verdict, 'INCONCLUSIVE');
    assert.equal(observed.verdict.reasonCode, 'EVIDENCE_MISSING');
    assert.equal(observed.anchorStatus, 'ANCHOR_UNLINKED');
    assert.equal(observed.reasonCode, 'ANCHOR_UNLINKED');
    assert.equal(observed.unlinkedAnchorId, anchorId);
    assert.equal(loadAnchor(trustRoot, anchorId).candidateSha256, env.candidateSha256);
    // D-05: синтаксически валидный, но неподписанный файл анкера не выдаётся за ANCHOR_UNLINKED.
    fs.writeFileSync(path.join(trustRoot, 'anchors', 'aaa-forged-unlinked.json'), JSON.stringify({ anchorId: 'aaa-forged-unlinked', runId: env.runId, candidateSha256: env.candidateSha256 }) + '\n');
    const observedAfterForged = observe(env);
    assert.equal(observedAfterForged.passed, false);
    assert.equal(observedAfterForged.unlinkedAnchorId, anchorId);
    fs.rmSync(path.join(trustRoot, 'anchors', 'aaa-forged-unlinked.json'));
    assert.equal(publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot }).created, false);
  } finally {
    fs.rmSync(profileFile, { force: true });
  }
});

test('бюджет анкера: по умолчанию 5000, диапазон 1…60000, профиль не заменяется вызывающим', async () => {
  const budgetWork = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-anchor-budget-'));
  const budgetSecrets = path.join(budgetWork, 'secrets');
  const budgetTrust = path.join(budgetWork, 'trust-root');
  await createTrustRoot({ secretsDir: budgetSecrets, trustRoot: budgetTrust });
  assert.equal(loadAnchorBudgetMs(budgetTrust), DEFAULT_ANCHOR_BUDGET_MS);
  assert.equal(DEFAULT_ANCHOR_BUDGET_MS, 5000);
  fs.writeFileSync(path.join(budgetTrust, 'profile.json'), JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-profile', anchorBudgetMs: 0 }) + '\n');
  assert.throws(() => loadAnchorBudgetMs(budgetTrust), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  fs.writeFileSync(path.join(budgetTrust, 'profile.json'), JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-profile', anchorBudgetMs: 60001 }) + '\n');
  assert.throws(() => loadAnchorBudgetMs(budgetTrust), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  fs.writeFileSync(path.join(budgetTrust, 'profile.json'), JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-profile', anchorBudgetMs: 60000 }) + '\n');
  assert.equal(loadAnchorBudgetMs(budgetTrust), 60000);
});

test('fail-without-anchor публикует один бизнес-FAIL без анкера', async () => {
  const run = makeRun('business-fail');
  const chain = await appendChain(run);
  const candidate = businessCandidate(run.frozen, chain.read.evidenceId, 'FAIL', 'BUSINESS_INVARIANT_VIOLATED');
  const published = publishCandidate(run.runDir, candidate);
  const env = { ...run, candidateSha256: published.candidateSha256 };
  publishTerminalChoice(run.runDir, buildTerminalChoice({ outcome: 'fail-without-anchor', candidateSha256: published.candidateSha256 }));
  assert.equal(stateOf(env), 'candidate-ready');
  const verdict = publishTerminalVerdict({ store, runDir: run.runDir, frozen: run.frozen, trust, trustRoot });
  assert.equal(verdict.verdict.verdict, 'FAIL');
  assert.equal(verdictItems(run.runDir).length, 1);
  const observed = observe(env);
  assert.equal(observed.state, 'terminal');
  assert.equal(observed.trusted, true);
  assert.equal(observed.passed, false);
  assert.equal(observed.verdict.verdict, 'FAIL');
  assert.equal(observed.anchorStatus, 'ANCHOR_MISSING');
});

test('inconclusive-without-anchor публикует ровно байты бизнес-INCONCLUSIVE', async () => {
  const run = makeRun('business-inconclusive');
  const chain = await appendChain(run);
  const candidate = businessCandidate(run.frozen, chain.read.evidenceId, 'INCONCLUSIVE', 'WORKER_LOST');
  const published = publishCandidate(run.runDir, candidate);
  const env = { ...run, candidateSha256: published.candidateSha256 };
  publishTerminalChoice(run.runDir, buildTerminalChoice({ outcome: 'inconclusive-without-anchor', candidateSha256: published.candidateSha256 }));
  const verdict = publishTerminalVerdict({ store, runDir: run.runDir, frozen: run.frozen, trust, trustRoot });
  assert.deepEqual(verdict.verdict, candidate);
  assert.equal(verdictItems(run.runDir).length, 1);
  const observed = observe(env);
  assert.equal(observed.state, 'terminal');
  assert.equal(observed.passed, false);
  assert.equal(observed.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(observed.verdict.reasonCode, 'WORKER_LOST');
  assert.throws(() => publishTerminalChoice(run.runDir, buildTerminalChoice({ outcome: 'inconclusive-without-anchor', candidateSha256: published.candidateSha256, anchorId: 'anchor-x' })), error => error.code === 'CONTRACT_INVALID');
});

test('второй терминальный verdict запрещён; повторный RECONCILE читает первый', async () => {
  const env = await trustedRun('second-verdict');
  const { anchorId } = await signFor(env, 'second');
  publishAnchorChoice(env, anchorId);
  publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  const firstItems = verdictItems(env.runDir);
  assert.equal(firstItems.length, 1);
  const reconciled = publishTerminalVerdict({ store, runDir: env.runDir, frozen: env.frozen, trust, trustRoot });
  assert.equal(reconciled.created, false);
  assert.equal(reconciled.evidenceId, firstItems[0].envelope.evidenceId);
  assert.equal(verdictItems(env.runDir).length, 1);
  assert.throws(() => store.appendEvidence(env.runDir, {
    runId: env.runId, manifestSha256: env.frozen.manifestSha256, fixtureId: env.frozen.fixture.fixtureId,
    stepId: env.frozen.scenario.nodes.at(-1).id, producer: 'verification', kind: 'verdict', artifact: env.candidate,
    parentEvidenceIds: [], checkIds: []
  }), error => String(error.message).includes('INTEGRITY_ERROR'));
  const observed = observe(env);
  assert.equal(observed.passed, true);
});

async function waitForFiles(files) {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    if (files.every(file => fs.existsSync(file))) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error('дочерний процесс не дошёл до барьера');
}

function exitOf(child) {
  return new Promise((resolve, reject) => {
    child.once('exit', code => code === 0 ? resolve() : reject(new Error('процесс завершился с ' + code)));
    child.once('error', reject);
  });
}