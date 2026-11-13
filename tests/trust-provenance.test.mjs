// WP-08 P0-01: регрессии достоверного происхождения Verification.
//
// Каждый кейс проверяет, что доверенный PASS строится только на подписанной
// verification-attestation доверенного Worker, а подложная цепочка/кандидат,
// чужой ключ, подмена хешей после аттестации и повтор другого runId отвергаются.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fork, spawn } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { canonical, digest, scenarioApprovalHash } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { verifyFrozenBundle } from '../packages/core/bundle.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { consumeDispatch, signApproval } from '../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import {
  buildTerminalChoice, loadAnchor, observeTrustedVerdict, publishCandidate, publishTerminalChoice,
  publishTerminalVerdict, readCandidate, verifyAnchorStatement, verificationPublicKeyRecord
} from '../packages/trust/anchor.mjs';
import { connectAnchorSigner, spawnAnchorSigner, startAnchorSigner } from '../packages/trust/anchor-signer.mjs';
import { buildVerificationEnv, verifyWithTrustedWorker } from '../apps/control/trusted.mjs';
import { currentUserSid } from '../packages/trust/windows-sid.mjs';
import { fileURLToPath } from 'node:url';

const SID = currentUserSid();

async function makeWorld(t, { stand: withStand = true } = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-provenance-'));
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust');
  const root = path.join(base, 'store');
  const created = await createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = withStand ? await serveLocalFixture({ generation: 1 }) : null;
  if (stand) {
    const record = signEnvironmentRecord(ownerKey, {
      environmentId: stand.environmentId, generation: stand.generation, kind: 'local-stand', status: 'active',
      origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: 'local:fixture-token'
    });
    commitEnvironmentRecord(trust, trustRoot, record);
  }
  const owner = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner',
    roles: ['owner'], keyId: created.ownerKeyId, windowsSid: SID, status: 'active'
  });
  const operator = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator',
    roles: ['operator'], keyId: created.ownerKeyId, windowsSid: SID, status: 'active'
  });
  t.after(async () => {
    if (stand) await stand.close();
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return { base, secretsDir, trustRoot, root, created, trust, ownerKey, stand, owner, operator };
}

function makeRun(w, runId, { descriptorOverrides = {} } = {}) {
  const baseDescriptor = w.stand
    ? { ...w.stand }
    : { environmentId: 'local-stand', baseUrl: 'http://127.0.0.1:9/', fingerprint: 'fp-local', ...descriptorOverrides };
  const contract = localFixtureContract(baseDescriptor, runId);
  if (w.stand) w.stand.fixtureId = contract.fixtureId;
  else baseDescriptor.fixtureId = contract.fixtureId;
  const descriptor = w.stand ? { ...w.stand, ...descriptorOverrides } : { ...baseDescriptor, ...descriptorOverrides };
  const bundle = localBundle(descriptor, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  bundle.manifest.budget.deadlineMs = 15000;
  const store = new RunStore(w.root);
  const runDir = store.snapshot(bundle, { pid: process.pid });
  const frozen = verifyFrozenBundle(store, runDir);
  return { store, runDir, frozen, bundle, contract };
}

async function realMutation(w, frozen) {
  const operation = frozen.operation;
  const response = await fetch(new URL('/records', w.stand.baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + w.stand.authToken },
    body: JSON.stringify({ ...operation.inputs, fixtureId: frozen.fixture.fixtureId })
  });
  assert.equal(response.status, 201);
  const body = await response.json();
  return { kind: operation.entityKind, id: body.id };
}

function appendChain(store, frozen, { entity, status = 201 }) {
  const { manifest, operation, fixture, manifestSha256 } = frozen;
  const runId = manifest.runId;
  const mutationStep = 'create';
  const verifyStep = frozen.scenario.nodes.at(-1).id;
  const requestId = randomUUID();
  const intentArtifact = {
    intentId: runId + ':' + mutationStep, stepId: mutationStep, operationId: operation.id,
    mutationName: operation.mutation.name, inputsSha256: digest(operation.inputs), fixtureId: fixture.fixtureId
  };
  const intent = store.appendEvidence(runDirOf(store, manifest.runId), {
    runId, manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep, producer: 'control',
    kind: 'mutation-intent', artifact: intentArtifact, parentEvidenceIds: []
  });
  return { intent, requestId, verifyStep, mutationStep };
}

// Полная запись цепочки в каталог прогона.
function appendFullChain(store, runDir, frozen, entity) {
  const { manifest, operation, fixture, manifestSha256 } = frozen;
  const runId = manifest.runId;
  const mutationStep = 'create';
  const verifyStep = frozen.scenario.nodes.at(-1).id;
  const requestId = randomUUID();
  const intentArtifact = {
    intentId: runId + ':' + mutationStep, stepId: mutationStep, operationId: operation.id,
    mutationName: operation.mutation.name, inputsSha256: digest(operation.inputs), fixtureId: fixture.fixtureId
  };
  const intent = store.appendEvidence(runDir, {
    runId, manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep, producer: 'control',
    kind: 'mutation-intent', artifact: intentArtifact, parentEvidenceIds: []
  });
  const requestArtifact = {
    requestId, intentId: intentArtifact.intentId, operationId: operation.id, method: 'POST',
    path: '/records', fixtureId: fixture.fixtureId, fields: { ...operation.inputs, fixtureId: fixture.fixtureId }
  };
  const request = store.appendEvidence(runDir, {
    runId, manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep, producer: 'browser',
    kind: 'request', requestId, artifact: requestArtifact, parentEvidenceIds: [intent.evidenceId]
  });
  const response = store.appendEvidence(runDir, {
    runId, manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep, producer: 'browser',
    kind: 'response', requestId, entity,
    artifact: { requestId, intentId: intentArtifact.intentId, operationId: operation.id, fixtureId: fixture.fixtureId, status: 201, entity },
    parentEvidenceIds: [request.evidenceId]
  });
  return { intent, request, response, requestId, verifyStep };
}

function runDirOf(store, runId) { return store.runPath(runId); }

async function approveRun(w, frozen, { approvalId = 'approval-' + randomUUID().slice(0, 8) } = {}) {
  const operation = frozen.operation;
  const issuedAt = new Date(Date.now() - 60000).toISOString();
  const expected = {
    operation, inputs: operation.inputs,
    effects: operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    scenarioContentSha256: scenarioApprovalHash(frozen.scenario),
    fixtureId: frozen.fixture.fixtureId,
    environmentId: frozen.manifest.environment.id,
    environmentGeneration: 1
  };
  const approval = signApproval(w.ownerKey, {
    approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: operation.id, operationVersion: operation.version,
    scenarioContentSha256: expected.scenarioContentSha256, operationSha256: digest(operation),
    approvedInputsHash: digest(operation.inputs), fixtureId: frozen.fixture.fixtureId,
    targetEnvironmentId: frozen.manifest.environment.id, environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: expected.effects, issuedAt,
    expiresAt: new Date(Date.parse(issuedAt) + 600000).toISOString(),
    approvalNonce: randomBytes(32).toString('hex'), keyId: w.created.ownerKeyId
  }, w.trust, w.trustRoot);
  consumeDispatch({
    trust: w.trust, trustRoot: w.trustRoot, approval, issuer: w.owner, subject: w.operator,
    windowsSid: SID, runId: frozen.manifest.runId, decisionId: 'decision-' + randomUUID().slice(0, 8), expected
  });
  return approvalId;
}

async function trustedWorker(w, run, approvalId) {
  return verifyWithTrustedWorker({
    runDir: run.runDir, frozen: run.frozen, trustRoot: w.trustRoot, approvalId,
    fixtureToken: w.stand?.authToken || '', standPublicKey: w.stand?.standPublicKey || null
  });
}

async function withWorker(w, run, approvalId, fn) {
  const worker = await trustedWorker(w, run, approvalId);
  try { return await fn(worker); }
  finally { await worker.close(); }
}

async function genuinePass(w, run, approvalId, anchorKeyPath) {
  const worker = await trustedWorker(w, run, approvalId);
  const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath });
  try {
    publishCandidate(run.runDir, worker.payload.verdict);
    await signer.registerVerificationKey(run.frozen.manifest.runId, worker.verificationPublicKey, worker.verificationPid, worker.sessionNonce);
    const anchorId = 'anchor-' + randomUUID().slice(0, 8);
    const statement = await signer.sign({ runDir: run.runDir, approvalId, anchorId, attestation: worker.attestation });
    publishTerminalChoice(run.runDir, buildTerminalChoice({
      outcome: 'anchor', candidateSha256: digest(worker.payload.verdict), anchorId
    }));
    const published = publishTerminalVerdict({ store: w.store, runDir: run.runDir, frozen: run.frozen, trust: w.trust, trustRoot: w.trustRoot });
    return { worker, anchorId, statement, published };
  } finally {
    await signer.close();
    await worker.close();
  }
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function dummyProcess() {
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' });
  await sleep(150);
  return child;
}

test('P0-01: доверенный Worker даёт PASS только с подписанной аттестацией и полной связкой', { timeout: 90000 }, async t => {
  const w = await makeWorld(t);
  const run = makeRun(w, 'prov-genuine');
  w.store = run.store;
  const entity = await realMutation(w, run.frozen);
  appendFullChain(run.store, run.runDir, run.frozen, entity);
  const approvalId = await approveRun(w, run.frozen);
  const worker = await trustedWorker(w, run, approvalId);
  try {
    assert.equal(worker.payload.verdict.verdict, 'PASS');
    assert.equal(worker.payload.verdict.reasonCode, 'NONE');
    assert.ok(worker.payload.reads.length >= 1);
    const attestation = worker.payload.attestation;
    assert.equal(attestation.domain, 'verification-attestation');
    assert.equal(attestation.schemaVersion, '0.2.1');
    assert.equal(attestation.runId, run.frozen.manifest.runId);
    assert.equal(attestation.approvalId, approvalId);
    assert.equal(attestation.candidateSha256, digest(worker.payload.verdict));
    assert.equal(attestation.decision.verdict, 'PASS');
    assert.equal(attestation.verificationKeyId, worker.verificationPublicKey.keyId);
    const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
    try {
      publishCandidate(run.runDir, worker.payload.verdict);
      await signer.registerVerificationKey(run.frozen.manifest.runId, worker.verificationPublicKey, worker.verificationPid, worker.sessionNonce);
      const anchorId = 'anchor-genuine';
      const statement = await signer.sign({ runDir: run.runDir, approvalId, anchorId, attestation: worker.attestation });
      const body = verifyAnchorStatement(w.trust, statement);
      assert.equal(body.verificationAttestationSha256, digest(worker.attestation));
      assert.equal(body.verificationKeyId, worker.verificationPublicKey.keyId);
      assert.equal(body.candidateSha256, digest(worker.payload.verdict));
      publishTerminalChoice(run.runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: digest(worker.payload.verdict), anchorId }));
      publishTerminalVerdict({ store: run.store, runDir: run.runDir, frozen: run.frozen, trust: w.trust, trustRoot: w.trustRoot });
    } finally {
      await signer.close();
    }
  } finally {
    await worker.close();
  }
  const recordFile = path.join(w.trustRoot, 'verification', run.frozen.manifest.runId + '.json');
  assert.equal(fs.existsSync(recordFile), true);
  const observed = observeTrustedVerdict({ store: run.store, runDir: run.runDir, frozen: run.frozen, trust: w.trust, trustRoot: w.trustRoot });
  assert.equal(observed.trusted, true);
  assert.equal(observed.passed, true);
  assert.equal(observed.verdict.verdict, 'PASS');
  assert.equal(observed.verification.verificationKeyId, worker.verificationPublicKey.keyId);
});

test('P0-01: подложная цепочка и кандидат без работающего Verification не получают анкер', { timeout: 90000 }, async t => {
  const w = await makeWorld(t, { stand: false });
  const run = makeRun(w, 'prov-forged');
  w.store = run.store;
  // Атакующий сам пишет «успешную» цепочку и durable PASS-candidate: реального чтения не было.
  const entity = { kind: run.frozen.operation.entityKind, id: 'record-forged' };
  const chain = appendFullChain(run.store, run.runDir, run.frozen, entity);
  const readArtifact = {
    method: 'GET', path: '/records', fixtureId: run.frozen.fixture.fixtureId,
    entity: { kind: run.frozen.operation.entityKind, id: entity.id },
    fields: { ...run.frozen.operation.inputs, fixtureId: run.frozen.fixture.fixtureId },
    environmentFingerprint: run.frozen.manifest.environment.fingerprint,
    requestId: chain.requestId, httpStatus: 200, observedAt: new Date().toISOString()
  };
  run.store.appendEvidence(run.runDir, {
    runId: run.frozen.manifest.runId, manifestSha256: run.frozen.manifestSha256,
    fixtureId: run.frozen.fixture.fixtureId, stepId: chain.verifyStep, producer: 'verification',
    kind: 'independent-read', requestId: chain.requestId, entity: readArtifact.entity,
    checkIds: run.frozen.operation.effects.map(effect => effect.id), artifact: readArtifact,
    parentEvidenceIds: [chain.response.evidenceId]
  });
  const { buildCandidate } = await import('../packages/trust/anchor.mjs');
  const candidate = buildCandidate({
    frozen: run.frozen, verdict: 'PASS', reasonCode: 'NONE', message: 'подложный candidate',
    checks: run.frozen.operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds: [run.store.readEvidence(run.runDir).at(-1).envelope.evidenceId] }))
  });
  publishCandidate(run.runDir, candidate);
  const approvalId = await approveRun(w, run.frozen);
  const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
  const fakeNonce = randomBytes(32).toString('hex');
  try {
    // Попытка выдать себя за доверенный Worker: ключ регистрируется с pid постороннего процесса.
    const dummy = await dummyProcess();
    try {
      const attacker = generateKeyPairSync('ed25519');
      await signer.registerVerificationKey(run.frozen.manifest.runId, verificationPublicKeyRecord(attacker.publicKey), dummy.pid, fakeNonce);
      const fakeAttestation = {
        schemaVersion: '0.2.1', domain: 'verification-attestation', runId: run.frozen.manifest.runId,
        manifestSha256: run.frozen.manifestSha256, approvalId, candidateSha256: digest(candidate),
        readSetSha256: 'ab'.repeat(32),
        evidenceChainHead: { sequence: 1, envelopeSha256: 'ab'.repeat(32) },
        decision: { verdict: 'PASS', reasonCode: 'NONE' },
        verificationKeyId: verificationPublicKeyRecord(attacker.publicKey).keyId,
        pid: dummy.pid, startedAt: new Date().toISOString(), nonce: randomBytes(32).toString('hex'),
        keyId: verificationPublicKeyRecord(attacker.publicKey).keyId, signature: 'ab'.repeat(64), signatureAlgorithm: 'Ed25519'
      };
      await assert.rejects(
        () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-forged', attestation: fakeAttestation }),
        error => ['ANCHOR_BINDING_REJECTED', 'CONTRACT_INVALID', 'INTEGRITY_ERROR'].includes(error.code)
      );
    } finally {
      dummy.kill('SIGKILL');
    }
    // Без регистрации доверенного ключа подписант тоже отказывает.
    await assert.rejects(
      () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-forged-2', attestation: { domain: 'verification-attestation' } }),
      error => error.code === 'ANCHOR_BINDING_REJECTED' || error.code === 'CONTRACT_INVALID'
    );
  } finally {
    await signer.close();
  }
  assert.equal(fs.existsSync(path.join(w.trustRoot, 'anchors', 'anchor-forged.json')), false);
  const observed = observeTrustedVerdict({ store: run.store, runDir: run.runDir, frozen: run.frozen, trust: w.trust, trustRoot: w.trustRoot });
  assert.equal(observed.passed, false);
  assert.equal(observed.state, 'candidate-ready');
});

test('P0-01: аттестация от чужого ключа отвергается', { timeout: 90000 }, async t => {
  const w = await makeWorld(t);
  const run = makeRun(w, 'prov-foreign-key');
  w.store = run.store;
  const entity = await realMutation(w, run.frozen);
  appendFullChain(run.store, run.runDir, run.frozen, entity);
  const approvalId = await approveRun(w, run.frozen);
  const worker = await trustedWorker(w, run, approvalId);
  try {
    publishCandidate(run.runDir, worker.payload.verdict);
    const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
    try {
      // В сессии подписанта для runId регистрируется чужой ключ с настоящим pid Worker.
      const foreign = generateKeyPairSync('ed25519');
      await signer.registerVerificationKey(run.frozen.manifest.runId, verificationPublicKeyRecord(foreign.publicKey), worker.verificationPid, worker.sessionNonce);
      await assert.rejects(
        () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-foreign-key', attestation: worker.attestation }),
        error => error.code === 'ANCHOR_BINDING_REJECTED'
      );
      assert.equal(fs.existsSync(path.join(w.trustRoot, 'anchors', 'anchor-foreign-key.json')), false);
      // Повторная регистрация другого ключа на тот же runId запрещена.
      await assert.rejects(
        () => signer.registerVerificationKey(run.frozen.manifest.runId, worker.verificationPublicKey, worker.verificationPid, worker.sessionNonce),
        error => error.code === 'CONTRACT_INVALID'
      );
    } finally {
      await signer.close();
    }
  } finally {
    await worker.close();
  }
});

test('P0-01: подмена candidateSha256/readSetSha256 и candidate после аттестации отвергается', { timeout: 120000 }, async t => {
  const w = await makeWorld(t);
  const run = makeRun(w, 'prov-tamper');
  w.store = run.store;
  const entity = await realMutation(w, run.frozen);
  appendFullChain(run.store, run.runDir, run.frozen, entity);
  const approvalId = await approveRun(w, run.frozen);
  const worker = await trustedWorker(w, run, approvalId);
  try {
    publishCandidate(run.runDir, worker.payload.verdict);
    const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
    try {
      await signer.registerVerificationKey(run.frozen.manifest.runId, worker.verificationPublicKey, worker.verificationPid, worker.sessionNonce);
      // a) подмена поля candidateSha256 в аттестации ломает подпись.
      const tamperedCandidate = { ...worker.attestation, candidateSha256: 'ab'.repeat(32) };
      await assert.rejects(
        () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-tamper-sha', attestation: tamperedCandidate }),
        error => error.code === 'ANCHOR_BINDING_REJECTED'
      );
      // b) подмена readSetSha256 в аттестации ломает подпись.
      const tamperedReadSet = { ...worker.attestation, readSetSha256: 'cd'.repeat(32) };
      await assert.rejects(
        () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-tamper-readset', attestation: tamperedReadSet }),
        error => error.code === 'ANCHOR_BINDING_REJECTED'
      );
      // c) подмена durable readSet уже после аттестации: добавляем лишнее независимое чтение.
      const existingRead = run.store.readEvidence(run.runDir).find(item => item.envelope.kind === 'independent-read');
      run.store.appendEvidence(run.runDir, {
        runId: run.frozen.manifest.runId, manifestSha256: run.frozen.manifestSha256,
        fixtureId: run.frozen.fixture.fixtureId, stepId: existingRead.envelope.stepId, producer: 'verification',
        kind: 'independent-read', requestId: existingRead.artifact.requestId, entity: existingRead.artifact.entity,
        checkIds: existingRead.envelope.checkIds, artifact: { ...existingRead.artifact, observedAt: new Date().toISOString() },
        parentEvidenceIds: existingRead.envelope.parentEvidenceIds
      });
      await assert.rejects(
        () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-readset-durable', attestation: worker.attestation }),
        error => error.code === 'INTEGRITY_ERROR' || error.code === 'ANCHOR_BINDING_REJECTED'
      );
    } finally {
      await signer.close();
    }
  } finally {
    await worker.close();
  }
});

test('P0-01: повтор аттестации другого runId отвергается', { timeout: 120000 }, async t => {
  const w = await makeWorld(t);
  const first = makeRun(w, 'prov-run-a');
  w.store = first.store;
  const entityA = await realMutation(w, first.frozen);
  appendFullChain(first.store, first.runDir, first.frozen, entityA);
  const approvalA = await approveRun(w, first.frozen);
  const workerA = await trustedWorker(w, first, approvalA);
  try {
    const second = makeRun(w, 'prov-run-b');
    const entityB = await realMutation(w, second.frozen);
    appendFullChain(second.store, second.runDir, second.frozen, entityB);
    const approvalB = await approveRun(w, second.frozen);
    publishCandidate(second.runDir, (await (async () => {
      const workerB = await trustedWorker(w, second, approvalB);
      try { return workerB.payload.verdict; } finally { await workerB.close(); }
    })()));
    const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
    try {
      await signer.registerVerificationKey(second.frozen.manifest.runId, workerA.verificationPublicKey, workerA.verificationPid, workerA.sessionNonce);
      await assert.rejects(
        () => signer.sign({ runDir: second.runDir, approvalId: approvalB, anchorId: 'anchor-replay', attestation: workerA.attestation }),
        error => error.code === 'ANCHOR_BINDING_REJECTED'
      );
      assert.equal(fs.existsSync(path.join(w.trustRoot, 'anchors', 'anchor-replay.json')), false);
    } finally {
      await signer.close();
    }
  } finally {
    await workerA.close();
  }
});

test('P0-01: наблюдатель не показывает PASS на подложном прогоне и без аттестации', { timeout: 120000 }, async t => {
  const w = await makeWorld(t);
  const run = makeRun(w, 'prov-observer');
  w.store = run.store;
  const entity = await realMutation(w, run.frozen);
  appendFullChain(run.store, run.runDir, run.frozen, entity);
  const approvalId = await approveRun(w, run.frozen);
  const result = await genuinePass(w, run, approvalId, path.join(w.secretsDir, 'anchor.key'));
  const observedBefore = observeTrustedVerdict({ store: run.store, runDir: run.runDir, frozen: run.frozen, trust: w.trust, trustRoot: w.trustRoot });
  assert.equal(observedBefore.passed, true);
  // a) удаление аттестации Verification из trust root закрывает PASS.
  const recordFile = path.join(w.trustRoot, 'verification', run.frozen.manifest.runId + '.json');
  const savedRecord = fs.readFileSync(recordFile);
  fs.rmSync(recordFile);
  const withoutRecord = observeTrustedVerdict({ store: run.store, runDir: run.runDir, frozen: run.frozen, trust: w.trust, trustRoot: w.trustRoot });
  assert.equal(withoutRecord.passed, false);
  assert.equal(withoutRecord.trusted, false);
  assert.equal(withoutRecord.reasonCode, 'VERIFICATION_ATTESTATION_MISSING');
  // b) подмена аттестации ломает подпись и тоже закрывает PASS.
  fs.writeFileSync(recordFile, canonical({ ...JSON.parse(savedRecord.toString('utf8')), nonce: 'ef'.repeat(32) }) + String.fromCharCode(10));
  const tampered = observeTrustedVerdict({ store: run.store, runDir: run.runDir, frozen: run.frozen, trust: w.trust, trustRoot: w.trustRoot });
  assert.equal(tampered.passed, false);
  assert.equal(tampered.trusted, false);
  // c) подложный прогон без доверенного Worker: PASS-candidate без анкера не становится PASS.
  fs.writeFileSync(recordFile, savedRecord);
  const forged = makeRun(w, 'prov-forged-observe', { descriptorOverrides: {} });
  const forgedEntity = { kind: forged.frozen.operation.entityKind, id: 'forged-record' };
  const chain = appendFullChain(forged.store, forged.runDir, forged.frozen, forgedEntity);
  const { buildCandidate } = await import('../packages/trust/anchor.mjs');
  publishCandidate(forged.runDir, buildCandidate({
    frozen: forged.frozen, verdict: 'PASS', reasonCode: 'NONE', message: 'forged',
    checks: forged.frozen.operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds: [chain.response.evidenceId] }))
  }));
  const observedForged = observeTrustedVerdict({ store: forged.store, runDir: forged.runDir, frozen: forged.frozen, trust: w.trust, trustRoot: w.trustRoot });
  assert.equal(observedForged.passed, false);
  assert.equal(observedForged.trusted, false);
  void result;
});

test('P0-01: подмена сертифицированного публичного ключа Verification не даёт анкер', { timeout: 90000 }, async t => {
  const w = await makeWorld(t);
  const run = makeRun(w, 'prov-key-substitution');
  w.store = run.store;
  const entity = await realMutation(w, run.frozen);
  appendFullChain(run.store, run.runDir, run.frozen, entity);
  const approvalId = await approveRun(w, run.frozen);
  const worker = await trustedWorker(w, run, approvalId);
  try {
    publishCandidate(run.runDir, worker.payload.verdict);
    const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
    try {
      await signer.registerVerificationKey(run.frozen.manifest.runId, worker.verificationPublicKey, worker.verificationPid, worker.sessionNonce);
      const forged = { ...worker.attestation, verificationKeyId: 'ff'.repeat(32), keyId: 'ff'.repeat(32) };
      await assert.rejects(
        () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-key-forged', attestation: forged }),
        error => error.code === 'ANCHOR_BINDING_REJECTED'
      );
    } finally {
      await signer.close();
    }
  } finally {
    await worker.close();
  }
  assert.equal(fs.existsSync(path.join(w.trustRoot, 'anchors', 'anchor-key-forged.json')), false);
});

test('P0-01: Worker без IPC-сеанса Control не получает session nonce и не даёт анкер', { timeout: 60000 }, async t => {
  const w = await makeWorld(t);
  const run = makeRun(w, 'prov-no-session');
  w.store = run.store;
  const entity = await realMutation(w, run.frozen);
  appendFullChain(run.store, run.runDir, run.frozen, entity);
  const approvalId = await approveRun(w, run.frozen);
  const entry = fileURLToPath(new URL('../apps/verification/trusted-worker.mjs', import.meta.url));
  // Тот же образ/путь/аргументы, но IPC-сеанс Control не открыт: SESSION не отправляется.
  const child = fork(entry, [run.runDir, run.frozen.manifestSha256], {
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    env: {
      ...process.env,
      ...buildVerificationEnv({
        trustRoot: w.trustRoot,
        environmentId: run.frozen.manifest.environment.id,
        environmentGeneration: 1,
        standPublicKey: w.stand.standPublicKey,
        fixtureToken: w.stand.authToken,
        approvalId
      })
    }
  });
  try {
    const message = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { try { child.kill(); } catch { /* уже завершён */ } reject(new Error('Worker не сообщил об отсутствии IPC-сеанса')); }, 12000);
      child.on('message', value => { clearTimeout(timer); resolve(value); });
      child.once('exit', code => { clearTimeout(timer); resolve({ type: 'EXIT', code }); });
    });
    assert.equal(message.type, 'ERROR');
    assert.equal(message.code, 'SESSION_MISSING');
    assert.equal(fs.existsSync(path.join(w.trustRoot, 'anchors')), false);
  } finally {
    try { child.kill(); } catch { /* уже завершён */ }
  }
});

test('P0-01: подмена session nonce после аттестации отвергается', { timeout: 90000 }, async t => {
  const w = await makeWorld(t);
  const run = makeRun(w, 'prov-nonce-tamper');
  w.store = run.store;
  const entity = await realMutation(w, run.frozen);
  appendFullChain(run.store, run.runDir, run.frozen, entity);
  const approvalId = await approveRun(w, run.frozen);
  const worker = await trustedWorker(w, run, approvalId);
  try {
    publishCandidate(run.runDir, worker.payload.verdict);
    const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
    try {
      await signer.registerVerificationKey(run.frozen.manifest.runId, worker.verificationPublicKey, worker.verificationPid, worker.sessionNonce);
      const tampered = { ...worker.payload.attestation, nonce: 'ef'.repeat(32) };
      await assert.rejects(
        () => signer.sign({ runDir: run.runDir, approvalId, anchorId: 'anchor-nonce-tamper', attestation: tampered }),
        error => error.code === 'ANCHOR_BINDING_REJECTED'
      );
      assert.equal(fs.existsSync(path.join(w.trustRoot, 'anchors', 'anchor-nonce-tamper.json')), false);
    } finally {
      await signer.close();
    }
  } finally {
    await worker.close();
  }
});

test('P0-01: повтор session nonce другого runId отвергается', { timeout: 120000 }, async t => {
  const w = await makeWorld(t);
  const runA = makeRun(w, 'prov-nonce-a');
  w.store = runA.store;
  const entityA = await realMutation(w, runA.frozen);
  appendFullChain(runA.store, runA.runDir, runA.frozen, entityA);
  const approvalA = await approveRun(w, runA.frozen);
  const workerA = await trustedWorker(w, runA, approvalA);
  const runB = makeRun(w, 'prov-nonce-b');
  const entityB = await realMutation(w, runB.frozen);
  appendFullChain(runB.store, runB.runDir, runB.frozen, entityB);
  const approvalB = await approveRun(w, runB.frozen);
  const workerB = await trustedWorker(w, runB, approvalB);
  try {
    publishCandidate(runB.runDir, workerB.payload.verdict);
    const signer = spawnAnchorSigner({ trustRoot: w.trustRoot, anchorKeyPath: path.join(w.secretsDir, 'anchor.key') });
    try {
      // Для runId B регистрируется ключ/pid B, но session nonce от сеанса другого runId.
      await signer.registerVerificationKey(runB.frozen.manifest.runId, workerB.verificationPublicKey, workerB.verificationPid, workerA.sessionNonce);
      await assert.rejects(
        () => signer.sign({ runDir: runB.runDir, approvalId: approvalB, anchorId: 'anchor-nonce-replay', attestation: workerB.payload.attestation }),
        error => error.code === 'ANCHOR_BINDING_REJECTED'
      );
      assert.equal(fs.existsSync(path.join(w.trustRoot, 'anchors', 'anchor-nonce-replay.json')), false);
    } finally {
      await signer.close();
    }
  } finally {
    await workerA.close();
    await workerB.close();
  }
});
