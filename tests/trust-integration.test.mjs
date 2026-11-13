import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { revokeApproval, signApproval } from '../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import { startAnchorSigner } from '../packages/trust/anchor-signer.mjs';
import { verifyAnchorStatement, loadAnchor, readCandidate, readTerminalChoice } from '../packages/trust/anchor.mjs';
import { currentUserSid } from '../packages/trust/windows-sid.mjs';
import { start } from '../apps/control/run.mjs';
import { observeTrusted, startTrusted } from '../apps/control/trusted.mjs';

// Сквозной доверенный прогон на живом локальном стенде. Не мок: реальный Chromium,
// реальный POST, реальный независимый GET, реальный подписант в named pipe.
const sid = currentUserSid();

async function world(t, { standOptions = {}, recordOverrides = {} } = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-e2e-'));
  const root = path.join(base, 'store');
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust');
  const created = await createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = await serveLocalFixture({ generation: 1, ...standOptions });
  const record = signEnvironmentRecord(ownerKey, {
    environmentId: stand.environmentId,
    generation: stand.generation,
    kind: 'local-stand',
    status: 'active',
    origin: stand.baseUrl,
    standKeyId: stand.standKeyId,
    credentialRef: 'local:fixture-token',
    ...recordOverrides
  });
  commitEnvironmentRecord(trust, trustRoot, record);
  const signer = startAnchorSigner({ trustRoot, secretsDir });
  await signer.ready;
  const owner = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner',
    roles: ['owner'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  // Карточку подписывает owner, поэтому keyId указывает на его публичный ключ; личность оператора
  // подтверждается SID Windows, а не ключом подписи.
  const operator = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator',
    roles: ['operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  t.after(async () => {
    await signer.close();
    await stand.close();
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return { base, root, secretsDir, trustRoot, trust, ownerKey, stand, record, signer, owner, operator, created };
}

function prepare(w, { runId = 'trust-run-' + randomUUID().slice(0, 8) } = {}) {
  const contract = localFixtureContract(w.stand, runId);
  w.stand.fixtureId = contract.fixtureId;
  const bundle = localBundle(w.stand, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  // Запас на загруженной машине: срок не входит в подписанные поля approval.
  bundle.manifest.budget.deadlineMs = 60000;
  return { bundle, contract, runId };
}

function approvalFields(w, { bundle, contract, overrides = {}, approvalId = 'approval-' + randomUUID().slice(0, 8) } = {}) {
  const issuedAt = new Date().toISOString();
  return {
    approvalId,
    issuerPrincipalId: 'local-owner',
    subjectPrincipalId: 'local-operator',
    operationId: bundle.operation.id,
    operationVersion: bundle.operation.version,
    scenarioContentSha256: bundle.scenario.approval.contentSha256,
    operationSha256: digest(bundle.operation),
    approvedInputsHash: digest(bundle.operation.inputs),
    fixtureId: contract.fixtureId,
    targetEnvironmentId: w.stand.environmentId,
    environmentGeneration: w.stand.generation,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt,
    expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
    approvalNonce: 'ab'.repeat(32),
    keyId: w.created.ownerKeyId,
    ...overrides
  };
}

function trustedOptions(w, approval, extra = {}) {
  return {
    root: w.root,
    trustRoot: w.trustRoot,
    approvalId: approval.approvalId,
    approval,
    issuer: w.owner,
    subject: w.operator,
    signerPipe: w.signer.pipePath,
    standPublicKey: w.stand.standPublicKey,
    fixtureToken: w.stand.authToken,
    ...extra
  };
}

function evidenceOf(w, runId) {
  const store = new RunStore(w.root);
  return store.readEvidence(store.runPath(runId));
}

test('T-01: доверенный прогон публикует PASS только с анкером', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  const result = await startTrusted(bundle, trustedOptions(w, approval));
  assert.equal(result.verdict.verdict, 'PASS');
  assert.equal(w.stand.mutationCount, 1);
  const choice = readTerminalChoice(result.runDir);
  assert.equal(choice.outcome, 'anchor');
  const statement = loadAnchor(w.trustRoot, choice.anchorId);
  const body = verifyAnchorStatement(w.trust, statement);
  assert.equal(body.candidateSha256, digest(result.verdict));
  assert.equal(body.runId, bundle.manifest.runId);
  const items = evidenceOf(w, bundle.manifest.runId);
  assert.equal(items.filter(item => item.envelope.kind === 'verdict').length, 1);
  assert.equal(items.filter(item => item.envelope.kind === 'request').length, 1);
  const consumption = path.join(w.trustRoot, 'consumption', approval.approvalId + '.json');
  assert.equal(fs.existsSync(consumption), true);
  const observed = await observeTrusted({ root: w.root, trustRoot: w.trustRoot, runId: bundle.manifest.runId });
  assert.equal(observed.passed, true);
  assert.equal(observed.verdict.verdict, 'PASS');
  assert.equal(w.stand.mutationCount, 1);
});

test('T-02: тот же approval на другом runId не даёт второй мутации', { timeout: 60000 }, async t => {
  const w = await world(t);
  const first = prepare(w, { runId: 'trust-replay-1' });
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle: first.bundle, contract: first.contract }), w.trust, w.trustRoot);
  const ok = await startTrusted(first.bundle, trustedOptions(w, approval));
  assert.equal(ok.verdict.verdict, 'PASS');
  const second = prepare(w, { runId: 'trust-replay-2' });
  const blocked = await startTrusted(second.bundle, trustedOptions(w, approval));
  assert.equal(blocked.verdict.verdict, 'BLOCKED');
  assert.equal(w.stand.mutationCount, 1);
});

test('T-03: чужой SID не получает доверенный прогон', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  const foreign = signTrustedDocument(w.ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator',
    roles: ['operator'], keyId: w.created.ownerKeyId, windowsSid: 'S-1-5-21-9999999999-1-1-1', status: 'active'
  });
  const result = await startTrusted(bundle, trustedOptions(w, approval, { subject: foreign }));
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'AUTH_UNAVAILABLE');
  assert.equal(w.stand.mutationCount, 0);
});

test('T-04: просроченный approval не даёт мутации', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const past = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const fields = approvalFields(w, { bundle, contract });
  const approval = signApproval(w.ownerKey, { ...fields, issuedAt: past, expiresAt: new Date(Date.parse(past) + 60 * 1000).toISOString() }, w.trust, w.trustRoot);
  const result = await startTrusted(bundle, trustedOptions(w, approval));
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(w.stand.mutationCount, 0);
});

test('T-05: отозванный approval не даёт мутации', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  revokeApproval(w.ownerKey, w.trustRoot, { approvalId: approval.approvalId, revokedAt: new Date().toISOString(), reason: 'owner-revoked', keyId: w.created.ownerKeyId });
  const result = await startTrusted(bundle, trustedOptions(w, approval));
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(w.stand.mutationCount, 0);
});

test('T-06: approval на другие входы не даёт мутации', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const fields = approvalFields(w, { bundle, contract });
  const approval = signApproval(w.ownerKey, { ...fields, approvedInputsHash: digest({ title: 'подмена', executorId: 'x', comment: 'y' }) }, w.trust, w.trustRoot);
  const result = await startTrusted(bundle, trustedOptions(w, approval));
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'CONTRACT_INVALID');
  assert.equal(w.stand.mutationCount, 0);
});

test('T-07: вид среды dev не получает ALLOW', { timeout: 60000 }, async t => {
  const w = await world(t, { recordOverrides: { kind: 'dev', origin: 'https://example.invalid/' } });
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract, overrides: { targetEnvironmentId: w.stand.environmentId } }), w.trust, w.trustRoot);
  const result = await startTrusted(bundle, trustedOptions(w, approval));
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'ENVIRONMENT_CHANGED');
  assert.equal(w.stand.mutationCount, 0);
});

test('T-08: без анкера PASS не публикуется, POST остаётся один', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  const result = await startTrusted(bundle, trustedOptions(w, approval, { signerPipe: null }));
  assert.equal(result.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(result.verdict.reasonCode, 'EVIDENCE_MISSING');
  assert.equal(w.stand.mutationCount, 1);
  const choice = readTerminalChoice(result.runDir);
  assert.equal(choice.outcome, 'budget-inconclusive');
  const observed = await observeTrusted({ root: w.root, trustRoot: w.trustRoot, runId: bundle.manifest.runId });
  assert.equal(observed.passed, false);
  assert.equal(w.stand.mutationCount, 1);
});

test('T-09: старый start() отвергает аргументы доверенного режима', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  await assert.rejects(
    () => start(bundle, { root: w.root, trustRoot: w.trustRoot, approvalId: approval.approvalId, fixtureToken: w.stand.authToken }),
    error => error.code === 'CONTRACT_INVALID'
  );
  assert.equal(w.stand.mutationCount, 0);
});
test('T-10: отказ на T-A не запускает Browser и не выдаёт секрет мутации', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  const expired = signApproval(w.ownerKey, {
    ...approvalFields(w, { bundle, contract }),
    issuedAt: new Date(Date.now() - 3_600_000).toISOString(),
    expiresAt: new Date(Date.now() - 3_000_000).toISOString()
  }, w.trust, w.trustRoot);
  const result = await startTrusted(bundle, trustedOptions(w, expired));
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(w.stand.mutationCount, 0);
  const store = new RunStore(w.root);
  const events = store.readEvents(result.runDir).map(event => event.type);
  assert.equal(events.includes('READY'), false);
  assert.equal(events.includes('REQUEST_DURABLE'), false);
  const items = store.readEvidence(result.runDir);
  assert.equal(items.some(item => item.envelope.kind === 'request'), false);
  assert.equal(items.filter(item => item.envelope.kind === 'verdict').length, 1);
  assert.equal(fs.existsSync(path.join(w.trustRoot, 'consumption', approval.approvalId + '.json')), false);
});
test('T-11: старый PASS, принятый через startTrusted, не показывается как доверенный', { timeout: 90000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const legacy = await start(bundle, { root: w.root, fixtureToken: w.stand.authToken });
  assert.equal(legacy.verdict.verdict, 'PASS');
  assert.equal(w.stand.mutationCount, 1);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  await assert.rejects(
    () => startTrusted(bundle, trustedOptions(w, approval)),
    error => error.code === 'INTEGRITY_ERROR'
  );
  assert.equal(w.stand.mutationCount, 1);
  const observed = await observeTrusted({ root: w.root, trustRoot: w.trustRoot, runId: bundle.manifest.runId });
  assert.equal(observed.passed, false);
});

test('T-12: потеря анкера закрывает доверенный PASS для start и reconcile', { timeout: 90000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  const first = await startTrusted(bundle, trustedOptions(w, approval));
  assert.equal(first.verdict.verdict, 'PASS');
  const choice = readTerminalChoice(first.runDir);
  fs.rmSync(path.join(w.trustRoot, 'anchors', choice.anchorId + '.json'));
  await assert.rejects(
    () => startTrusted(bundle, trustedOptions(w, approval)),
    error => error.code === 'INTEGRITY_ERROR'
  );
  await assert.rejects(
    () => import('../apps/control/trusted.mjs').then(module => module.reconcileTrusted({
      root: w.root, trustRoot: w.trustRoot, approvalId: approval.approvalId, approval,
      issuer: w.owner, subject: w.operator, signerPipe: w.signer.pipePath,
      standPublicKey: w.stand.standPublicKey, runId: bundle.manifest.runId
    })),
    error => error.code === 'INTEGRITY_ERROR'
  );
  assert.equal(w.stand.mutationCount, 1);
  const observed = await observeTrusted({ root: w.root, trustRoot: w.trustRoot, runId: bundle.manifest.runId });
  assert.equal(observed.passed, false);
});
test('T-13: повреждённый реестр сред даёт AUTH_UNAVAILABLE и ноль мутаций', { timeout: 60000 }, async t => {
  const w = await world(t);
  const { bundle, contract } = prepare(w);
  const approval = signApproval(w.ownerKey, approvalFields(w, { bundle, contract }), w.trust, w.trustRoot);
  fs.writeFileSync(path.join(w.trustRoot, 'environments', w.stand.environmentId, '1.json'), '{');
  const result = await startTrusted(bundle, trustedOptions(w, approval));
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'AUTH_UNAVAILABLE');
  assert.equal(w.stand.mutationCount, 0);
});
