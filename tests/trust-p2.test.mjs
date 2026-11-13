// WP-08 P2-регрессии: R-02 (junction в keygen), approvalId-only, E-04, публикация.
// Каждый тест воспроизводит дефект аудита WP-08 и падает, если дефект вернётся.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { digest, scenarioApprovalHash } from '../packages/core/canonical.mjs';
import { verifyFrozenBundle } from '../packages/core/bundle.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { consumeDispatch, readApprovalState, signApproval } from '../packages/trust/approval.mjs';

const KEYGEN = path.resolve('packages/trust/keygen.mjs');

function work(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'qa-p2-' + prefix + '-'));
}

function runKeygen(secrets, trustRoot) {
  return spawnSync(process.execPath, [KEYGEN, '--secrets', secrets, '--trust-root', trustRoot], {
    cwd: path.resolve('.'), encoding: 'utf8', windowsHide: true, timeout: 60000
  });
}

// R-02: реальный путь (junction) в каталог прогонов обходит строковую проверку сегмента "runs".
test('R-02: keygen отвергает junction внутрь каталога прогонов', () => {
  const base = work('r02-junction');
  try {
    const store = new RunStore(path.join(base, 'store'));
    const runDir = store.runPath('run-02');
    fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
    const alias = path.join(base, 'aliased-run');
    // junction не требует прав администратора на Windows и разрешается как реальный каталог.
    fs.symlinkSync(runDir, alias, 'junction');
    const secrets = path.join(alias, 'secrets');
    const result = runKeygen(secrets, path.join(base, 'trust'));
    assert.notEqual(result.status, 0, 'keygen не должен принимать путь секретов через junction в runs');
    assert.match(String(result.stderr), /TRUST_STORE_UNAVAILABLE/);
    assert.equal(fs.existsSync(path.join(runDir, 'secrets')), false, 'секреты не должны появиться в каталоге прогона');
    assert.equal(fs.existsSync(path.join(secrets, 'owner.key')), false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('R-02: keygen отвергает junction для trust root внутрь каталога прогонов', () => {
  const base = work('r02-junction-trust');
  try {
    const store = new RunStore(path.join(base, 'store'));
    const runDir = store.runPath('run-03');
    fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
    const alias = path.join(base, 'aliased-trust');
    fs.symlinkSync(runDir, alias, 'junction');
    const result = runKeygen(path.join(base, 'secrets'), path.join(alias, 'trust'));
    assert.notEqual(result.status, 0);
    assert.match(String(result.stderr), /TRUST_STORE_UNAVAILABLE/);
    assert.equal(fs.existsSync(path.join(runDir, 'trust')), false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});
const P2_SID = 'S-1-5-21-p2-operator';
let p2Counter = 0;
const p2Next = prefix => prefix + '-' + String(++p2Counter).padStart(4, '0');

async function trustFixture(prefix) {
  const base = work(prefix);
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust-root');
  const created = await createTrustRoot({ secretsDir, trustRoot });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const issuer = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner', 'operator'],
    keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-owner', status: 'active'
  });
  const subject = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'],
    keyId: created.ownerKeyId, windowsSid: P2_SID, status: 'active'
  });
  const store = new RunStore(path.join(base, 'store'));
  return { base, secretsDir, trustRoot, trust, ownerKey, created, issuer, subject, store, cleanup: () => fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }) };
}

function p2Run(store, tag) {
  const runId = p2Next('run-p2-' + tag);
  const descriptor = { environmentId: 'local-stand', baseUrl: 'http://127.0.0.1:9/', fingerprint: 'fp-p2', fixtureId: 'fixture-' + runId };
  const fixture = localFixtureContract(descriptor, runId);
  const bundle = localBundle({ ...descriptor, fixtureId: fixture.fixtureId }, { runId });
  bundle.fixture = fixture;
  bundle.manifest.fixtureSha256 = digest(fixture);
  const runDir = store.snapshot(bundle, null);
  return { runId, runDir, bundle, fixture };
}
function p2Frozen(store, tag) {
  const run = p2Run(store, tag);
  return { ...run, frozen: verifyFrozenBundle(store, run.runDir) };
}

function p2Approval(env, frozen, overrides = {}) {
  const issuedAt = new Date(Date.now() - 60000).toISOString();
  const approvalId = p2Next('approval-p2');
  const approval = signApproval(env.ownerKey, {
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
    expiresAt: new Date(Date.parse(issuedAt) + 10 * 60000).toISOString(),
    approvalNonce: 'cd'.repeat(32),
    keyId: env.created.ownerKeyId,
    ...overrides
  }, env.trust, env.trustRoot);
  return { approvalId, approval };
}

function p2Expected(frozen) {
  return {
    operation: frozen.operation,
    inputs: frozen.operation.inputs,
    effects: frozen.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    scenarioContentSha256: scenarioApprovalHash(frozen.scenario),
    fixtureId: frozen.fixture.fixtureId,
    environmentId: frozen.manifest.environment.id,
    environmentGeneration: 1,
    resource: { method: 'POST', path: '/records' }
  };
}

// P2-02: путь «только approvalId» — документ читается из trust root, проверки те же.
test('P2-02: consumeDispatch/readApprovalState работают по approvalId без документа', async () => {
  const env = await trustFixture('p2-approval-id');
  try {
    const run = p2Frozen(env.store, 'approval-id');
    const { approvalId, approval } = p2Approval(env, run.frozen);
    const cards = { issuer: env.issuer, subject: env.subject, windowsSid: P2_SID, trustRoot: env.trustRoot };
    const state = readApprovalState(env.trust, null, { ...cards, approvalId, expected: p2Expected(run.frozen) });
    assert.equal(state.body.approvalId, approvalId);
    assert.equal(state.state, 'issued');
    const consumed = consumeDispatch({
      trust: env.trust, trustRoot: env.trustRoot, approval: null, approvalId,
      issuer: env.issuer, subject: env.subject, windowsSid: P2_SID,
      expected: p2Expected(run.frozen), runId: run.runId, decisionId: p2Next('decision-p2')
    });
    assert.equal(consumed.ack, true);
    assert.equal(consumed.consumption.runId, run.runId);
    assert.equal(fs.existsSync(path.join(env.trustRoot, 'consumption', approvalId + '.json')), true);
    const replay = consumeDispatch({
      trust: env.trust, trustRoot: env.trustRoot, approval: null, approvalId,
      issuer: env.issuer, subject: env.subject, windowsSid: P2_SID,
      expected: p2Expected(run.frozen), runId: run.runId, decisionId: p2Next('decision-p2')
    });
    assert.equal(replay.ack, false);
    assert.equal(replay.code, 'APPROVAL_CONSUMED');
    // С документом и без документа одинаковый отказ для чужого SID.
    const byId = (() => { try { return consumeDispatch({ trust: env.trust, trustRoot: env.trustRoot, approval: null, approvalId, issuer: env.issuer, subject: env.subject, windowsSid: 'S-1-5-21-foreign', expected: p2Expected(run.frozen), runId: run.runId, decisionId: p2Next('decision-p2') }); } catch (error) { return error.code; } })();
    const byDoc = (() => { try { consumeDispatch({ trust: env.trust, trustRoot: env.trustRoot, approval, approvalId, issuer: env.issuer, subject: env.subject, windowsSid: 'S-1-5-21-foreign', expected: p2Expected(run.frozen), runId: run.runId, decisionId: p2Next('decision-p2') }); } catch (error) { return error.code; } })();
    assert.equal(byId, 'CALLER_UNAUTHENTICATED');
    assert.equal(byDoc, byId);
  } finally {
    env.cleanup();
  }
});

// P2-02: подмена закреплённого документа видна и на пути без переданного документа.
test('P2-02: путь approvalId-only отвергает повреждённый закреплённый approval', async () => {
  const env = await trustFixture('p2-approval-corrupt');
  try {
    const run = p2Frozen(env.store, 'approval-corrupt');
    const { approvalId } = p2Approval(env, run.frozen);
    fs.writeFileSync(path.join(env.trustRoot, 'approvals', approvalId + '.json'), '{"schemaVersion":"0.2.0"');
    assert.throws(() => consumeDispatch({
      trust: env.trust, trustRoot: env.trustRoot, approval: null, approvalId,
      issuer: env.issuer, subject: env.subject, windowsSid: P2_SID,
      expected: p2Expected(run.frozen), runId: run.runId, decisionId: p2Next('decision-p2')
    }), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  } finally {
    env.cleanup();
  }
});
