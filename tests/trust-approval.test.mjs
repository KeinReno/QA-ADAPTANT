import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { digest } from '../packages/core/canonical.mjs';
import { consumeDispatch, readApprovalState, revokeApproval, signApproval, verifyApproval } from '../packages/trust/approval.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-approval-'));
const secretsDir = path.join(root, 'secrets');
const trustRoot = path.join(root, 'trust-root');
const created = await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const anchorKey = await unwrapPrivateKey(path.join(secretsDir, 'anchor.key'));
const issuedAt = '2026-11-13T00:00:00.000Z';
const expiresAt = '2026-11-13T00:10:00.000Z';
const now = '2026-11-13T00:05:00.000Z';
const inputs = { comment: 'заметка', executorId: 'operator-1', title: 'запись' };
const effects = [
  { id: 'title-saved', field: 'title', equals: 'запись' },
  { id: 'executor-saved', field: 'executorId', equals: 'operator-1' },
  { id: 'comment-saved', field: 'comment', equals: 'заметка' }
];
const operation = { id: 'local-create-record', version: '1.0.0', effects };
const scenarioContentSha256 = digest({ schemaVersion: '0.1.0', id: 'local-create', status: 'APPROVED' });
const issuer = signTrustedDocument(ownerKey, {
  schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner', 'operator'],
  keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-owner', status: 'active'
});
const subject = signTrustedDocument(ownerKey, {
  schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'],
  keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-operator', status: 'active'
});

test('одно поле входа меняет хеш, подмена не создаёт расход', () => {
  assert.notEqual(digest(inputs), digest({ ...inputs, title: 'другая' }));
  const approval = approvalFor('approval-inputs');
  assert.throws(() => verifyApproval(trust, approval, { ...context(approval), expected: { ...expected(), inputs: { ...inputs, title: 'другая' } } }), error => error.code === 'APPROVAL_MISMATCH');
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-inputs.json')), false);
});

test('чужая операция, fixture, сценарий, эффект и runId не получают ACK', () => {
  const approval = approvalFor('approval-mismatch');
  const file = path.join(trustRoot, 'consumption', 'approval-mismatch.json');
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-mismatch', decisionId: 'decision-mismatch', expected: { ...expected(), fixtureId: 'fixture-other' } })), error => error.code === 'APPROVAL_MISMATCH');
  assert.equal(fs.existsSync(file), false);
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-mismatch', decisionId: 'decision-mismatch', expected: { ...expected(), scenarioContentSha256: digest({ id: 'other' }) } })), error => error.code === 'APPROVAL_MISMATCH');
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-mismatch', decisionId: 'decision-mismatch', expected: { ...expected(), effects: [...effects].reverse() } })), error => error.code === 'APPROVAL_MISMATCH');
  const first = consumeDispatch(dispatch(approval, { runId: 'run-owner', decisionId: 'decision-owner' }));
  assert.equal(first.ack, true);
  const kept = fs.readFileSync(file);
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-other', decisionId: 'decision-other' })), error => error.code === 'APPROVAL_REPLAY');
  assert.deepEqual(fs.readFileSync(file), kept);
});

test('повтор того же runId не шлёт второй ACK и не восстанавливает право', () => {
  const approval = approvalFor('approval-once');
  const file = path.join(trustRoot, 'consumption', 'approval-once.json');
  const first = consumeDispatch(dispatch(approval, { runId: 'run-once', decisionId: 'decision-once' }));
  const kept = fs.readFileSync(file);
  const second = consumeDispatch(dispatch(approval, { runId: 'run-once', decisionId: 'decision-again' }));
  assert.equal(first.ack, true);
  assert.equal(second.ack, false);
  assert.equal(second.code, 'APPROVAL_CONSUMED');
  assert.deepEqual(fs.readFileSync(file), kept);
  const viewed = readApprovalState(trust, approval, { ...context(approval), now: '2026-11-13T00:20:00.000Z' });
  assert.equal(viewed.state, 'consumed');
  assert.equal(viewed.ack, false);
});

test('отзыв и просрочка до расхода запрещают мутацию и не создают файл', () => {
  const revoked = approvalFor('approval-revoked');
  revokeApproval(ownerKey, trustRoot, { approvalId: 'approval-revoked', reason: 'owner-revoked', revokedAt: now, keyId: created.ownerKeyId });
  assert.throws(() => consumeDispatch(dispatch(revoked, { runId: 'run-revoked', decisionId: 'decision-revoked' })), error => error.code === 'APPROVAL_REVOKED');
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-revoked.json')), false);
  assert.equal(fs.existsSync(path.join(trustRoot, 'revocations', 'approval-revoked.json')), true);
  const expired = approvalFor('approval-expired', { issuedAt: '2026-11-13T00:00:00.000Z', expiresAt: '2026-11-13T00:10:00.000Z' });
  assert.throws(() => consumeDispatch(dispatch(expired, { runId: 'run-expired', decisionId: 'decision-expired', now: '2026-11-13T00:10:00.000Z' })), error => error.code === 'APPROVAL_EXPIRED');
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-expired.json')), false);
  assert.throws(() => signApproval(ownerKey, fields('approval-long', { expiresAt: '2026-11-13T00:15:00.001Z' })), error => error.code === 'CONTRACT_INVALID');
});

test('чужой издатель, чужой субъект и ключ анкера не создают годный расход', () => {
  const foreignIssuer = approvalFor('approval-foreign-issuer', { issuerPrincipalId: 'other-owner' });
  assert.throws(() => verifyApproval(trust, foreignIssuer, context(foreignIssuer)), error => error.code === 'ROLE_DENIED');
  const foreignSubject = approvalFor('approval-foreign-subject', { subjectPrincipalId: 'other-operator' });
  assert.throws(() => consumeDispatch(dispatch(foreignSubject, { runId: 'run-subject', decisionId: 'decision-subject' })), error => error.code === 'ROLE_DENIED');
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-foreign-subject.json')), false);
  assert.throws(() => consumeDispatch(dispatch(approvalFor('approval-sid'), { runId: 'run-sid', decisionId: 'decision-sid', windowsSid: 'S-1-5-21-other' })), error => error.code === 'CALLER_UNAUTHENTICATED');
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-sid.json')), false);
  const anchorSigned = signTrustedDocument(anchorKey, { ...fields('approval-anchor'), schemaVersion: '0.2.0', domain: 'approval', keyId: created.anchorKeyId });
  assert.throws(() => verifyApproval(trust, anchorSigned, context(anchorSigned)), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
});

test('обрыв после CREATE_NEW и повреждённый файл не заменяются и не дают ACK', () => {
  const approval = approvalFor('approval-torn');
  const file = path.join(trustRoot, 'consumption', 'approval-torn.json');
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-torn', decisionId: 'decision-torn', fault: 'after-create' })), error => error.code === 'CONSUMPTION_INCOMPLETE');
  const torn = fs.readFileSync(file);
  assert.equal(torn.includes(Buffer.from('bodySha256')), false);
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-torn', decisionId: 'decision-torn' })), error => error.code === 'CONSUMPTION_INCOMPLETE');
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-torn-2', decisionId: 'decision-torn-2' })), error => error.code === 'CONSUMPTION_INCOMPLETE');
  assert.deepEqual(fs.readFileSync(file), torn);
  const corrupt = approvalFor('approval-corrupt');
  const corruptFile = path.join(trustRoot, 'consumption', 'approval-corrupt.json');
  fs.mkdirSync(path.dirname(corruptFile), { recursive: true });
  fs.writeFileSync(corruptFile, '{"approvalId":"approval-corrupt","bodySha256":"00"}\n');
  const before = fs.readFileSync(corruptFile);
  assert.throws(() => consumeDispatch(dispatch(corrupt, { runId: 'run-corrupt', decisionId: 'decision-corrupt' })), error => error.code === 'CONSUMPTION_INCOMPLETE');
  assert.deepEqual(fs.readFileSync(corruptFile), before);
});

test('EPERM синхронизации каталога не заменяет полное тело файла', () => {
  const approval = approvalFor('approval-dirsync');
  const result = consumeDispatch(dispatch(approval, { runId: 'run-dirsync', decisionId: 'decision-dirsync' }));
  assert.equal(result.ack, true);
  assert.equal(result.directorySync, 'EPERM');
  assert.equal(result.code, 'TRUST_OK');
  const file = path.join(trustRoot, 'consumption', 'approval-dirsync.json');
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(saved.bodySha256, digest({
    approvalId: saved.approvalId, runId: saved.runId, decisionId: saved.decisionId,
    inputsHash: saved.inputsHash, environmentGeneration: saved.environmentGeneration, consumedAt: saved.consumedAt
  }));
});

test('два процесса и один approval оставляют один полный файл и не больше одного ACK', async () => {
  const approval = approvalFor('approval-race');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-approval-race-'));
  const goFile = path.join(directory, 'go');
  const runs = [
    { runId: 'run-race-a', decisionId: 'decision-race-a' },
    { runId: 'run-race-b', decisionId: 'decision-race-b' }
  ];
  const children = runs.map(run => startRacer(directory, goFile, approval, run));
  await Promise.all(children.map(child => child.ready));
  fs.writeFileSync(goFile, 'go');
  const results = await Promise.all(children.map(child => child.done));
  const file = path.join(trustRoot, 'consumption', 'approval-race.json');
  const firstRead = fs.readFileSync(file);
  assert.equal(results.filter(result => result.ack).length, 1);
  assert.equal(results.filter(result => !result.ack && (result.code === 'APPROVAL_REPLAY' || result.code === 'CONSUMPTION_INCOMPLETE')).length, 1);
  const saved = JSON.parse(firstRead.toString('utf8'));
  assert.equal(saved.bodySha256, digest({
    approvalId: saved.approvalId, runId: saved.runId, decisionId: saved.decisionId,
    inputsHash: saved.inputsHash, environmentGeneration: saved.environmentGeneration, consumedAt: saved.consumedAt
  }));
  assert.throws(() => consumeDispatch(dispatch(approval, { runId: 'run-race-c', decisionId: 'decision-race-c' })), error => error.code === 'APPROVAL_REPLAY');
  assert.deepEqual(fs.readFileSync(file), firstRead);
});

test('просмотр состояния не расходует approval и модуль не ходит в сеть', () => {
  const approval = approvalFor('approval-view');
  const viewed = readApprovalState(trust, approval, context(approval));
  assert.equal(viewed.state, 'issued');
  assert.equal(viewed.ack, false);
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-view.json')), false);
  const source = fs.readFileSync(new URL('../packages/trust/approval.mjs', import.meta.url), 'utf8');
  for (const token of ['node:http', 'node:net', 'playwright', 'fetch(', 'rename(', 'unlink', 'rmSync']) assert.equal(source.includes(token), false);
  for (const file of ['apps/control/run.mjs', 'apps/browser/worker.mjs', 'apps/verification/worker.mjs']) {
    assert.equal(fs.readFileSync(file, 'utf8').includes('packages/trust'), false);
  }
});

function approvalFor(approvalId, overrides = {}) {
  return signApproval(ownerKey, fields(approvalId, overrides));
}

function fields(approvalId, overrides = {}) {
  return {
    approvalId,
    issuerPrincipalId: 'local-owner',
    subjectPrincipalId: 'local-operator',
    operationId: operation.id,
    operationVersion: operation.version,
    scenarioContentSha256,
    operationSha256: digest(operation),
    approvedInputsHash: digest(inputs),
    fixtureId: 'fixture-local',
    targetEnvironmentId: 'local-stand',
    environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: effects,
    issuedAt,
    expiresAt,
    approvalNonce: 'ab'.repeat(32),
    keyId: created.ownerKeyId,
    ...overrides
  };
}

function expected() {
  return {
    operation, inputs, effects, scenarioContentSha256, fixtureId: 'fixture-local',
    environmentId: 'local-stand', environmentGeneration: 1
  };
}

function context(approval) {
  return { trustRoot, issuer, subject, windowsSid: 'S-1-5-21-operator', now, approval };
}

function dispatch(approval, overrides) {
  return { ...context(approval), expected: expected(), consumedAt: now, ...overrides };
}

function startRacer(directory, goFile, approval, run) {
  const requestFile = path.join(directory, `${run.runId}.json`);
  const readyFile = path.join(directory, `${run.runId}.ready`);
  const resultFile = path.join(directory, `${run.runId}.result`);
  fs.writeFileSync(requestFile, JSON.stringify({ ...dispatch(approval, run), readyFile, goFile, resultFile }));
  const child = spawn(process.execPath, [path.join('tests', 'approval-consume-worker.mjs'), requestFile], { stdio: 'ignore' });
  return {
    ready: waitFor(readyFile),
    done: new Promise((resolve, reject) => {
      child.on('exit', code => {
        if (code !== 0) reject(new Error(`worker ${run.runId} завершился с ${code}`));
        else resolve(JSON.parse(fs.readFileSync(resultFile, 'utf8')));
      });
    })
  };
}

async function waitFor(file) {
  for (let attempt = 0; attempt < 200 && !fs.existsSync(file); attempt += 1) await new Promise(resolve => setTimeout(resolve, 10));
  if (!fs.existsSync(file)) throw new Error(`процесс не дошёл до барьера: ${file}`);
}
