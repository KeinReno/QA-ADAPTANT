import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { digest } from '../packages/core/canonical.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { consumeDispatch, revokeApproval, signApproval } from '../packages/trust/approval.mjs';

// R-01: аварийное завершение владельца файловой блокировки approval.
// Поведение остаётся fail-closed: второй ACK и второй расход не появляются.
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-r01-'));
const secretsDir = path.join(base, 'secrets');
const trustRoot = path.join(base, 'trust');
const created = await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const issuedAt = new Date(Date.now() - 60_000).toISOString();
const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
const inputs = { comment: 'заметка', executorId: 'operator-1', title: 'запись' };
const effects = [
  { id: 'title-saved', field: 'title', equals: 'запись' },
  { id: 'executor-saved', field: 'executorId', equals: 'operator-1' },
  { id: 'comment-saved', field: 'comment', equals: 'заметка' }
];
const operation = { id: 'local-create-record', version: '1.0.0', effects };
const scenarioContentSha256 = digest({ schemaVersion: '0.1.0', id: 'local-create', status: 'APPROVED' });
const sid = 'S-1-5-21-r01';
const issuer = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner', 'operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active' });
const subject = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active' });

function approvalFor(approvalId) {
  return signApproval(ownerKey, {
    approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: operation.id, operationVersion: operation.version, scenarioContentSha256,
    operationSha256: digest(operation), approvedInputsHash: digest(inputs),
    fixtureId: 'fixture-r01', targetEnvironmentId: 'local-stand', environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' }, allowedEffects: effects,
    issuedAt, expiresAt, approvalNonce: 'cd'.repeat(32), keyId: created.ownerKeyId
  }, trust, trustRoot);
}

function expected() {
  return { operation, inputs, effects, scenarioContentSha256, fixtureId: 'fixture-r01', environmentId: 'local-stand', environmentGeneration: 1 };
}

function request(approval, runId) {
  return { trustRoot, approval, issuer, subject, windowsSid: sid, expected: expected(), runId, decisionId: 'decision-' + runId };
}

test('R-01: осиротевшая блокировка оставляет систему fail-closed, второго ACK нет', { timeout: 30000 }, () => {
  const approval = approvalFor('approval-r01-orphan');
  const directory = path.join(trustRoot, 'guards');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'approval-r01-orphan.lock'), '');
  const started = Date.now();
  assert.throws(() => consumeDispatch(request(approval, 'run-r01')), error => error.code === 'CONSUMPTION_INCOMPLETE');
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= 4000, 'ожидание блокировки должно быть ограничено и fail-closed');
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-r01-orphan.json')), false);
});

test('R-01: отзыв при осиротевшей блокировке тоже не создаёт файл', { timeout: 30000 }, () => {
  const approval = approvalFor('approval-r01-revoke');
  const directory = path.join(trustRoot, 'guards');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'approval-r01-revoke.lock'), '');
  assert.throws(
    () => revokeApproval(ownerKey, trustRoot, { approvalId: approval.approvalId, revokedAt: new Date().toISOString(), reason: 'owner-revoked', keyId: created.ownerKeyId }),
    error => error.code === 'CONSUMPTION_INCOMPLETE'
  );
  assert.equal(fs.existsSync(path.join(trustRoot, 'revocations', 'approval-r01-revoke.json')), false);
});

test('R-01: ручное восстановление допустимо только после доказанной остановки и не даёт второго ACK', () => {
  const approval = approvalFor('approval-r01-recover');
  const directory = path.join(trustRoot, 'guards');
  fs.mkdirSync(directory, { recursive: true });
  const lock = path.join(directory, 'approval-r01-recover.lock');
  fs.writeFileSync(lock, '');
  // Владелец убедился, что ни один процесс QA не жив и расход не создан, после чего снял блокировку.
  assert.equal(fs.existsSync(path.join(trustRoot, 'consumption', 'approval-r01-recover.json')), false);
  fs.rmSync(lock);
  const first = consumeDispatch(request(approval, 'run-r01-recover'));
  assert.equal(first.ack, true);
  const again = consumeDispatch(request(approval, 'run-r01-recover'));
  assert.equal(again.ack, false);
  assert.equal(again.code, 'APPROVAL_CONSUMED');
  const file = path.join(trustRoot, 'consumption', 'approval-r01-recover.json');
  assert.equal(fs.existsSync(path.join(directory, 'approval-r01-recover.lock')), false);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).runId, 'run-r01-recover');
});
