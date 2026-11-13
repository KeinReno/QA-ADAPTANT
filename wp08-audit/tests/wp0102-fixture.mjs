// wp0102: независимая оснастка аудита WP-01/WP-02.
// Не импортирует тестовые хелперы поставки (tests/redteam/_lib.mjs и т.п.) — только продуктовый код.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { digest } from '../../packages/core/canonical.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../../packages/trust/identity.mjs';
import { signApproval } from '../../packages/trust/approval.mjs';
import { currentUserSid } from '../../packages/trust/windows-sid.mjs';

export function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Реальный SID не хранится в репозитории: читается у токена процесса, как в продукте.
export const SID = currentUserSid();
export const FOREIGN_SID = 'S-1-5-21-9999999999-8888888888-7777777777-1002';

export async function makeWorld({ prefix = 'wp0102-world-', sid = SID, principalId = 'wp0102-operator' } = {}) {
  const base = tempDir(prefix);
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust-root');
  const created = await createTrustRoot({ secretsDir, trustRoot });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const anchorKey = await unwrapPrivateKey(path.join(secretsDir, 'anchor.key'));

  const inputs = { title: 'Запись аудита WP-08', executorId: 'wp0102-operator', comment: 'независимый прогон' };
  const effects = [
    { id: 'title-saved', field: 'title', equals: 'Запись аудита WP-08' },
    { id: 'executor-saved', field: 'executorId', equals: 'wp0102-operator' },
    { id: 'comment-saved', field: 'comment', equals: 'независимый прогон' }
  ];
  const operation = { id: 'local-create-record', version: '1.0.0', effects };
  const scenarioContentSha256 = digest({ schemaVersion: '0.1.0', id: 'local-create', status: 'APPROVED' });
  const fixtureId = 'fixture-wp0102';

  const issuer = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'wp0102-owner',
    roles: ['owner'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const subject = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId,
    roles: ['operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });

  return { base, secretsDir, trustRoot, created, trust, ownerKey, anchorKey, sid, inputs, effects, operation, scenarioContentSha256, fixtureId, issuer, subject };
}

export function fields(world, approvalId, overrides = {}) {
  const now = Date.now();
  return {
    approvalId,
    issuerPrincipalId: 'wp0102-owner',
    subjectPrincipalId: 'wp0102-operator',
    operationId: world.operation.id,
    operationVersion: world.operation.version,
    scenarioContentSha256: world.scenarioContentSha256,
    operationSha256: digest(world.operation),
    approvedInputsHash: digest(world.inputs),
    fixtureId: world.fixtureId,
    targetEnvironmentId: 'local-stand',
    environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: world.effects,
    issuedAt: new Date(now - 60_000).toISOString(),
    expiresAt: new Date(now + 10 * 60_000).toISOString(),
    approvalNonce: 'ab'.repeat(32),
    keyId: world.created.ownerKeyId,
    ...overrides
  };
}

export function expected(world, overrides = {}) {
  return {
    operation: world.operation,
    inputs: world.inputs,
    effects: world.effects,
    scenarioContentSha256: world.scenarioContentSha256,
    fixtureId: world.fixtureId,
    environmentId: 'local-stand',
    environmentGeneration: 1,
    resource: { method: 'POST', path: '/records' },
    ...overrides
  };
}

export function commit(world, approvalId, overrides = {}) {
  return signApproval(world.ownerKey, fields(world, approvalId, overrides), world.trust, world.trustRoot);
}

export function dispatchRequest(world, approval, { runId, decisionId, fault, overrides = {} } = {}) {
  const request = {
    trustRoot: world.trustRoot,
    approval,
    issuer: world.issuer,
    subject: world.subject,
    windowsSid: world.sid,
    expected: expected(world),
    runId,
    decisionId: decisionId || 'decision-' + runId,
    ...overrides
  };
  if (fault) request.fault = fault;
  return request;
}

export function consumptionFile(world, approvalId) {
  return path.join(world.trustRoot, 'consumption', approvalId + '.json');
}

export function approvalFile(world, approvalId) {
  return path.join(world.trustRoot, 'approvals', approvalId + '.json');
}

export function removeWorld(world) {
  try { fs.rmSync(world.base, { recursive: true, force: true }); } catch { /* временный каталог */ }
}

export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value) + '\n');
}

export function waitForFile(file, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(file)) {
    if (Date.now() > deadline) throw new Error('не дождались файла: ' + file);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
  }
  return file;
}