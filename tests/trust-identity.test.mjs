import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { readAcl } from '../packages/trust/acl.mjs';
import { assertPrincipal, createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey, verifyTrustedDocument } from '../packages/trust/identity.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-'));
const secretsDir = path.join(root, 'secrets');
const trustRoot = path.join(root, 'trust-root');
const created = await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);

test('корень доверия загружает только публичные ключи', () => {
  assert.equal(trust.owner.keyId, created.ownerKeyId);
  assert.equal(trust['anchor-signer'].keyId, created.anchorKeyId);
  assert.equal(trust.owner.privateKey, undefined);
  assert.equal(JSON.stringify(trust).includes('protectedPkcs8'), false);
});

test('приватные файлы закрыты DPAPI и ACL текущего пользователя', async () => {
  for (const name of ['owner.key', 'anchor.key']) {
    const file = path.join(secretsDir, name);
    const bytes = fs.readFileSync(file);
    assert.equal(bytes.includes(created.ownerPkcs8), false);
    assert.equal(bytes.includes(created.anchorPkcs8), false);
    const acl = await readAcl(file);
    assert.equal(acl.protected, true);
    assert.deepEqual(acl.aces, [`${acl.current}|Allow`]);
  }
  const owner = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const card = signTrustedDocument(owner, principal());
  assert.equal(verifyTrustedDocument(trust, card).principalId, 'local-owner');
});

test('ключ анкера не создаёт годный approval, ключ owner не создаёт годный анкер', () => {
  const anchorSigned = signTrustedDocument(created.anchorPrivate, { schemaVersion: '0.2.0', domain: 'approval', keyId: created.anchorKeyId, approvalId: 'a-1' });
  assert.throws(() => verifyTrustedDocument(trust, anchorSigned), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  assert.throws(() => signTrustedDocument(created.anchorPrivate, { schemaVersion: '0.2.0', domain: 'approval', keyId: created.ownerKeyId, approvalId: 'a-2' }), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  const ownerSigned = signTrustedDocument(created.ownerPrivate, { schemaVersion: '0.2.0', domain: 'anchor-statement', keyId: created.ownerKeyId, runId: 'run-1' });
  assert.throws(() => verifyTrustedDocument(trust, ownerSigned), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
});

test('runner не издаёт approval, отозванный principal и чужой SID отвергаются', () => {
  const owner = verifyTrustedDocument(trust, signTrustedDocument(created.ownerPrivate, principal()));
  assertPrincipal(owner, { role: 'owner', domain: 'approval', windowsSid: 'S-1-5-21-owner' });
  assert.throws(() => assertPrincipal({ domain: 'principal', principalId: 'control', roles: ['runner'], keyId: null, windowsSid: null, status: 'active' }, { domain: 'approval' }), error => error.code === 'ROLE_DENIED');
  assert.throws(() => assertPrincipal({ ...owner, status: 'revoked' }), error => error.code === 'PRINCIPAL_REVOKED');
  assert.throws(() => assertPrincipal(owner, { windowsSid: 'S-1-5-21-other' }), error => error.code === 'CALLER_UNAUTHENTICATED');
});

test('отсутствующий корень доверия не подменяется пустым успехом', () => {
  assert.throws(() => loadTrustRoot(path.join(root, 'missing')), error => error.code === 'TRUST_STORE_UNAVAILABLE');
});

test('утилита генерации печатает только keyId и не вызывается из Control', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-cli-'));
  const result = spawnSync(process.execPath, [path.join('packages', 'trust', 'keygen.mjs'), '--secrets', path.join(dir, 'secrets'), '--trust-root', path.join(dir, 'trust-root')], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^owner [a-f0-9]{64}\r?\nanchor-signer [a-f0-9]{64}\r?\n$/);
  assert.equal(result.stdout.includes('BEGIN'), false);
  assert.equal(result.stdout.includes('protectedPkcs8'), false);
  for (const file of ['apps/control/run.mjs', 'apps/browser/worker.mjs', 'apps/verification/worker.mjs']) {
    assert.equal(fs.readFileSync(file, 'utf8').includes('packages/trust'), false);
  }
});

function principal() {
  return {
    schemaVersion: '0.2.0',
    domain: 'principal',
    principalId: 'local-owner',
    roles: ['owner', 'operator'],
    keyId: created.ownerKeyId,
    windowsSid: 'S-1-5-21-owner',
    status: 'active'
  };
}
