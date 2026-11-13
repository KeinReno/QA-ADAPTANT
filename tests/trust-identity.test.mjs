import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readAcl } from '../packages/trust/acl.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey, verifyAndAssertPrincipal, verifyTrustedDocument } from '../packages/trust/identity.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-'));
const secretsDir = path.join(root, 'secrets');
const trustRoot = path.join(root, 'trust-root');
const created = await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const anchorKey = await unwrapPrivateKey(path.join(secretsDir, 'anchor.key'));

test('корень доверия загружает только публичные ключи', () => {
  assert.deepEqual(Object.keys(created).sort(), ['anchorKeyId', 'ownerKeyId']);
  assert.equal(trust.owner.keyId, created.ownerKeyId);
  assert.equal(trust['anchor-signer'].keyId, created.anchorKeyId);
  assert.equal(JSON.stringify(trust).includes('protectedPkcs8'), false);
});

test('приватные файлы закрыты DPAPI и ACL текущего пользователя', async () => {
  for (const name of ['owner.key', 'anchor.key']) {
    const file = path.join(secretsDir, name);
    const key = await unwrapPrivateKey(file);
    const pkcs8 = key.export({ type: 'pkcs8', format: 'der' });
    assert.equal(fs.readFileSync(file).includes(pkcs8), false);
    const acl = await readAcl(file);
    assert.equal(acl.protected, true);
    assert.deepEqual(acl.aces, [`${acl.current}|Allow`]);
  }
  const card = signTrustedDocument(ownerKey, principal());
  assert.equal(verifyAndAssertPrincipal(trust, card, { role: 'owner', domain: 'approval' }).principalId, 'local-owner');
});

test('ключ анкера не создаёт годный approval, ключ owner не создаёт годный анкер', () => {
  const anchorSigned = signTrustedDocument(anchorKey, { schemaVersion: '0.2.0', domain: 'approval', keyId: created.anchorKeyId, approvalId: 'a-1' });
  assert.throws(() => verifyTrustedDocument(trust, anchorSigned), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  assert.throws(() => signTrustedDocument(anchorKey, { schemaVersion: '0.2.0', domain: 'approval', keyId: created.ownerKeyId, approvalId: 'a-2' }), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  const ownerSigned = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'anchor-statement', keyId: created.ownerKeyId, runId: 'run-1' });
  assert.throws(() => verifyTrustedDocument(trust, ownerSigned), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
});

test('неподписанная карточка не авторизует, даже если поля формально верны', () => {
  const signed = signTrustedDocument(ownerKey, principal());
  assert.throws(() => verifyAndAssertPrincipal(trust, principal(), { role: 'owner', domain: 'approval' }), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  const forged = { ...signed, roles: ['owner'] };
  assert.throws(() => verifyAndAssertPrincipal(trust, forged, { role: 'owner', domain: 'approval' }), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
});

test('после верной подписи runner, отзыв и чужой SID отвергаются', () => {
  const owner = verifyAndAssertPrincipal(trust, signTrustedDocument(ownerKey, principal()), { role: 'owner', domain: 'approval', windowsSid: 'S-1-5-21-owner' });
  const runner = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'control', roles: ['runner'], keyId: created.ownerKeyId, windowsSid: null, status: 'active' });
  assert.throws(() => verifyAndAssertPrincipal(trust, runner, { domain: 'approval' }), error => error.code === 'ROLE_DENIED');
  const revoked = signTrustedDocument(ownerKey, { ...principal(), status: 'revoked' });
  assert.throws(() => verifyAndAssertPrincipal(trust, revoked), error => error.code === 'PRINCIPAL_REVOKED');
  assert.throws(() => verifyAndAssertPrincipal(trust, signTrustedDocument(ownerKey, principal()), { windowsSid: 'S-1-5-21-other' }), error => error.code === 'CALLER_UNAUTHENTICATED');
  assert.equal(owner.principalId, 'local-owner');
});

test('отсутствующий и незавершённый корень доверия недействительны', async () => {
  assert.throws(() => loadTrustRoot(path.join(root, 'missing')), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  const broken = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-broken-'));
  await assert.rejects(createTrustRoot({ secretsDir: path.join(broken, 'secrets'), trustRoot: path.join(broken, 'trust-root'), fault: 'after-owner' }), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  assert.equal(fs.existsSync(path.join(broken, 'secrets', 'owner.key')), false);
  assert.equal(fs.existsSync(path.join(broken, 'trust-root', 'owner.pub')), false);
  assert.throws(() => loadTrustRoot(path.join(broken, 'trust-root')), error => error.code === 'TRUST_STORE_UNAVAILABLE');
});

test('ключи не попадают в репозиторий, каталог прогона, trust root и не заменяют существующие', async () => {
  const nested = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-nested-'));
  await assert.rejects(createTrustRoot({ secretsDir: nested, trustRoot: nested }), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  await assert.rejects(createTrustRoot({ secretsDir: path.join(nested, 'inner'), trustRoot: nested }), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  await assert.rejects(createTrustRoot({ secretsDir: path.join(repoRoot, 'must-not-create-secrets'), trustRoot: path.join(os.tmpdir(), 'qa-trust-outside') }), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  assert.equal(fs.existsSync(path.join(repoRoot, 'must-not-create-secrets')), false);
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-run-'));
  await assert.rejects(createTrustRoot({ secretsDir: path.join(runDir, 'secrets'), trustRoot: path.join(os.tmpdir(), 'qa-trust-run-public'), runDir }), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  const linkParent = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-link-'));
  const link = path.join(linkParent, 'secrets-link');
  fs.symlinkSync(repoRoot, link, 'junction');
  await assert.rejects(createTrustRoot({ secretsDir: link, trustRoot: path.join(linkParent, 'public') }), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  assert.equal(fs.existsSync(path.join(repoRoot, 'owner.key')), false);
  const kept = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-kept-'));
  const keptSecrets = path.join(kept, 'secrets');
  fs.mkdirSync(keptSecrets);
  fs.writeFileSync(path.join(keptSecrets, 'owner.key'), 'keep');
  await assert.rejects(createTrustRoot({ secretsDir: keptSecrets, trustRoot: path.join(kept, 'trust-root') }), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  assert.equal(fs.readFileSync(path.join(keptSecrets, 'owner.key'), 'utf8'), 'keep');
  assert.equal(fs.existsSync(path.join(kept, 'trust-root', 'owner.pub')), false);
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
