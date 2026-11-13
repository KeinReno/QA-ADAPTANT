// wp0102: независимая проверка WP-01 (identity, SID, domain separation, DPAPI/ACL, ready.json).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readAcl } from '../../packages/trust/acl.mjs';
import { protect, unprotect } from '../../packages/trust/dpapi.mjs';
import {
  createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey,
  verifyAndAssertPrincipal, verifyTrustedDocument
} from '../../packages/trust/identity.mjs';
import { assertCallerSid, currentUserSid, isValidSid } from '../../packages/trust/windows-sid.mjs';
import { signApproval } from '../../packages/trust/approval.mjs';
import { makeWorld, removeWorld, tempDir, SID, FOREIGN_SID, fields as approvalFields } from './wp0102-fixture.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const world = await makeWorld({ prefix: 'wp0102-identity-' });
test.after(() => removeWorld(world));

test('SID вызывающего читается у токена Windows, а не из окружения/JSON', () => {
  const sid = currentUserSid();
  assert.equal(isValidSid(sid), true, 'SID имеет форму S-1-5-21-...');
  const whoami = execFileSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
  const match = whoami.match(/"(S-\d-\d+(?:-\d+)+)"/);
  assert.ok(match, 'whoami вернул SID');
  assert.equal(sid, match[1], 'источник из токена совпал с независимым whoami');
  // Подмена всех правдоподобных источников «из строки» не меняет ответ.
  const moduleUrl = pathToFileURL(path.join(repoRoot, 'packages', 'trust', 'windows-sid.mjs')).href;
  const code = 'const m = await import(' + JSON.stringify(moduleUrl) + '); console.log(m.currentUserSid());';
  const spoofed = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, USERNAME: 'attacker', USERDOMAIN: 'EVIL', SID: FOREIGN_SID, QA_SID: FOREIGN_SID, WINDOWS_SID: FOREIGN_SID, windowsSid: FOREIGN_SID }
  });
  assert.equal(spoofed.status, 0, spoofed.stderr);
  assert.equal(spoofed.stdout.trim(), sid, 'переменные окружения не подменяют SID');
  assert.equal(spoofed.stdout.trim() === FOREIGN_SID, false);
});

test('карточка Principal с чужим SID не авторизует вызывающего', () => {
  const ownerCard = verifyAndAssertPrincipal(world.trust, world.issuer, { role: 'owner', domain: 'approval', windowsSid: world.sid });
  assert.equal(ownerCard.principalId, 'wp0102-owner');
  const forgedSidCard = signTrustedDocument(world.ownerKey, { ...world.subject, windowsSid: FOREIGN_SID });
  assert.throws(
    () => verifyAndAssertPrincipal(world.trust, forgedSidCard, { windowsSid: world.sid }),
    error => error.code === 'CALLER_UNAUTHENTICATED'
  );
  assert.throws(() => assertCallerSid(forgedSidCard, world.sid), error => error.code === 'CALLER_UNAUTHENTICATED');
  // Карточка без SID (runner) не проходит проверку SID вызывающего.
  const runner = signTrustedDocument(world.ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'wp0102-control',
    roles: ['runner'], keyId: world.created.ownerKeyId, windowsSid: null, status: 'active'
  });
  assert.throws(() => assertCallerSid(runner, world.sid), error => error.code === 'PRINCIPAL_UNKNOWN');
});

test('domain separation: ключ anchor не создаёт approval/revocation, ключ owner не создаёт anchor-statement', () => {
  // Наблюдение: signTrustedDocument связывает keyId с ключом, но не связывает домен с назначением ключа.
  // Технически подписать approval anchor-ключом можно; границу держат verifyTrustedDocument и закрепление.
  const anchorApproval = signTrustedDocument(world.anchorKey, {
    schemaVersion: '0.2.0', domain: 'approval', approvalId: 'wp0102-anchor-doc', keyId: world.created.anchorKeyId
  });
  assert.throws(() => verifyTrustedDocument(world.trust, anchorApproval), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  // Закрепление approval anchor-ключом отвергается: ключ не того назначения.
  assert.throws(
    () => signApprovalTest(world.anchorKey, 'wp0102-anchor-commit', world.created.anchorKeyId),
    error => error.code === 'APPROVAL_SIGNATURE_INVALID'
  );
  // Подпись anchor-ключом с подставленным keyId owner отвергается уже на подписи.
  assert.throws(
    () => signTrustedDocument(world.anchorKey, {
      schemaVersion: '0.2.0', domain: 'approval', approvalId: 'wp0102-anchor-subst', keyId: world.created.ownerKeyId
    }),
    error => error.code === 'APPROVAL_SIGNATURE_INVALID'
  );
  // Owner не создаёт годный anchor-statement и подпись domain=revocation для anchor-ключа.
  const ownerAnchor = signTrustedDocument(world.ownerKey, {
    schemaVersion: '0.2.0', domain: 'anchor-statement', anchorId: 'wp0102-anchor', keyId: world.created.ownerKeyId
  });
  assert.throws(() => verifyTrustedDocument(world.trust, ownerAnchor), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  const anchorRevocation = signTrustedDocument(world.anchorKey, {
    schemaVersion: '0.2.0', domain: 'revocation', approvalId: 'wp0102-anchor-rev', revokedAt: new Date().toISOString(), reason: 'owner-revoked', keyId: world.created.anchorKeyId
  });
  assert.throws(() => verifyTrustedDocument(world.trust, anchorRevocation), error => error.code === 'APPROVAL_SIGNATURE_INVALID');
  // Домен вне 0.2 отвергается до подписи.
  assert.throws(
    () => signTrustedDocument(world.ownerKey, { schemaVersion: '0.2.0', domain: 'terminal-choice', keyId: world.created.ownerKeyId }),
    error => error.code === 'CONTRACT_INVALID'
  );
  // Перепутанные keyId в документах public-key отвергаются при загрузке корня.
  const mixed = tempDir('wp0102-identity-mixed-');
  fs.cpSync(world.trustRoot, mixed, { recursive: true });
  const ownerPub = JSON.parse(fs.readFileSync(path.join(mixed, 'owner.pub'), 'utf8'));
  ownerPub.keyId = world.created.anchorKeyId;
  fs.writeFileSync(path.join(mixed, 'owner.pub'), JSON.stringify(ownerPub));
  assert.throws(() => loadTrustRoot(mixed), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  fs.rmSync(mixed, { recursive: true, force: true });
});

test('частичная инициализация ready.json fail-closed, существующие ключи не перезаписываются', async () => {
  // (a) публичный ключ без второго и без ready.json
  const partial = tempDir('wp0102-identity-partial-');
  fs.cpSync(path.join(world.trustRoot, 'owner.pub'), path.join(partial, 'owner.pub'));
  assert.throws(() => loadTrustRoot(partial), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  // (b) полный набор, но ready.json отсутствует (обрыв после записи ключей)
  const noReady = tempDir('wp0102-identity-noready-');
  fs.cpSync(world.trustRoot, noReady, { recursive: true });
  fs.rmSync(path.join(noReady, 'ready.json'));
  assert.throws(() => loadTrustRoot(noReady), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  // (c) ready.json с чужим keyId
  const badReady = tempDir('wp0102-identity-badready-');
  fs.cpSync(world.trustRoot, badReady, { recursive: true });
  const ready = JSON.parse(fs.readFileSync(path.join(badReady, 'ready.json'), 'utf8'));
  ready.anchorKeyId = 'f'.repeat(64);
  fs.writeFileSync(path.join(badReady, 'ready.json'), JSON.stringify(ready));
  assert.throws(() => loadTrustRoot(badReady), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  // (d) повторная инициализация поверх частичного корня отвергается, чужие байты не меняются
  const kept = fs.readFileSync(path.join(partial, 'owner.pub'));
  const secrets = path.join(partial, 'secrets');
  await assert.rejects(
    () => createTrustRoot({ secretsDir: secrets, trustRoot: partial }),
    error => error.code === 'TRUST_STORE_UNAVAILABLE'
  );
  assert.deepEqual(fs.readFileSync(path.join(partial, 'owner.pub')), kept);
  assert.equal(fs.existsSync(path.join(partial, 'ready.json')), false);
  assert.equal(fs.existsSync(path.join(partial, 'anchor.pub')), false);
  // (e) обрыв после первого ключа (fault) откатывает созданные файлы
  const aborted = tempDir('wp0102-identity-abort-');
  await assert.rejects(
    () => createTrustRoot({ secretsDir: path.join(aborted, 'secrets'), trustRoot: path.join(aborted, 'trust-root'), fault: 'after-owner' }),
    error => error.code === 'TRUST_STORE_UNAVAILABLE'
  );
  assert.equal(fs.existsSync(path.join(aborted, 'secrets', 'owner.key')), false);
  assert.equal(fs.existsSync(path.join(aborted, 'trust-root', 'owner.pub')), false);
  assert.throws(() => loadTrustRoot(path.join(aborted, 'trust-root')), error => error.code === 'TRUST_STORE_UNAVAILABLE');
  for (const dir of [partial, noReady, badReady, aborted]) fs.rmSync(dir, { recursive: true, force: true });
});

test('корень доверия не имеет собственной целостностной привязки: подмена public-ключей даёт новый корень', async () => {
  // Наблюдение (P3): loadTrustRoot доверяет файлам trust root; ACL на trust root не ставится.
  const rogue = await makeWorld({ prefix: 'wp0102-identity-rogue-' });
  const swapped = tempDir('wp0102-identity-swap-');
  fs.cpSync(rogue.trustRoot, swapped, { recursive: true });
  const loaded = loadTrustRoot(swapped);
  assert.equal(loaded.owner.keyId, rogue.created.ownerKeyId, 'подменённый набор принят как корень доверия');
  assert.notEqual(loaded.owner.keyId, world.created.ownerKeyId);
  // Старый approval (подписанный настоящим owner) таким корнем не проверяется.
  assert.throws(
    () => verifyTrustedDocument(loaded, signTrustedDocument(world.ownerKey, { schemaVersion: '0.2.0', domain: 'approval', approvalId: 'wp0102-swap', keyId: world.created.ownerKeyId })),
    error => error.code === 'APPROVAL_SIGNATURE_INVALID'
  );
  removeWorld(rogue);
  fs.rmSync(swapped, { recursive: true, force: true });
});

test('DPAPI: обёртка не содержит открытого ключа, шифртекст нестабилен, порча отвергается', async () => {
  const key = await unwrapPrivateKey(path.join(world.secretsDir, 'owner.key'));
  const pkcs8 = key.export({ type: 'pkcs8', format: 'der' });
  const wrapped = fs.readFileSync(path.join(world.secretsDir, 'owner.key'));
  assert.equal(wrapped.includes(pkcs8), false, 'PKCS8 не лежит открытым текстом');
  assert.equal(fs.readFileSync(path.join(world.secretsDir, 'owner.key'), 'utf8').includes('BEGIN'), false);
  const first = await protect(Buffer.from('wp0102-dpapi-probe'));
  const second = await protect(Buffer.from('wp0102-dpapi-probe'));
  assert.equal(Buffer.compare(first, second) === 0, false, 'два шифртекста различаются');
  assert.equal((await unprotect(first)).toString('utf8'), 'wp0102-dpapi-probe');
  const tampered = Buffer.from(first);
  tampered[tampered.length - 1] ^= 0xff;
  await assert.rejects(() => unprotect(tampered), error => error.code === 'TRUST_STORE_UNAVAILABLE');
});

test('ACL: каталог секретов и ключевые файлы закрыты, trust root — нет', async () => {
  const secretsAcl = await readAcl(world.secretsDir);
  assert.equal(secretsAcl.protected, true);
  assert.deepEqual(secretsAcl.aces, [secretsAcl.current + '|Allow']);
  for (const name of ['owner.key', 'anchor.key']) {
    const acl = await readAcl(path.join(world.secretsDir, name));
    assert.equal(acl.protected, true, name + ' защищён');
    assert.deepEqual(acl.aces, [acl.current + '|Allow']);
  }
  const trustAcl = await readAcl(world.trustRoot);
  const parentAcl = await readAcl(path.dirname(world.trustRoot));
  // Наблюдение (P3): trust root (approvals/consumption/revocations) не ужесточён.
  assert.equal(trustAcl.protected, false, 'trust root наследует ACL каталога-родителя');
  assert.equal(trustAcl.protected, parentAcl.protected);
});

test('Control не получает приватные ключи: только public-ключи и отдельный процесс подписанта', () => {
  const sources = ['apps/control/trusted.mjs', 'apps/control/run.mjs'].map(file => fs.readFileSync(path.join(repoRoot, file), 'utf8'));
  for (const source of sources) {
    for (const token of ['unwrapPrivateKey', 'createPrivateKey', 'protectedPkcs8', 'owner.key', 'anchor.key', 'secretsDir']) {
      assert.equal(source.includes(token), false, 'Control не ссылается на ' + token);
    }
  }
  assert.equal(JSON.stringify(world.trust).includes('protectedPkcs8'), false);
  assert.deepEqual(Object.keys(world.trust).sort(), ['anchor-signer', 'owner']);
  const trusted = sources[0];
  assert.match(trusted, /currentUserSid\(\)/, 'startTrusted читает SID процесса');
  assert.equal(/options\.(?:sid|windowsSid)\b/.test(trusted), false, 'SID не берётся из аргументов startTrusted');
  assert.match(trusted, /connectAnchorSigner\(options\.signerPipe\)/, 'приватный ключ анкера — в отдельном процессе по pipe');
});

function signApprovalTest(privateKey, approvalId, keyId) {
  return signApproval(privateKey, { ...approvalFields(world, approvalId), keyId }, world.trust, world.trustRoot);
}

test('хранилище секретов через junction/symlink в репозиторий и в runDir отвергается', async () => {
  const linkParent = tempDir('wp0102-identity-link-');
  const repoLink = path.join(linkParent, 'not-runs-name');
  fs.symlinkSync(repoRoot, repoLink, 'junction');
  await assert.rejects(
    () => createTrustRoot({ secretsDir: repoLink, trustRoot: path.join(linkParent, 'public') }),
    error => error.code === 'TRUST_STORE_UNAVAILABLE'
  );
  assert.equal(fs.existsSync(path.join(repoRoot, 'owner.key')), false);
  const runBase = tempDir('wp0102-identity-run-');
  const runDir = path.join(runBase, 'runs', 'run-1');
  fs.mkdirSync(runDir, { recursive: true });
  const runLink = path.join(linkParent, 'looks-safe');
  fs.symlinkSync(runDir, runLink, 'junction');
  await assert.rejects(
    () => createTrustRoot({ secretsDir: path.join(runLink, 'secrets'), trustRoot: path.join(linkParent, 'public2'), runDir }),
    error => error.code === 'TRUST_STORE_UNAVAILABLE'
  );
  for (const dir of [linkParent, runBase]) fs.rmSync(dir, { recursive: true, force: true });
});
