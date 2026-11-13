// QWEN-F1: подмена trust root не должна давать доверенный PASS.
// Регрессионный тест на закрепление корня доверия (trust-pin).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { createTrustRoot, loadTrustRoot, publicKeyId, resealTrustRootPin } from '../packages/trust/identity.mjs';
import { localFixtureContract, localBundle } from './helpers.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { loadTarget, makeWorld } from './redteam/_w2.mjs';

function tempRoots() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-trust-pin-'));
  return { base, secretsDir: path.join(base, 'secrets'), trustRoot: path.join(base, 'trust') };
}

function writePublic(file, purpose, keyId, publicKey) {
  fs.writeFileSync(file, JSON.stringify({
    schemaVersion: '0.2.0', domain: 'public-key', purpose, keyId,
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  }) + '\n');
}

function substituteTrustRoot(trustRoot) {
  const owner = generateKeyPairSync('ed25519');
  const anchor = generateKeyPairSync('ed25519');
  const ownerKeyId = publicKeyId(owner.publicKey);
  const anchorKeyId = publicKeyId(anchor.publicKey);
  writePublic(path.join(trustRoot, 'owner.pub'), 'owner', ownerKeyId, owner.publicKey);
  writePublic(path.join(trustRoot, 'anchor.pub'), 'anchor-signer', anchorKeyId, anchor.publicKey);
  fs.writeFileSync(path.join(trustRoot, 'ready.json'), JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-root-ready', ownerKeyId, anchorKeyId }) + '\n');
  return { ownerKeyId, anchorKeyId };
}

test('легитимный корень загружается и содержит закрепление', async () => {
  const roots = tempRoots();
  await createTrustRoot(roots);
  assert.ok(fs.existsSync(path.join(roots.trustRoot, 'trust-pin.json')));
  const trust = loadTrustRoot(roots.trustRoot);
  assert.equal(trust.owner.keyId, JSON.parse(fs.readFileSync(path.join(roots.trustRoot, 'owner.pub'), 'utf8')).keyId);
});

test('подмена owner.pub/anchor.pub/ready.json отвергается закреплением', async () => {
  const roots = tempRoots();
  await createTrustRoot(roots);
  substituteTrustRoot(roots.trustRoot);
  assert.throws(() => loadTrustRoot(roots.trustRoot), error => error.code === 'TRUST_ROOT_KEY_SUBSTITUTION');
});

test('отсутствие закрепления — отказ, а не принятие новых ключей', async () => {
  const roots = tempRoots();
  await createTrustRoot(roots);
  fs.rmSync(path.join(roots.trustRoot, 'trust-pin.json'));
  assert.throws(() => loadTrustRoot(roots.trustRoot), error => error.code === 'TRUST_ROOT_UNPINNED');
});

test('повреждённый конверт закрепления отвергается', async () => {
  const roots = tempRoots();
  await createTrustRoot(roots);
  const file = path.join(roots.trustRoot, 'trust-pin.json');
  const pin = JSON.parse(fs.readFileSync(file, 'utf8'));
  pin.sealed = Buffer.from('tampered-envelope').toString('base64');
  fs.writeFileSync(file, JSON.stringify(pin));
  assert.throws(() => loadTrustRoot(roots.trustRoot), error => error.code === 'TRUST_ROOT_PIN_INVALID');
});

test('закрепление, скопированное из другого корня, отвергается', async () => {
  const first = tempRoots();
  const second = tempRoots();
  await createTrustRoot(first);
  await createTrustRoot(second);
  fs.copyFileSync(path.join(first.trustRoot, 'trust-pin.json'), path.join(second.trustRoot, 'trust-pin.json'));
  assert.throws(() => loadTrustRoot(second.trustRoot), error => error.code === 'TRUST_ROOT_KEY_SUBSTITUTION');
});

test('санкционированная ротация: reseal требует приватный ключ владельца', async () => {
  const roots = tempRoots();
  await createTrustRoot(roots);
  await resealTrustRootPin(roots);
  const trust = loadTrustRoot(roots.trustRoot);
  assert.ok(trust.owner.keyId);
  const foreign = tempRoots();
  await createTrustRoot(foreign);
  fs.copyFileSync(path.join(foreign.secretsDir, 'owner.key'), path.join(roots.secretsDir, 'owner.key'));
  await assert.rejects(() => resealTrustRootPin(roots), error => error.code === 'TRUST_ROOT_PIN_INVALID');
});

test('QWEN-F1 end-to-end: подмена корня до запуска не даёт POST и PASS', async () => {
  const modules = await loadTarget(process.cwd());
  const world = await makeWorld(modules);
  try {
    substituteTrustRoot(world.trustRoot);
    const { bundle, contract } = world.prepare({ runId: 'qwen-f1-substitution' });
    const approval = world.approvalFor({ bundle, contract });
    await assert.rejects(
      () => modules.trusted.startTrusted(bundle, world.trustedOptions(approval)),
      error => ['TRUST_ROOT_KEY_SUBSTITUTION', 'TRUST_ROOT_UNPINNED', 'TRUST_ROOT_PIN_INVALID', 'TRUST_STORE_UNAVAILABLE'].includes(error.code)
    );
    assert.equal(world.stand.mutationCount, 0);
    await assert.rejects(
      () => modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId }),
      error => ['TRUST_ROOT_KEY_SUBSTITUTION', 'TRUST_STORE_UNAVAILABLE'].includes(error.code)
    );
  } finally {
    await world.cleanup();
  }
});
