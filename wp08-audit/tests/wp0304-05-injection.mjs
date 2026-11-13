// WP-08: E-05 (fail-closed реестра) и попытки подсунуть approval/факты мимо верификации.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, startControlledStand, evidenceOf } from './wp0304-lib.mjs';

const modules = await loadModules();
const env = modules.environment;

async function setupWorld(options = {}) {
  const stand = options.stand || await startControlledStand(modules, {});
  const world = await makeWorld(modules, { standalone: stand, ...options.world });
  return { world, stand };
}

test('E-05: повреждённый реестр сред — fail-closed без POST', async () => {
  const { world, stand } = await setupWorld();
  try {
    const { bundle, contract } = world.prepare({ runId: 'wp08-e05' });
    const approval = world.approvalFor({ bundle, contract });
    const directory = path.join(world.trustRoot, 'environments', stand.environmentId);
    const file = path.join(directory, stand.generation + '.json');
    const original = fs.readFileSync(file);
    fs.writeFileSync(file, '{повреждено');
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
    fs.writeFileSync(file, original);
    assert.equal(result.verdict.verdict, 'BLOCKED');
    assert.ok(['AUTH_UNAVAILABLE', 'CONTRACT_INVALID'].includes(result.verdict.reasonCode), 'код: ' + result.verdict.reasonCode);
    assert.equal(stand.mutationCount, 0);
    const kinds = evidenceOf(modules, world.root, 'wp08-e05').map(item => item.envelope.kind);
    assert.ok(!kinds.includes('mutation-intent'), kinds.join(','));
  } finally { await world.cleanup(); }
});

test('Подмена approval вне верификации: подделка, незакреплённый документ, чужой owner', async () => {
  const { world, stand } = await setupWorld();
  try {
    const run = world.prepare({ runId: 'wp08-inject' });
    const good = world.approvalFor({ bundle: run.bundle, contract: run.contract });

    // (a) Подпись снята/изменено поле: документ обязан быть отвергнут.
    const tampered = { ...good, approvedInputsHash: 'a'.repeat(64) };
    const tamperedResult = await modules.trusted.startTrusted(run.bundle, world.trustedOptions(tampered));
    assert.equal(tamperedResult.verdict.verdict, 'BLOCKED');
    assert.equal(stand.mutationCount, 0);

    // (b) Незакреплённый в trust root документ (подписан owner, но не проходил commitApproval).
    const uncommitted = modules.approval.signApproval(world.ownerKey, {
      approvalId: 'approval-uncommitted', issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
      operationId: run.bundle.operation.id, operationVersion: run.bundle.operation.version,
      scenarioContentSha256: run.bundle.scenario.approval.contentSha256,
      operationSha256: modules.digest(run.bundle.operation),
      approvedInputsHash: modules.digest(run.bundle.operation.inputs), fixtureId: run.contract.fixtureId,
      targetEnvironmentId: stand.environmentId, environmentGeneration: stand.generation,
      targetResource: { method: 'POST', path: '/records' },
      allowedEffects: run.bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600000).toISOString(),
      approvalNonce: 'cd'.repeat(32), keyId: world.ownerKeyId
    });
    const uncommittedRun = world.prepare({ runId: 'wp08-inject-uncommitted' });
    const uncommittedResult = await modules.trusted.startTrusted(uncommittedRun.bundle, { ...world.trustedOptions(uncommitted), approvalId: uncommitted.approvalId });
    assert.equal(uncommittedResult.verdict.verdict, 'BLOCKED');
    assert.equal(stand.mutationCount, 0);

    // (c) Approval, подписанный чужим owner и закреплённый в чужом trust root, не принимается этим корнем.
    const foreign = await makeWorld(modules);
    try {
      const foreignRun = foreign.prepare({ runId: 'wp08-inject-foreign' });
      const foreignApproval = foreign.approvalFor({ bundle: foreignRun.bundle, contract: foreignRun.contract });
      const result = await modules.trusted.startTrusted(run.bundle, { ...world.trustedOptions(foreignApproval), approvalId: foreignApproval.approvalId });
      assert.equal(result.verdict.verdict, 'BLOCKED');
      assert.equal(stand.mutationCount, 0);
    } finally { await foreign.cleanup(); }

    // Контроль: настоящий approval даёт ALLOW preflight (иначе тест ничего не доказывает).
    const goodRun = world.prepare({ runId: 'wp08-inject-good' });
    const goodApproval = world.approvalFor({ bundle: goodRun.bundle, contract: goodRun.contract });
    const store = new modules.store.RunStore(world.root);
    const runDir = store.snapshot(goodRun.bundle, { runId: goodRun.runId, pid: process.pid, at: new Date().toISOString() });
    const frozen = modules.bundle.verifyFrozenBundle(store, runDir);
    const context = modules.trusted.createTrustContext({
      trust: world.trust, trustRoot: world.trustRoot, approvalId: goodApproval.approvalId, approval: goodApproval,
      issuer: world.cards.owner, subject: world.cards.operator, sid: world.sid, standPublicKey: stand.standPublicKey
    });
    const preflight = await context.preflight({ runDir, frozen });
    assert.equal(preflight.allow, true, JSON.stringify(preflight.denial || {}));
  } finally { await world.cleanup(); }
});
