// WP08-QWEN-SECURITY-GATE — общий помощник негативных проверок F1 (repro/neg).
// Самодостаточен: только %TEMP% и локальный стенд 127.0.0.1. Продуктовый код не изменяется.
// Исходные R1–R4 (repro/r1…r4) — базовые доказательства, не переписываются; этот набор дополняет их.
// Переносимость: импорты относительные, SHA продукта читается из git — набор работает в любом
// worktree (базовый SHA и SHA исправления) без правок атакующей логики.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { digest } from '../../packages/core/canonical.mjs';
import { localBundle, localFixtureContract } from '../../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey, verifyTrustedDocument } from '../../packages/trust/identity.mjs';
import { signApproval, commitApproval } from '../../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../../packages/trust/environment.mjs';
import { currentUserSid } from '../../packages/trust/windows-sid.mjs';
import { observeTrusted, startTrusted, reconcileTrusted } from '../../apps/control/trusted.mjs';

export { fs, path, randomUUID, digest, createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey, verifyTrustedDocument, signApproval, commitApproval, commitEnvironmentRecord, signEnvironmentRecord, currentUserSid, observeTrusted, startTrusted, reconcileTrusted };

export function gitSha() {
  const head = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
  // Идентичность продуктового кода — хеши деревьев packages/apps/adapters (точно сравниваются между ревизиями).
  const productTree = execSync('git rev-parse HEAD:packages HEAD:apps HEAD:adapters', { encoding: 'utf8' }).trim().split(/\s+/).join(':');
  // Явная метка продуктового SHA для журнала (базовый SHA аудита или SHA исправления).
  const productSha = process.env.QA_AUDIT_PRODUCT_SHA || null;
  return { head, productTree, productSha };
}

export function world() {
  const bases = [];
  const stands = [];
  return {
    tmp(prefix) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); bases.push(dir); return dir; },
    async stand(options) { const stand = await serveLocalFixture(options || { generation: 1 }); stands.push(stand); return stand; },
    async cleanup() {
      for (const stand of stands) await stand.close().catch(() => {});
      for (const dir of bases) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  };
}

export function principalCards(ownerKey, ownerKeyId, prefix) {
  const sid = currentUserSid();
  return {
    operator: signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: prefix + '-operator', roles: ['operator'], keyId: ownerKeyId, windowsSid: sid, status: 'active' }),
    owner: signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: prefix + '-owner', roles: ['owner'], keyId: ownerKeyId, windowsSid: sid, status: 'active' })
  };
}

// Легитимный мир жертвы. load:false — корень ещё не загружался (сценарий «подмена до загрузки»).
export async function victimWorld(w, { stand = true, load = true } = {}) {
  const base = w.tmp('qa-neg-victim-');
  const v = { root: path.join(base, 'store'), secretsDir: path.join(base, 'secrets'), trustRoot: path.join(base, 'trust') };
  v.created = await createTrustRoot({ secretsDir: v.secretsDir, trustRoot: v.trustRoot, runDir: v.root });
  v.ownerKey = await unwrapPrivateKey(path.join(v.secretsDir, 'owner.key'));
  v.anchorKeyPath = path.join(v.secretsDir, 'anchor.key');
  Object.assign(v, principalCards(v.ownerKey, v.created.ownerKeyId, 'victim'));
  if (load) v.trust = loadTrustRoot(v.trustRoot);
  if (stand) {
    v.stand = await w.stand();
    v.record = signEnvironmentRecord(v.ownerKey, {
      environmentId: v.stand.environmentId, generation: 1, kind: 'local-stand', status: 'active',
      origin: v.stand.baseUrl, standKeyId: v.stand.standKeyId, credentialRef: 'local:fixture-token'
    });
    if (load) commitEnvironmentRecord(v.trust, v.trustRoot, v.record);
  }
  return v;
}

// Мир атакующего: собственные ключи, собственная DPAPI-обёртка (НЕ извлечение ключей жертвы).
export async function attackerWorld(w, prefix = 'attacker') {
  const base = w.tmp('qa-neg-attacker-');
  const a = { secretsDir: path.join(base, 'secrets'), trustRoot: path.join(base, 'trust') };
  a.created = await createTrustRoot({ secretsDir: a.secretsDir, trustRoot: a.trustRoot });
  a.ownerKey = await unwrapPrivateKey(path.join(a.secretsDir, 'owner.key'));
  a.anchorKey = await unwrapPrivateKey(path.join(a.secretsDir, 'anchor.key'));
  a.anchorKeyPath = path.join(a.secretsDir, 'anchor.key');
  a.trust = loadTrustRoot(a.trustRoot);
  Object.assign(a, principalCards(a.ownerKey, a.created.ownerKeyId, prefix));
  return a;
}

// A2-действие: перезапись файлов публичного корня жертвы файлами атакующего.
export function substitute(v, a, names = ['owner.pub', 'anchor.pub', 'ready.json']) {
  for (const name of names) fs.copyFileSync(path.join(a.trustRoot, name), path.join(v.trustRoot, name));
}

export function bundleFor(stand, runId) {
  const contract = localFixtureContract(stand, runId);
  stand.fixtureId = contract.fixtureId;
  const bundle = localBundle(stand, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  bundle.manifest.budget.deadlineMs = 60000;
  return { bundle, contract };
}

export function approvalFields({ ownerKeyId, issuerId, subjectId, bundle, contract, stand }) {
  const issuedAt = new Date().toISOString();
  return {
    approvalId: 'approval-' + randomUUID().slice(0, 8),
    issuerPrincipalId: issuerId, subjectPrincipalId: subjectId,
    operationId: bundle.operation.id, operationVersion: bundle.operation.version,
    scenarioContentSha256: bundle.scenario.approval.contentSha256,
    operationSha256: digest(bundle.operation), approvedInputsHash: digest(bundle.operation.inputs),
    fixtureId: contract.fixtureId, targetEnvironmentId: stand.environmentId, environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
    approvalNonce: 'cd'.repeat(32), keyId: ownerKeyId
  };
}

export function environmentRecordFor(ownerKey, stand) {
  return signEnvironmentRecord(ownerKey, {
    environmentId: stand.environmentId, generation: 1, kind: 'local-stand', status: 'active',
    origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: 'local:fixture-token'
  });
}

// Доверенный прогон с заданными ключами/документами. Фиксирует verdict, observer, ошибки.
// signTrust/commitApprovalTo — чем подписывается и где закрепляется approval;
// registerRecord:true — опубликовать запись среды для stand (подложный стенд).
export async function runTrusted({ root, trustRoot, signTrust, commitApprovalTo, ownerKey, ownerKeyId, issuer, subject, issuerId, subjectId, stand, anchorKeyPath, registerRecord = false, recordTrust = null, extraOptions = {}, fault = null }) {
  const runId = 'neg-' + randomUUID().slice(0, 8);
  const { bundle, contract } = bundleFor(stand, runId);
  const out = { runId };
  if (registerRecord) commitEnvironmentRecord(recordTrust || signTrust, trustRoot, environmentRecordFor(ownerKey, stand));
  const approval = signApproval(ownerKey, approvalFields({ ownerKeyId, issuerId, subjectId, bundle, contract, stand }), signTrust, commitApprovalTo || null);
  out.approvalId = approval.approvalId;
  out.approval = approval;
  try {
    const result = await startTrusted(bundle, {
      root, trustRoot, approvalId: approval.approvalId, approval, issuer, subject,
      anchorKeyPath, standPublicKey: stand.standPublicKey,
      credentials: { 'local:fixture-token': stand.authToken },
      ...(fault ? { fault } : {}), ...extraOptions
    });
    out.result = { verdict: result.verdict?.verdict ?? null, reasonCode: result.verdict?.reasonCode ?? null };
  } catch (error) { out.error = { code: error.code || null, message: String(error.message || error) }; }
  Object.assign(out, await observe({ root, trustRoot, runId }));
  return out;
}

export async function observe({ root, trustRoot, runId }) {
  try {
    const observed = await observeTrusted({ root, trustRoot, runId });
    return { observer: { trusted: observed.trusted, passed: observed.passed, verdict: observed.verdict?.verdict ?? null, reasonCode: observed.reasonCode ?? null, anchorId: observed.anchorId ?? null } };
  } catch (error) { return { observerError: { code: error.code || null, message: String(error.message || error) } }; }
}

export function err(error) { return { code: error.code || null, message: String(error.message || error) }; }

// Единый отчёт атаки: граница, verdict, observer, мутации. exit 0 = атака выполнена и зафиксирована
// (независимо от исхода); exit 2 = инфраструктурная ошибка (не засчитывается как проверка).
export function report(attack, title, data) {
  const { head, productTree, productSha } = gitSha();
  const observer = data.observer || null;
  const computed = Boolean(observer && observer.trusted === true && observer.passed === true && observer.verdict === 'PASS');
  const out = {
    attack, title, head, productTree, productSha,
    boundaryReached: data.boundaryReached || null,
    verdict: data.verdict ?? null,
    reasonCode: data.reasonCode ?? null,
    observer,
    observerError: data.observerError || null,
    mutations: data.mutations || null,
    falseTrustedPass: data.falseTrustedPass !== undefined ? Boolean(data.falseTrustedPass) : computed,
    notes: data.notes || null,
    details: data.details || null
  };
  out.outcome = out.falseTrustedPass ? 'ATTACK_REACHED_TRUSTED_PASS' : 'NO_TRUSTED_PASS';
  if (data.infraError) { out.outcome = 'INFRA_ERROR'; out.infraError = data.infraError; }
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = data.infraError ? 2 : 0;
  return out;
}