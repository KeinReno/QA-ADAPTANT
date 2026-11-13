// WP-08 QWEN independent audit — repro R2.
// Проверки envBefore/envAfter в доверенном Verification Worker тавтологичны:
// environmentRead синтезируется из манифеста (apps/verification/trusted-worker.mjs:194-198),
// реальный GET /environment после мутации не выполняется. Стенд с fault='changedEnvironment'
// меняет fingerprint после POST, но доверенный прогон всё равно даёт PASS.
// Инструментация http.createServer выполняется ТОЛЬКО в процессе этого теста (продуктовый код не меняется).
// Запуск: node repro/r2-fingerprint-tautology.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { digest } from '../packages/core/canonical.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { signApproval } from '../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import { currentUserSid } from '../packages/trust/windows-sid.mjs';
import { startTrusted } from '../apps/control/trusted.mjs';

const sid = currentUserSid();
const requests = [];
const originalCreateServer = http.createServer;
http.createServer = function patched(...args) {
  const server = originalCreateServer.apply(this, args);
  server.on('request', (req, res) => {
    requests.push({ method: req.method, path: (req.url || '').split('?')[0], at: Date.now() });
    res.on('finish', () => {});
  });
  return server;
};

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-r2-'));
const out = { repro: 'R2', sha: '1a510a5d5929534d400dc965f58c78cf468bc270' };
let stand = null;
try {
  const root = path.join(base, 'store');
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust');
  const created = await createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  stand = await serveLocalFixture({ generation: 1, fault: 'changedEnvironment' });
  const record = signEnvironmentRecord(ownerKey, {
    environmentId: stand.environmentId, generation: 1, kind: 'local-stand', status: 'active',
    origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: 'local:fixture-token'
  });
  commitEnvironmentRecord(trust, trustRoot, record);
  const owner = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner',
    roles: ['owner'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const operator = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator',
    roles: ['operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const runId = 'r2-drift-' + randomUUID().slice(0, 8);
  const contract = localFixtureContract(stand, runId);
  stand.fixtureId = contract.fixtureId;
  const bundle = localBundle(stand, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  bundle.manifest.budget.deadlineMs = 60000;
  const manifestFingerprint = bundle.manifest.environment.fingerprint;
  const issuedAt = new Date().toISOString();
  const approval = signApproval(ownerKey, {
    approvalId: 'approval-' + randomUUID().slice(0, 8),
    issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: bundle.operation.id, operationVersion: bundle.operation.version,
    scenarioContentSha256: bundle.scenario.approval.contentSha256,
    operationSha256: digest(bundle.operation), approvedInputsHash: digest(bundle.operation.inputs),
    fixtureId: contract.fixtureId, targetEnvironmentId: stand.environmentId, environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
    approvalNonce: 'ef'.repeat(32), keyId: created.ownerKeyId
  }, trust, trustRoot);
  const result = await startTrusted(bundle, {
    root, trustRoot, approvalId: approval.approvalId, approval, issuer: owner, subject: operator,
    anchorKeyPath: path.join(secretsDir, 'anchor.key'), standPublicKey: stand.standPublicKey,
    credentials: { 'local:fixture-token': stand.authToken }
  });
  out.verdict = result.verdict.verdict;
  out.reasonCode = result.verdict.reasonCode;
  // Снимок журнала продуктовых запросов ДО диагностического чтения (оно тоже попадает в лог).
  const productRequests = requests.slice();

  // Прямое чтение /environment ПОСЛЕ прогона: fingerprint стенда изменился.
  const envResponse = await fetch(new URL('/environment', stand.baseUrl), { headers: { connection: 'close' } });
  const envBody = await envResponse.json();
  out.manifestFingerprint = manifestFingerprint;
  out.standFingerprintAfter = envBody.fingerprint;
  out.fingerprintDrift = envBody.fingerprint !== manifestFingerprint;

  // Ни одного GET /environment после POST /records: доверенная проверка среду не перечитывает.
  const postIndex = productRequests.findIndex(r => r.method === 'POST' && r.path === '/records');
  const envReadsAfterPost = productRequests.filter((r, i) => i > postIndex && r.method === 'GET' && r.path === '/environment');
  out.postIndex = postIndex;
  out.environmentReadsAfterPost = envReadsAfterPost.length;
  out.requestLog = productRequests.map(r => `${r.method} ${r.path}`);
  out.tautologyConfirmed = out.verdict === 'PASS' && out.fingerprintDrift && envReadsAfterPost.length === 0;
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = out.tautologyConfirmed ? 0 : 1;
} catch (error) {
  out.error = { code: error.code || null, message: String(error.message || error) };
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = 2;
} finally {
  http.createServer = originalCreateServer;
  if (stand) await stand.close().catch(() => {});
  fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}