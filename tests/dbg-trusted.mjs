import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { digest } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { signApproval } from '../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import { currentUserSid } from '../packages/trust/windows-sid.mjs';
import { startTrusted } from '../apps/control/trusted.mjs';

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-dbg-'));
const root = path.join(base, 'store');
const secretsDir = path.join(base, 'secrets');
const trustRoot = path.join(base, 'trust');
const sid = currentUserSid();
let stand;
try {
  const created = await createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  stand = await serveLocalFixture({ generation: 1 });
  const record = signEnvironmentRecord(ownerKey, { environmentId: stand.environmentId, generation: stand.generation, kind: 'local-stand', status: 'active', origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: 'local:fixture-token' });
  commitEnvironmentRecord(trust, trustRoot, record);
  const owner = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active' });
  const operator = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active' });
  const runId = 'dbg-run-1';
  const contract = localFixtureContract(stand, runId);
  stand.fixtureId = contract.fixtureId;
  const bundle = localBundle(stand, { runId });
  bundle.fixture = contract; bundle.manifest.fixtureSha256 = digest(contract); bundle.manifest.budget.deadlineMs = 60000;
  const issuedAt = new Date().toISOString();
  const approval = signApproval(ownerKey, {
    approvalId: 'approval-dbg-1', issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: bundle.operation.id, operationVersion: bundle.operation.version,
    scenarioContentSha256: bundle.scenario.approval.contentSha256,
    operationSha256: digest(bundle.operation), approvedInputsHash: digest(bundle.operation.inputs),
    fixtureId: contract.fixtureId, targetEnvironmentId: stand.environmentId, environmentGeneration: stand.generation,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: bundle.operation.effects.map(e => ({ id: e.id, field: e.field, equals: e.equals })),
    issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 600000).toISOString(),
    approvalNonce: 'ab'.repeat(32), keyId: created.ownerKeyId
  }, trust, trustRoot);
  try {
    const result = await startTrusted(bundle, { root, trustRoot, approvalId: approval.approvalId, approval, issuer: owner, subject: operator, anchorKeyPath: path.join(secretsDir, 'anchor.key'), standPublicKey: stand.standPublicKey, fixtureToken: stand.authToken });
    console.log('RESULT', result.verdict.verdict, result.verdict.reasonCode, result.verdict.message);
  } catch (error) {
    console.log('THROW', error.code, error.message);
  }
  const store = new RunStore(root);
  const runDir = store.runPath(runId);
  console.log('EVENTS', store.readEvents(runDir).map(e => e.type + ':' + (e.state || e.code || '')).join(' | '));
  for (const e of store.readEvents(runDir)) if (e.type === 'BROWSER_ERROR' || e.type === 'BROWSER_DONE') console.log('ERRPAYLOAD', JSON.stringify(e));
  console.log('MUTATIONS', stand.mutationCount, 'READS', stand.readCount);
} catch (error) {
  console.log('FATAL', error.code, error.message, (error.stack || '').split('\n').slice(0, 5).join(' / '));
} finally {
  try { if (stand) await stand.close(); } catch {}
  fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
