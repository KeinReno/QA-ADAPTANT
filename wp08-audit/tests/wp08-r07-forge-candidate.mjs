// WP-08 независимый тест R-07: подложный PASS-candidate, подписанный anchor-signer.
// Сценарий: процесс того же SID, умеющий писать только каталог прогона и обращаться
// к каналу подписанта (R-06), создаёт candidate PASS и цепочку evidence сам, затем
// получает валидный анкер и публикует terminal verdict. Owner-ключ не используется
// для подделки: approval выписан owner на точные входы и израсходован на этот runId.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { digest, scenarioApprovalHash } from '../../packages/core/canonical.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { localBundle, localFixtureContract } from '../../adapters/local/bundle.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../../packages/trust/identity.mjs';
import { consumeDispatch, signApproval } from '../../packages/trust/approval.mjs';
import { buildCandidate, buildTerminalChoice, observeTrustedVerdict, publishCandidate, publishTerminalChoice, publishTerminalVerdict } from '../../packages/trust/anchor.mjs';
import { connectAnchorSigner, startAnchorSigner } from '../../packages/trust/anchor-signer.mjs';
import { observe } from '../../apps/control/run.mjs';
import { observeTrusted } from '../../apps/control/trusted.mjs';

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'wp08-r07-'));
const secretsDir = path.join(work, 'secrets');
const trustRoot = path.join(work, 'trust-root');
const storeRoot = path.join(work, 'store');
const created = await createTrustRoot({ secretsDir, trustRoot, runDir: storeRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const store = new RunStore(storeRoot);
const signer = startAnchorSigner({ trustRoot, secretsDir });
await signer.ready;
const client = connectAnchorSigner(signer.pipePath);

const issuedAt = new Date(Date.now() - 60000).toISOString();
const expiresAt = new Date(Date.now() + 10 * 60000).toISOString();
const issuer = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner', 'operator'], keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-owner', status: 'active' });
const subject = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'], keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-operator', status: 'active' });

const runId = 'run-r07-forged';
const descriptor = { environmentId: 'local-stand', baseUrl: 'http://127.0.0.1:9/', fingerprint: 'fp-local', fixtureId: 'fixture-' + runId };
const fixture = localFixtureContract(descriptor, runId);
const bundle = localBundle({ ...descriptor, fixtureId: fixture.fixtureId }, { runId });
bundle.fixture = fixture;
bundle.manifest.fixtureSha256 = digest(fixture);
const runDir = store.snapshot(bundle, null);
const frozen = verifyFrozenBundle(store, runDir);

let counter = 0;
const nextId = p => p + '-' + String(++counter).padStart(4, '0');
const operation = frozen.operation;
const mutationStep = 'create';
const verifyStep = frozen.scenario.nodes.at(-1).id;
const requestId = nextId('req');
const intent = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep, producer: 'control', kind: 'mutation-intent', artifact: { intentId: runId + ':' + mutationStep, stepId: mutationStep, operationId: operation.id, mutationName: operation.mutation.name, inputsSha256: digest(operation.inputs), fixtureId: fixture.fixtureId }, parentEvidenceIds: [] });
const request = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep, producer: 'browser', kind: 'request', requestId, artifact: { requestId, intentId: runId + ':' + mutationStep, operationId: operation.id, method: 'POST', path: '/records', fixtureId: fixture.fixtureId, fields: { ...operation.inputs, fixtureId: fixture.fixtureId } }, parentEvidenceIds: [intent.evidenceId] });
const entity = { kind: 'local-record', id: nextId('record') };
const response = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep, producer: 'browser', kind: 'response', requestId, entity, artifact: { requestId, intentId: runId + ':' + mutationStep, operationId: operation.id, fixtureId: fixture.fixtureId, status: 201, entity }, parentEvidenceIds: [request.evidenceId] });
// Подложный independent-read: утверждает, что GET вернул совпадающие поля. Реального GET не было.
const read = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: verifyStep, producer: 'verification', kind: 'independent-read', requestId, entity, checkIds: operation.effects.map(e => e.id), artifact: { method: 'GET', path: '/records', fixtureId: fixture.fixtureId, entity, fields: { ...operation.inputs, fixtureId: fixture.fixtureId }, environmentFingerprint: frozen.manifest.environment.fingerprint, requestId, httpStatus: 200, observedAt: new Date().toISOString() }, parentEvidenceIds: [response.evidenceId] });

const candidate = buildCandidate({ frozen, verdict: 'PASS', reasonCode: 'NONE', message: 'Проверка пройдена (подложный candidate)', checks: operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds: [read.evidenceId] })) });
// Атакующий пишет durable candidate напрямую, минуя Verification/Control.
publishCandidate(runDir, candidate);

const approvalId = 'approval-r07';
const approval = signApproval(ownerKey, {
  approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
  operationId: operation.id, operationVersion: operation.version,
  scenarioContentSha256: scenarioApprovalHash(frozen.scenario), operationSha256: digest(operation),
  approvedInputsHash: digest(operation.inputs), fixtureId: fixture.fixtureId,
  targetEnvironmentId: frozen.manifest.environment.id, environmentGeneration: 1,
  targetResource: { method: 'POST', path: '/records' },
  allowedEffects: operation.effects.map(e => ({ id: e.id, field: e.field, equals: e.equals })),
  issuedAt, expiresAt, approvalNonce: randomBytes(32).toString('hex'), keyId: created.ownerKeyId
}, trust, trustRoot);
consumeDispatch({ trust, trustRoot, approval, issuer, subject, windowsSid: 'S-1-5-21-operator', runId, decisionId: 'decision-r07', expected: { operation, inputs: operation.inputs, effects: operation.effects.map(e => ({ id: e.id, field: e.field, equals: e.equals })), scenarioContentSha256: scenarioApprovalHash(frozen.scenario), fixtureId: fixture.fixtureId, environmentId: frozen.manifest.environment.id, environmentGeneration: 1 } });

const anchorId = 'anchor-r07';
let signResult;
try {
  const statement = await client.sign({ runDir, approvalId, anchorId });
  signResult = { ok: true, statement };
} catch (error) {
  signResult = { ok: false, code: error.code, message: error.message };
}
console.log('SIGNER_RESULT', JSON.stringify(signResult.ok ? { ok: true, verdict: signResult.statement.verdict, candidateSha256: signResult.statement.candidateSha256 } : signResult));

let final;
if (signResult.ok) {
  publishTerminalChoice(runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: digest(candidate), anchorId }));
  publishTerminalVerdict({ store, runDir, frozen, trust, trustRoot });
}
const obs = observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot });
let oldObserve = null;
try { const o = await observe({ root: storeRoot, runId }); oldObserve = { verdict: o.verdict?.verdict, reasonCode: o.verdict?.reasonCode }; } catch (e) { oldObserve = { error: e.message }; }
console.log('TRUSTED_OBSERVE', JSON.stringify({ state: obs.state, trusted: obs.trusted, passed: obs.passed, verdict: obs.verdict?.verdict, anchorStatus: obs.anchorStatus }));
console.log('OLD_OBSERVE', JSON.stringify(oldObserve));
let publicTrusted = null;
try { const pt = await observeTrusted({ root: storeRoot, trustRoot, runId }); publicTrusted = { trusted: pt.trusted, passed: pt.passed, verdict: pt.verdict?.verdict, publication: pt.publication, anchorStatus: pt.anchorStatus }; } catch (e) { publicTrusted = { error: e.code || e.message }; }
console.log('PUBLIC_OBSERVE_TRUSTED', JSON.stringify(publicTrusted));
console.log('VERDICT_FALSE_PASS_SHOWN', obs.trusted === true && obs.passed === true);
await client.close(); await signer.close();
