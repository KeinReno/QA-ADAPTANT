// WP-08 независимый тест V-06 (WP-05): авария после durable response до анкера,
// восстановление новым процессом reconcileTrusted. Инъекция аварии — SIGKILL
// процесса Control сразу после появления durable response в evidence. Продукт не меняется.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { digest, scenarioApprovalHash } from '../../packages/core/canonical.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { pathToFileURL } from 'node:url';
import { localBundle, localFixtureContract } from '../../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../../packages/trust/identity.mjs';
import { signApproval } from '../../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../../packages/trust/environment.mjs';
import { startAnchorSigner } from '../../packages/trust/anchor-signer.mjs';
import { observeTrustedVerdict, readTerminalChoice } from '../../packages/trust/anchor.mjs';
import { currentUserSid } from '../../packages/trust/windows-sid.mjs';
import { observe } from '../../apps/control/run.mjs';
import { reconcileTrusted } from '../../apps/control/trusted.mjs';

const REPO = path.resolve('.');
const sid = currentUserSid();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wp08-v06-'));
const root = path.join(base, 'store');
const secretsDir = path.join(base, 'secrets');
const trustRoot = path.join(base, 'trust');
const created = await createTrustRoot({ secretsDir, trustRoot, runDir: root });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const stand = await serveLocalFixture({ generation: 1 });
const record = signEnvironmentRecord(ownerKey, {
  environmentId: stand.environmentId, generation: stand.generation, kind: 'local-stand', status: 'active',
  origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: 'local:fixture-token'
});
commitEnvironmentRecord(trust, trustRoot, record);
const signer = startAnchorSigner({ trustRoot, secretsDir });
await signer.ready;
const owner = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active' });
const operator = signTrustedDocument(ownerKey, { schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'], keyId: created.ownerKeyId, windowsSid: sid, status: 'active' });

const runId = 'v06-run-' + randomUUID().slice(0, 8);
const contract = localFixtureContract(stand, runId);
stand.fixtureId = contract.fixtureId;
const bundle = localBundle(stand, { runId });
bundle.fixture = contract;
bundle.manifest.fixtureSha256 = digest(contract);
bundle.manifest.budget.deadlineMs = 60000;
const issuedAt = new Date().toISOString();
const approvalId = 'approval-v06-' + randomUUID().slice(0, 8);
const approval = signApproval(ownerKey, {
  approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
  operationId: bundle.operation.id, operationVersion: bundle.operation.version,
  scenarioContentSha256: scenarioApprovalHash(bundle.scenario), operationSha256: digest(bundle.operation),
  approvedInputsHash: digest(bundle.operation.inputs), fixtureId: contract.fixtureId,
  targetEnvironmentId: stand.environmentId, environmentGeneration: stand.generation,
  targetResource: { method: 'POST', path: '/records' },
  allowedEffects: bundle.operation.effects.map(e => ({ id: e.id, field: e.field, equals: e.equals })),
  issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
  approvalNonce: 'ab'.repeat(32), keyId: created.ownerKeyId
}, trust, trustRoot);

const bundleFile = path.join(base, 'bundle.json');
const optionsFile = path.join(base, 'options.json');
const resultFile = path.join(base, 'child-result.json');
fs.writeFileSync(bundleFile, JSON.stringify(bundle));
fs.writeFileSync(optionsFile, JSON.stringify({
  root, trustRoot, approvalId, approval, issuer: owner, subject: operator,
  signerPipe: signer.pipePath, standPublicKey: stand.standPublicKey, fixtureToken: stand.authToken
}));
const childScript = path.join(base, 'control-child.mjs');
fs.writeFileSync(childScript, String.raw`
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const [repo, bundleFile, optionsFile, resultFile] = process.argv.slice(2);
const { startTrusted } = await import(pathToFileURL(path.join(repo, 'apps/control/trusted.mjs')).href);
const bundle = JSON.parse(fs.readFileSync(bundleFile, 'utf8'));
const options = JSON.parse(fs.readFileSync(optionsFile, 'utf8'));
let out;
try { const result = await startTrusted(bundle, options); out = { ok: true, verdict: result.verdict }; }
catch (error) { out = { ok: false, code: error.code || null, message: error.message }; }
fs.writeFileSync(resultFile, JSON.stringify(out));
process.exit(0);
`);

const store = new RunStore(root);
const runDir = store.runPath(runId);
const child = spawn(process.execPath, [childScript, REPO, bundleFile, optionsFile, resultFile], { stdio: 'ignore', windowsHide: true });
let responseSeen = false;
let killed = false;
const started = Date.now();
while (Date.now() - started < 120000) {
  await sleep(15);
  try {
    const items = store.readEvidence(runDir);
    if (items.some(item => item.envelope.kind === 'response')) { responseSeen = true; break; }
  } catch { /* журнал может быть посередине записи */ }
  if (child.exitCode !== null) break;
}
if (responseSeen) { killed = child.kill('SIGKILL'); }
await new Promise(resolve => { if (child.exitCode !== null) resolve(); else child.once('exit', resolve); });
await sleep(500);
let evidenceAtKill = [];
try { evidenceAtKill = store.readEvidence(runDir).map(item => item.envelope.kind); } catch (error) { evidenceAtKill = ['UNREADABLE: ' + error.message]; }
const frozen = verifyFrozenBundle(store, runDir);
const responseId = store.readEvidence(runDir).find(item => item.envelope.kind === 'response').envelope.evidenceId;
const consumptionFile = path.join(trustRoot, 'consumption', approvalId + '.json');
const genuineConsumption = fs.existsSync(consumptionFile);
// Атакующий того же SID: candidate PASS пишется напрямую, минуя Verification Worker.
const _anchor = await import(pathToFileURL(path.join(REPO, 'packages/trust/anchor.mjs')).href);
const _signer = await import(pathToFileURL(path.join(REPO, 'packages/trust/anchor-signer.mjs')).href);
const candidate = _anchor.buildCandidate({
  frozen, verdict: 'PASS', reasonCode: 'NONE', message: 'подложный PASS после аварии реального прогона',
  checks: frozen.operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds: [responseId] }))
});
const published = _anchor.publishCandidate(runDir, candidate);
const client = _signer.connectAnchorSigner(signer.pipePath);
const anchorId = 'anchor-forged-' + randomUUID();
let signOk = null;
let signError = null;
try {
  const statement = await client.sign({ runDir, approvalId, anchorId });
  signOk = { candidateSha256: statement.candidateSha256, verdict: statement.verdict, keyId: statement.keyId };
} catch (error) { signError = { code: error.code || null, message: error.message }; }
if (signOk) {
  _anchor.publishTerminalChoice(runDir, _anchor.buildTerminalChoice({ outcome: 'anchor', candidateSha256: published.candidateSha256, anchorId }));
  _anchor.publishTerminalVerdict({ store, runDir, frozen, trust, trustRoot });
}
const observed = observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot });
const evidenceAfter = store.readEvidence(runDir);
const reads = evidenceAfter.filter(item => item.envelope.kind === 'independent-read').length;
let oldObserve = null;
try { const o = await observe({ root, runId }); oldObserve = o.verdict ? { verdict: o.verdict.verdict, reasonCode: o.verdict.reasonCode } : null; } catch (error) { oldObserve = { error: error.message }; }
const summary = {
  tool: 'WP08-V06-CRASH-FORGE',
  revision: '07c21c4db936627df9a3c874015327ea992a335a',
  runId,
  responseSeen, killedAtResponse: killed,
  evidenceAtKill,
  genuineConsumption,
  realIndependentReads: reads,
  signOk, signError,
  mutationCount: stand.mutationCount,
  requests: evidenceAfter.filter(item => item.envelope.kind === 'request').length,
  verdicts: evidenceAfter.filter(item => item.envelope.kind === 'verdict').length,
  observeTrusted: { state: observed.state, trusted: observed.trusted, passed: observed.passed, verdict: observed.verdict?.verdict || null, reasonCode: observed.reasonCode, anchorStatus: observed.anchorStatus },
  oldObserve
};
console.log(JSON.stringify(summary, null, 2));
console.log('FORGE_ASSERT signerAccepted:', Boolean(signOk));
console.log('FORGE_ASSERT trustedFalsePass:', observed.trusted === true && observed.passed === true && observed.verdict?.verdict === 'PASS');
console.log('FORGE_ASSERT noRealVerificationReads:', reads === 0);
console.log('FORGE_ASSERT mutationCount===1:', stand.mutationCount === 1);
await client.close();
await signer.close();
await stand.close();
fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
