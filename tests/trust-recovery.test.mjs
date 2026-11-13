// WP-08 P1-02/V-06: восстановление после аварии Control.
// Сценарии — реальный доверенный прогон (Chromium, локальный стенд, настоящий подписант),
// SIGKILL процесса Control в двух точках: после durable candidate и после записи анкера.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { digest, scenarioApprovalHash } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { signApproval } from '../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import { startAnchorSigner } from '../packages/trust/anchor-signer.mjs';
import { readCandidate, readTerminalChoice } from '../packages/trust/anchor.mjs';
import { currentUserSid } from '../packages/trust/windows-sid.mjs';
import { observe } from '../apps/control/run.mjs';
import { reconcileTrusted } from '../apps/control/trusted.mjs';

const REPO = path.resolve('.');
const CREDENTIAL_REF = 'local:fixture-token';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function crashWorld(prefix) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-recovery-' + prefix + '-'));
  const root = path.join(base, 'store');
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust');
  const created = await createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = await serveLocalFixture({ generation: 1 });
  const record = signEnvironmentRecord(ownerKey, {
    environmentId: stand.environmentId, generation: stand.generation, kind: 'local-stand', status: 'active',
    origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: CREDENTIAL_REF
  });
  commitEnvironmentRecord(trust, trustRoot, record);
  const signer = startAnchorSigner({ trustRoot, secretsDir });
  await signer.ready;
  const sid = currentUserSid();
  const owner = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner'],
    keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const operator = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'],
    keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const runId = 'recovery-' + randomUUID().slice(0, 8);
  const contract = localFixtureContract(stand, runId);
  stand.fixtureId = contract.fixtureId;
  const bundle = localBundle(stand, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  bundle.manifest.budget.deadlineMs = 60000;
  const issuedAt = new Date().toISOString();
  const approvalId = 'approval-' + randomUUID().slice(0, 8);
  const approval = signApproval(ownerKey, {
    approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: bundle.operation.id, operationVersion: bundle.operation.version,
    scenarioContentSha256: bundle.scenario.approval.contentSha256, operationSha256: digest(bundle.operation),
    approvedInputsHash: digest(bundle.operation.inputs), fixtureId: contract.fixtureId,
    targetEnvironmentId: stand.environmentId, environmentGeneration: stand.generation,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
    approvalNonce: randomBytes(32).toString('hex'), keyId: created.ownerKeyId
  }, trust, trustRoot);
  const store = new RunStore(root);
  const options = {
    root, trustRoot, approvalId, approval, issuer: owner, subject: operator,
    signerPipe: signer.pipePath, standPublicKey: stand.standPublicKey,
    fixtureToken: stand.authToken, credentials: { [CREDENTIAL_REF]: stand.authToken }
  };
  return {
    base, root, secretsDir, trustRoot, trust, stand, signer, store, bundle, approval, approvalId,
    owner, operator, runId, runDir: store.runPath(runId),
    async cleanup() {
      try { await signer.close(); } catch { /* канал закрыт */ }
      try { await stand.close(); } catch { /* стенд закрыт */ }
      try { fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* временный каталог */ }
    }
  };
}

function anchorFiles(w) {
  const directory = path.join(w.trustRoot, 'anchors');
  return fs.existsSync(directory) ? fs.readdirSync(directory).filter(name => name.endsWith('.json')).sort() : [];
}

function verdictItems(w) {
  return w.store.readEvidence(w.runDir).filter(item => item.envelope.kind === 'verdict');
}

// Запускает Control в дочернем процессе и убивает его сразу после выполнения predicate.
async function runAndKillAfter(w, predicate) {
  const bundleFile = path.join(w.base, 'bundle.json');
  const optionsFile = path.join(w.base, 'options.json');
  fs.writeFileSync(bundleFile, JSON.stringify(w.bundle));
  fs.writeFileSync(optionsFile, JSON.stringify(w.approval ? { ...w.bundleOptions, approval: w.approval } : w.bundleOptions));
  const childScript = path.join(w.base, 'control-child.mjs');
  fs.writeFileSync(childScript, [
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    "import { pathToFileURL } from 'node:url';",
    'const [repo, bundleFile, optionsFile, resultFile] = process.argv.slice(2);',
    "const { startTrusted } = await import(pathToFileURL(path.join(repo, 'apps/control/trusted.mjs')).href);",
    "const bundle = JSON.parse(fs.readFileSync(bundleFile, 'utf8'));",
    "const options = JSON.parse(fs.readFileSync(optionsFile, 'utf8'));",
    'let out;',
    'try { const result = await startTrusted(bundle, options); out = { ok: true, verdict: result.verdict }; }',
    'catch (error) { out = { ok: false, code: error.code || null, message: error.message }; }',
    'fs.writeFileSync(resultFile, JSON.stringify(out));',
    'process.exit(0);',
    ''
  ].join('\n'));
  const resultFile = path.join(w.base, 'child-result.json');
  const child = spawn(process.execPath, [childScript, REPO, bundleFile, optionsFile, resultFile], { stdio: 'ignore', windowsHide: true });
  const started = Date.now();
  let observed = false;
  while (Date.now() - started < 120000) {
    await sleep(10);
    try { if (predicate()) { observed = true; break; } } catch { /* каталог ещё пишется */ }
    if (child.exitCode !== null) break;
  }
  const killed = observed ? child.kill('SIGKILL') : false;
  await new Promise(resolve => { if (child.exitCode !== null) resolve(); else child.once('exit', resolve); });
  await sleep(400);
  return { observed, killed, childCode: child.exitCode };
}

function reconcileOptions(w, extra = {}) {
  return {
    root: w.root, trustRoot: w.trustRoot, approvalId: w.approvalId,
    issuer: w.owner, subject: w.operator, signerPipe: w.signer.pipePath,
    standPublicKey: w.stand.standPublicKey, runId: w.runId,
    fixtureToken: w.stand.authToken, credentials: { [CREDENTIAL_REF]: w.stand.authToken },
    ...extra
  };
}

// V-06/P2-03: авария после durable PASS-candidate и до анкера. Reconcile с доступным подписантом
// обязан дойти до PASS, а не всегда возвращать INCONCLUSIVE/WORKER_LOST.
test('V-06: reconcile после аварии с durable PASS-candidate доходит до PASS с подписантом', { timeout: 180000 }, async () => {
  const w = await crashWorld('v06');
  try {
    w.bundleOptions = {
      root: w.root, trustRoot: w.trustRoot, approvalId: w.approvalId, approval: null,
      issuer: w.owner, subject: w.operator, signerPipe: w.signer.pipePath,
      standPublicKey: w.stand.standPublicKey, fixtureToken: w.stand.authToken,
      credentials: { [CREDENTIAL_REF]: w.stand.authToken }
    };
    const crash = await runAndKillAfter(w, () => fs.existsSync(path.join(w.runDir, 'trust', 'candidate.json')));
    assert.equal(crash.observed, true, 'Control должен был записать durable candidate до аварии');
    const beforeCandidate = readCandidate(w.runDir);
    assert.equal(beforeCandidate?.candidate.verdict, 'PASS', 'durable candidate PASS');
    const anchorsBefore = anchorFiles(w);
    const result = await reconcileTrusted(reconcileOptions(w));
    assert.equal(result.verdict.verdict, 'PASS', 'reconcile обязан дойти до PASS, а не WORKER_LOST/INCONCLUSIVE');
    assert.equal(result.verdict.reasonCode, 'NONE');
    assert.equal(w.stand.mutationCount, 1, 'второго POST нет');
    const items = w.store.readEvidence(w.runDir);
    assert.equal(items.filter(item => item.envelope.kind === 'request').length, 1);
    assert.equal(verdictItems(w).length, 1, 'терминальный verdict ровно один');
    assert.equal(digest(result.verdict), beforeCandidate.candidateSha256, 'восстановлены ровно байты durable candidate');
    const choice = readTerminalChoice(w.runDir);
    assert.equal(choice.outcome, 'anchor');
    assert.equal(anchorFiles(w).length, anchorsBefore.length + 1, 'анкер выпущен один раз');
    assert.equal(anchorFiles(w).includes(choice.anchorId + '.json'), true);
    // Повторный reconcile не создаёт второй verdict и не трогает анкер.
    const repeat = await reconcileTrusted(reconcileOptions(w));
    assert.equal(digest(repeat.verdict), beforeCandidate.candidateSha256);
    assert.equal(verdictItems(w).length, 1);
    assert.equal(anchorFiles(w).length, anchorsBefore.length + 1);
  } finally {
    await w.cleanup();
  }
});

// P1-02/V-07 (вариант Control): анкер записан, terminal-choice ещё нет. Восстановление обязано
// переиспользовать уже подписанный анкер: без второго anchorId, второго раунда бюджета и verdict.
test('P1-02: reconcile переиспользует уже выданный анкер и пишет ровно выбранные байты', { timeout: 180000 }, async () => {
  const w = await crashWorld('v07');
  try {
    w.bundleOptions = {
      root: w.root, trustRoot: w.trustRoot, approvalId: w.approvalId, approval: null,
      issuer: w.owner, subject: w.operator, signerPipe: w.signer.pipePath,
      standPublicKey: w.stand.standPublicKey, fixtureToken: w.stand.authToken,
      credentials: { [CREDENTIAL_REF]: w.stand.authToken }
    };
    const crash = await runAndKillAfter(w, () => anchorFiles(w).length > 0);
    assert.equal(crash.observed, true, 'Control должен был записать анкер до аварии');
    const anchorsBefore = anchorFiles(w);
    assert.equal(anchorsBefore.length, 1);
    const existingAnchorId = anchorsBefore[0].replace(/\.json$/, '');
    assert.equal(fs.existsSync(path.join(w.runDir, 'trust', 'terminal-choice.json')), false, 'падение до terminal-choice');
    assert.equal(verdictItems(w).length, 0, 'verdict ещё не опубликован');
    const candidate = readCandidate(w.runDir);
    assert.equal(candidate?.candidate.verdict, 'PASS');
    const result = await reconcileTrusted(reconcileOptions(w));
    assert.equal(result.verdict.verdict, 'PASS');
    assert.equal(digest(result.verdict), candidate.candidateSha256, 'дописаны ровно выбранные байты');
    assert.equal(verdictItems(w).length, 1);
    assert.equal(anchorFiles(w).length, 1, 'второй анкер не выпущен: бюджет заново не разыгрывается');
    const choice = readTerminalChoice(w.runDir);
    assert.equal(choice.outcome, 'anchor');
    assert.equal(choice.anchorId, existingAnchorId, 'выбор связан с уже выданным анкером');
    assert.equal(w.stand.mutationCount, 1);
    const old = await observe({ root: w.root, runId: w.runId });
    assert.equal(old.verdict.verdict, 'PASS');
  } finally {
    await w.cleanup();
  }
});