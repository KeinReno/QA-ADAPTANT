import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { start, observe, cancel } from '../apps/control/run.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from './helpers.mjs';
import { canonical, digest, scenarioApprovalHash } from '../packages/core/canonical.mjs';

const cliPath = path.resolve('apps/control/cli.mjs');

async function setup(t, { fault = null, runId = `audit-${crypto.randomUUID()}` } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-audit-'));
  const fixture = await serveLocalFixture({ fault });
  t.after(async () => {
    await fixture.close();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const contract = localFixtureContract(fixture, runId);
  fixture.fixtureId = contract.fixtureId;
  const bundle = localBundle(fixture, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  return { root, fixture, bundle, runId, contract };
}

function launchCli(args, token) {
  const child = spawn(process.execPath, [cliPath, ...args], {
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    env: { ...process.env, QA_ADAPTANT_FIXTURE_TOKEN: token || '' }
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, done };
}

function bundleFile(root, name, bundle) {
  const file = path.join(root, name);
  fs.writeFileSync(file, JSON.stringify(bundle));
  return file;
}

async function waitUntil(predicate, timeoutMs = 8000) {
  const end = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= end) throw new Error('Условие теста не наступило до deadline');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

test('WP-A: второй START во время preflight не публикует вердикт и не портит журнал', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { fault: 'slowEnvironment', runId: 'audit-start-race' });
  const file = bundleFile(root, 'bundle.json', bundle);
  const first = launchCli(['start', '--root', root, '--bundle', file, '--fault', 'slowEnvironment'], fixture.authToken);
  const runDir = path.join(root, 'runs', runId);
  await waitUntil(() => fs.existsSync(path.join(runDir, 'manifest.json')) && fs.existsSync(path.join(runDir, 'events.jsonl')));
  assert.equal(fs.existsSync(path.join(runDir, 'owner.json')), true);
  const second = launchCli(['start', '--root', root, '--bundle', file, '--fault', 'slowEnvironment'], fixture.authToken);
  const [owner, rival] = await Promise.all([first.done, second.done]);
  assert.equal(owner.code, 0, owner.stderr);
  assert.equal(rival.code, 0, rival.stderr);
  assert.equal(JSON.parse(owner.stdout).verdict.verdict, 'PASS');
  assert.equal(JSON.parse(rival.stdout).verdict, null);
  assert.equal(fixture.mutationCount, 1);
  const viewed = await observe({ root, runId });
  assert.equal(viewed.verdict.verdict, 'PASS');
  assert.equal(viewed.state, 'FINISHED');
});

test('WP-A: удаление locks и leases не создаёт второй объект', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, contract } = await setup(t, { fault: 'delayResponse', runId: 'audit-lock-owner-1' });
  const pending = start(bundle, { root, fault: 'delayResponse', fixtureToken: fixture.authToken });
  await waitUntil(() => fixture.mutationCount === 1);
  for (const name of ['locks', 'leases']) {
    const dir = path.join(root, name);
    if (!fs.existsSync(dir)) continue;
    for (const file of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, file));
  }
  const second = structuredClone(bundle);
  second.manifest.runId = 'audit-lock-owner-2';
  second.fixture = { ...contract, runId: 'audit-lock-owner-2' };
  second.manifest.fixtureSha256 = digest(second.fixture);
  const blocked = await start(second, { root, fault: 'delayResponse', fixtureToken: fixture.authToken });
  const first = await pending;
  assert.equal(first.verdict.verdict, 'PASS');
  assert.equal(blocked.verdict.verdict, 'BLOCKED');
  assert.equal(blocked.verdict.reasonCode, 'CONTRACT_INVALID');
  assert.equal(fixture.mutationCount, 1);
  assert.equal(fixture.recordCount, 1);
});

test('WP-A: новый runId с тем же fixtureId не создаёт второй объект', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, contract } = await setup(t, { runId: 'audit-fixture-run-1' });
  const first = await start(bundle, { root, fixtureToken: fixture.authToken });
  assert.equal(first.verdict.verdict, 'PASS');
  const second = structuredClone(bundle);
  second.manifest.runId = 'audit-fixture-run-2';
  second.fixture = { ...contract, runId: 'audit-fixture-run-2' };
  second.manifest.fixtureSha256 = digest(second.fixture);
  const blocked = await start(second, { root, fixtureToken: fixture.authToken });
  assert.equal(blocked.verdict.verdict, 'BLOCKED');
  assert.equal(fixture.mutationCount, 1);
  assert.equal(fixture.recordCount, 1);
});

test('WP-B: правка только хвоста evidence не превращает INCONCLUSIVE в PASS', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { fault: 'crashAfterMutation', runId: 'audit-tail' });
  const first = await start(bundle, { root, fault: 'crashAfterMutation', fixtureToken: fixture.authToken });
  assert.equal(first.verdict.verdict, 'INCONCLUSIVE');
  const file = path.join(first.runDir, 'evidence.jsonl');
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  const envelope = JSON.parse(lines.at(-1));
  const artifactFile = path.join(first.runDir, 'evidence', envelope.artifact.path);
  const artifact = JSON.parse(fs.readFileSync(artifactFile, 'utf8'));
  artifact.verdict = 'PASS';
  artifact.reasonCode = 'NONE';
  artifact.message = 'подмена хвоста';
  fs.writeFileSync(artifactFile, `${JSON.stringify(artifact)}\n`);
  envelope.artifact.sha256 = digest(fs.readFileSync(artifactFile));
  lines[lines.length - 1] = canonical(envelope);
  fs.writeFileSync(file, `${lines.join('\n')}\n`);
  fs.writeFileSync(path.join(first.runDir, 'evidence-anchor.json'), `${canonical({ sequence: envelope.sequence, envelopeSha256: digest(envelope) })}\n`);
  await assert.rejects(observe({ root, runId }), /INTEGRITY_ERROR/);
  await assert.rejects(start(bundle, { root, fault: 'crashAfterMutation', fixtureToken: fixture.authToken }), /INTEGRITY_ERROR/);
});

test('WP-B: самодекларация approval и урезанные effects не дают PASS', { timeout: 30000 }, async t => {
  const { root, fixture, bundle } = await setup(t, { fault: 'wrongExecutor', runId: 'audit-self-approval' });
  bundle.operation.effects = bundle.operation.effects.filter(effect => effect.id !== 'executor-saved');
  bundle.scenario.operation.sha256 = digest(bundle.operation);
  bundle.scenario.approval.actor = 'operator-self';
  bundle.scenario.approval.contentSha256 = scenarioApprovalHash(bundle.scenario);
  bundle.manifest.operation.sha256 = digest(bundle.operation);
  bundle.manifest.scenario.sha256 = digest(bundle.scenario);
  const result = await start(bundle, { root, fault: 'wrongExecutor', fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'CONTRACT_INVALID');
  assert.equal(fixture.mutationCount, 0);
});

test('WP-C: CANCEL после BROWSER_DONE публикует INCONCLUSIVE, а не PASS', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { fault: 'pauseVerificationRead', runId: 'audit-cancel-verify' });
  const pending = start(bundle, { root, fault: 'pauseVerificationRead', fixtureToken: fixture.authToken });
  await fixture.verificationReadStarted;
  const file = path.join(root, 'runs', runId, 'events.jsonl');
  const events = [];
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean)) {
    try { events.push(JSON.parse(line)); } catch { /* незавершённый хвост журнала не считается событием */ }
  }
  const browserDone = events.some(event => event.type === 'BROWSER_DONE');
  const verifying = events.some(event => event.type === 'STATE' && event.state === 'VERIFYING');
  const terminal = events.some(event => event.type === 'VERDICT_DURABLE');
  assert.ok(browserDone && verifying && !terminal, 'verification read gate наступает после BROWSER_DONE, до verdict');
  const requested = await cancel({ root, runId });
  assert.equal(requested.state, 'CANCEL_REQUESTED');
  fixture.releaseVerificationRead();
  const result = await pending;
  assert.equal(result.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(result.verdict.reasonCode, 'CANCELED');
  assert.equal(fixture.mutationCount, 1);
});

test('WP-C: POST без fixtureId не считается мутацией', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const response = await fetch(new URL('/records', fixture.baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${fixture.authToken}` },
    body: JSON.stringify({ title: 'без fixture' })
  });
  assert.equal(response.status, 400);
  assert.equal(fixture.mutationCount, 0);
  assert.equal(fixture.recordCount, 0);
});

function resign(bundle) {
  bundle.scenario.operation.sha256 = digest(bundle.operation);
  bundle.scenario.approval.contentSha256 = scenarioApprovalHash(bundle.scenario);
  bundle.manifest.operation.sha256 = digest(bundle.operation);
  bundle.manifest.scenario.sha256 = digest(bundle.scenario);
}

test('DS-P1-022: appliesWhen не превращает нарушенный эффект в PASS', { timeout: 30000 }, async t => {
  const { root, fixture, bundle } = await setup(t, { fault: 'wrongExecutor', runId: 'audit-applies-when' });
  bundle.operation.effects = bundle.operation.effects.map(effect => effect.id === 'title-saved' ? effect : { ...effect, appliesWhen: { field: 'title', equals: 'never-matches' } });
  resign(bundle);
  const result = await start(bundle, { root, fault: 'wrongExecutor', fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'CONTRACT_INVALID');
  assert.equal(fixture.mutationCount, 0);
});

test('DS-P1-022: подмена equals не подтверждает чужое сохранённое значение', { timeout: 30000 }, async t => {
  const { root, fixture, bundle } = await setup(t, { fault: 'wrongExecutor', runId: 'audit-equals' });
  bundle.operation.effects = bundle.operation.effects.map(effect => effect.id === 'executor-saved' ? { ...effect, equals: 'operator-wrong' } : effect);
  resign(bundle);
  const result = await start(bundle, { root, fault: 'wrongExecutor', fixtureToken: fixture.authToken });
  assert.notEqual(result.verdict.verdict, 'PASS');
  assert.equal(fixture.mutationCount, 0);
});

test('DS-P2-025: байты после анкера не выглядят как повреждение журнала', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-gap-'));
  const store = new RunStore(root);
  const runDir = path.join(root, 'runs', 'gap-run');
  fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), '');
  fs.writeFileSync(path.join(runDir, 'evidence-anchor.json'), `${canonical({ sequence: 0, envelopeSha256: null, byteLength: 0 })}\n`);
  const envelope = store.appendEvidence(runDir, {
    runId: 'gap-run', manifestSha256: 'ab'.repeat(32), fixtureId: 'fixture-gap', stepId: 'create',
    producer: 'control', kind: 'mutation-intent', artifact: { marker: 'committed' }
  });
  fs.appendFileSync(path.join(runDir, 'evidence.jsonl'), '{"torn":');
  const records = store.readEvidence(runDir);
  assert.equal(records.length, 1);
  assert.equal(records[0].envelope.evidenceId, envelope.evidenceId);
  fs.rmSync(root, { recursive: true, force: true });
});

test('DS-P2-013: пустой каталог прогона не отдаёт сырой ENOENT и не удваивает мутацию', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { runId: 'audit-empty-rundir' });
  fs.mkdirSync(path.join(root, 'runs', runId), { recursive: true });
  const result = await start(bundle, { root, fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'PASS');
  assert.equal(fixture.mutationCount, 1);
});

test('DS-P2-013: усечённый evidence останавливает повторную мутацию', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { runId: 'audit-truncated' });
  const first = await start(bundle, { root, fixtureToken: fixture.authToken });
  assert.equal(first.verdict.verdict, 'PASS');
  const file = path.join(first.runDir, 'evidence.jsonl');
  const raw = fs.readFileSync(file);
  fs.writeFileSync(file, raw.subarray(0, Math.max(1, Math.floor(raw.length / 2))));
  await assert.rejects(observe({ root, runId }), /INCOMPLETE_RUN|INTEGRITY_ERROR/);
  await assert.rejects(start(bundle, { root, fixtureToken: fixture.authToken }), /INCOMPLETE_RUN|INTEGRITY_ERROR/);
  assert.equal(fixture.mutationCount, 1);
});

test('DS-P2-026: каталог fixture без bind.json не блокирует прогон навсегда', { timeout: 30000 }, async t => {
  const { root, fixture, bundle } = await setup(t, { runId: 'audit-poison-bind' });
  const name = digest({ environmentId: bundle.manifest.environment.id, fixtureId: bundle.fixture.fixtureId });
  fs.mkdirSync(path.join(root, 'fixtures', name), { recursive: true });
  const result = await start(bundle, { root, fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'PASS');
  assert.equal(fixture.mutationCount, 1);
});

test('DS-P2-027: HTTP 200 существующего объекта не становится PASS нового прогона', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, contract } = await setup(t, { runId: 'audit-reuse-1' });
  const first = await start(bundle, { root, fixtureToken: fixture.authToken });
  assert.equal(first.verdict.verdict, 'PASS');
  for (const name of ['fixtures', 'locks', 'leases']) fs.rmSync(path.join(root, name), { recursive: true, force: true });
  const second = structuredClone(bundle);
  second.manifest.runId = 'audit-reuse-2';
  second.fixture = { ...contract, runId: 'audit-reuse-2' };
  second.manifest.fixtureSha256 = digest(second.fixture);
  const reused = await start(second, { root, fixtureToken: fixture.authToken });
  assert.equal(reused.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(reused.verdict.reasonCode, 'RESULT_UNCONFIRMED');
  assert.equal(fixture.mutationCount, 1);
  assert.equal(fixture.recordCount, 1);
});
