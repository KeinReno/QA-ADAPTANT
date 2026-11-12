import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { start, reconcile } from '../apps/control/run.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from './helpers.mjs';
import { digest } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';

const cliPath = path.resolve('apps/control/cli.mjs');

async function setup(t, { fault = null, runId = `review-${crypto.randomUUID()}` } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-review-'));
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
  return { root, fixture, bundle, runId };
}

async function waitUntil(predicate, timeoutMs = 7000) {
  const end = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= end) throw new Error('Условие теста не наступило до deadline');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

function hasEvent(root, runId, type) {
  const file = path.join(root, 'runs', runId, 'events.jsonl');
  if (!fs.existsSync(file)) return false;
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).some(line => JSON.parse(line).type === type);
  } catch { return false; }
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

function bundleFile(root, bundle) {
  const file = path.join(root, 'bundle.json');
  fs.writeFileSync(file, JSON.stringify(bundle));
  return file;
}

test('Grok P0: сохранённый PASS с вымышленными evidence отклоняется при START и OBSERVE', async t => {
  const { root, fixture, bundle, runId } = await setup(t);
  const first = await start(bundle, { root, fixtureToken: fixture.authToken });
  assert.equal(first.verdict.verdict, 'PASS');
  const store = new RunStore(root);
  const records = store.readEvidence(first.runDir);
  const forged = {
    ...first.verdict,
    completedAt: new Date().toISOString(),
    checks: first.verdict.checks.map(check => ({ ...check, evidenceIds: ['evidence-that-does-not-exist'] }))
  };
  store.appendEvidence(first.runDir, {
    runId, manifestSha256: first.verdict.manifestSha256, fixtureId: bundle.fixture.fixtureId,
    stepId: bundle.scenario.nodes.at(-1).id, producer: 'verification', kind: 'verdict', artifact: forged,
    parentEvidenceIds: records.map(item => item.envelope.evidenceId), checkIds: forged.checks.map(check => check.id)
  });
  await assert.rejects(start(bundle, { root, fixtureToken: fixture.authToken }), /INTEGRITY_ERROR|Эффект|evidence/i);
  await assert.rejects(reconcile({ root, runId }), /INTEGRITY_ERROR|Эффект|evidence/i);
});

test('Grok P0: cross-process CANCEL не публикует вердикт до остановки владельца и не допускает поздний POST', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { runId: 'review-cross-process-cancel' });
  const file = bundleFile(root, bundle);
  const owner = launchCli(['start', '--root', root, '--bundle', file, '--fault', 'pauseBeforeIntent'], fixture.authToken);
  await waitUntil(() => hasEvent(root, runId, 'STATE'));
  const cancellation = await launchCli(['cancel', '--root', root, '--run-id', runId], fixture.authToken).done;
  const ownerResult = await owner.done;
  await new Promise(resolve => setTimeout(resolve, 1800));
  assert.equal(cancellation.code, 0, cancellation.stderr);
  const requested = JSON.parse(cancellation.stdout);
  assert.equal(requested.state, 'CANCEL_REQUESTED');
  assert.equal(requested.verdict, null);
  assert.equal(ownerResult.code, 0, ownerResult.stderr);
  const finished = JSON.parse(ownerResult.stdout);
  assert.equal(finished.verdict.verdict, 'BLOCKED');
  assert.equal(finished.verdict.reasonCode, 'CANCELED');
  assert.equal(fixture.mutationCount, 0);
});

test('Grok P0: reconcile после потери Control без durable intent сохраняет неизвестность и не оставляет поздний POST', { timeout: 30000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { runId: 'review-orphan-before-intent' });
  const owner = launchCli(['start', '--root', root, '--bundle', bundleFile(root, bundle), '--fault', 'pauseBeforeIntent'], fixture.authToken);
  await waitUntil(() => hasEvent(root, runId, 'STATE'));
  owner.child.kill('SIGKILL');
  await owner.done;
  const recovered = await launchCli(['reconcile', '--root', root, '--run-id', runId], fixture.authToken).done;
  await new Promise(resolve => setTimeout(resolve, 1800));
  assert.equal(recovered.code, 0, recovered.stderr);
  const result = JSON.parse(recovered.stdout);
  assert.equal(result.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(result.verdict.reasonCode, 'WORKER_LOST');
  assert.equal(fixture.mutationCount, 0);
});

test('Grok P1: удаление fixture lock не разрешает два POST для одного fixture', { timeout: 30000 }, async t => {
  const first = await setup(t, { runId: 'review-lock-owner' });
  const pending = start(first.bundle, { root: first.root, fault: 'pauseBeforeIntent', fixtureToken: first.fixture.authToken });
  const locksDir = path.join(first.root, 'locks');
  await waitUntil(() => fs.existsSync(locksDir) && fs.readdirSync(locksDir).some(name => name.endsWith('.lock')));
  for (const name of fs.readdirSync(locksDir)) if (name.endsWith('.lock')) fs.unlinkSync(path.join(locksDir, name));
  const runId = 'review-lock-competitor';
  const contract = { ...first.bundle.fixture, runId };
  const secondBundle = localBundle(first.fixture, { runId });
  secondBundle.fixture = contract;
  secondBundle.manifest.fixtureSha256 = digest(contract);
  const second = await start(secondBundle, { root: first.root, fixtureToken: first.fixture.authToken });
  const owner = await pending;
  await new Promise(resolve => setTimeout(resolve, 500));
  assert.ok(first.fixture.mutationCount <= 1, `Допущены параллельные мутации: ${first.fixture.mutationCount}`);
  assert.ok(owner.verdict.verdict !== 'PASS' || second.verdict.verdict !== 'PASS');
});

test('Grok P2: временные HTTP 503 при независимом чтении не обрывают budget', async t => {
  const { root, fixture, bundle } = await setup(t, { fault: 'transientRead' });
  const result = await start(bundle, { root, fault: 'transientRead', fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'PASS', JSON.stringify(result.verdict));
  assert.ok(fixture.readCount >= 3);
  assert.equal(fixture.mutationCount, 1);
});

test('Grok P2: неполная цепочка evidence не помечается как проверенная целостность', async t => {
  const { root, fixture, bundle } = await setup(t);
  const result = await start(bundle, { root, fault: 'dropIntentAck', fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(result.verdict.reasonCode, 'INTEGRITY_ERROR');
  assert.equal(result.verdict.integrityVerified, false);
});

test('Grok P1: fixture требует авторизацию и фильтр, идемпотентен и не считает отклонённое тело мутацией', async t => {
  const { fixture } = await setup(t, { runId: 'review-fixture-api' });
  const payload = { fixtureId: fixture.fixtureId, title: 'API', executorId: 'operator-local', comment: 'comment' };
  const unauthenticated = await fetch(new URL('/records', fixture.baseUrl), {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload)
  });
  assert.equal(unauthenticated.status, 401);
  const headers = {
    'content-type': 'application/json', authorization: `Bearer ${fixture.authToken}`, 'idempotency-key': 'review-fixed-intent'
  };
  const first = await fetch(new URL('/records', fixture.baseUrl), { method: 'POST', headers, body: JSON.stringify(payload) });
  const repeated = await fetch(new URL('/records', fixture.baseUrl), { method: 'POST', headers, body: JSON.stringify(payload) });
  assert.equal(first.status, 201);
  assert.ok([200, 201].includes(repeated.status));
  assert.equal((await first.json()).id, (await repeated.json()).id);
  assert.equal(fixture.mutationCount, 1);
  assert.equal(fixture.recordCount, 1);
  const missingFilter = await fetch(new URL('/records', fixture.baseUrl), { headers: { authorization: `Bearer ${fixture.authToken}` } });
  assert.equal(missingFilter.status, 400);
  const oversized = await fetch(new URL('/records', fixture.baseUrl), {
    method: 'POST', headers: { ...headers, 'idempotency-key': 'review-oversized' },
    body: JSON.stringify({ ...payload, comment: 'x'.repeat(20_000) })
  });
  assert.equal(oversized.status, 413);
  assert.equal(fixture.mutationCount, 1);
  assert.equal(fixture.recordCount, 1);
});
