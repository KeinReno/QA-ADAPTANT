import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { start, observe, cancel, cleanup } from '../apps/control/run.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from './helpers.mjs';
import { digest } from '../packages/core/canonical.mjs';
import { RunStore } from '../packages/core/store.mjs';

const cliPath = path.resolve('apps/control/cli.mjs');

async function setup(t, { fault = null, runId = `life-${crypto.randomUUID()}` } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-life-'));
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

async function waitUntil(predicate, timeoutMs = 5000) {
  const end = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= end) throw new Error('Условие теста не наступило до deadline');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

function invokeCli(args, token = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
      env: { ...process.env, QA_ADAPTANT_FIXTURE_TOKEN: token }
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

test('повторный START и OBSERVE не запускают браузер и не меняют терминальный результат', async t => {
  const { root, fixture, bundle, runId } = await setup(t);
  const first = await start(bundle, { root, fixtureToken: fixture.authToken });
  const before = await observe({ root, runId });
  const second = await start(bundle, { root, fixtureToken: fixture.authToken });
  const after = await observe({ root, runId });
  assert.equal(first.verdict.verdict, 'PASS');
  assert.deepEqual(second, first);
  assert.deepEqual(after, before);
  assert.equal(fixture.mutationCount, 1);
  const changed = structuredClone(bundle);
  changed.operation.inputs.title = 'Подменённое значение';
  await assert.rejects(start(changed, { root }), error => error.code === 'CONTRACT_INVALID');
  assert.equal(fixture.mutationCount, 1);
});

test('CANCEL до durable intent не отправляет POST', async t => {
  const { root, fixture, bundle, runId } = await setup(t, { fault: 'pauseBeforeIntent' });
  const pending = start(bundle, { root, fault: 'pauseBeforeIntent', fixtureToken: fixture.authToken });
  await new Promise(resolve => setTimeout(resolve, 300));
  const requested = await cancel({ root, runId });
  assert.equal(requested.state, 'CANCEL_REQUESTED');
  const result = await pending;
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'CANCELED');
  assert.equal(fixture.mutationCount, 0);
});

test('CANCEL после dispatch сохраняет неизвестность и не повторяет POST', async t => {
  const { root, fixture, bundle, runId } = await setup(t, { fault: 'delayResponse' });
  const pending = start(bundle, { root, fault: 'delayResponse', fixtureToken: fixture.authToken });
  await waitUntil(() => fixture.mutationCount === 1);
  await cancel({ root, runId });
  const result = await pending;
  assert.equal(result.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(result.verdict.reasonCode, 'CANCELED');
  assert.equal(fixture.mutationCount, 1);
});

test('CANCEL до HTTP ACK сериализуется с разрешением POST', async t => {
  const { root, fixture, bundle, runId } = await setup(t);
  const pending = start(bundle, { root, fault: 'pauseBeforeRequestAck', fixtureToken: fixture.authToken });
  const store = new RunStore(root);
  await waitUntil(() => {
    try { return store.readEvents(store.runPath(runId)).some(event => event.state === 'REQUEST_ACK_PAUSED'); }
    catch { return false; }
  });
  const requested = await cancel({ root, runId });
  assert.equal(requested.state, 'CANCEL_REQUESTED');
  const result = await pending;
  assert.equal(result.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(result.verdict.reasonCode, 'CANCELED');
  assert.equal(fixture.mutationCount, 0);
  assert.equal(store.readEvents(store.runPath(runId)).some(event => event.type === 'REQUEST_DURABLE'), false);
});

test('durable lock блокирует второй прогон того же fixture', async t => {
  const first = await setup(t, { fault: 'pauseBeforeIntent', runId: 'lock-owner' });
  const pending = start(first.bundle, { root: first.root, fault: 'pauseBeforeIntent', fixtureToken: first.fixture.authToken });
  await new Promise(resolve => setTimeout(resolve, 300));
  const runId = 'lock-competitor';
  const contract = { ...first.bundle.fixture, runId };
  const secondBundle = localBundle(first.fixture, { runId });
  secondBundle.fixture = contract;
  secondBundle.manifest.fixtureSha256 = digest(contract);
  const second = await start(secondBundle, { root: first.root, fixtureToken: first.fixture.authToken });
  const owner = await pending;
  assert.equal(owner.verdict.verdict, 'PASS');
  assert.equal(second.verdict.verdict, 'BLOCKED');
  assert.equal(first.fixture.mutationCount, 1);
});

test('очистка чужого объекта отклоняется без удаления', async t => {
  const { root, fixture, bundle } = await setup(t);
  const result = await start(bundle, { root, fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'PASS');
  await assert.rejects(cleanup({ root, entity: { kind: 'local-record', id: 'foreign' } }), error => error.code === 'UNSUPPORTED');
  assert.equal(fixture.recordCount, 1);
});

test('повреждение evidence обнаруживается при чтении после завершения', async t => {
  const { root, fixture, bundle, runId } = await setup(t);
  const result = await start(bundle, { root, fixtureToken: fixture.authToken });
  const store = new RunStore(root);
  const response = store.readEvidence(result.runDir).find(item => item.envelope.kind === 'response');
  fs.writeFileSync(path.join(result.runDir, 'evidence', response.envelope.artifact.path), '{"id":"forged"}\n');
  await assert.rejects(observe({ root, runId }), /INTEGRITY_ERROR/);
  assert.equal(fixture.mutationCount, 1);
});

test('Browser отклоняет snapshot, изменённый после preflight Control', async t => {
  const { root, fixture, bundle } = await setup(t, { fault: 'tamperSnapshotBeforeBrowser' });
  const result = await start(bundle, { root, fault: 'tamperSnapshotBeforeBrowser', fixtureToken: fixture.authToken });
  assert.equal(result.verdict.verdict, 'BLOCKED');
  assert.equal(result.verdict.reasonCode, 'CONTRACT_INVALID');
  assert.equal(fixture.mutationCount, 0);
  assert.equal(fixture.readCount, 0);
});

test('новый Control процесс после аварии выполняет reconcile без повторного POST', { timeout: 45000 }, async t => {
  const { root, fixture, bundle, runId } = await setup(t, { fault: 'crashControlAfterMutation', runId: 'process-restart' });
  const bundlePath = path.join(root, 'bundle.json');
  fs.writeFileSync(bundlePath, JSON.stringify(bundle));
  const crashed = await invokeCli(['start', '--root', root, '--bundle', bundlePath, '--fault', 'crashControlAfterMutation'], fixture.authToken);
  assert.notEqual(crashed.code, 0);
  assert.equal(fixture.mutationCount, 1);

  const recovered = await invokeCli(['reconcile', '--root', root, '--run-id', runId], fixture.authToken);
  assert.equal(recovered.code, 0, recovered.stderr);
  const recoveredResult = JSON.parse(recovered.stdout);
  assert.equal(recoveredResult.verdict.verdict, 'INCONCLUSIVE');
  assert.equal(fixture.mutationCount, 1);

  const repeated = await invokeCli(['start', '--root', root, '--bundle', bundlePath], fixture.authToken);
  assert.equal(repeated.code, 0, repeated.stderr);
  assert.deepEqual(JSON.parse(repeated.stdout), recoveredResult);
  assert.equal(fixture.mutationCount, 1);
});
