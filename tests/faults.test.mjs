import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run } from '../apps/control/run.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from './helpers.mjs';
import { digest } from '../packages/core/canonical.mjs';

async function executeFault(t, fault) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `qa-adaptant-${fault}-`));
  const fixture = await serveLocalFixture({ fault });
  t.after(async () => {
    await fixture.close();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  const runId = `fault-${fault}`;
  const contract = localFixtureContract(fixture, runId);
  fixture.fixtureId = contract.fixtureId;
  const bundle = localBundle(fixture, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  const result = await run(bundle, { root, fault, fixtureToken: fixture.authToken });
  const events = fs.readFileSync(path.join(result.runDir, 'events.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  return { fixture, result, root, events };
}

const cases = [
  { fault: 'delayedRead', verdict: 'PASS', mutations: 1, check: (t, { fixture }) => assert.ok(fixture.readCount >= 3, 'Нужны ограниченные повторные GET') },
  { fault: 'wrongExecutor', verdict: 'FAIL', mutations: 1, check: (t, { result }) => assert.equal(result.verdict.checks.find(c => c.id === 'executor-saved').status, 'VIOLATED') },
  { fault: 'partialSave', verdict: 'FAIL', mutations: 1, check: (t, { result }) => assert.equal(result.verdict.checks.find(c => c.id === 'comment-saved').status, 'VIOLATED') },
  { fault: 'lostResponse', verdict: 'INCONCLUSIVE', mutations: 1, check: (t, { result }) => assert.ok(result.evidenceIds.length >= 4, 'Объект должен быть обнаружен read-only reconciliation') },
  { fault: 'crashAfterMutation', verdict: 'INCONCLUSIVE', mutations: 1 },
  { fault: 'missingEvidence', verdict: 'INCONCLUSIVE', mutations: 1 },
  { fault: 'changedEnvironment', verdict: 'INCONCLUSIVE', mutations: 1, check: (t, { result }) => assert.equal(result.verdict.reasonCode, 'ENVIRONMENT_CHANGED') },
  { fault: 'untrustedId', verdict: 'INCONCLUSIVE', mutations: 1 },
  { fault: 'duplicateIntent', verdict: 'PASS', mutations: 1, check: (t, { events }) => assert.equal(events.filter(event => event.type === 'INTENT_DURABLE').length, 1) },
  { fault: 'dropIntentAck', verdict: 'INCONCLUSIVE', mutations: 0 },
  { fault: 'driftBody', verdict: 'INCONCLUSIVE', mutations: 0 },
  { fault: 'ambiguousButton', verdict: 'BLOCKED', mutations: 0, check: (t, { result }) => assert.equal(result.verdict.reasonCode, 'ELEMENT_AMBIGUOUS') }
];

for (const item of cases) {
  test(`fault ${item.fault}: ${item.verdict}, POST=${item.mutations}`, { timeout: 30000 }, async t => {
    const context = await executeFault(t, item.fault);
    assert.equal(context.result.verdict.verdict, item.verdict, JSON.stringify(context.result.verdict));
    assert.equal(context.fixture.mutationCount, item.mutations, JSON.stringify(context.events));
    item.check?.(t, context);
  });
}
