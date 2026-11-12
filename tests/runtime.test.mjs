import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run } from '../apps/control/run.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from './helpers.mjs';
import { digest } from '../packages/core/canonical.mjs';

test('локальная вертикаль: реальные Browser и Verification подтверждают создание записи', { timeout: 30000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-adaptant-runtime-'));
  const fixture = await serveLocalFixture();
  t.after(async () => {
    await fixture.close();
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  const runId = 'normal-path';
  const contract = localFixtureContract(fixture, runId);
  fixture.fixtureId = contract.fixtureId;
  const bundle = localBundle(fixture, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);

  const result = await run(bundle, { root, fixtureToken: fixture.authToken });

  assert.equal(result.verdict.verdict, 'PASS', JSON.stringify(result.verdict));
  assert.equal(fixture.mutationCount, 1);
  assert.ok(fixture.readCount >= 1);
  assert.ok(result.evidenceIds.length >= 5);
});
