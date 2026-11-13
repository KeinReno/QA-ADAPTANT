// Подготовка реального локального прогона 0.1 (Chromium, стенд 127.0.0.1) для атак Red Team.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { run, start, observe, reconcile } from '../../apps/control/run.mjs';
import { serveLocalFixture } from '../../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from '../../adapters/local/bundle.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { remove } from './_lib.mjs';

export { run, start, observe, reconcile };

export async function prepareRun(options = {}) {
  const { fault = null, inputs, runId } = options;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-redteam-run-'));
  const fixture = await serveLocalFixture({ fault });
  const id = runId || 'rt-' + randomUUID();
  const contract = localFixtureContract(fixture, id);
  fixture.fixtureId = contract.fixtureId;
  const bundle = localBundle(fixture, { runId: id, inputs });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  return {
    root, fixture, bundle, runId: id, runDir: path.join(root, 'runs', id), fixtureToken: fixture.authToken,
    async close() { try { await fixture.close(); } catch { /* стенд уже закрыт */ } remove(root); }
  };
}

export function evidenceFiles(runDir) {
  const dir = path.join(runDir, 'evidence');
  return fs.existsSync(dir) ? fs.readdirSync(dir).sort() : [];
}

export function readEvidenceJsonl(runDir) {
  const file = path.join(runDir, 'evidence.jsonl');
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
}
