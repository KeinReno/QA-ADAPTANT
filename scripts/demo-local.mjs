import fs from 'node:fs';
import path from 'node:path';
import { start, observe } from '../apps/control/run.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { digest } from '../packages/core/canonical.mjs';

const runId = `demo-${Date.now()}`;
const root = path.resolve('data', runId);
const fixture = await serveLocalFixture();
try {
  const contract = localFixtureContract(fixture, runId);
  fixture.fixtureId = contract.fixtureId;
  const bundle = localBundle(fixture, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'bundle.json'), `${JSON.stringify(bundle, null, 2)}\n`);

  const result = await start(bundle, { root, fixtureToken: fixture.authToken });
  const saved = await observe({ root, runId });
  console.log(JSON.stringify({
    runId,
    verdict: result.verdict.verdict,
    reasonCode: result.verdict.reasonCode,
    checks: result.verdict.checks,
    mutationCount: fixture.mutationCount,
    independentReadCount: fixture.readCount,
    eventCount: saved.events.length,
    runDirectory: result.runDir
  }, null, 2));
  if (result.verdict.verdict !== 'PASS') process.exitCode = 1;
} finally {
  await fixture.close();
}
