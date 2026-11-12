import { validateBundleLinks } from '../contracts/index.mjs';
import { digest, scenarioApprovalHash } from './canonical.mjs';

export function verifyFrozenBundle(store, runDir) {
  const scenario = store.readSnapshot(runDir, 'scenario');
  const operation = store.readSnapshot(runDir, 'operation');
  const fixture = store.readSnapshot(runDir, 'fixture');
  const manifestSnapshot = store.readSnapshot(runDir, 'manifest');
  const manifest = manifestSnapshot.value;
  if (manifest.scenario.sha256 !== digest(scenario.value) || manifest.operation.sha256 !== digest(operation.value) || manifest.fixtureSha256 !== digest(fixture.value)) {
    throw new Error('CONTRACT_INVALID: hash snapshot не совпадает с manifest');
  }
  if (scenario.value.operation.sha256 !== digest(operation.value)) throw new Error('CONTRACT_INVALID: scenario ссылается на другой operation hash');
  if (scenarioApprovalHash(scenario.value) !== scenario.value.approval?.contentSha256) throw new Error('CONTRACT_INVALID: approval hash не совпадает со сценарием');
  if (fixture.value.runId !== manifest.runId || fixture.value.environmentId !== manifest.environment.id) throw new Error('CONTRACT_INVALID: fixture не привязан к run/environment');
  validateBundleLinks({ scenario: scenario.value, operation: operation.value, fixture: fixture.value, manifest });
  return {
    scenario: scenario.value, operation: operation.value, fixture: fixture.value,
    manifest, manifestSha256: digest(manifest)
  };
}
