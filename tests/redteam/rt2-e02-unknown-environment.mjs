// E-02: environmentId отсутствует в реестре.
// Ожидание: DENY ENVIRONMENT_CHANGED (ENVIRONMENT_UNKNOWN), 0 POST, нет intent.
import { caseMain, makeWorld, rebindBundle, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'E-02', title: 'environmentId отсутствует в реестре', targetDir: globalThis.__RT2_TARGET, async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const unknownId = 'unknown-environment';
  const prepared = world.prepare({ runId: 'rt2-e02', mutate({ bundle, contract }) {
    contract.environmentId = unknownId;
    bundle.manifest.environment.id = unknownId;
    rebindBundle(modules, { bundle, contract });
  } });
  const approval = world.approvalFor({ bundle: prepared.bundle, contract: prepared.contract, overrides: { targetEnvironmentId: unknownId } });
  const result = await modules.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['ENVIRONMENT_CHANGED', 'CONTRACT_INVALID'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, prepared.bundle.manifest.runId, ['mutation-intent', 'request']);
  return { checks };
} });