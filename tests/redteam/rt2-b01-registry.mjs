// B-01: операция не из доверенного реестра 0.1.
// Ожидание: DENY CONTRACT_INVALID до мутации, реестр не обойдён.
import { caseMain, makeWorld, rebindBundle, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'B-01', title: 'Операция вне реестра 0.1', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const prepared = world.prepare({ runId: 'rt2-b01', mutate({ bundle, contract }) {
    bundle.operation = { ...bundle.operation, id: 'foreign-operation' };
    rebindBundle(modules, { bundle, contract });
  } });
  const approval = world.approvalFor({ bundle: prepared.bundle, contract: prepared.contract });
  const result = await modules.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['CONTRACT_INVALID'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, prepared.bundle.manifest.runId, ['mutation-intent', 'request']);
  return { checks };
} });