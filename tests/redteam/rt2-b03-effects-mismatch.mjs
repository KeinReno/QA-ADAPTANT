// B-03: в approval три эффекта, в операции снят один.
// Ожидание: DENY APPROVAL_MISMATCH (CONTRACT_INVALID) до мутации.
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'B-03', title: 'Набор эффектов не совпал с approval', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-b03' });
  const projected = bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals }));
  const approval = world.approvalFor({ bundle, contract, overrides: { allowedEffects: projected.slice(0, 2) } });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['CONTRACT_INVALID'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, bundle.manifest.runId, ['mutation-intent', 'request']);
  return { checks };
} });