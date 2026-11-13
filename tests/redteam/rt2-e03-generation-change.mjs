// E-03: поколение стенда не совпало с записью реестра (смена поколения).
// Ожидание: DENY ENVIRONMENT_ATTESTATION_FAILED (ENVIRONMENT_CHANGED) до intent, 0 POST.
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'E-03', title: 'Поколение стенда сменилось относительно реестра', async body({ modules, cleanup, checks }) {
  // Запись реестра — поколение 1, живой стенд — поколение 2.
  const world = await makeWorld(modules, { generation: 2, recordOverrides: { generation: 1 } });
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-e03' });
  const approval = world.approvalFor({ bundle, contract, overrides: { environmentGeneration: 1 } });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['ENVIRONMENT_CHANGED'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, bundle.manifest.runId, ['mutation-intent', 'request']);
  check(checks, 'approval не израсходован', !(await import('node:fs')).existsSync(world.trustRoot + '\\consumption\\' + approval.approvalId + '.json'));
  return { checks };
} });