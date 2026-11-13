// B-04: подпись на fixtureId=A, снимок с fixtureId=B.
// Ожидание: DENY APPROVAL_MISMATCH (проекция CONTRACT_INVALID) до мутации, объекта B нет.
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'B-04', title: 'Снимок fixtureId не совпал с approval', targetDir: globalThis.__RT2_TARGET, async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-b04' });
  const approval = world.approvalFor({ bundle, contract: { ...contract, fixtureId: 'fixture-other' } });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['CONTRACT_INVALID', 'AUTH_UNAVAILABLE'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, bundle.manifest.runId, ['mutation-intent', 'request']);
  check(checks, 'объект fixtureId=B не создан', world.stand.recordCount === 0, { recordCount: world.stand.recordCount });
  return { checks };
} });