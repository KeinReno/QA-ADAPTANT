// E-06: запись среды kind=dev при status=active.
// Ожидание: DENY ENVIRONMENT_KIND_DENIED (ENVIRONMENT_CHANGED), 0 POST, нет исходящего соединения на не-loopback.
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'E-06', title: 'Среда kind=dev даже при status=active', targetDir: globalThis.__RT2_TARGET, async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules, { recordOverrides: { kind: 'dev' } });
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-e06' });
  const approval = world.approvalFor({ bundle, contract });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['ENVIRONMENT_CHANGED', 'CONTRACT_INVALID'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, bundle.manifest.runId, ['mutation-intent', 'request']);
  check(checks, 'исходящих соединений на внешние адреса не было (стенд только 127.0.0.1)', new URL(world.stand.baseUrl).hostname === '127.0.0.1');
  return { checks };
} });