// Атака WP-06: чужой SID (подмена личности в JSON не помогает).
// Ожидание: BLOCKED AUTH_UNAVAILABLE, 0 POST, нет intent.
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'WP06-SID', title: 'Чужой SID не получает доверенный прогон', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-sid' });
  const approval = world.approvalFor({ bundle, contract });
  const foreign = modules.identity.signTrustedDocument(world.ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'],
    keyId: world.created.ownerKeyId, windowsSid: 'S-1-5-21-9999999999-1-1-1', status: 'active'
  });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { subject: foreign }));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['AUTH_UNAVAILABLE'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, bundle.manifest.runId, ['mutation-intent', 'request']);
  return { checks };
} });
