// L-06: новая попытка с уже использованным approval.
// Ожидание: доверенный PASS на первом прогоне; повторный расход на новом runId -> APPROVAL_REPLAY;
// повторное закрепление approvalId с другим содержимым отвергается; второй доверенный старт не даёт POST.
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, expectCode } from './_w2.mjs';

await caseMain({ id: 'L-06', title: 'Новая попытка с использованным approval', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const first = world.prepare({ runId: 'rt2-l06-first' });
  const approval = world.approvalFor({ bundle: first.bundle, contract: first.contract });
  const ok = await modules.trusted.startTrusted(first.bundle, world.trustedOptions(approval));
  check(checks, 'первый доверенный прогон PASS', ok.verdict.verdict === 'PASS', { verdict: ok.verdict.verdict, reasonCode: ok.verdict.reasonCode });
  checkNoMutation(checks, world, 1);

  // Модульный повтор: тот же документ, новый runId -> APPROVAL_REPLAY, файл расхода не меняется.
  const store = new modules.store.RunStore(world.root);
  const frozenForReplay = modules.bundle.verifyFrozenBundle(store, store.runPath(first.runId));
  const expected = modules.facts.expectedFromFrozen(frozenForReplay);
  expected.environmentGeneration = world.record.generation;
  const dispatch = {
    trust: world.trust, trustRoot: world.trustRoot, approval,
    issuer: world.cards.owner, subject: world.cards.operator, windowsSid: world.sid,
    expected, runId: 'rt2-l06-other', decisionId: 'decision-l06'
  };
  await expectCode(checks, 'повторный расход на новом runId -> APPROVAL_REPLAY', () => modules.approval.consumeDispatch(dispatch), 'APPROVAL_REPLAY');

  // Повторное закрепление того же approvalId с другим содержимым.
  const issuedAt = new Date().toISOString();
  const fields = {
    approvalId: approval.approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: first.bundle.operation.id, operationVersion: first.bundle.operation.version,
    scenarioContentSha256: first.bundle.scenario.approval.contentSha256, operationSha256: modules.digest(first.bundle.operation),
    approvedInputsHash: modules.digest(first.bundle.operation.inputs), fixtureId: first.contract.fixtureId,
    targetEnvironmentId: world.stand.environmentId, environmentGeneration: world.stand.generation,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: first.bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 600000).toISOString(), approvalNonce: 'cd'.repeat(32), keyId: world.created.ownerKeyId
  };
  await expectCode(checks, 'повторное закрепление approvalId с другим содержимым отвергнуто',
    () => modules.approval.signApproval(world.ownerKey, fields, world.trust, world.trustRoot), 'CONTRACT_INVALID');

  // Второй доверенный старт со старым документом на другом сценарии/фикстуре — только отказ.
  const second = world.prepare({ runId: 'rt2-l06-second' });
  const blocked = await modules.trusted.startTrusted(second.bundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, blocked, { verdict: 'BLOCKED', reasonCodes: ['CONTRACT_INVALID', 'AUTH_UNAVAILABLE'] });
  checkNoMutation(checks, world, 1);
  return { checks };
} });