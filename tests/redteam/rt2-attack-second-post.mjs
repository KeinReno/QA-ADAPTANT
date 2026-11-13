// Атака WP-06: второй POST, второй terminal verdict, reconcile после PASS.
// Ожидание: один POST и один verdict; reconcile/повторный старт не мутируют; вставка второго verdict запрещена.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkNoMutation } from './_w2.mjs';

await caseMain({ id: 'WP06-2POST', title: 'Второй POST и второй terminal verdict', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-2post' });
  const approval = world.approvalFor({ bundle, contract });
  const first = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  check(checks, 'первый доверенный прогон PASS', first.verdict.verdict === 'PASS');
  checkNoMutation(checks, world, 1);
  const store = new modules.store.RunStore(world.root);
  const runDir = store.runPath(bundle.manifest.runId);
  const before = store.readEvidence(runDir);
  check(checks, 'ровно один request evidence', before.filter(item => item.envelope.kind === 'request').length === 1);

  const reconciled = await modules.trusted.reconcileTrusted({
    root: world.root, trustRoot: world.trustRoot, approvalId: approval.approvalId, approval,
    issuer: world.cards.owner, subject: world.cards.operator, standPublicKey: world.stand.standPublicKey,
    anchorKeyPath: path.join(world.secretsDir, 'anchor.key'),
    credentials: { [world.record.credentialRef]: world.stand.authToken },
    runId: bundle.manifest.runId
  });
  check(checks, 'reconcile возвращает тот же PASS', reconciled.verdict.verdict === 'PASS');
  checkNoMutation(checks, world, 1);
  check(checks, 'reconcile не добавил evidence', store.readEvidence(runDir).length === before.length);
  check(checks, 'второго request нет', store.readEvidence(runDir).filter(item => item.envelope.kind === 'request').length === 1);

  const repeated = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  check(checks, 'повторный старт возвращает тот же терминальный PASS', repeated.verdict.verdict === 'PASS');
  checkNoMutation(checks, world, 1);

  // store.mjs бросает Error('INTEGRITY_ERROR: ...') без code — проверяем по сообщению.
  let secondVerdictBlocked = false;
  try {
    store.appendEvidence(runDir, { runId: bundle.manifest.runId, manifestSha256: 'a'.repeat(64), fixtureId: contract.fixtureId, stepId: bundle.scenario.nodes.at(-1).id, producer: 'verification', kind: 'verdict', artifact: first.verdict });
  } catch (error) { secondVerdictBlocked = String(error.message || '').includes('INTEGRITY_ERROR'); }
  check(checks, 'второй verdict отвергнут INTEGRITY_ERROR', secondVerdictBlocked);
  check(checks, 'в evidence ровно один verdict', store.readEvidence(runDir).filter(item => item.envelope.kind === 'verdict').length === 1);

  // Повторный старт того же прогона не расходует новый approval и не меняет расход.
  const consumedBefore = fs.readFileSync(path.join(world.trustRoot, 'consumption', approval.approvalId + '.json'));
  const secondApproval = world.approvalFor({ bundle, contract });
  const repeatedAgain = await modules.trusted.startTrusted(bundle, world.trustedOptions(secondApproval));
  check(checks, 'повторный старт с новым approval возвращает прежний терминальный PASS', repeatedAgain.verdict.verdict === 'PASS');
  check(checks, 'файл расхода прежнего approval не изменён', fs.readFileSync(path.join(world.trustRoot, 'consumption', approval.approvalId + '.json')).equals(consumedBefore));
  check(checks, 'новый approval не израсходован', !fs.existsSync(path.join(world.trustRoot, 'consumption', secondApproval.approvalId + '.json')));
  checkNoMutation(checks, world, 1);
  return { checks };
} });
