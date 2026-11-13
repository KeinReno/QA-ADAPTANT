// L-03: падение после consumption и до POST (потерянный ACK intent).
// Ожидание: расход есть, POST нет; reconcile не отправляет POST и не разыгрывает dispatch заново;
// новая попытка требует нового approval.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, evidenceOf } from './_w2.mjs';

await caseMain({ id: 'L-03', title: 'Падение после consumption и до POST', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-l03' });
  const approval = world.approvalFor({ bundle, contract });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { fault: 'dropIntentAck' }));
  check(checks, 'прогон терминальный и не PASS', ['INCONCLUSIVE', 'BLOCKED', 'FAIL'].includes(result.verdict.verdict), { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode });
  const consumptionFile = path.join(world.trustRoot, 'consumption', approval.approvalId + '.json');
  check(checks, 'файл расхода создан', fs.existsSync(consumptionFile));
  const consumption = fs.existsSync(consumptionFile) ? JSON.parse(fs.readFileSync(consumptionFile, 'utf8')) : null;
  check(checks, 'расход связан с runId', consumption?.runId === bundle.manifest.runId, { consumption });
  checkNoMutation(checks, world);
  const evidence = evidenceOf(modules, world.root, bundle.manifest.runId);
  check(checks, 'mutation-intent записан', evidence.filter(item => item.envelope.kind === 'mutation-intent').length === 1);
  check(checks, 'request (POST) отсутствует', evidence.filter(item => item.envelope.kind === 'request').length === 0);

  const reconciled = await modules.trusted.reconcileTrusted({
    root: world.root, trustRoot: world.trustRoot, approvalId: approval.approvalId, approval,
    issuer: world.cards.owner, subject: world.cards.operator, standPublicKey: world.stand.standPublicKey,
    signerPipe: world.signer.pipePath, runId: bundle.manifest.runId
  });
  check(checks, 'reconcile сохраняет терминальный verdict', reconciled.verdict.verdict === result.verdict.verdict, { before: result.verdict.verdict, after: reconciled.verdict.verdict });
  checkNoMutation(checks, world);
  check(checks, 'второго request evidence нет', evidenceOf(modules, world.root, bundle.manifest.runId).filter(item => item.envelope.kind === 'request').length === 0);
  check(checks, 'verdict ровно один', evidenceOf(modules, world.root, bundle.manifest.runId).filter(item => item.envelope.kind === 'verdict').length === 1);

  const { bundle: secondBundle, contract: secondContract } = world.prepare({ runId: 'rt2-l03-retry' });
  const second = await modules.trusted.startTrusted(secondBundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, second, { verdict: 'BLOCKED', reasonCodes: ['CONTRACT_INVALID', 'AUTH_UNAVAILABLE'] });
  checkNoMutation(checks, world);
  return { checks };
} });