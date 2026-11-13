// L-03: потерянный ACK после consumption оставляет неполную evidence chain.
// Ожидание: расход есть, POST/PASS нет; reconcile закрывается fail-closed, повтор требует нового approval.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, evidenceOf } from './_w2.mjs';

await caseMain({ id: 'L-03', title: 'Потерянный ACK после consumption без POST', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-l03' });
  const approval = world.approvalFor({ bundle, contract });
  let startError = null;
  try { await modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { fault: 'dropIntentAck' })); }
  catch (error) { startError = error; }
  check(checks, 'потерянный ACK приводит к fail-closed integrity error', String(startError?.message || '').includes('INTEGRITY_ERROR: EVIDENCE_CHAIN'), { message: startError?.message || null });
  const consumptionFile = path.join(world.trustRoot, 'consumption', approval.approvalId + '.json');
  check(checks, 'файл расхода создан', fs.existsSync(consumptionFile));
  const consumption = fs.existsSync(consumptionFile) ? JSON.parse(fs.readFileSync(consumptionFile, 'utf8')) : null;
  check(checks, 'расход связан с runId', consumption?.runId === bundle.manifest.runId, { consumption });
  checkNoMutation(checks, world);
  const evidence = evidenceOf(modules, world.root, bundle.manifest.runId);
  check(checks, 'mutation-intent записан', evidence.filter(item => item.envelope.kind === 'mutation-intent').length === 1);
  check(checks, 'request (POST) отсутствует', evidence.filter(item => item.envelope.kind === 'request').length === 0);
  check(checks, 'verdict PASS не опубликован', evidence.filter(item => item.envelope.kind === 'verdict' && item.artifact.verdict === 'PASS').length === 0);

  let reconcileError = null;
  try {
    await modules.trusted.reconcileTrusted({
      root: world.root, trustRoot: world.trustRoot, approvalId: approval.approvalId, approval,
      issuer: world.cards.owner, subject: world.cards.operator, standPublicKey: world.stand.standPublicKey,
      anchorKeyPath: path.join(world.secretsDir, 'anchor.key'),
      credentials: { [world.record.credentialRef]: world.stand.authToken },
      runId: bundle.manifest.runId
    });
  } catch (error) { reconcileError = error; }
  check(checks, 'reconcile не реконструирует PASS из неполной evidence chain', String(reconcileError?.message || '').includes('INTEGRITY_ERROR: EVIDENCE_CHAIN'), { message: reconcileError?.message || null });
  checkNoMutation(checks, world);
  check(checks, 'второго request evidence нет', evidenceOf(modules, world.root, bundle.manifest.runId).filter(item => item.envelope.kind === 'request').length === 0);
  check(checks, 'PASS verdict отсутствует', evidenceOf(modules, world.root, bundle.manifest.runId).filter(item => item.envelope.kind === 'verdict' && item.artifact.verdict === 'PASS').length === 0);

  const { bundle: secondBundle, contract: secondContract } = world.prepare({ runId: 'rt2-l03-retry' });
  const second = await modules.trusted.startTrusted(secondBundle, world.trustedOptions(approval));
  checkTrustedDenial(checks, second, { verdict: 'BLOCKED', reasonCodes: ['CONTRACT_INVALID', 'AUTH_UNAVAILABLE'] });
  checkNoMutation(checks, world);
  return { checks };
} });
