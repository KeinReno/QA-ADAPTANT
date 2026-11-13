// L-08: старый start() не принимает аргументы доверенного режима (иначе обход PEP).
// Ожидание: CONTRACT_INVALID до snapshot/мутации, approval остаётся issued, consumption нет.
import fs from 'node:fs';
import { caseMain, makeWorld, check, expectCode, checkNoMutation } from './_w2.mjs';

await caseMain({ id: 'L-08', title: 'Старый start() отвергает аргументы доверия', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-l08' });
  const approval = world.approvalFor({ bundle, contract });
  const extraArgs = { trustRoot: world.trustRoot, approvalId: approval.approvalId, approval, standPublicKey: world.stand.standPublicKey, signerPipe: world.signer.pipePath, adapter: 'local' };
  for (const key of Object.keys(extraArgs)) {
    await expectCode(checks, 'start() с аргументом ' + key + ' отвергнут', () => modules.run.start(bundle, { root: world.root, fixtureToken: world.stand.authToken, [key]: extraArgs[key] }), 'CONTRACT_INVALID');
  }
  checkNoMutation(checks, world);
  const runDir = modules.store.RunStore ? world.root + '\\runs\\rt2-l08' : null;
  check(checks, 'каталог прогона не создан', !fs.existsSync(runDir));
  check(checks, 'consumption не создан', !fs.existsSync(world.trustRoot + '\\consumption\\' + approval.approvalId + '.json'));
  const state = modules.approval.readApprovalState(world.trust, approval, { issuer: world.cards.owner, subject: world.cards.operator, windowsSid: world.sid, trustRoot: world.trustRoot });
  check(checks, 'approval остаётся issued', state.state === 'issued', { state: state.state });
  return { checks };
} });