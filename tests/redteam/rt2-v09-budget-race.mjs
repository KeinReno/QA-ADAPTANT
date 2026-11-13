// V-09: бюджет истекает в тот же момент, когда подписант создал анкер PASS.
// Ожидание: один терминальный выбор; опоздавший анкер — ANCHOR_UNLINKED, перехода в PASS нет,
// ANCHOR_CONFLICT нет; POST остаётся один.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkNoMutation, trustedContext, runWithContext, writeTrustProfile, sleep, connectSigner, evidenceOf } from './_w2.mjs';

await caseMain({ id: 'V-09', title: 'Гонка бюджета и уже созданного анкера PASS', async body({ modules, cleanup }) {
  const checks = [];
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  writeTrustProfile(world.trustRoot, 1500);
  const { bundle, contract } = world.prepare({ runId: 'rt2-v09' });
  const approval = world.approvalFor({ bundle, contract });
  const real = await connectSigner(modules, world);
  cleanup(() => { try { real.close(); } catch { /* канал закрыт */ } });
  const slowSigner = {
    async sign(request) {
      const statementPromise = real.sign(request); // анкер создаётся сразу
      const anchorsDir = path.join(world.trustRoot, 'anchors');
      for (let attempt = 0; attempt < 300; attempt++) {
        if (fs.existsSync(anchorsDir) && fs.readdirSync(anchorsDir).some(name => name.endsWith('.json'))) break;
        await sleep(10);
      }
      await sleep(2200); // ответ приходит после бюджета 1500 мс
      return statementPromise;
    }
  };
  const context = await trustedContext(modules, world, approval, slowSigner);
  const result = await runWithContext(modules, world, bundle, context);
  await sleep(400); // дать опоздавшему подписанту дописать анкер
  check(checks, 'выбран один исход budget-inconclusive', modules.anchor.readTerminalChoice(result.runDir)?.outcome === 'budget-inconclusive', { outcome: modules.anchor.readTerminalChoice(result.runDir)?.outcome });
  check(checks, 'вердикт INCONCLUSIVE', result.verdict.verdict === 'INCONCLUSIVE', { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode });
  checkNoMutation(checks, world, 1);
  const anchorsDir = path.join(world.trustRoot, 'anchors');
  const anchors = fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')) : [];
  check(checks, 'опоздавший анкер PASS существует в trust root', anchors.length === 1, { anchors });
  const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'нет перехода в PASS', observed.passed === false, { passed: observed.passed });
  check(checks, 'анкер помечен ANCHOR_UNLINKED', observed.anchorStatus === 'ANCHOR_UNLINKED' || observed.reasonCode === 'ANCHOR_UNLINKED', { anchorStatus: observed.anchorStatus, reasonCode: observed.reasonCode });
  check(checks, 'состояние терминальное, а не inconsistent (нет ANCHOR_CONFLICT)', observed.publication === 'terminal', { publication: observed.publication });
  check(checks, 'unlinkedAnchorId указывает на опоздавший анкер', Boolean(observed.unlinkedAnchorId), { unlinkedAnchorId: observed.unlinkedAnchorId });
  const repeated = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'повторное наблюдение не даёт PASS', repeated.passed === false && repeated.publication === 'terminal');
  check(checks, 'в evidence ровно один verdict', evidenceOf(modules, world.root, bundle.manifest.runId).filter(item => item.envelope.kind === 'verdict').length === 1);
  return { checks };
} });