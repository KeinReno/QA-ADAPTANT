// V-03: candidate PASS записан, но подписант недоступен дольше anchorBudgetMs.
// Ожидание: один INCONCLUSIVE EVIDENCE_MISSING, POST остаётся один; повторное наблюдение не даёт PASS.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkNoMutation, trustedContext, runWithContext, writeTrustProfile, sleep, evidenceOf } from './_w2.mjs';

await caseMain({ id: 'V-03', title: 'Подписант недоступен дольше бюджета анкера', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  writeTrustProfile(world.trustRoot, 500);
  const { bundle, contract } = world.prepare({ runId: 'rt2-v03' });
  const approval = world.approvalFor({ bundle, contract });
  const unavailableSigner = {
    async sign() {
      await sleep(800);
      throw Object.assign(new Error('Подписант недоступен'), { code: 'ANCHOR_UNAVAILABLE' });
    }
  };
  const context = await trustedContext(modules, world, approval, unavailableSigner);
  const result = await runWithContext(modules, world, bundle, context);
  check(checks, 'вердикт INCONCLUSIVE/EVIDENCE_MISSING', result.verdict.verdict === 'INCONCLUSIVE' && result.verdict.reasonCode === 'EVIDENCE_MISSING', { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode });
  checkNoMutation(checks, world, 1);
  const choice = modules.anchor.readTerminalChoice(result.runDir);
  check(checks, 'выбран исход budget-inconclusive', choice?.outcome === 'budget-inconclusive', { outcome: choice?.outcome });
  const anchorsDir = path.join(world.trustRoot, 'anchors');
  const anchors = fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')) : [];
  check(checks, 'анкер не создан (подписант недоступен)', anchors.length === 0, { anchors });
  const verdicts = evidenceOf(modules, world.root, bundle.manifest.runId).filter(item => item.envelope.kind === 'verdict');
  check(checks, 'в evidence ровно один verdict и это INCONCLUSIVE', verdicts.length === 1 && verdicts[0].artifact.verdict === 'INCONCLUSIVE', { verdicts: verdicts.length });
  const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'observeTrusted не показывает PASS', observed.passed === false && observed.verdict?.verdict === 'INCONCLUSIVE', { passed: observed.passed, verdict: observed.verdict?.verdict || null });
  const repeated = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'повторное наблюдение не превращает INCONCLUSIVE в PASS', repeated.passed === false && repeated.verdict?.verdict === 'INCONCLUSIVE');
  checkNoMutation(checks, world, 1);
  return { checks };
} });