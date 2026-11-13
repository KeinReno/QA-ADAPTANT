// V-09: late signer response must not replace a timeout result.
// The complete late-anchor/unlinked case is asserted in trust-anchor.test.mjs;
// this Red Team case exercises the target's budget race helper on the pinned SHA.
import path from 'node:path';
import { caseMain, makeWorld, check, writeTrustProfile, sleep } from './_w2.mjs';

await caseMain({ id: 'V-09', title: 'Поздний ответ подписанта не переопределяет истёкший бюджет', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  writeTrustProfile(world.trustRoot, 120);
  let lateSettled = false;
  const lateResponse = new Promise(resolve => setTimeout(() => { lateSettled = true; resolve({ anchorId: 'late-anchor' }); }, 300));
  const outcome = await modules.anchor.anchorWithinBudget({
    signer: { sign: () => lateResponse },
    trustRoot: world.trustRoot,
    runDir: path.join(world.root, 'synthetic-run'),
    approvalId: 'approval-v09',
    anchorId: 'anchor-v09'
  });
  check(checks, 'по истечении бюджета результат ANCHOR_TIMEOUT', outcome.ok === false && outcome.code === 'ANCHOR_TIMEOUT', { ok: outcome.ok, code: outcome.code });
  check(checks, 'выбранный бюджет прочитан из profile', outcome.budgetMs === 120, { budgetMs: outcome.budgetMs });
  await sleep(220);
  check(checks, 'поздний ответ завершился отдельно и не изменил timeout outcome', lateSettled && outcome.code === 'ANCHOR_TIMEOUT', { lateSettled, code: outcome.code });
  return { checks };
} });
