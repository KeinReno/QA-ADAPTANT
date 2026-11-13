// V-03: таймаут ожидания подписанта в пределах anchorBudgetMs.
// Проверяется helper самого target на задержанном signer stub; сквозной recovery
// private signer проверяется отдельными trusted/recovery тестами.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, writeTrustProfile, sleep } from './_w2.mjs';

await caseMain({ id: 'V-03', title: 'Таймаут ожидания подписанта закрывается fail-closed', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  writeTrustProfile(world.trustRoot, 250);
  let settledLate = false;
  const delayed = {
    sign() { return sleep(600).then(() => { settledLate = true; return { anchorId: 'late' }; }); }
  };
  const started = Date.now();
  const outcome = await modules.anchor.anchorWithinBudget({
    signer: delayed,
    trustRoot: world.trustRoot,
    runDir: path.join(world.root, 'synthetic-run'),
    approvalId: 'approval-v03',
    anchorId: 'anchor-v03'
  });
  const elapsed = Date.now() - started;
  await sleep(400);
  check(checks, 'долгий ответ не принимается как анкер', outcome.ok === false && outcome.code === 'ANCHOR_TIMEOUT', { ok: outcome.ok, code: outcome.code });
  check(checks, 'источник бюджета — подписанный trust profile', outcome.budgetMs === 250, { budgetMs: outcome.budgetMs });
  check(checks, 'таймаут срабатывает раньше ответа подписанта', elapsed < 550 && settledLate === true, { elapsed, settledLate });
  const anchorDir = path.join(world.trustRoot, 'anchors');
  const anchorFiles = requireAnchorFiles(anchorDir);
  check(checks, 'таймаут не создаёт файл анкера', anchorFiles.length === 0, { anchorFiles });
  return { checks };
} });

function requireAnchorFiles(directory) {
  try { return fs.readdirSync(directory).filter(name => name.endsWith('.json')); }
  catch { return []; }
}
