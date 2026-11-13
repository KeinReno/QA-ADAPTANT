// V-08: ключ owner предъявлен как подпись анкера.
// Ожидание: ANCHOR_SIGNATURE_INVALID; PASS не показывается; ключи не взаимозаменяемы.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkTrustedDenial } from './_w2.mjs';

await caseMain({ id: 'V-08', title: 'Ключ owner как подпись анкера', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-v08' });
  const approval = world.approvalFor({ bundle, contract });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  check(checks, 'исходный доверенный прогон PASS', result.verdict.verdict === 'PASS', { verdict: result.verdict.verdict });
  const choice = modules.anchor.readTerminalChoice(result.runDir);
  check(checks, 'выбран исход anchor', choice?.outcome === 'anchor', { outcome: choice?.outcome });
  const anchorFile = path.join(world.trustRoot, 'anchors', choice.anchorId + '.json');
  const originalBytes = fs.readFileSync(anchorFile);
  const statement = modules.anchor.loadAnchor(world.trustRoot, choice.anchorId);
  const body = modules.anchor.verifyAnchorStatement(world.trust, statement);

  // Тот же смысл заявления, но подпись owner-ключом.
  const forged = modules.identity.signTrustedDocument(world.ownerKey, { ...body, keyId: world.created.ownerKeyId });
  await (async () => {
    try {
      modules.anchor.verifyAnchorStatement(world.trust, forged);
      check(checks, 'owner-подпись анкера отвергнута ANCHOR_SIGNATURE_INVALID', false, { actual: 'подпись принята' });
    } catch (error) {
      check(checks, 'owner-подпись анкера отвергнута ANCHOR_SIGNATURE_INVALID', error.code === 'ANCHOR_SIGNATURE_INVALID', { code: error.code || null, message: error.message });
    }
  })();

  fs.writeFileSync(anchorFile, JSON.stringify(forged) + '\n');
  const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'observeTrusted не показывает PASS при owner-подписи', observed.passed === false, { passed: observed.passed, verdict: observed.verdict?.verdict || null, state: observed.publication, anchorStatus: observed.anchorStatus });
  fs.writeFileSync(anchorFile, originalBytes);
  const restored = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'после восстановления анкера PASS снова виден', restored.passed === true, { passed: restored.passed });
  return { checks };
} });