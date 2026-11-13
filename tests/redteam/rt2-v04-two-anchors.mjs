// V-04: два разных заявления на один runId; второй не становится истиной.
// Состояние anchor-held воспроизводится гибелью процесса после записи анкера и до terminal-choice.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { caseMain, makeWorld, check, runDirOf, runChildProcess } from './_w2.mjs';

await caseMain({ id: 'V-04', title: 'Два заявления анкера на один runId', async body({ modules, cleanup, target, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-v04' });
  const approval = world.approvalFor({ bundle, contract });
  const base = world.base;
  const bundleFile = path.join(base, 'bundle.json');
  const issuerFile = path.join(base, 'issuer.json');
  const subjectFile = path.join(base, 'subject.json');
  const anchorFile = path.join(base, 'first-anchor.json');
  const errorFile = path.join(base, 'child-error.json');
  fs.writeFileSync(bundleFile, JSON.stringify(bundle));
  fs.writeFileSync(issuerFile, JSON.stringify(world.cards.owner));
  fs.writeFileSync(subjectFile, JSON.stringify(world.cards.operator));
  const requestFile = path.join(base, 'crash-request.json');
  const resultFile = path.join(base, 'child-result.json');
  fs.writeFileSync(requestFile, JSON.stringify({
    targetDir: target.dir, trustRoot: world.trustRoot, approvalId: approval.approvalId,
    issuerFile, subjectFile, sid: world.sid, standPublicKey: world.stand.standPublicKey,
    pipePath: world.signer.pipePath, root: world.root, fixtureToken: world.stand.authToken,
    bundleFile, anchorFile, errorFile, resultFile
  }));
  const childScript = path.join(path.dirname(fileURLToPath(import.meta.url)), '_w2-crash-child.mjs');
  const child = await runChildProcess(childScript, requestFile);
  const childError = fs.existsSync(errorFile) ? fs.readFileSync(errorFile, 'utf8') : null;
  const childResult = fs.existsSync(resultFile) ? fs.readFileSync(resultFile, 'utf8') : null;
  check(checks, 'процесс-жертва записал анкер и погиб до terminal-choice', child.status === 42, { status: child.status, childError, childResult, stderr: String(child.stderr || '').slice(0, 600) });
  const runDir = runDirOf(modules, world, bundle.manifest.runId);
  check(checks, 'анкер в trust root существует', fs.existsSync(anchorFile));
  check(checks, 'terminal-choice отсутствует', !fs.existsSync(path.join(runDir, 'trust', 'terminal-choice.json')));
  const evidence = modules.store ? new modules.store.RunStore(world.root).readEvidence(runDir) : [];
  check(checks, 'verdict ещё не опубликован', evidence.filter(item => item.envelope.kind === 'verdict').length === 0);
  const candidate = modules.anchor.readCandidate(runDir);
  check(checks, 'durable candidate PASS существует', candidate?.candidate?.verdict === 'PASS', { verdict: candidate?.candidate?.verdict || null });
  const anchorsDir = path.join(world.trustRoot, 'anchors');
  const anchorsBefore = fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')) : [];
  check(checks, 'в trust root ровно один анкер', anchorsBefore.length === 1, { anchors: anchorsBefore });

  // Публикация второго заявления для того же runId.
  const signer = await modules.anchorSigner.connectAnchorSigner(world.signer.pipePath);
  const firstAnchorBytes = fs.readFileSync(path.join(base, 'first-anchor.json'));
  try {
    await signer.sign({ runDir, approvalId: approval.approvalId, anchorId: 'anchor-second-attempt' });
    check(checks, 'второе заявление для runId отвергнуто ANCHOR_CONFLICT', false, { actual: 'подпись выдана' });
  } catch (error) {
    check(checks, 'второе заявление для runId отвергнуто ANCHOR_CONFLICT', error.code === 'ANCHOR_CONFLICT', { code: error.code || null, message: error.message });
  } finally {
    if (typeof signer.close === 'function') signer.close();
  }
  const anchorsAfter = fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')) : [];
  check(checks, 'второй анкер не создан', anchorsAfter.length === 1, { anchors: anchorsAfter });
  check(checks, 'первое заявление не изменено', fs.readFileSync(path.join(base, 'first-anchor.json')).equals(firstAnchorBytes));
  const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'PASS не появляется без терминальной публикации', observed.passed === false, { passed: observed.passed, state: observed.publication });
  return { checks };
} });