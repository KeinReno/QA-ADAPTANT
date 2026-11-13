// AUD-P1-02 / V-07: уже выданный анкерованный PASS не должен теряться при восстановлении.
// Инъекция аварии: родитель следит за trustRoot/anchors и убивает Control сразу после записи
// анкера, до терминального verdict. Затем новый процесс выполняет reconcileTrusted.
//
// FAIL = дефект воспроизводится: анкерованный PASS теряется (verdict не равен candidate,
//        INCONCLUSIVE/ANCHOR_UNLINKED, появляется второй анкер или второй POST).
// PASS = восстановление дописывает ровно выбранный candidate, PASS связан с анкером,
//        новых анкеров/verdict/POST нет.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { loadModules, makeWorld, runScenario, check, targetRoot, sleep, spawnNode, tempDir, removeDir } from './audit-lib.mjs';

function childSource() {
  return [
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    "import { pathToFileURL } from 'node:url';",
    "const [target, requestFile] = process.argv.slice(2);",
    "const request = JSON.parse(fs.readFileSync(requestFile, 'utf8'));",
    "const imp = rel => import(pathToFileURL(path.join(target, rel)).href);",
    "const trusted = await imp('apps/control/trusted.mjs');",
    "const approval = JSON.parse(fs.readFileSync(path.join(request.trustRoot, 'approvals', request.approvalId + '.json'), 'utf8'));",
    "const issuer = JSON.parse(fs.readFileSync(request.issuerFile, 'utf8'));",
    "const subject = JSON.parse(fs.readFileSync(request.subjectFile, 'utf8'));",
    "const bundle = JSON.parse(fs.readFileSync(request.bundleFile, 'utf8'));",
    "try {",
    "  const result = await trusted.startTrusted(bundle, {",
    "    root: request.root, trustRoot: request.trustRoot, approvalId: request.approvalId, approval, issuer, subject,",
    "    standPublicKey: request.standPublicKey, anchorKeyPath: request.anchorKeyPath,",
    "    credentials: { 'local:fixture-token': request.fixtureToken }, fixtureToken: request.fixtureToken,",
    "    fault: 'afterAnchorBeforeTerminalChoice'",
    "  });",
    "  fs.writeFileSync(request.resultFile, JSON.stringify({ verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null }));",
    "  process.exit(43);",
    "} catch (error) {",
    "  fs.writeFileSync(request.errorFile, JSON.stringify({ code: error?.code || null, message: String(error?.message || error) }));",
    "  process.exit(44);",
    "}",
    "process.exit(0);"
  ].join('\n') + '\n';
}

function killTree(pid) {
  try { spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true, timeout: 20000 }); } catch { /* уже завершён */ }
}

async function crashAtAnchor(M, world, workDir, { runId, tamperAfterAnchor = false }) {
  const casePrepared = world.prepare({ runId });
  const approval = world.approvalFor(casePrepared);
  const bundleFile = path.join(workDir, runId + '-bundle.json');
  const issuerFile = path.join(workDir, runId + '-issuer.json');
  const subjectFile = path.join(workDir, runId + '-subject.json');
  const requestFile = path.join(workDir, runId + '-request.json');
  const resultFile = path.join(workDir, runId + '-result.json');
  const errorFile = path.join(workDir, runId + '-error.json');
  fs.writeFileSync(bundleFile, JSON.stringify(casePrepared.bundle));
  fs.writeFileSync(issuerFile, JSON.stringify(world.cards.owner));
  fs.writeFileSync(subjectFile, JSON.stringify(world.cards.operator));
  fs.writeFileSync(requestFile, JSON.stringify({
    target: targetRoot(), trustRoot: world.trustRoot,
    issuerFile, subjectFile, sid: world.sid, standPublicKey: world.stand.standPublicKey,
    secretsDir: world.secretsDir, root: world.root, fixtureToken: world.stand.authToken,
    approvalId: approval.approvalId, bundleFile, resultFile, errorFile,
    anchorKeyPath: path.join(world.secretsDir, 'anchor.key')
  }));
  const childScript = path.join(workDir, 'crash-child.mjs');
  fs.writeFileSync(childScript, childSource());
  const anchorDir = path.join(world.trustRoot, 'anchors');
  const initialAnchors = fs.existsSync(anchorDir) ? fs.readdirSync(anchorDir).filter(name => name.endsWith('.json')) : [];
  const { spawn } = await import('node:child_process');
  const child = spawn(process.execPath, [childScript, targetRoot(), requestFile], { stdio: 'ignore', windowsHide: true });
  let sawNewAnchor = false;
  const observeAnchor = setInterval(() => {
    const current = fs.existsSync(anchorDir) ? fs.readdirSync(anchorDir).filter(name => name.endsWith('.json')) : [];
    if (current.some(name => !initialAnchors.includes(name))) {
      sawNewAnchor = true;
      clearInterval(observeAnchor);
      killTree(child.pid);
    }
  }, 25);
  observeAnchor.unref();
  const exitCode = await new Promise(resolve => {
    const timer = setTimeout(() => { clearInterval(observeAnchor); killTree(child.pid); resolve('TIMEOUT'); }, 120000);
    child.once('exit', code => { clearTimeout(timer); clearInterval(observeAnchor); resolve(code); });
    child.once('error', () => { clearTimeout(timer); clearInterval(observeAnchor); resolve('ERROR'); });
  });
  await sleep(400);
  killTree(child.pid);
  const store = new M.store.RunStore(world.root);
  const runDir = store.runPath(runId);
  let verdicts = 0;
  try { verdicts = store.readEvidence(runDir).filter(item => item.envelope.kind === 'verdict').length; } catch { verdicts = -1; }
  const anchorFiles = fs.existsSync(anchorDir) ? fs.readdirSync(anchorDir).filter(name => name.endsWith('.json')) : [];
  const candidateFile = path.join(runDir, 'trust', 'candidate.json');
  const candidateExists = fs.existsSync(candidateFile);
  let tamperedCandidate = null;
  if (tamperAfterAnchor && candidateExists) {
    const original = fs.readFileSync(candidateFile);
    const candidate = JSON.parse(original.toString('utf8'));
    candidate.message = 'подмена candidate после подписи анкера';
    fs.writeFileSync(candidateFile, Buffer.from(JSON.stringify(candidate) + '\n'));
    tamperedCandidate = { originalSha256: M.digest(JSON.parse(original.toString('utf8'))), tamperedSha256: M.digest(candidate) };
  }
  return {
    casePrepared, approval, store, runDir, exitCode, anchorFiles, candidateExists, tamperedCandidate,
    verdictsAtKill: verdicts,
    anchorSeen: sawNewAnchor,
    childResult: fs.existsSync(resultFile) ? JSON.parse(fs.readFileSync(resultFile, 'utf8')) : null,
    childError: fs.existsSync(errorFile) ? JSON.parse(fs.readFileSync(errorFile, 'utf8')) : null
  };
}

await runScenario({
  id: 'AUD-P1-02',
  title: 'V-07: восстановление после анкера не теряет уже выданный анкерованный PASS',
  expected: 'reconcile дописывает ровно выбранный candidate; 1 verdict; anchorId сохранён; нет второго анкера/verdict/POST',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const workDir = tempDir('wp08-p102-');
    const world = await makeWorld(M, {});
    try {
      // 1) Авария сразу после записи анкера (до терминального verdict).
      let crash = null;
      const attempts = [];
      for (let attempt = 1; attempt <= 3; attempt++) {
        const current = await crashAtAnchor(M, world, workDir, { runId: 'reaudit-p102-' + attempt });
        attempts.push({ attempt, exitCode: current.exitCode, childResult: current.childResult, childError: current.childError, anchorSeen: current.anchorSeen, anchorFiles: current.anchorFiles, verdictsAtKill: current.verdictsAtKill });
        if (current.anchorSeen && current.anchorFiles.length >= 1 && current.verdictsAtKill === 0) { crash = current; break; }
        // Не целое состояние: повторяем на новом runId.
      }
      if (!crash) {
        check(checks, 'удалось зафиксировать состояние anchor-held (гибель после анкера до verdict)', false);
        return { defectObserved: false, actual: 'аварию после анкера зафиксировать не удалось: V-07 не проверен (INCONCLUSIVE)', evidence: { attempts }, checks };
      }
      check(checks, 'состояние anchor-held зафиксировано', true, { attemptsRunId: crash.casePrepared.runId, anchorFiles: crash.anchorFiles, verdictsAtKill: crash.verdictsAtKill });
      const candidateBefore = M.anchor.readCandidate(crash.runDir);
      const anchorIdBefore = crash.anchorFiles[0].replace(/\.json$/, '');

      // 2) Восстановление новым процессом.
      let reconciled = null;
      let reconcileError = null;
      try {
        reconciled = await M.trusted.reconcileTrusted({
          root: world.root, trustRoot: world.trustRoot, approvalId: crash.approval.approvalId, approval: crash.approval,
          issuer: world.cards.owner, subject: world.cards.operator,
          standPublicKey: world.stand.standPublicKey,
          anchorKeyPath: path.join(world.secretsDir, 'anchor.key'),
          credentials: { 'local:fixture-token': world.stand.authToken },
          runId: crash.casePrepared.runId
        });
      } catch (error) {
        reconcileError = { code: error?.code || null, message: String(error?.message || error) };
      }
      const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: crash.casePrepared.runId }).catch(error => ({ error: String(error?.message || error), passed: null, trusted: null }));
      const store = crash.store;
      const kinds = (() => { try { return store.readEvidence(crash.runDir).map(item => item.envelope.kind); } catch { return ['UNREADABLE']; } })();
      const verdictItems = (() => { try { return store.readEvidence(crash.runDir).filter(item => item.envelope.kind === 'verdict'); } catch { return []; } })();
      const anchorFilesAfter = fs.existsSync(path.join(world.trustRoot, 'anchors')) ? fs.readdirSync(path.join(world.trustRoot, 'anchors')).filter(name => name.endsWith('.json')) : [];
      const choice = M.anchor.readTerminalChoice(crash.runDir);
      const candidateAfter = M.anchor.readCandidate(crash.runDir);
      const verdictMatchesCandidate = verdictItems.length === 1 && candidateBefore !== null &&
        M.digest(verdictItems[0].artifact) === candidateBefore.candidateSha256;
      const anchorPreserved = anchorFilesAfter.length === 1 && anchorFilesAfter[0].replace(/\.json$/, '') === anchorIdBefore && choice?.anchorId === anchorIdBefore;
      const recoveredPass = observed?.passed === true && observed?.anchorStatus === 'ANCHOR_OK' && verdictMatchesCandidate && anchorPreserved;

      const evidence = {
        runId: crash.casePrepared.runId,
        killedAtAnchor: crash.anchorSeen,
        childExitCode: crash.exitCode,
        childError: crash.childError,
        childResult: crash.childResult,
        reconcileError,
        reconcileVerdict: reconciled?.verdict?.verdict || null,
        reconcileReasonCode: reconciled?.verdict?.reasonCode || null,
        observed: { trusted: observed?.trusted ?? null, passed: observed?.passed ?? null, publication: observed?.publication || null, anchorStatus: observed?.anchorStatus || null, reasonCode: observed?.reasonCode || null },
        evidenceKinds: kinds,
        verdictCount: verdictItems.length,
        verdictMatchesCandidate,
        anchorIdBefore,
        anchorFilesAfter,
        anchorPreserved,
        choice: choice ? { outcome: choice.outcome, anchorId: choice.anchorId } : null,
        candidateSha256Before: candidateBefore?.candidateSha256 || null,
        candidateSha256After: candidateAfter?.candidateSha256 || null,
        standMutationCount: world.stand.mutationCount,
        requestCount: kinds.filter(kind => kind === 'request').length
      };
      const defect = !recoveredPass;
      if (defect) {
        evidence.defectReason = !verdictMatchesCandidate ? 'verdict не равен выбранному candidate или его нет'
          : !anchorPreserved ? 'анкер не сохранён (потерян/второй/не связан с выбором)'
            : 'доверенный PASS не восстановлен';
      }
      if (!defect) {
        check(checks, 'нового POST при восстановлении не было (mutationCount = 1)', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
        check(checks, 'ровно один request-evidence', evidence.requestCount === 1, { requestCount: evidence.requestCount });
        check(checks, 'ровно один терминальный verdict', verdictItems.length === 1, { verdicts: verdictItems.length });
      }
      return {
        defectObserved: defect,
        actual: defect
          ? 'анкерованный PASS потерян при восстановлении: ' + evidence.defectReason + ' (reconcile: ' + (reconcileError?.code || reconciled?.verdict?.verdict || 'нет') + ')'
          : 'восстановление дописало ровно выбранный candidate; PASS связан с исходным анкером',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
      removeDir(workDir);
    }
  }
});
