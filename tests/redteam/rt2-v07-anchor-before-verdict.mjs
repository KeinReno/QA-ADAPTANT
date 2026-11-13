// V-07: анкер и выбор исхода записаны, verdict ещё нет, процесс упал.
// Ожидание: восстановление дописывает ровно один verdict, равный выбранному candidate; второго бюджета нет.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { caseMain, makeWorld, check, runDirOf, runChildProcess } from './_w2.mjs';

await caseMain({ id: 'V-07', title: 'Анкер записан, verdict не опубликован', async body({ modules, cleanup, target, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-v07' });
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
    credentials: world.record ? { [world.record.credentialRef]: world.stand.authToken } : {},
    bundleFile, anchorFile, errorFile, resultFile
  }));
  const childScript = path.join(path.dirname(fileURLToPath(import.meta.url)), '_w2-crash-child.mjs');
  const child = await runChildProcess(childScript, requestFile);
  const childError = fs.existsSync(errorFile) ? fs.readFileSync(errorFile, 'utf8') : null;
  const childResult = fs.existsSync(resultFile) ? fs.readFileSync(resultFile, 'utf8') : null;
  check(checks, 'процесс погиб после анкера (exit 42)', child.status === 42, { status: child.status, childError, childResult, stderr: String(child.stderr || '').slice(0, 600) });
  const runDir = runDirOf(modules, world, bundle.manifest.runId);
  const store = new modules.store.RunStore(world.root);
  const frozen = modules.bundle.verifyFrozenBundle(store, runDir);
  const candidate = modules.anchor.readCandidate(runDir);
  check(checks, 'durable candidate PASS', candidate?.candidate?.verdict === 'PASS');
  const statement = JSON.parse(fs.readFileSync(anchorFile, 'utf8'));
  // Восстановление: сначала фиксируется выбор исхода (как в доверенной публикации), затем verdict.
  modules.anchor.publishTerminalChoice(runDir, {
    schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'anchor',
    candidateSha256: candidate.candidateSha256, discardedCandidateSha256: null,
    anchorId: statement.anchorId, createdAt: new Date().toISOString()
  });
  const first = modules.anchor.publishTerminalVerdict({ store, runDir, frozen, trust: world.trust, trustRoot: world.trustRoot });
  const second = modules.anchor.publishTerminalVerdict({ store, runDir, frozen, trust: world.trust, trustRoot: world.trustRoot });
  const verdictItems = store.readEvidence(runDir).filter(item => item.envelope.kind === 'verdict');
  check(checks, 'дописан ровно один verdict', verdictItems.length === 1, { count: verdictItems.length });
  check(checks, 'байты verdict равны выбранному candidate', modules.digest(verdictItems[0]?.artifact) === candidate.candidateSha256);
  check(checks, 'первый вызов создал verdict', first.created === true);
  check(checks, 'второй вызов не создаёт второй verdict', second.created === false && second.evidenceId === first.evidenceId);
  const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'после восстановления PASS связан с анкером', observed.passed === true && observed.anchorStatus === 'ANCHOR_OK', { passed: observed.passed, anchorStatus: observed.anchorStatus });
  check(checks, 'нового POST при восстановлении не было', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
  return { checks };
} });