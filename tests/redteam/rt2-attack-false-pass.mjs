// GAP-01: PASS без годного анкера на интеграции должен быть невозможен.
// Проверяется: (A) прогон без подписанта -> INCONCLUSIVE, не PASS; (B) подделанный terminal-choice
// с несуществующим анкером; (C) чужой анкер от другого runId; (D) полностью подделанная локальная
// цепочка PASS без POST — observeTrusted не PASS, старый observe() как доказательство не годится.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkNoMutation, evidenceOf } from './_w2.mjs';

await caseMain({ id: 'GAP-01', title: 'Ложный PASS без анкера невозможен', async body({ modules, cleanup, checks }) {
  const observeSafe = async (root, trustRoot, runId) => {
    try { return await modules.trusted.observeTrusted({ root, trustRoot, runId }); }
    catch (error) { return { passed: false, publication: 'error', reasonCode: error.code || String(error.message || error) }; }
  };
  // Эталон: настоящий доверенный PASS с анкером.
  const trustedWorld = await makeWorld(modules);
  cleanup(trustedWorld.cleanup);
  const trustedRun = trustedWorld.prepare({ runId: 'rt2-gap01-real' });
  const trustedApproval = trustedWorld.approvalFor({ bundle: trustedRun.bundle, contract: trustedRun.contract });
  const real = await modules.trusted.startTrusted(trustedRun.bundle, trustedWorld.trustedOptions(trustedApproval));
  check(checks, 'эталонный доверенный прогон PASS', real.verdict.verdict === 'PASS', { verdict: real.verdict.verdict });
  const realObserved = await modules.trusted.observeTrusted({ root: trustedWorld.root, trustRoot: trustedWorld.trustRoot, runId: trustedRun.bundle.manifest.runId });
  check(checks, 'эталон: observeTrusted показывает PASS с анкером', realObserved.passed === true && realObserved.anchorStatus === 'ANCHOR_OK', { passed: realObserved.passed, anchorStatus: realObserved.anchorStatus });
  const realAnchorFile = path.join(trustedWorld.trustRoot, 'anchors', realObserved.anchorId + '.json');
  const realAnchor = fs.readFileSync(realAnchorFile);

  // V-02: подмена verdict после публикации — observeTrusted не PASS.
  const realStore = new modules.store.RunStore(trustedWorld.root);
  const realRunDir = realStore.runPath(trustedRun.bundle.manifest.runId);
  const realEvidence = realStore.readEvidence(realRunDir);
  const verdictItem = realEvidence.at(-1);
  const verdictArtifactFile = path.join(realRunDir, 'evidence', verdictItem.envelope.artifact.path);
  const originalVerdictBytes = fs.readFileSync(verdictArtifactFile);
  fs.writeFileSync(verdictArtifactFile, Buffer.concat([originalVerdictBytes, Buffer.from(' ')]));
  const tamperedVerdict = await observeSafe(trustedWorld.root, trustedWorld.trustRoot, trustedRun.bundle.manifest.runId);
  check(checks, '(V-02) подменённый verdict после публикации не даёт PASS', tamperedVerdict.passed === false, { passed: tamperedVerdict.passed, state: tamperedVerdict.publication, reasonCode: tamperedVerdict.reasonCode });
  fs.writeFileSync(verdictArtifactFile, originalVerdictBytes);

  // V-01: подмена терминального коммита evidence при старом анкере.
  const commitsDir = path.join(realRunDir, 'evidence-commits');
  const lastCommit = path.join(commitsDir, fs.readdirSync(commitsDir).sort().at(-1));
  const originalCommit = fs.readFileSync(lastCommit);
  fs.writeFileSync(lastCommit, JSON.stringify({ schemaVersion: '0.1.0', sequence: 1, envelopeSha256: 'f'.repeat(64), byteLength: 1 }) + '\n');
  const tamperedCommit = await observeSafe(trustedWorld.root, trustedWorld.trustRoot, trustedRun.bundle.manifest.runId);
  check(checks, '(V-01) подменённый терминальный коммит не даёт PASS при старом анкере', tamperedCommit.passed === false, { passed: tamperedCommit.passed, state: tamperedCommit.publication, reasonCode: tamperedCommit.reasonCode });
  fs.writeFileSync(lastCommit, originalCommit);
  const restoredReal = await modules.trusted.observeTrusted({ root: trustedWorld.root, trustRoot: trustedWorld.trustRoot, runId: trustedRun.bundle.manifest.runId });
  check(checks, 'после восстановления коммита и verdict PASS снова виден', restoredReal.passed === true);

  // (A) Нет подписанта: бизнес-PASS не публикуется как PASS.
  const noSignerWorld = await makeWorld(modules, { withSigner: false });
  cleanup(noSignerWorld.cleanup);
  const noSignerRun = noSignerWorld.prepare({ runId: 'rt2-gap01-nosigner' });
  const noSignerApproval = noSignerWorld.approvalFor({ bundle: noSignerRun.bundle, contract: noSignerRun.contract });
  const noSignerResult = await modules.trusted.startTrusted(noSignerRun.bundle, noSignerWorld.trustedOptions(noSignerApproval));
  check(checks, '(A) без подписанта вердикт INCONCLUSIVE/EVIDENCE_MISSING', noSignerResult.verdict.verdict === 'INCONCLUSIVE' && noSignerResult.verdict.reasonCode === 'EVIDENCE_MISSING', { verdict: noSignerResult.verdict.verdict, reasonCode: noSignerResult.verdict.reasonCode });
  const noSignerObserved = await modules.trusted.observeTrusted({ root: noSignerWorld.root, trustRoot: noSignerWorld.trustRoot, runId: noSignerRun.bundle.manifest.runId });
  check(checks, '(A) observeTrusted не показывает PASS', noSignerObserved.passed === false, { passed: noSignerObserved.passed, verdict: noSignerObserved.verdict?.verdict || null });
  checkNoMutation(checks, noSignerWorld, 1);

  // (B) Подделанный terminal-choice: исход anchor, файла анкера нет.
  const runDir = modules.store.RunStore ? new modules.store.RunStore(noSignerWorld.root).runPath(noSignerRun.bundle.manifest.runId) : null;
  const realChoice = modules.anchor.readTerminalChoice(runDir);
  const forgedChoice = {
    schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'anchor',
    candidateSha256: realChoice.candidateSha256, discardedCandidateSha256: null,
    anchorId: 'forged-missing-anchor', createdAt: new Date().toISOString()
  };
  fs.writeFileSync(path.join(runDir, 'trust', 'terminal-choice.json'), JSON.stringify(forgedChoice) + '\n');
  const forgedObserved = await modules.trusted.observeTrusted({ root: noSignerWorld.root, trustRoot: noSignerWorld.trustRoot, runId: noSignerRun.bundle.manifest.runId });
  check(checks, '(B) подделанный выбор без анкера не даёт PASS', forgedObserved.passed === false, { passed: forgedObserved.passed, state: forgedObserved.publication, reasonCode: forgedObserved.reasonCode, anchorStatus: forgedObserved.anchorStatus });

  // (C) Чужой анкер от другого runId.
  const anchorsDir = path.join(noSignerWorld.trustRoot, 'anchors');
  fs.mkdirSync(anchorsDir, { recursive: true });
  fs.writeFileSync(path.join(anchorsDir, 'borrowed-anchor.json'), realAnchor);
  const borrowedChoice = { ...forgedChoice, anchorId: 'borrowed-anchor' };
  fs.writeFileSync(path.join(runDir, 'trust', 'terminal-choice.json'), JSON.stringify(borrowedChoice) + '\n');
  const borrowedObserved = await modules.trusted.observeTrusted({ root: noSignerWorld.root, trustRoot: noSignerWorld.trustRoot, runId: noSignerRun.bundle.manifest.runId });
  check(checks, '(C) чужой анкер (другой runId) не даёт PASS', borrowedObserved.passed === false, { passed: borrowedObserved.passed, state: borrowedObserved.publication, reasonCode: borrowedObserved.reasonCode, anchorStatus: borrowedObserved.anchorStatus });
  fs.rmSync(path.join(anchorsDir, 'borrowed-anchor.json'));

  // (D) Полностью подделанная локальная цепочка PASS без POST и без candidate/anchor.
  const forgedRunId = 'rt2-gap01-forged';
  const forgedPrepared = noSignerWorld.prepare({ runId: forgedRunId });
  const store = new modules.store.RunStore(noSignerWorld.root);
  const forgedRunDir = store.snapshot(forgedPrepared.bundle, { runId: forgedRunId, pid: process.pid, at: new Date().toISOString() });
  const frozen = modules.bundle.verifyFrozenBundle(store, forgedRunDir);
  const { operation, fixture, manifest } = frozen;
  const manifestSha256 = modules.digest(manifest);
  const fixtureId = fixture.fixtureId;
  const baseEvidence = { runId: forgedRunId, manifestSha256, fixtureId };
  const click = frozen.scenario.nodes.find(node => node.action.type === 'click');
  const verifyNode = frozen.scenario.nodes.at(-1);
  const intentArtifact = { operationId: operation.id, mutationName: operation.mutation.name, intentId: forgedRunId + ':' + click.id, stepId: click.id, inputsSha256: modules.digest(operation.inputs), fixtureId };
  const intent = store.appendEvidence(forgedRunDir, { ...baseEvidence, stepId: click.id, producer: 'control', kind: 'mutation-intent', artifact: intentArtifact, parentEvidenceIds: [] });
  const requestId = 'forged-request';
  const requestArtifact = { requestId, intentId: intentArtifact.intentId, operationId: operation.id, method: 'POST', path: '/records', fixtureId, fields: { ...operation.inputs, fixtureId } };
  const request = store.appendEvidence(forgedRunDir, { ...baseEvidence, stepId: click.id, producer: 'browser', kind: 'request', artifact: requestArtifact, requestId, parentEvidenceIds: [intent.evidenceId] });
  const entity = { kind: operation.entityKind, id: 'forged-entity' };
  const responseArtifact = { requestId, intentId: intentArtifact.intentId, operationId: operation.id, fixtureId, status: 201, entity: { ...entity } };
  const response = store.appendEvidence(forgedRunDir, { ...baseEvidence, stepId: click.id, producer: 'browser', kind: 'response', artifact: responseArtifact, requestId, entity, parentEvidenceIds: [request.evidenceId] });
  const readArtifact = { method: 'GET', path: '/records', fixtureId, entity: { ...entity }, fields: { ...operation.inputs, fixtureId }, environmentFingerprint: manifest.environment.fingerprint, requestId, httpStatus: 200, observedAt: new Date().toISOString() };
  const read = store.appendEvidence(forgedRunDir, { ...baseEvidence, stepId: verifyNode.id, producer: 'verification', kind: 'independent-read', artifact: readArtifact, requestId, entity, parentEvidenceIds: [response.evidenceId], checkIds: operation.effects.map(effect => effect.id) });
  const forgedVerdict = {
    schemaVersion: '0.1.0', runId: forgedRunId, manifestSha256, verdict: 'PASS', reasonCode: 'NONE', message: 'поддельный PASS без POST',
    checks: operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds: [read.evidenceId] })),
    ownershipVerified: true, integrityVerified: true, completedAt: new Date().toISOString()
  };
  const verdictEnvelope = store.appendEvidence(forgedRunDir, { ...baseEvidence, stepId: verifyNode.id, producer: 'verification', kind: 'verdict', artifact: forgedVerdict, parentEvidenceIds: [read.evidenceId], checkIds: operation.effects.map(effect => effect.id) });
  store.appendEvent(forgedRunDir, { type: 'VERDICT_DURABLE', evidenceId: verdictEnvelope.evidenceId, verdict: 'PASS' });
  store.appendEvent(forgedRunDir, { type: 'STATE', state: 'FINISHED', verdict: 'PASS', reasonCode: 'NONE' });
  const forgedTrusted = await modules.trusted.observeTrusted({ root: noSignerWorld.root, trustRoot: noSignerWorld.trustRoot, runId: forgedRunId });
  check(checks, '(D) observeTrusted не показывает PASS для подделанной цепочки', forgedTrusted.passed === false, { passed: forgedTrusted.passed, state: forgedTrusted.publication, reasonCode: forgedTrusted.reasonCode });
  const oldObserve = await modules.run.observe({ root: noSignerWorld.root, runId: forgedRunId });
  check(checks, '(D) старый observe() показывает PASS — он не является доказательством доверенного PASS', oldObserve.verdict?.verdict === 'PASS', { oldVerdict: oldObserve.verdict?.verdict || null });
  // Имя проверки совпадает со смыслом: подделка не добавила ни одного POST.
  check(checks, '(D) подделанный прогон не добавил POST (мутация только от эталонного no-signer прогона)', noSignerWorld.stand.mutationCount === 1, { mutationCount: noSignerWorld.stand.mutationCount });
  return { checks };
} });