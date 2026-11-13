// N04: согласованная замена всех трёх файлов (owner.pub + anchor.pub + ready.json)
// ПОСЛЕ легитимного прогона. Дополнительно: что observer показывает для старого легитимного run.
// Это атака R1 в моменте «после начала эксплуатации корня». Ожидание на исправлении: fail-closed.
import { world, victimWorld, attackerWorld, substitute, runTrusted, observe, loadTrustRoot, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const legit = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: v.trust, commitApprovalTo: v.trustRoot,
    ownerKey: v.ownerKey, ownerKeyId: v.created.ownerKeyId, issuer: v.owner, subject: v.operator,
    issuerId: 'victim-owner', subjectId: 'victim-operator', stand: v.stand, anchorKeyPath: v.anchorKeyPath
  });
  const legitObserverBefore = legit.observer || null;
  const mutationsBefore = v.stand.mutationCount;
  substitute(v, a);
  const taken = loadTrustRoot(v.trustRoot);
  const rootTakeover = taken.owner.keyId === a.created.ownerKeyId && taken['anchor-signer'].keyId === a.created.anchorKeyId;
  const rogueStand = await w.stand();
  const forged = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: taken, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
    issuerId: 'attacker-owner', subjectId: 'attacker-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
    registerRecord: true, recordTrust: taken
  }).catch(error => ({ error: err(error) }));
  const legitAfter = await observe({ root: v.root, trustRoot: v.trustRoot, runId: legit.runId });
  report('N04', 'Согласованная замена всех трёх файлов после легитимного прогона', {
    boundaryReached: rootTakeover ? 'loadTrustRoot принял подменённый корень (keyId атакующего)' : 'loadTrustRoot отверг подмену',
    verdict: forged.result?.verdict ?? null, reasonCode: forged.result?.reasonCode ?? forged.error?.code ?? null,
    observer: forged.observer || null, observerError: forged.observerError || forged.error || null,
    mutations: { victim: v.stand.mutationCount, victimBefore: mutationsBefore, rogue: rogueStand.mutationCount },
    falseTrustedPass: forged.observer?.trusted === true && forged.observer?.passed === true && forged.observer?.verdict === 'PASS',
    details: { rootTakeover, legitRunBefore: legit.result || legit.error || null, legitObserverBefore, legitObserverAfter: legitAfter.observer || legitAfter.observerError || null },
    notes: 'Базовое ожидание (1a510a5): ложный trusted PASS (R1). Исправление обязано отвергать подмену независимо от момента.'
  });
} catch (error) {
  report('N04', 'Согласованная замена всех трёх файлов после легитимного прогона', { infraError: err(error) });
} finally { await w.cleanup(); }