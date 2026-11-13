// N03: замена ТОЛЬКО ready.json (owner.pub и anchor.pub — оригинальные).
// Ожидание на исправленном продукте: fail-closed, ложного trusted PASS нет.
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
  const mutationsBefore = v.stand.mutationCount;
  substitute(v, a, ['ready.json']);
  let loadError = null;
  try { loadTrustRoot(v.trustRoot); } catch (error) { loadError = err(error); }
  const rogueStand = await w.stand();
  const forged = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: a.trust, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
    issuerId: 'attacker-owner', subjectId: 'attacker-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
    registerRecord: true
  }).catch(error => ({ error: err(error) }));
  const legitAfter = await observe({ root: v.root, trustRoot: v.trustRoot, runId: legit.runId });
  report('N03', 'Замена только ready.json', {
    boundaryReached: loadError ? 'loadTrustRoot: ' + loadError.code : 'loadTrustRoot принял корень',
    verdict: forged.result?.verdict ?? null, reasonCode: forged.result?.reasonCode ?? forged.error?.code ?? null,
    observer: forged.observer || null, observerError: forged.observerError || forged.error || null,
    mutations: { victim: v.stand.mutationCount, victimBefore: mutationsBefore, rogue: rogueStand.mutationCount },
    falseTrustedPass: forged.observer?.trusted === true && forged.observer?.passed === true && forged.observer?.verdict === 'PASS',
    details: { loadError, legitRunBefore: legit.result || legit.error || null, legitObserverAfter: legitAfter.observer || legitAfter.observerError || null },
    notes: 'ready.json с чужими keyId рассогласуется с оригинальными pub-файлами — ожидается TRUST_STORE_UNAVAILABLE.'
  });
} catch (error) {
  report('N03', 'Замена только ready.json', { infraError: err(error) });
} finally { await w.cleanup(); }