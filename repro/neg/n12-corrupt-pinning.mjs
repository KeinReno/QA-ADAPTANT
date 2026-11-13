// N12: повреждение или отсутствие закрепления ключей.
// Три подрежима на завершённом легитимном прогоне: удалён ready.json; испорчен owner.pub; удалён anchor.pub.
// Ожидание (и на базовом SHA): fail-closed TRUST_STORE_UNAVAILABLE, ложного PASS нет; легитимный PASS
// становится ненаблюдаемым (DoS-эффект фиксируется отдельно).
import { world, victimWorld, attackerWorld, runTrusted, observe, loadTrustRoot, fs, path, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const legit = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: v.trust, commitApprovalTo: v.trustRoot,
    ownerKey: v.ownerKey, ownerKeyId: v.created.ownerKeyId, issuer: v.owner, subject: v.operator,
    issuerId: 'victim-owner', subjectId: 'victim-operator', stand: v.stand, anchorKeyPath: v.anchorKeyPath
  });
  const files = {
    ready: path.join(v.trustRoot, 'ready.json'),
    owner: path.join(v.trustRoot, 'owner.pub'),
    anchor: path.join(v.trustRoot, 'anchor.pub')
  };
  const backups = Object.fromEntries(Object.entries(files).map(([key, file]) => [key, fs.readFileSync(file)]));
  const mutationsBefore = v.stand.mutationCount;
  async function probe(label, damage, restore) {
    damage();
    let loadError = null;
    try { loadTrustRoot(v.trustRoot); } catch (error) { loadError = err(error); }
    const observed = await observe({ root: v.root, trustRoot: v.trustRoot, runId: legit.runId });
    const rogueStand = await w.stand();
    const forged = await runTrusted({
      root: v.root, trustRoot: v.trustRoot, signTrust: a.trust, commitApprovalTo: v.trustRoot,
      ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
      issuerId: 'attacker-owner', subjectId: 'attacker-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
      registerRecord: true
    }).catch(error => ({ error: err(error) }));
    restore();
    return {
      label, loadError,
      observer: observed.observer || null, observerError: observed.observerError || null,
      forgedError: forged.error || null, forgedObserver: forged.observer || null,
      rogueMutations: rogueStand.mutationCount,
      trustedPass: forged.observer?.trusted === true && forged.observer?.passed === true && forged.observer?.verdict === 'PASS'
    };
  }
  const readyMissing = await probe('ready.json удалён', () => fs.rmSync(files.ready), () => fs.writeFileSync(files.ready, backups.ready));
  const ownerCorrupt = await probe('owner.pub повреждён', () => fs.writeFileSync(files.owner, '{"broken":'), () => fs.writeFileSync(files.owner, backups.owner));
  const anchorMissing = await probe('anchor.pub удалён', () => fs.rmSync(files.anchor), () => fs.writeFileSync(files.anchor, backups.anchor));
  const afterRestore = await observe({ root: v.root, trustRoot: v.trustRoot, runId: legit.runId });
  report('N12', 'Повреждение или отсутствие закрепления ключей', {
    boundaryReached: 'loadTrustRoot на повреждённом корне (три подрежима)',
    verdict: legit.result?.verdict ?? null, reasonCode: legit.result?.reasonCode ?? null,
    observer: afterRestore.observer || null, observerError: afterRestore.observerError || null,
    mutations: { victim: v.stand.mutationCount, victimBefore: mutationsBefore, rogue: readyMissing.rogueMutations + ownerCorrupt.rogueMutations + anchorMissing.rogueMutations },
    falseTrustedPass: [readyMissing, ownerCorrupt, anchorMissing].some(p => p.trustedPass),
    details: { readyMissing, ownerCorrupt, anchorMissing, legitObserverAfterRestore: afterRestore.observer || afterRestore.observerError || null },
    notes: 'Повреждение корня обязано давать fail-closed, а не PASS. DoS-эффект: легитимный прогон ненаблюдаем до восстановления файлов — отдельное замечание, не ложный PASS.'
  });
} catch (error) {
  report('N12', 'Повреждение или отсутствие закрепления ключей', { infraError: err(error) });
} finally { await w.cleanup(); }