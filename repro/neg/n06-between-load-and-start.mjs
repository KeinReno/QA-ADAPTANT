// N06: подмена МЕЖДУ загрузкой корня и началом прогона.
// Control загрузил корень (ключи в памяти), затем атакующий перезаписывает файлы, затем старт.
// Фиксируется: (а) иммунен ли in-memory снимок; (б) перечитывает ли публичный вход корень.
// Ожидание на исправленном продукте: fail-closed; закреплённые keyId не принимают чужой корень.
import { world, victimWorld, attackerWorld, substitute, runTrusted, loadTrustRoot, verifyTrustedDocument, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const snapshotVerifiesVictim = verifyTrustedDocument(v.trust, v.operator).principalId;
  substitute(v, a);
  let snapshotRejectsAttacker = null;
  try { verifyTrustedDocument(v.trust, a.operator); snapshotRejectsAttacker = false; } catch (error) { snapshotRejectsAttacker = error.code; }
  // Проба повторной загрузки обёрнута для фиксации отказа продукта; атакующие шаги не изменены.
  let reloadTakeover = false;
  let reloadError = null;
  try { reloadTakeover = loadTrustRoot(v.trustRoot).owner.keyId === a.created.ownerKeyId; } catch (error) { reloadError = err(error); }
  const rogueStand = await w.stand();
  const forged = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: a.trust, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
    issuerId: 'attacker-owner', subjectId: 'attacker-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
    registerRecord: true
  }).catch(error => ({ error: err(error) }));
  report('N06', 'Подмена между загрузкой корня и началом прогона', {
    boundaryReached: forged.observer?.trusted ? 'публичный вход перечитал подменённый корень и провёл прогон' : 'публичный вход отверг подменённый корень',
    verdict: forged.result?.verdict ?? null, reasonCode: forged.result?.reasonCode ?? forged.error?.code ?? null,
    observer: forged.observer || null, observerError: forged.observerError || forged.error || null,
    mutations: { victim: v.stand.mutationCount, rogue: rogueStand.mutationCount },
    falseTrustedPass: forged.observer?.trusted === true && forged.observer?.passed === true && forged.observer?.verdict === 'PASS',
    details: { snapshotVerifiesVictim, snapshotRejectsAttacker, reloadTakeover, reloadError },
    notes: 'In-memory снимок не подвержен перезаписи файлов, но каждый публичный вход (startTrusted/observeTrusted/reconcileTrusted) вызывает loadTrustRoot заново — момент подмены не ограничен «до старта».'
  });
} catch (error) {
  report('N06', 'Подмена между загрузкой корня и началом прогона', { infraError: err(error) });
} finally { await w.cleanup(); }