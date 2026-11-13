// N05: подмена ДО первой загрузки корня. Корень жертвы создан, но loadTrustRoot ещё не вызывался;
// атакующий перезаписывает три файла до первого чтения. Первая же загрузка возвращает ключи атакующего.
// Ожидание на исправленном продукте: fail-closed (внешнее закрепление обнаруживает подмену до старта).
import { world, victimWorld, attackerWorld, substitute, runTrusted, loadTrustRoot, verifyTrustedDocument, commitEnvironmentRecord, environmentRecordFor, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w, { load: false });
  const a = await attackerWorld(w);
  substitute(v, a);
  // Проба первой загрузки обёрнута для фиксации отказа продукта на исправленной ревизии;
  // атакующие шаги (подмена до первой загрузки + попытка доверенного прогона) не изменены.
  let firstLoad = null;
  let firstLoadError = null;
  try { firstLoad = loadTrustRoot(v.trustRoot); } catch (error) { firstLoadError = err(error); }
  const firstLoadTakeover = Boolean(firstLoad && firstLoad.owner.keyId === a.created.ownerKeyId && firstLoad['anchor-signer'].keyId === a.created.anchorKeyId);
  let victimPrincipalRejected = null;
  if (firstLoad) { try { verifyTrustedDocument(firstLoad, v.operator); victimPrincipalRejected = false; } catch (error) { victimPrincipalRejected = error.code; } }
  else victimPrincipalRejected = firstLoadError?.code || null;
  let victimRecordRejected = null;
  if (firstLoad) { try { commitEnvironmentRecord(firstLoad, v.trustRoot, environmentRecordFor(v.ownerKey, v.stand)); victimRecordRejected = false; } catch (error) { victimRecordRejected = error.code; } }
  else victimRecordRejected = firstLoadError?.code || null;
  const rogueStand = await w.stand();
  const forged = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: firstLoad || a.trust, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
    issuerId: 'attacker-owner', subjectId: 'attacker-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
    registerRecord: true, recordTrust: firstLoad || a.trust
  }).catch(error => ({ error: err(error) }));
  report('N05', 'Подмена до первой загрузки корня', {
    boundaryReached: firstLoadTakeover ? 'первый loadTrustRoot вернул ключи атакующего' : 'первый loadTrustRoot отверг подмену',
    verdict: forged.result?.verdict ?? null, reasonCode: forged.result?.reasonCode ?? forged.error?.code ?? null,
    observer: forged.observer || null, observerError: forged.observerError || forged.error || null,
    mutations: { victim: v.stand.mutationCount, rogue: rogueStand.mutationCount },
    falseTrustedPass: forged.observer?.trusted === true && forged.observer?.passed === true && forged.observer?.verdict === 'PASS',
    details: { firstLoadTakeover, firstLoadError, victimPrincipalRejected, victimRecordRejected },
    notes: 'WP-00 04-THREAT-MODEL.md:18 принимает подмену до старта как остаток; исправление F1 должно закрыть и этот момент либо явно оставить принятый остаток с решением владельца.'
  });
} catch (error) {
  report('N05', 'Подмена до первой загрузки корня', { infraError: err(error) });
} finally { await w.cleanup(); }