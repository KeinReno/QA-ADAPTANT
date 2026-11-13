// N11: попытка несанкционированной ротации ключей.
// (а) createTrustRoot поверх существующего корня; (б) он же после удаления только ready.json;
// (в) «ротация» перезаписью трёх файлов новым ключами атакующего (A2) + подложный прогон.
// Ожидание: (а)/(б) fail-closed штатным механизмом; (в) на исправлении — обнаружение подмены.
import { world, victimWorld, attackerWorld, substitute, runTrusted, createTrustRoot, fs, path, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w, 'rotator');
  let recreateRejected = null;
  try { await createTrustRoot({ secretsDir: v.secretsDir, trustRoot: v.trustRoot, runDir: v.root }); recreateRejected = false; } catch (error) { recreateRejected = error.code; }
  const readyFile = path.join(v.trustRoot, 'ready.json');
  const readyBackup = fs.readFileSync(readyFile);
  fs.rmSync(readyFile);
  let partialRecreateRejected = null;
  try { await createTrustRoot({ secretsDir: v.secretsDir, trustRoot: v.trustRoot, runDir: v.root }); partialRecreateRejected = false; } catch (error) { partialRecreateRejected = error.code; }
  fs.writeFileSync(readyFile, readyBackup);
  const mutationsBefore = v.stand.mutationCount;
  substitute(v, a);
  const rogueStand = await w.stand();
  const forged = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: a.trust, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
    issuerId: 'rotator-owner', subjectId: 'rotator-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
    registerRecord: true
  }).catch(error => ({ error: err(error) }));
  report('N11', 'Несанкционированная ротация ключей', {
    boundaryReached: forged.observer?.trusted ? 'перезапись трёх файлов новыми ключами принята (ротация без полномочий)' : 'перезапись обнаружена/отвергнута',
    verdict: forged.result?.verdict ?? null, reasonCode: forged.result?.reasonCode ?? forged.error?.code ?? null,
    observer: forged.observer || null, observerError: forged.observerError || forged.error || null,
    mutations: { victim: v.stand.mutationCount, victimBefore: mutationsBefore, rogue: rogueStand.mutationCount },
    falseTrustedPass: forged.observer?.trusted === true && forged.observer?.passed === true && forged.observer?.verdict === 'PASS',
    details: { recreateRejected, partialRecreateRejected, newOwnerKeyId: a.created.ownerKeyId, originalOwnerKeyId: v.created.ownerKeyId },
    notes: 'Штатный createTrustRoot не перезаписывает существующие ключи (flag wx). Ротация перезаписью файлов — та же атака R1; право ротации должно принадлежать только владельцу через защищённый механизм.'
  });
} catch (error) {
  report('N11', 'Несанкционированная ротация ключей', { infraError: err(error) });
} finally { await w.cleanup(); }