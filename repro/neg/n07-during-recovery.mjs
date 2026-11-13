// N07: подмена корня ВО ВРЕМЯ Recovery.
// Вариант A: легитимный прогон с fault missingEvidence (мутация есть, доказательства неполные) → подмена → reconcile.
// Вариант B: завершённый легитимный PASS → подмена → reconcile и повторное наблюдение.
// Фиксируется: принимает ли Recovery чужой корень, даёт ли повторную мутацию, что показывает observer.
// Ожидание на исправленном продукте: fail-closed, мутации не повторяются, ложного trusted PASS нет.
import { world, victimWorld, attackerWorld, substitute, runTrusted, observe, reconcileTrusted, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const rogueStand = await w.stand();
  const runA = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: v.trust, commitApprovalTo: v.trustRoot,
    ownerKey: v.ownerKey, ownerKeyId: v.created.ownerKeyId, issuer: v.owner, subject: v.operator,
    issuerId: 'victim-owner', subjectId: 'victim-operator', stand: v.stand, anchorKeyPath: v.anchorKeyPath,
    fault: 'missingEvidence'
  });
  const runB = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: v.trust, commitApprovalTo: v.trustRoot,
    ownerKey: v.ownerKey, ownerKeyId: v.created.ownerKeyId, issuer: v.owner, subject: v.operator,
    issuerId: 'victim-owner', subjectId: 'victim-operator', stand: v.stand, anchorKeyPath: v.anchorKeyPath
  });
  const mutationsBefore = v.stand.mutationCount;
  substitute(v, a);
  async function tryReconcile(label, run, who) {
    const p = who === 'attacker'
      ? { issuer: a.owner, subject: a.operator, anchorKeyPath: a.anchorKeyPath, standPublicKey: rogueStand.standPublicKey, credentials: { 'local:fixture-token': rogueStand.authToken } }
      : { issuer: v.owner, subject: v.operator, anchorKeyPath: v.anchorKeyPath, standPublicKey: v.stand.standPublicKey, credentials: { 'local:fixture-token': v.stand.authToken } };
    try {
      const result = await reconcileTrusted({ root: v.root, trustRoot: v.trustRoot, approvalId: run.approvalId, approval: null, runId: run.runId, ...p });
      return { label, verdict: result.verdict?.verdict ?? null, reasonCode: result.verdict?.reasonCode ?? null };
    } catch (error) { return { label, error: err(error) }; }
  }
  const reconcileAAttacker = await tryReconcile('A: незавершённый прогон, документы атакующего', runA, 'attacker');
  const reconcileAVictim = await tryReconcile('A: незавершённый прогон, документы жертвы', runA, 'victim');
  const reconcileBAttacker = await tryReconcile('B: завершённый PASS, документы атакующего', runB, 'attacker');
  const observeA = await observe({ root: v.root, trustRoot: v.trustRoot, runId: runA.runId });
  const observeB = await observe({ root: v.root, trustRoot: v.trustRoot, runId: runB.runId });
  const anyTrustedPass = [observeA.observer, observeB.observer].some(o => o && o.trusted === true && o.passed === true && o.verdict === 'PASS');
  report('N07', 'Подмена корня во время Recovery', {
    boundaryReached: 'reconcileTrusted после согласованной подмены трёх файлов',
    verdict: runB.result?.verdict ?? null, reasonCode: runB.result?.reasonCode ?? null,
    observer: observeB.observer || null, observerError: observeB.observerError || null,
    mutations: { victim: v.stand.mutationCount, victimBefore: mutationsBefore, rogue: rogueStand.mutationCount, repeatedMutation: v.stand.mutationCount > mutationsBefore },
    falseTrustedPass: anyTrustedPass,
    details: {
      runA: { result: runA.result || runA.error || null, observerBefore: runA.observer || null },
      runB: { result: runB.result || runB.error || null, observerBefore: runB.observer || null },
      reconcileAAttacker, reconcileAVictim, reconcileBAttacker,
      observeAAfter: observeA.observer || observeA.observerError || null,
      observeBAfter: observeB.observer || observeB.observerError || null
    },
    notes: 'Recovery не должен принимать чужой корень и не должен повторять мутацию. На базовом SHA подмена ломает и легитимное восстановление (хранимый approval больше не верифицируется) — фиксируется фактическое поведение.'
  });
} catch (error) {
  report('N07', 'Подмена корня во время Recovery', { infraError: err(error) });
} finally { await w.cleanup(); }