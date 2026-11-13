// P01: положительный контроль — настоящий владелец с легитимными ключами получает обоснованный PASS.
// Дополнительно: reconcile завершённого прогона идемпотентен и не выполняет вторую мутацию.
// Обязателен для приёмки исправления: защита не должна ломать легитимный доверенный маршрут.
import { world, victimWorld, runTrusted, observe, reconcileTrusted, verifyTrustedDocument, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const principalVerifies = verifyTrustedDocument(v.trust, v.operator).principalId;
  const legit = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: v.trust, commitApprovalTo: v.trustRoot,
    ownerKey: v.ownerKey, ownerKeyId: v.created.ownerKeyId, issuer: v.owner, subject: v.operator,
    issuerId: 'victim-owner', subjectId: 'victim-operator', stand: v.stand, anchorKeyPath: v.anchorKeyPath
  });
  const mutationsAfterRun = v.stand.mutationCount;
  let reconcile = null;
  try {
    const result = await reconcileTrusted({
      root: v.root, trustRoot: v.trustRoot, approvalId: legit.approvalId, approval: null,
      issuer: v.owner, subject: v.operator, anchorKeyPath: v.anchorKeyPath,
      standPublicKey: v.stand.standPublicKey, credentials: { 'local:fixture-token': v.stand.authToken }, runId: legit.runId
    });
    reconcile = { verdict: result.verdict?.verdict ?? null, reasonCode: result.verdict?.reasonCode ?? null };
  } catch (error) { reconcile = { error: err(error) }; }
  const observed = await observe({ root: v.root, trustRoot: v.trustRoot, runId: legit.runId });
  const legitPass = legit.observer?.trusted === true && legit.observer?.passed === true && legit.observer?.verdict === 'PASS';
  const reconcileOk = reconcile && !reconcile.error && reconcile.verdict === 'PASS';
  report('P01', 'Положительный контроль: легитимный владелец, обоснованный PASS', {
    boundaryReached: 'полный доверенный маршрут: approval → мутация → Verification → анкер → observer',
    verdict: legit.result?.verdict ?? null, reasonCode: legit.result?.reasonCode ?? null,
    observer: observed.observer || null, observerError: observed.observerError || null,
    mutations: { victim: v.stand.mutationCount, afterRun: mutationsAfterRun, repeatedMutation: v.stand.mutationCount > mutationsAfterRun },
    falseTrustedPass: false,
    details: { positiveControl: true, legitPass, principalVerifies, runResult: legit.result || legit.error || null, reconcile, reconcileIdempotent: reconcileOk && v.stand.mutationCount === mutationsAfterRun },
    notes: 'PASS легитимен: observer trusted+passed, мутация одна, reconcile не повторяет мутацию. Поле falseTrustedPass=false по смыслу проверки (это не атака).'
  });
} catch (error) {
  report('P01', 'Положительный контроль: легитимный владелец, обоснованный PASS', { infraError: err(error) });
} finally { await w.cleanup(); }