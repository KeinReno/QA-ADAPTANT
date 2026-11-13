// N08: подложный approval от чужого owner при НЕПОВРЕЖДЁННОМ корне жертвы.
// Атакующий подписывает approval своим ключом и пытается провести прогон под корнем жертвы.
// Ожидание (и на базовом SHA): fail-closed — APPROVAL_SIGNATURE_INVALID, мутаций нет.
import { world, victimWorld, attackerWorld, bundleFor, approvalFields, signApproval, commitApproval, startTrusted, observe, randomUUID, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const runId = 'neg-' + randomUUID().slice(0, 8);
  const { bundle, contract } = bundleFor(v.stand, runId);
  const approval = signApproval(a.ownerKey, approvalFields({
    ownerKeyId: a.created.ownerKeyId, issuerId: 'attacker-owner', subjectId: 'attacker-operator', bundle, contract, stand: v.stand
  }), a.trust, null);
  let commitRejected = null;
  try { commitApproval(v.trust, v.trustRoot, approval); commitRejected = false; } catch (error) { commitRejected = error.code; }
  let startError = null;
  let result = null;
  try {
    const started = await startTrusted(bundle, {
      root: v.root, trustRoot: v.trustRoot, approvalId: approval.approvalId, approval,
      issuer: a.owner, subject: a.operator, anchorKeyPath: a.anchorKeyPath,
      standPublicKey: v.stand.standPublicKey, credentials: { 'local:fixture-token': v.stand.authToken }
    });
    result = { verdict: started.verdict?.verdict ?? null, reasonCode: started.verdict?.reasonCode ?? null };
  } catch (error) { startError = err(error); }
  const observed = await observe({ root: v.root, trustRoot: v.trustRoot, runId });
  report('N08', 'Подложный approval от чужого owner (корень не повреждён)', {
    boundaryReached: commitRejected ? 'commitApproval: ' + commitRejected : 'approval закреплён под корнем жертвы',
    verdict: result?.verdict ?? null, reasonCode: result?.reasonCode ?? startError?.code ?? null,
    observer: observed.observer || null, observerError: observed.observerError || null,
    mutations: { victim: v.stand.mutationCount, rogue: 0 },
    falseTrustedPass: observed.observer?.trusted === true && observed.observer?.passed === true && observed.observer?.verdict === 'PASS',
    details: { commitRejected, startError, approvalKeyId: approval.keyId, rootOwnerKeyId: v.created.ownerKeyId },
    notes: 'Подпись чужого owner не проходит под неповреждённым корнем; закрепление чужого approval также отвергается.'
  });
} catch (error) {
  report('N08', 'Подложный approval от чужого owner (корень не повреждён)', { infraError: err(error) });
} finally { await w.cleanup(); }