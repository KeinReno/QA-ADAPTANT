// AUD-P1-01: доверенный наблюдатель обязан выполнять паритет с 0.1
// (assertEvidenceRefs + assertTerminalEvidence + validateVerdictCoverage).
// Сценарий: существует валидный анкер на PASS-candidate, но проверки candidate не подтверждены
// независимым чтением. Старый путь 0.1 обязан отказать (VERDICT_COVERAGE), значит и доверенный
// наблюдатель не имеет права показывать trusted/PASS.
//
// FAIL = дефект воспроизводится: 0.1-паритет нарушен, а доверенный наблюдатель показывает PASS.
// PASS = наблюдатель не слабее 0.1.
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, forgeRun, signViaSignerClients, signAnchorDirect, observeAll, runScenario, check, targetRoot } from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P1-01',
  title: 'Доверенный наблюдатель не должен быть слабее 0.1 (паритет evidence/coverage)',
  expected: 'Если 0.1-паритет (assertEvidenceRefs/assertTerminalEvidence/validateVerdictCoverage) нарушен, trusted/PASS не показывается',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const world = await makeWorld(M);
    try {
      const runId = 'reaudit-p101';
      // candidate PASS, но его checks не подтверждены независимым чтением (evidenceIds пустые).
      const forged = forgeRun(M, world, { runId, mode: 'parity-broken' });
      const approval = world.approvalFor({ bundle: forged.bundle, contract: forged.contract });
      const expected = world.expectedFor({ bundle: forged.bundle, contract: forged.contract });
      M.approval.consumeDispatch({
        trust: world.trust, trustRoot: world.trustRoot, approval,
        issuer: world.cards.owner, subject: world.cards.operator, windowsSid: world.sid,
        expected, runId, decisionId: 'decision-p101'
      });

      const anchorId = 'anchor-reaudit-p101';
      let anchor = await signViaSignerClients(M, world, { runDir: forged.runDir, approvalId: approval.approvalId, anchorId });
      let method = 'public-signer';
      if (!anchor.ok) {
        try {
          anchor = await signAnchorDirect(M, world, { runDir: forged.runDir, approvalId: approval.approvalId, anchorId });
          method = 'direct-anchor-key';
        } catch (error) {
          anchor = { ok: false, error: { code: error?.code || null, message: String(error?.message || error) } };
          method = 'unavailable';
        }
      }
      const evidence = {
        runId,
        anchor: anchor.ok ? { method, anchorId, verdict: anchor.statement?.verdict } : { ok: false, method, error: anchor.error },
        candidateVerdict: forged.candidate.verdict,
        candidateChecks: forged.candidate.checks
      };
      if (!anchor.ok) {
        // Анкер недоступен: проверить паритет наблюдателя напрямую нельзя, но и PASS показать нечем.
        const observed = await observeAll(M, world, runId);
        check(checks, 'без годного анкера доверенный PASS не показывается', observed.trustedObserver.passed !== true, { trusted: observed.trustedObserver.trusted });
        return { defectObserved: false, actual: 'анкер не получен (' + (anchor.error?.code || 'нет') + '): атака на наблюдателя не выполнена, PASS не показан', evidence, checks };
      }

      M.anchor.publishTerminalChoice(forged.runDir, M.anchor.buildTerminalChoice({
        outcome: 'anchor', candidateSha256: forged.published.candidateSha256, anchorId
      }));
      M.anchor.publishTerminalVerdict({ store: forged.store, runDir: forged.runDir, frozen: forged.frozen, trust: world.trust, trustRoot: world.trustRoot });
      const observed = await observeAll(M, world, runId);
      evidence.parity = observed.parity;
      evidence.trustedObserver = {
        state: observed.trustedObserver.state, trusted: observed.trustedObserver.trusted, passed: observed.trustedObserver.passed,
        verdict: observed.trustedObserver.verdict?.verdict || null, anchorStatus: observed.trustedObserver.anchorStatus || null,
        reasonCode: observed.trustedObserver.reasonCode || null
      };
      evidence.publicObserveTrusted = observed.publicTrusted ? {
        trusted: observed.publicTrusted.trusted, passed: observed.publicTrusted.passed,
        verdict: observed.publicTrusted.verdict?.verdict || null, anchorStatus: observed.publicTrusted.anchorStatus || null
      } : null;

      const parityBroken = typeof observed.parity.error === 'string' && observed.parity.error.length > 0;
      check(checks, '0.1-паритет действительно нарушен (assertEvidenceRefs/coverage)', parityBroken, observed.parity);
      const weakObserver = parityBroken && observed.trustedObserver.trusted === true && observed.trustedObserver.passed === true && observed.trustedObserver.verdict?.verdict === 'PASS';
      return {
        defectObserved: weakObserver,
        actual: weakObserver
          ? 'доверенный наблюдатель слабее 0.1: PASS показан при нарушенном VERDICT_COVERAGE'
          : 'наблюдатель отказал при нарушенном паритете (reasonCode: ' + (observed.trustedObserver.reasonCode || 'нет') + ')',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
    }
  }
});
