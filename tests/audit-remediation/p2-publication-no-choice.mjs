// AUD-P2-04: ошибка trust.publish не должна приводить к терминальному verdict без terminal-choice.
// Инъекция: trusted publication прерывается после durable signed receipt и до candidate/choice.
//
// FAIL = дефект: записан verdict без terminal-choice (состояние PUBLICATION_PENDING нарушено).
// PASS = verdict без terminal-choice не пишется; состояние остаётся pending/ошибкой.
import { loadModules, makeWorld, runScenario, check, targetRoot } from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P2-PUBLICATION',
  title: 'Ошибка публикации не создаёт verdict без terminal-choice',
  expected: 'При ошибке trust.publish терминальный verdict без terminal-choice не пишется',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const world = await makeWorld(M, { privateSigner: true });
    try {
      const prepared = world.prepare({ runId: 'reaudit-p204' });
      const approval = world.approvalFor(prepared);
      let runError = null;
      let result = null;
      try {
        result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval, {
          fault: 'throwAfterVerificationReceiptBeforeCandidate'
        }));
      }
      catch (error) { runError = { code: error?.code || null, message: String(error?.message || error) }; }
      const store = new M.store.RunStore(world.root);
      const runDir = store.runPath(prepared.runId);
      let kinds = [];
      try { kinds = store.readEvidence(runDir).map(item => item.envelope.kind); } catch { kinds = ['UNREADABLE']; }
      const choice = M.anchor.readTerminalChoice(runDir);
      const yes = (() => { try { return store.readEvidence(runDir).filter(item => item.envelope.kind === 'verdict').length; } catch { return -1; } })();
      const evidence = {
        runId: prepared.runId,
        runError,
        resultVerdict: result?.verdict?.verdict || null,
        evidenceKinds: kinds,
        verdictCount: yes,
        terminalChoice: choice ? { outcome: choice.outcome } : null,
        standMutationCount: world.stand.mutationCount
      };
      check(checks, 'ошибка после receipt возникла после ровно одной мутации', runError?.code === 'ANCHOR_CONFLICT' && world.stand.mutationCount === 1, { code: runError?.code || null, mutationCount: world.stand.mutationCount });
      const defect = yes >= 1 && choice === null;
      if (!defect) {
        check(checks, 'verdict без terminal-choice отсутствует', yes === 0 || choice !== null, { verdicts: yes, choice: evidence.terminalChoice });
        check(checks, 'состояние публикации не терминальное PASS', evidence.resultVerdict !== 'PASS', { verdict: evidence.resultVerdict });
      }
      return {
        defectObserved: defect,
        actual: defect
          ? 'ошибка publish привела к verdict без terminal-choice (' + (evidence.resultVerdict || 'verdict') + ')'
          : 'verdict без terminal-choice не записан; публикация осталась незавершённой',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
    }
  }
});
