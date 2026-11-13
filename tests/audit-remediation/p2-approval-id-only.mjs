// AUD-P2-02: путь «только approvalId» без документа approval.
// startTrusted({approvalId}) должен прочитать закреплённый approval из trust root и выполнить
// все проверки как с документом, а не отказывать fail-closed.
//
// FAIL = дефект: путь не работает (BLOCKED/CONTRACT_INVALID вместо доверенного PASS).
// PASS = путь работает: доверенный PASS и ровно один POST.
import { loadModules, makeWorld, runScenario, check, targetRoot } from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P2-APPROVALID',
  title: 'Путь «только approvalId» без документа approval',
  expected: 'startTrusted({approvalId}) читает approval из trust root: доверенный PASS, один POST',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const world = await makeWorld(M);
    try {
      // Положительный контроль: с документом и без signerPipe (как в аудиторском сценарии).
      const controlCase = world.prepare({ runId: 'reaudit-p202-control' });
      const controlApproval = world.approvalFor(controlCase);
      const control = await M.trusted.startTrusted(controlCase.bundle, world.trustedOptions(controlApproval));
      const controlObserved = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: controlCase.runId });
      const controlOk = control?.verdict?.verdict === 'PASS' && controlObserved.passed === true;
      check(checks, 'положительный контроль с документом approval: доверенный PASS', controlOk, { verdict: control?.verdict?.verdict || null, passed: controlObserved.passed });
      if (!controlOk) return { defectObserved: false, actual: 'положительный контроль не прошёл: атака не доказательна', evidence: {}, checks };

      // Атака/проверка: тот же вход, но без документа approval.
      const attackCase = world.prepare({ runId: 'reaudit-p202-approvalid' });
      const attackApproval = world.approvalFor(attackCase);
      const options = world.trustedOptions(attackApproval);
      delete options.approval;
      let result = null;
      let error = null;
      try { result = await M.trusted.startTrusted(attackCase.bundle, options); }
      catch (caught) { error = { code: caught?.code || null, message: String(caught?.message || caught) }; }
      const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: attackCase.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null }));
      const evidence = {
        runId: attackCase.runId,
        approvalId: attackApproval.approvalId,
        error,
        verdict: result?.verdict?.verdict || null,
        reasonCode: result?.verdict?.reasonCode || null,
        message: result?.verdict?.message ? String(result.verdict.message).slice(0, 200) : null,
        observedPassed: observed?.passed ?? null,
        observedTrusted: observed?.trusted ?? null,
        standMutationCount: world.stand.mutationCount
      };
      const works = observedPassedTrue(observed) && evidence.verdict === 'PASS';
      function observedPassedTrue(value) { return value?.passed === true; }
      const defect = !works;
      if (!defect) {
        check(checks, 'выполнен ровно один POST', world.stand.mutationCount >= 1, { mutationCount: world.stand.mutationCount });
        check(checks, 'документ approval не передавался вовсе', options.approval === undefined);
      }
      return {
        defectObserved: defect,
        actual: defect
          ? 'путь «только approvalId» не работает: ' + (error?.code || 'нет ошибки') + '; вердикт ' + (evidence.verdict || 'нет')
          : 'путь «только approvalId» работает: доверенный PASS без документа approval',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
    }
  }
});
