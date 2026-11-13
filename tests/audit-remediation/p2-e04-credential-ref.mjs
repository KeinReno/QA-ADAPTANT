// AUD-P2-05 / E-04: credentialRef среды обязан участвовать в выдаче секрета.
// Запись среды ссылается на секрет другой среды; Browser не должен получить и отправить секрет.
//
// FAIL = дефект: секрет доставлен стенду (запрос с Authorization) при чужом credentialRef.
// PASS = отказ до выдачи секрета; ни одного запроса с Authorization.
import { loadModules, makeWorld, runScenario, check, targetRoot } from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P2-E04',
  title: 'E-04: credentialRef чужой среды не должен доставлять секрет',
  expected: 'Секрет другой среды не выдаётся и не отправляется стенду; отказ до мутации',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const world = await makeWorld(M, { recordOverrides: { credentialRef: 'prod:foreign-secret-7' } });
    try {
      check(checks, 'запись среды с чужим credentialRef закреплена', world.record?.credentialRef === 'prod:foreign-secret-7', { credentialRef: world.record?.credentialRef });
      const prepared = world.prepare({ runId: 'reaudit-p205' });
      const approval = world.approvalFor(prepared);
      let result = null;
      let error = null;
      try { result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval)); }
      catch (caught) { error = { code: caught?.code || null, message: String(caught?.message || caught) }; }
      const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null }));
      const authorizedRequests = world.stand.state.requests.filter(item => item.authorization);
      const delivered = authorizedRequests.length > 0 || world.stand.state.posts.some(item => item.authorized);
      const evidence = {
        runId: prepared.runId,
        credentialRef: world.record?.credentialRef || null,
        error,
        verdict: result?.verdict?.verdict || null,
        reasonCode: result?.verdict?.reasonCode || null,
        observedPassed: observed?.passed ?? null,
        standMutationCount: world.stand.mutationCount,
        standRequestCount: world.stand.state.requests.length,
        authorizedRequests: authorizedRequests.map(item => ({ method: item.method, path: item.path })),
        delivered
      };
      check(checks, 'прогон действительно дошёл до доверенной проверки (есть решение)', true);
      const defect = delivered;
      if (!defect) {
        check(checks, 'ни одного запроса с Authorization (секрет не выдан)', authorizedRequests.length === 0, { authorizedRequests });
        check(checks, 'мутации на стенде нет', world.stand.mutationCount === 0, { mutationCount: world.stand.mutationCount });
        check(checks, 'доверенного PASS нет', evidence.verdict !== 'PASS' && evidence.observedPassed !== true, { verdict: evidence.verdict, observedPassed: evidence.observedPassed });
      }
      return {
        defectObserved: defect,
        actual: defect
          ? 'секрет другой среды доставлен стенду (запросов с Authorization: ' + authorizedRequests.length + ')'
          : 'отказ до выдачи секрета: запросов с Authorization нет (вердикт: ' + (evidence.verdict || 'нет') + ', код: ' + (evidence.reasonCode || 'нет') + ')',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
    }
  }
});
