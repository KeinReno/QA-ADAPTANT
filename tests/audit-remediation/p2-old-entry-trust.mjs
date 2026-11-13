// AUD-P2-OLDENTRY: старый вход start()/observe()/reconcile() не должен принимать аргументы
// доверенного режима (trust, approvalId, approval, trustRoot, adapter, standPublicKey, signerPipe,
// anchorKeyPath): иначе появляется обход PEP через старый вход.
//
// FAIL = старый вход принимает хотя бы один аргумент доверенного режима.
// PASS = все аргументы отвергнуты с кодом CONTRACT_INVALID.
import { loadModules, runScenario, check, targetRoot } from './audit-lib.mjs';

const FORBIDDEN = ['trust', 'approvalId', 'approval', 'trustRoot', 'adapter', 'adapterId', 'standPublicKey', 'signerPipe', 'anchorKeyPath'];

await runScenario({
  id: 'AUD-P2-OLDENTRY',
  title: 'Обход через старый вход start() с аргументом trust',
  expected: 'Старый вход не принимает ни одного аргумента доверенного режима',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const bundle = { manifest: { runId: 'reaudit-oldentry' }, scenario: null, operation: null, fixture: null };
    const results = [];
    for (const name of FORBIDDEN) {
      const options = { root: 'C:\\__reaudit_nonexistent_root__\\store', [name]: name === 'trust' ? { fake: true } : (name === 'approval' ? { approvalId: 'x' } : 'x') };
      let accepted = false;
      let code = null;
      let message = null;
      try {
        await M.run.start(bundle, options);
        accepted = true;
      } catch (error) {
        message = String(error?.message || error);
        code = error?.code || null;
        accepted = !message.includes('Старый вход не принимает аргумент доверенного режима');
      }
      results.push({ option: name, accepted, code, message: message ? message.slice(0, 160) : null });
    }
    const acceptedOptions = results.filter(item => item.accepted).map(item => item.option);
    check(checks, 'старый вход отверг все аргументы доверенного режима', acceptedOptions.length === 0, { acceptedOptions });
    return {
      defectObserved: acceptedOptions.length > 0,
      actual: acceptedOptions.length > 0
        ? 'старый вход принял аргументы доверенного режима: ' + acceptedOptions.join(', ')
        : 'старый вход отверг все аргументы доверенного режима',
      evidence: { results },
      checks
    };
  }
});
