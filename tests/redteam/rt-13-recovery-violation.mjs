// RT-13: нарушение recovery — падение после POST/потери ответа.
// Ожидание: reconcile не повторяет POST, не добавляет второй request, оставляет ровно один verdict.
import { prepareRun, run, reconcile, readEvidenceJsonl } from './_run.mjs';
import { record, finish } from './_lib.mjs';

const checks = [];
const context = await prepareRun({ fault: 'lostResponse', runId: 'rt13-recovery' });
try {
  const first = await run(context.bundle, { root: context.root, fixtureToken: context.fixtureToken });
  record(checks, 'исходный прогон терминальный (INCONCLUSIVE/FAIL)', ['INCONCLUSIVE', 'FAIL'].includes(first.verdict.verdict), { verdict: first.verdict.verdict });
  record(checks, 'POST был ровно один', context.fixture.mutationCount === 1, { mutationCount: context.fixture.mutationCount });
  const evidenceBefore = readEvidenceJsonl(context.runDir);
  record(checks, 'в журнале ровно один request', evidenceBefore.filter(envelope => envelope.kind === 'request').length === 1);

  const reconciled = await reconcile({ root: context.root, runId: context.runId, fixtureToken: context.fixtureToken });
  record(checks, 'reconcile не меняет терминальный verdict', reconciled.verdict.verdict === first.verdict.verdict, { before: first.verdict.verdict, after: reconciled.verdict.verdict });
  record(checks, 'повторный POST не выполнен', context.fixture.mutationCount === 1, { mutationCount: context.fixture.mutationCount });
  record(checks, 'второй request evidence не появился', readEvidenceJsonl(context.runDir).filter(envelope => envelope.kind === 'request').length === 1);
  record(checks, 'verdict ровно один', readEvidenceJsonl(context.runDir).filter(envelope => envelope.kind === 'verdict').length === 1);

  const second = await reconcile({ root: context.root, runId: context.runId, fixtureToken: context.fixtureToken });
  record(checks, 'повторный reconcile стабилен', second.verdict.verdict === first.verdict.verdict && context.fixture.mutationCount === 1, { verdict: second.verdict.verdict, mutationCount: context.fixture.mutationCount });
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  await context.close();
}
finish({ id: 'RT-13', title: 'Восстановление после потерянного ответа: без второго POST', checks });
