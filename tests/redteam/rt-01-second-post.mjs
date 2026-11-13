// RT-01: второй POST бизнес-мутации и второй терминальный verdict на реальном прогоне 0.1.
// Ожидание: ровно один POST, второй reconcile/start не мутирует, второй verdict невозможен,
// Bearer стенда не попадает в каталог прогона.
import fs from 'node:fs';
import path from 'node:path';
import { prepareRun, run, start, reconcile, readEvidenceJsonl, evidenceFiles } from './_run.mjs';
import { record, finish, expectThrowLike, findText } from './_lib.mjs';
import { RunStore } from '../../packages/core/store.mjs';

const checks = [];
const context = await prepareRun({ runId: 'rt01-second-post' });
try {
  const first = await run(context.bundle, { root: context.root, fixtureToken: context.fixtureToken });
  record(checks, 'первый прогон даёт PASS', first.verdict.verdict === 'PASS', { verdict: first.verdict.verdict, reasonCode: first.verdict.reasonCode });
  record(checks, 'стенд получил ровно один POST', context.fixture.mutationCount === 1, { mutationCount: context.fixture.mutationCount });
  const evidenceBefore = readEvidenceJsonl(context.runDir);
  const requestsBefore = evidenceBefore.filter(envelope => envelope.kind === 'request').length;
  record(checks, 'в журнале ровно один request', requestsBefore === 1, { requests: requestsBefore });

  const reconciled = await reconcile({ root: context.root, runId: context.runId, fixtureToken: context.fixtureToken });
  record(checks, 'reconcile завершённого прогона не меняет verdict', reconciled.verdict.verdict === first.verdict.verdict, { verdict: reconciled.verdict.verdict });
  record(checks, 'reconcile не шлёт второй POST', context.fixture.mutationCount === 1, { mutationCount: context.fixture.mutationCount });
  record(checks, 'reconcile не добавляет evidence', readEvidenceJsonl(context.runDir).length === evidenceBefore.length, { before: evidenceBefore.length, after: readEvidenceJsonl(context.runDir).length });

  const secondStart = await start(context.bundle, { root: context.root, fixtureToken: context.fixtureToken });
  record(checks, 'повторный start возвращает тот же терминальный verdict', secondStart.verdict.verdict === first.verdict.verdict);
  record(checks, 'повторный start не шлёт второй POST', context.fixture.mutationCount === 1, { mutationCount: context.fixture.mutationCount });

  const store = new RunStore(context.root);
  await expectThrowLike(checks, 'второй terminal verdict запрещён журналом', () => store.appendEvidence(context.runDir, {
    runId: context.runId,
    manifestSha256: reconciled.manifestSha256 || first.manifestSha256,
    fixtureId: 'fixture-' + context.runId,
    stepId: 'verify',
    producer: 'verification',
    kind: 'verdict',
    artifact: first.verdict
  }), { messageIncludes: 'INTEGRITY_ERROR' });

  const evidence = readEvidenceJsonl(context.runDir);
  const verdicts = evidence.filter(envelope => envelope.kind === 'verdict').length;
  record(checks, 'в evidence ровно один verdict', verdicts === 1, { verdicts });
  const events = fs.readFileSync(path.join(context.runDir, 'events.jsonl'), 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
  record(checks, 'в событиях ровно один VERDICT_DURABLE', events.filter(event => event.type === 'VERDICT_DURABLE').length === 1);
  record(checks, 'в событиях ровно один REQUEST_DURABLE', events.filter(event => event.type === 'REQUEST_DURABLE').length === 1);

  const tokenLeaks = findText(context.runDir, context.fixtureToken);
  record(checks, 'Bearer стенда не записан в каталог прогона', tokenLeaks.length === 0, { files: tokenLeaks });
  record(checks, 'файлов evidence ровно столько, сколько конвертов', evidenceFiles(context.runDir).length === evidence.length);
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  await context.close();
}
finish({ id: 'RT-01', title: 'Второй POST, второй terminal verdict и утечка Bearer (реальный прогон)', checks });