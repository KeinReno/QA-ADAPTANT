// RT-12: подмена evidence на реальном прогоне.
// Ожидание: изменение байтов артефакта, подмена файлов, изменение конверта или журнала событий
// дают INTEGRITY_ERROR/INCOMPLETE_RUN, а не PASS.
import fs from 'node:fs';
import path from 'node:path';
import { prepareRun, run, observe, readEvidenceJsonl } from './_run.mjs';
import { record, finish, expectThrowLike } from './_lib.mjs';

const checks = [];
const context = await prepareRun({ runId: 'rt12-evidence-substitution' });
try {
  const first = await run(context.bundle, { root: context.root, fixtureToken: context.fixtureToken });
  record(checks, 'исходный прогон PASS', first.verdict.verdict === 'PASS');
  const evidence = readEvidenceJsonl(context.runDir);
  const verdictEnvelope = evidence.at(-1);
  const artifactDir = path.join(context.runDir, 'evidence');
  const verdictFile = path.join(artifactDir, verdictEnvelope.artifact.path);
  const original = fs.readFileSync(verdictFile);

  fs.writeFileSync(verdictFile, Buffer.concat([original, Buffer.from(' ')]));
  await expectThrowLike(checks, 'изменённый артефакт verdict -> INTEGRITY_ERROR',
    () => observe({ root: context.root, runId: context.runId }), { messageIncludes: 'INTEGRITY_ERROR' });
  fs.writeFileSync(verdictFile, original);

  const requestEnvelope = evidence.find(envelope => envelope.kind === 'request');
  const requestFile = path.join(artifactDir, requestEnvelope.artifact.path);
  const requestOriginal = fs.readFileSync(requestFile);
  fs.writeFileSync(requestFile, original);
  await expectThrowLike(checks, 'подмена артефакта request байтами verdict -> INTEGRITY_ERROR',
    () => observe({ root: context.root, runId: context.runId }), { messageIncludes: 'INTEGRITY_ERROR' });
  fs.writeFileSync(requestFile, requestOriginal);

  fs.rmSync(verdictFile);
  await expectThrowLike(checks, 'удалённый артефакт verdict -> INTEGRITY_ERROR',
    () => observe({ root: context.root, runId: context.runId }), { messageIncludes: 'INTEGRITY_ERROR' });
  fs.writeFileSync(verdictFile, original);

  // Изменение конверта в журнале evidence.
  const journalFile = path.join(context.runDir, 'evidence.jsonl');
  const journalOriginal = fs.readFileSync(journalFile);
  const lines = journalOriginal.toString('utf8').split('\n').filter(Boolean);
  const forged = JSON.parse(lines.at(-1));
  forged.evidenceId = 'forged-evidence-id';
  lines[lines.length - 1] = JSON.stringify(forged);
  fs.writeFileSync(journalFile, lines.join('\n') + '\n');
  await expectThrowLike(checks, 'изменённый конверт verdict -> INTEGRITY_ERROR',
    () => observe({ root: context.root, runId: context.runId }), { messageIncludes: 'INTEGRITY_ERROR' });
  fs.writeFileSync(journalFile, journalOriginal);

  // Изменение журнала событий.
  const eventsFile = path.join(context.runDir, 'events.jsonl');
  const eventsOriginal = fs.readFileSync(eventsFile, 'utf8');
  fs.writeFileSync(eventsFile, eventsOriginal.replace('"verdict":"PASS"', '"verdict":"FAIL"'));
  const outcome = await observe({ root: context.root, runId: context.runId }).then(value => ({ ok: true, value }), error => ({ ok: false, error }));
  record(checks, 'подмена журнала событий не даёт PASS', outcome.ok === false || outcome.value.verdict === null || outcome.value.verdict.verdict !== 'PASS', { outcome: outcome.ok ? 'наблюдение прошло' : outcome.error.message });
  fs.writeFileSync(eventsFile, eventsOriginal);

  const restored = await observe({ root: context.root, runId: context.runId });
  record(checks, 'после восстановления файлов наблюдение снова PASS', restored.verdict.verdict === 'PASS');
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  await context.close();
}
finish({ id: 'RT-12', title: 'Подмена evidence и журналов', checks });
