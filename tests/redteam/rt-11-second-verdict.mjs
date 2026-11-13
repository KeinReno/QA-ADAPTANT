// RT-11: повторный терминальный verdict на реальном прогоне.
// Ожидание: ровно один verdict; reconcile не добавляет второй; необработанный хвост после коммита не считается вердиктом.
import fs from 'node:fs';
import path from 'node:path';
import { prepareRun, run, reconcile, readEvidenceJsonl } from './_run.mjs';
import { record, finish, expectThrowLike } from './_lib.mjs';
import { RunStore } from '../../packages/core/store.mjs';

const checks = [];
const context = await prepareRun({ runId: 'rt11-second-verdict' });
try {
  const first = await run(context.bundle, { root: context.root, fixtureToken: context.fixtureToken });
  record(checks, 'прогон даёт PASS', first.verdict.verdict === 'PASS');
  const evidenceBefore = readEvidenceJsonl(context.runDir);
  const store = new RunStore(context.root);
  await expectThrowLike(checks, 'appendEvidence второго verdict запрещён', () => store.appendEvidence(context.runDir, {
    runId: context.runId, manifestSha256: first.manifestSha256 || 'a'.repeat(64), fixtureId: 'fixture-' + context.runId,
    stepId: 'verify', producer: 'verification', kind: 'verdict', artifact: first.verdict
  }), { messageIncludes: 'INTEGRITY_ERROR' });

  const reconciled = await reconcile({ root: context.root, runId: context.runId, fixtureToken: context.fixtureToken });
  record(checks, 'reconcile возвращает тот же verdict', reconciled.verdict.verdict === first.verdict.verdict);
  record(checks, 'reconcile не добавляет evidence', readEvidenceJsonl(context.runDir).length === evidenceBefore.length);

  // Попытка дописать второй verdict «в хвост» после подтверждённого коммита.
  const file = path.join(context.runDir, 'evidence.jsonl');
  const last = evidenceBefore.at(-1);
  const forged = { ...last, sequence: last.sequence + 1, previousSha256: undefined, evidenceId: 'forged-verdict-envelope' };
  fs.appendFileSync(file, JSON.stringify(forged) + '\n');
  const observed = await reconcile({ root: context.root, runId: context.runId, fixtureToken: context.fixtureToken });
  record(checks, 'неподтверждённый хвост не превращается во второй verdict', observed.verdict.verdict === first.verdict.verdict && observed.evidenceIds.length === evidenceBefore.length, { evidenceIds: observed.evidenceIds.length });
  const confirmed = store.readEvidence(context.runDir);
  record(checks, 'подтверждённых verdict по-прежнему один', confirmed.filter(item => item.envelope.kind === 'verdict').length === 1, { confirmed: confirmed.length });
  const commits = fs.readdirSync(path.join(context.runDir, 'evidence-commits')).sort();
  record(checks, 'коммит второго verdict не опубликован', commits.length === evidenceBefore.length, { commits: commits.length, evidence: evidenceBefore.length });
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  await context.close();
}
finish({ id: 'RT-11', title: 'Второй терминальный verdict', checks });