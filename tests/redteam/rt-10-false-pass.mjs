// RT-10: ложный PASS. Атака: собрать полностью валидную локальную цепочку evidence
// с вердиктом PASS, не отправив ни одного POST (mutationCount=0) и не имея approval/consumption/анкера.
// Ожидание 0.2: PASS невозможен без анкера. На базе 0e7e6c2 анкер не реализован — проверяем факт разрыва.
import fs from 'node:fs';
import path from 'node:path';
import { serveLocalFixture } from '../../adapters/local/server.mjs';
import { prepareRun, observe } from './_run.mjs';
import { record, finish, digest } from './_lib.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';

const checks = [];
const context = await prepareRun({ runId: 'rt10-forged-pass' });
try {
  const store = new RunStore(context.root);
  const runDir = store.snapshot(context.bundle, { runId: context.runId, pid: process.pid, at: new Date().toISOString() });
  const frozen = verifyFrozenBundle(store, runDir);
  const { operation, fixture, manifest } = frozen;
  const manifestSha256 = digest(manifest);
  const clickNode = frozen.scenario.nodes.find(node => node.action.type === 'click');
  const verifyNode = frozen.scenario.nodes.at(-1);
  const fixtureId = fixture.fixtureId;
  const base = { runId: context.runId, manifestSha256, fixtureId };

  const intentArtifact = {
    operationId: operation.id, mutationName: operation.mutation.name,
    intentId: context.runId + ':' + clickNode.id, stepId: clickNode.id,
    inputsSha256: digest(operation.inputs), fixtureId
  };
  const intent = store.appendEvidence(runDir, { ...base, stepId: clickNode.id, producer: 'control', kind: 'mutation-intent', artifact: intentArtifact, parentEvidenceIds: [] });
  const requestId = 'forged-request';
  const requestArtifact = {
    requestId, intentId: intentArtifact.intentId, operationId: operation.id,
    method: 'POST', path: '/records', fixtureId, fields: { ...operation.inputs, fixtureId }
  };
  const request = store.appendEvidence(runDir, { ...base, stepId: clickNode.id, producer: 'browser', kind: 'request', artifact: requestArtifact, requestId, parentEvidenceIds: [intent.evidenceId] });
  const entity = { kind: operation.entityKind, id: 'forged-entity' };
  const responseArtifact = { requestId, intentId: intentArtifact.intentId, operationId: operation.id, fixtureId, status: 201, entity: { ...entity } };
  const response = store.appendEvidence(runDir, { ...base, stepId: clickNode.id, producer: 'browser', kind: 'response', artifact: responseArtifact, requestId, entity, parentEvidenceIds: [request.evidenceId] });
  const readArtifact = {
    method: 'GET', path: '/records', fixtureId, entity: { ...entity },
    fields: { ...operation.inputs, fixtureId },
    environmentFingerprint: manifest.environment.fingerprint, requestId, httpStatus: 200, observedAt: new Date().toISOString()
  };
  const read = store.appendEvidence(runDir, {
    ...base, stepId: verifyNode.id, producer: 'verification', kind: 'independent-read',
    artifact: readArtifact, requestId, entity, parentEvidenceIds: [response.evidenceId],
    checkIds: operation.effects.map(effect => effect.id)
  });
  const verdict = {
    schemaVersion: '0.1.0', runId: context.runId, manifestSha256, verdict: 'PASS', reasonCode: 'NONE',
    message: 'поддельный PASS без единого POST',
    checks: operation.effects.map(effect => ({ id: effect.id, status: 'SATISFIED', evidenceIds: [read.evidenceId] })),
    ownershipVerified: true, integrityVerified: true, completedAt: new Date().toISOString()
  };
  const envelope = store.appendEvidence(runDir, {
    ...base, stepId: verifyNode.id, producer: 'verification', kind: 'verdict', artifact: verdict,
    parentEvidenceIds: [read.evidenceId], checkIds: operation.effects.map(effect => effect.id)
  });
  store.appendEvent(runDir, { type: 'VERDICT_DURABLE', evidenceId: envelope.evidenceId, verdict: 'PASS' });
  store.appendEvent(runDir, { type: 'STATE', state: 'FINISHED', verdict: 'PASS', reasonCode: 'NONE' });

  const observed = await observe({ root: context.root, runId: context.runId });
  record(checks, 'локальный журнал принимает подделанную цепочку', observed.verdict?.verdict === 'PASS', { verdict: observed.verdict?.verdict || null });
  record(checks, 'стенд не получил ни одного POST', context.fixture.mutationCount === 0, { mutationCount: context.fixture.mutationCount });
  record(checks, 'стенд не создал ни одной записи', context.fixture.recordCount === 0, { recordCount: context.fixture.recordCount });
  record(checks, 'нет approval в доверенном корне', !fs.existsSync(path.join(context.root, 'trust-root')));
  record(checks, 'нет consumption', !fs.existsSync(path.join(context.root, 'consumption')));
  record(checks, 'нет анкера вне каталога прогона', !fs.existsSync(path.join(context.root, 'anchors')));
  record(checks, 'база 0.1 не может отличить подделанный PASS от реального', true, { note: 'проверяются только локальные хеши; внешнего корня/анкера нет' });
  record(checks, 'модуль анкера на ревизии отсутствует', !fs.existsSync(path.join(context.root, '..', 'anchors')) && !fs.existsSync('packages/trust/anchor.mjs'));
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  await context.close();
}
finish({ id: 'RT-10', title: 'Ложный PASS без POST, approval и анкера', checks,
  verdict: 'INCONCLUSIVE',
  notes: [
    'Атака удалась и это ОЖИДАЕМО на базе 0e7e6c2: анкер/T-D (WP-05+WP-06) ещё не реализованы. Это не дефект принятых WP-01/WP-02, а обязательство 0.2: observeTrusted должен требовать годный анкер на candidateSha256 и chainHead.',
    'Повторная проверка этой же атаки обязательна на SHA интеграции после WP-05/WP-06: она должна получить не PASS, а отказ/INCONCLUSIVE без анкера.',
    'Severity для 0.2: P1 (ложный PASS) — до закрытия анкером ветка не готова к приёмке доверенного PASS.'
  ] });
