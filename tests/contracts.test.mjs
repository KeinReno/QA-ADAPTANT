import test from 'node:test';
import assert from 'node:assert/strict';
import { validate, validateVerdictCoverage } from '../packages/contracts/index.mjs';
const hash = 'a'.repeat(64);
const effect = { id: 'saved', field: 'title', equals: 'Проверка', required: true, source: 'independent-read', deadlineMs: 100, intervalMs: 10 };
const operation = { schemaVersion: '0.1.0', id: 'local-create', version: '1', description: 'Создать тестовую запись', roles: ['author'], preconditions: [], inputs: { title: 'Проверка' }, entityKind: 'local-record', effects: [effect], mutation: { name: 'create', repeat: 'never-after-dispatch', ownershipField: 'fixtureId' }, verification: { adapter: 'local', readMethod: 'GET', lookupBy: 'fixtureId', identityFields: ['fixtureId'] } };
const scenario = { schemaVersion: '0.1.0', id: 'scenario', version: '1', status: 'DRAFT', originalTextSha256: hash, approval: null, mode: 'ACCEPTANCE', operation: { id: operation.id, version: '1', sha256: hash }, inputs: {}, nodes: [ { id: 'create', action: { type: 'click', locator: { containerRole: 'form', containerName: 'Создать', role: 'button', name: 'Добавить', exact: true }, mutation: true, operationId: operation.id, mutationName: 'create' }, timeoutMs: 500, retry: 'none' }, { id: 'verify', action: { type: 'verify', operationId: operation.id }, timeoutMs: 500, retry: 'none' } ], edges: [{ from: 'create', to: 'verify' }] };
test('операция требует хотя бы один безусловный обязательный эффект', () => {
  assert.equal(validate('OperationContract', operation).effects[0].id, 'saved');
  assert.throws(() => validate('OperationContract', { ...operation, effects: [{ ...effect, required: false }] }));
  assert.throws(() => validate('OperationContract', { ...operation, effects: [{ ...effect, appliesWhen: { field: 'unknown', equals: true } }] }));
  assert.throws(() => validate('OperationContract', { ...operation, effects: [effect, effect] }));
});
test('неподдерживаемые графы, чужая операция и скрытый повтор отклоняются', () => {
  validate('ScenarioSchema', scenario);
  assert.throws(() => validate('ScenarioSchema', { ...scenario, edges: [{from: 'verify', to: 'create'}] }));
  const changed = structuredClone(scenario); changed.nodes[1].action.operationId = 'other';
  assert.throws(() => validate('ScenarioSchema', changed));
  changed.nodes[1].action.operationId = operation.id; changed.nodes[0].retry = 'automatic';
  assert.throws(() => validate('ScenarioSchema', changed));
});
test('статус APPROVED требует квитанции, DRAFT не маскирует approval', () => {
  assert.throws(() => validate('ScenarioSchema', { ...scenario, status: 'APPROVED' }));
  assert.throws(() => validate('ScenarioSchema', { ...scenario, approval: { actor: 'human', approvedAt: new Date().toISOString(), contentSha256: hash } }));
});
test('PASS без владения, целостности и явных доказательств запрещён', () => {
  const result = { schemaVersion: '0.1.0', runId: 'run', manifestSha256: hash, verdict: 'PASS', reasonCode: 'NONE', message: 'Подтверждено', checks: [{ id: 'saved', status: 'SATISFIED', evidenceIds: ['read'] }], ownershipVerified: true, integrityVerified: true, completedAt: new Date().toISOString() };
  validate('VerdictPolicy', result);
  for (const patch of [{ checks: [] }, { ownershipVerified: false }, { integrityVerified: false }, { reasonCode: 'EVIDENCE_MISSING' }, { checks: [{ id: 'saved', status: 'SATISFIED', evidenceIds: [] }] }, { checks: [{ id: 'saved', status: 'UNKNOWN', evidenceIds: ['read'] }] }, { checks: [result.checks[0], result.checks[0]] }]) {
    assert.throws(() => validate('VerdictPolicy', { ...result, ...patch }));
  }
});
test('доказательство запрещает traversal и непредусмотренные поля', () => {
  const evidence = { schemaVersion: '0.1.0', evidenceId: 'e1', runId: 'run', stepId: 'create', manifestSha256: hash, fixtureId: 'fixture', producer: 'browser', kind: 'request', sequence: 1, previousSha256: null, parentEvidenceIds: [], checkIds: [], artifact: { path: 'e1.json', sha256: hash, mediaType: 'application/json' }, requestId: 'r1', cizId: null, entity: null, observedAt: new Date().toISOString() };
  validate('EvidenceSchema', evidence);
  assert.throws(() => validate('EvidenceSchema', { ...evidence, artifact: { ...evidence.artifact, path: '../secret.json' } }));
  assert.throws(() => validate('EvidenceSchema', { ...evidence, authorization: 'secret' }));
  assert.throws(() => validate('EvidenceSchema', { ...evidence, kind: 'independent-read' }));
});
test('полнота PASS связана с исходными effects, а не произвольным check', () => {
  const verdict = { schemaVersion: '0.1.0', runId: 'run', manifestSha256: hash, verdict: 'PASS', reasonCode: 'NONE', message: 'Подтверждено', checks: [{ id: 'invented', status: 'SATISFIED', evidenceIds: ['read'] }], ownershipVerified: true, integrityVerified: true, completedAt: new Date().toISOString() };
  assert.throws(() => validateVerdictCoverage(verdict, operation, []));
  verdict.checks[0].id = 'saved';
  assert.throws(() => validateVerdictCoverage(verdict, operation, []));
});
test('мутацию нельзя спрятать за mutation=false или чужим operationId', () => {
  for (const patch of [{ mutation: false }, { operationId: 'foreign' }, { mutationName: undefined }]) {
    const changed = structuredClone(scenario); Object.assign(changed.nodes[0].action, patch);
    assert.throws(() => validate('ScenarioSchema', changed));
  }
});
test('FAIL требует доказанного нарушения, а не пустого VIOLATED', () => {
  const result = { schemaVersion: '0.1.0', runId: 'run', manifestSha256: hash, verdict: 'FAIL', reasonCode: 'BUSINESS_INVARIANT_VIOLATED', message: 'Нарушение', checks: [{ id: 'saved', status: 'VIOLATED', evidenceIds: [] }], ownershipVerified: true, integrityVerified: true, completedAt: new Date().toISOString() };
  assert.throws(() => validateVerdictCoverage(result, operation, []));
  result.checks[0].evidenceIds = ['fiction'];
  assert.throws(() => validateVerdictCoverage(result, operation, []));
  result.checks[0].status = 'SATISFIED';
  assert.throws(() => validate('VerdictPolicy', result));
});

