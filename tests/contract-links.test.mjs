import test from 'node:test';
import assert from 'node:assert/strict';
import { validateBundleLinks, validateVerdictCoverage, validate } from '../packages/contracts/index.mjs';
const h = 'b'.repeat(64), date = '2026-11-12T10:00:00.000Z';
function bundle() {
  const operation = { schemaVersion: '0.1.0', id: 'op', version: '1', description: 'Сохранить', roles: ['author'], preconditions: [], inputs: { title: 'Тест', executor: 'author' }, entityKind: 'record', effects: [{ id: 'title', field: 'title', equals: 'Тест', required: true, source: 'independent-read', deadlineMs: 100, intervalMs: 10 }], mutation: { name: 'create', repeat: 'never-after-dispatch', ownershipField: 'fixtureId' }, verification: { adapter: 'local', readMethod: 'GET', lookupBy: 'fixtureId', identityFields: ['fixtureId'] } };
  const scenario = { schemaVersion: '0.1.0', id: 's', version: '1', status: 'APPROVED', approval: { actor: 'local-harness', approvedAt: date, contentSha256: h }, originalTextSha256: h, mode: 'ACCEPTANCE', operation: { id: 'op', version: '1', sha256: h }, inputs: { ...operation.inputs }, nodes: [{ id: 'create', timeoutMs: 1000, retry: 'none', action: { type: 'click', mutation: true, operationId: 'op', mutationName: 'create', locator: { containerRole: 'form', containerName: 'Форма', role: 'button', name: 'Создать', exact: true } } }, { id: 'verify', timeoutMs: 1000, retry: 'none', action: { type: 'verify', operationId: 'op' } }], edges: [{ from: 'create', to: 'verify' }] };
  const fixture = { schemaVersion: '0.1.0', fixtureId: 'fixture', runId: 'run', environmentId: 'instance-nonce', namespace: 'local', accounts: [{ role: 'author', credentialRef: 'local:none' }], allowedMutations: ['create'], selectedEntities: [], ownership: { field: 'fixtureId', value: 'fixture' }, cleanup: 'manual-after-independent-ownership-check', unknownMutation: 'read-only-reconciliation', authorization: { actor: 'harness', scope: 'local', confirmedAt: date } };
  const manifest = { schemaVersion: '0.1.0', runId: 'run', commandId: 'start', command: 'START', state: 'CREATED', scenario: { id: 's', version: '1', sha256: h }, operation: { id: 'op', version: '1', sha256: h }, fixtureSha256: h, environment: { id: 'instance-nonce', baseUrl: 'http://127.0.0.1:9000/', fingerprint: 'v1', sourceRevision: null, observedAt: date }, budget: { deadlineMs: 10000, maxReadAttempts: 10, maxModelCalls: 0 }, createdAt: date };
  return { operation, scenario, fixture, manifest };
}
test('bundle отклоняет подмену операции, входов, fixture и прав до отправки', () => {
  validateBundleLinks(bundle());
  const attacks = [
    b => b.scenario.inputs.executor = 'other',
    b => b.scenario.operation.version = '2',
    b => b.manifest.scenario.id = 'foreign',
    b => b.fixture.runId = 'foreign',
    b => b.fixture.environmentId = 'foreign',
    b => b.fixture.allowedMutations = [],
    b => b.fixture.accounts[0].role = 'viewer',
    b => b.operation.verification.identityFields = ['id'],
    b => b.scenario.nodes[0].action.mutationName = 'delete'
  ];
  for (const attack of attacks) { const b = bundle(); attack(b); assert.throws(() => validateBundleLinks(b)); }
});
test('network контракт не принимает Dev, hostname, userinfo и скрытый путь', () => {
  for (const url of ['https://example.com/', 'http://localhost:9000/', 'http://127.0.0.1:9000/private', 'http://user:pass@127.0.0.1:9000/', 'http://127.0.0.1:9000/?token=x', 'http://127.0.0.1/']) {
    const b = bundle(); b.manifest.environment.baseUrl = url;
    assert.throws(() => validate('RunProtocol', b.manifest));
  }
});
function proof(value) {
  return { envelope: { schemaVersion: '0.1.0', evidenceId: 'read', runId: 'run', stepId: 'verify', manifestSha256: h, fixtureId: 'fixture', producer: 'verification', kind: 'independent-read', sequence: 4, previousSha256: h, parentEvidenceIds: ['response'], checkIds: ['title'], artifact: { path: 'read.json', sha256: h, mediaType: 'application/json' }, requestId: 'read-request', cizId: null, entity: { kind: 'record', id: 'record1' }, observedAt: date }, artifact: { method: 'GET', path: '/records', fixtureId: 'fixture', entity: { kind: 'record', id: 'record1' }, fields: { title: value }, environmentFingerprint: 'v1', requestId: 'read-request', httpStatus: 200, observedAt: date } };
}
function result(verdict) {
  return { schemaVersion: '0.1.0', runId: 'run', manifestSha256: h, verdict, reasonCode: verdict === 'PASS' ? 'NONE' : 'BUSINESS_INVARIANT_VIOLATED', message: 'Результат проверки', checks: [{ id: 'title', status: verdict === 'PASS' ? 'SATISFIED' : 'VIOLATED', evidenceIds: ['read'] }], ownershipVerified: true, integrityVerified: true, completedAt: date };
}
test('доказательство должно проверять точное значение и принадлежать запуску', () => {
  const { operation } = bundle();
  validateVerdictCoverage(result('PASS'), operation, [proof('Тест')]);
  validateVerdictCoverage(result('FAIL'), operation, [proof('Неверно')]);
  assert.throws(() => validateVerdictCoverage(result('PASS'), operation, [proof('Неверно')]));
  assert.throws(() => validateVerdictCoverage(result('FAIL'), operation, [proof('Тест')]));
  const foreign = proof('Тест'); foreign.envelope.runId = 'foreign';
  assert.throws(() => validateVerdictCoverage(result('PASS'), operation, [foreign]));
});
test('unknown appliesWhen нельзя скрыть как неприменимую проверку', () => {
  const { operation } = bundle();
  operation.effects.push({ ...operation.effects[0], id: 'conditional', appliesWhen: { field: 'missing', equals: true } });
  const verdict = result('PASS'); verdict.checks.push({ id: 'conditional', status: 'NOT_APPLICABLE', evidenceIds: [] });
  assert.throws(() => validateVerdictCoverage(verdict, operation, [proof('Тест')]));
});
