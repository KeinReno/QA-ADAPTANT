import { randomUUID } from 'node:crypto';
import { digest, scenarioApprovalHash } from '../../packages/core/canonical.mjs';

export function localBundle(fixture, { runId = `run-${randomUUID()}`, inputs = {}, effects } = {}) {
  const createdAt = new Date().toISOString();
  const operationInputs = { title: `Проверка ${runId}`, executorId: 'operator-local', comment: `Комментарий ${runId}`, ...inputs };
  const operation = {
    schemaVersion: '0.1.0', id: 'local-create-record', version: '1.0.0',
    description: 'Создать запись на изолированном локальном стенде',
    roles: ['author'], preconditions: [], inputs: operationInputs, entityKind: 'local-record',
    effects: effects || [
      { id: 'title-saved', field: 'title', equals: operationInputs.title, required: true, source: 'independent-read', deadlineMs: 3000, intervalMs: 50 },
      { id: 'executor-saved', field: 'executorId', equals: operationInputs.executorId, required: true, source: 'independent-read', deadlineMs: 3000, intervalMs: 50 },
      { id: 'comment-saved', field: 'comment', equals: operationInputs.comment, required: true, source: 'independent-read', deadlineMs: 3000, intervalMs: 50 }
    ],
    mutation: { name: 'create-record', repeat: 'never-after-dispatch', ownershipField: 'fixtureId' },
    verification: { adapter: 'local', readMethod: 'GET', lookupBy: 'fixtureId', identityFields: ['fixtureId'] }
  };
  const locator = (role, name) => ({ containerRole: 'form', containerName: 'Создать запись', role, name, exact: true });
  const scenario = {
    schemaVersion: '0.1.0', id: 'local-create-record', version: '1.0.0', status: 'APPROVED',
    originalTextSha256: digest('Локальный исполняемый сценарий для автоматических проверок'),
    approval: null, mode: 'ACCEPTANCE',
    operation: { id: operation.id, version: operation.version, sha256: digest(operation) },
    inputs: { ...operationInputs },
    nodes: [
      { id: 'open', timeoutMs: 5000, retry: 'none', action: { type: 'navigate', path: '/' } },
      { id: 'title', timeoutMs: 5000, retry: 'none', action: { type: 'fill', value: operationInputs.title, locator: locator('textbox', 'Название') } },
      { id: 'executor', timeoutMs: 5000, retry: 'none', action: { type: 'fill', value: operationInputs.executorId, locator: locator('textbox', 'Исполнитель') } },
      { id: 'comment', timeoutMs: 5000, retry: 'none', action: { type: 'fill', value: operationInputs.comment, locator: locator('textbox', 'Комментарий') } },
      { id: 'marker', timeoutMs: 5000, retry: 'none', action: { type: 'fill', value: fixture.fixtureId, locator: locator('textbox', 'Маркер fixture') } },
      { id: 'create', timeoutMs: 5000, retry: 'none', action: { type: 'click', mutation: true, operationId: operation.id, mutationName: operation.mutation.name, locator: locator('button', 'Создать') } },
      { id: 'verify', timeoutMs: 5000, retry: 'none', action: { type: 'verify', operationId: operation.id } }
    ],
    edges: [
      { from: 'open', to: 'title' }, { from: 'title', to: 'executor' },
      { from: 'executor', to: 'comment' }, { from: 'comment', to: 'marker' },
      { from: 'marker', to: 'create' }, { from: 'create', to: 'verify' }
    ]
  };
  scenario.approval = { actor: 'local-test-harness', approvedAt: createdAt, contentSha256: scenarioApprovalHash(scenario) };
  const manifest = {
    schemaVersion: '0.1.0', runId, commandId: `start-${runId}`, command: 'START', state: 'CREATED',
    scenario: { id: scenario.id, version: scenario.version, sha256: digest(scenario) },
    operation: { id: operation.id, version: operation.version, sha256: digest(operation) },
    fixtureSha256: digest(fixture),
    environment: { id: fixture.environmentId, baseUrl: fixture.baseUrl, fingerprint: fixture.fingerprint, sourceRevision: 'local-fixture-v1', observedAt: createdAt },
    budget: { deadlineMs: 12000, maxReadAttempts: 20, maxModelCalls: 0 }, createdAt
  };
  return { scenario, operation, fixture, manifest };
}

export function localFixtureContract(fixture, runId) {
  return {
    schemaVersion: '0.1.0', fixtureId: `fixture-${runId}`, runId,
    environmentId: fixture.environmentId, namespace: 'local-automated-tests',
    accounts: [{ role: 'author', credentialRef: 'local:none' }],
    allowedMutations: ['create-record'], selectedEntities: [],
    ownership: { field: 'fixtureId', value: `fixture-${runId}` },
    cleanup: 'manual-after-independent-ownership-check', unknownMutation: 'read-only-reconciliation',
    authorization: { actor: 'local-test-harness', scope: 'isolated-local-fixture', confirmedAt: new Date().toISOString() }
  };
}
