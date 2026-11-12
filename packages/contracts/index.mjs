import { z } from 'zod';

export const VERSION = '0.1.0';
const id = z.string().min(1).max(160);
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const version = z.literal(VERSION);
const scalar = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
const fields = z.record(id, scalar);
const ref = z.strictObject({ id, version: id, sha256: hash });
const entity = z.strictObject({ kind: id, id });
export const reasonCodes = ['NONE', 'REQUIREMENT_MISMATCH', 'AUTH_UNAVAILABLE', 'FIXTURE_UNAVAILABLE', 'ELEMENT_AMBIGUOUS', 'ENVIRONMENT_CHANGED', 'BUSINESS_INVARIANT_VIOLATED', 'EVIDENCE_MISSING', 'RESULT_UNCONFIRMED', 'WORKER_LOST', 'CANCELED', 'CONTRACT_INVALID', 'UNSUPPORTED', 'INTEGRITY_ERROR'];
const reasonCode = z.enum(reasonCodes);
const check = z.strictObject({
  id, field: id, equals: scalar,
  required: z.boolean(),
  appliesWhen: z.strictObject({ field: id, equals: scalar }).optional(),
  source: z.literal('independent-read'),
  deadlineMs: z.number().int().min(1).max(120000),
  intervalMs: z.number().int().min(10).max(10000)
});

export const OperationContract = z.strictObject({
  schemaVersion: version, id, version: id, description: id,
  roles: z.array(id).min(1),
  preconditions: z.array(z.strictObject({ field: id, equals: scalar })),
  inputs: fields,
  entityKind: id,
  effects: z.array(check).min(1),
  mutation: z.strictObject({ name: id, repeat: z.literal('never-after-dispatch'), ownershipField: id }),
  verification: z.strictObject({ adapter: id, readMethod: z.literal('GET'), lookupBy: z.literal('fixtureId'), identityFields: z.array(id).min(1) })
});

const locator = z.strictObject({ containerRole: id, containerName: id, role: id, name: id, exact: z.literal(true) });
const action = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('navigate'), path: z.string().regex(/^\/(?!\/)/) }),
  z.strictObject({ type: z.literal('fill'), locator, value: z.string() }),
  z.strictObject({ type: z.literal('click'), locator, mutation: z.boolean(), operationId: id.optional(), mutationName: id.optional() }),
  z.strictObject({ type: z.literal('verify'), operationId: id })
]);
export const ScenarioSchema = z.strictObject({
  schemaVersion: version, id, version: id,
  status: z.enum(['DRAFT', 'APPROVED']),
  originalTextSha256: hash,
  approval: z.strictObject({ actor: id, approvedAt: z.iso.datetime(), contentSha256: hash }).nullable(),
  mode: z.literal('ACCEPTANCE'),
  operation: ref,
  inputs: fields,
  nodes: z.array(z.strictObject({ id, action, timeoutMs: z.number().int().min(1).max(120000), retry: z.literal('none') })).min(1),
  edges: z.array(z.strictObject({ from: id, to: id }))
});

export const FixtureContract = z.strictObject({
  schemaVersion: version, fixtureId: id, runId: id,
  environmentId: id, namespace: id,
  accounts: z.array(z.strictObject({ role: id, credentialRef: id })).min(1),
  allowedMutations: z.array(id),
  selectedEntities: z.array(entity),
  ownership: z.strictObject({ field: id, value: id }),
  cleanup: z.literal('manual-after-independent-ownership-check'),
  unknownMutation: z.literal('read-only-reconciliation'),
  authorization: z.strictObject({ actor: id, scope: id, confirmedAt: z.iso.datetime() })
});

export const RunProtocol = z.strictObject({
  schemaVersion: version, runId: id, commandId: id,
  command: z.enum(['START', 'OBSERVE', 'CANCEL', 'RECONCILE']),
  state: z.enum(['CREATED', 'PREFLIGHT', 'RUNNING', 'VERIFYING', 'RECONCILING', 'FINISHED']),
  scenario: ref, operation: ref, fixtureSha256: hash,
  environment: z.strictObject({ id, baseUrl: z.url(), fingerprint: id, sourceRevision: id.nullable(), observedAt: z.iso.datetime() }),
  budget: z.strictObject({ deadlineMs: z.number().int().min(1).max(600000), maxReadAttempts: z.number().int().min(1).max(100), maxModelCalls: z.literal(0) }),
  createdAt: z.iso.datetime()
});

export const EvidenceSchema = z.strictObject({
  schemaVersion: version, evidenceId: id, runId: id, stepId: id,
  manifestSha256: hash, fixtureId: id,
  producer: z.enum(['browser', 'verification', 'control']),
  kind: z.enum(['request', 'response', 'independent-read', 'observation', 'mutation-intent', 'verdict']),
  sequence: z.number().int().positive(), previousSha256: hash.nullable(),
  parentEvidenceIds: z.array(id),
  checkIds: z.array(id),
  artifact: z.strictObject({ path: z.string().regex(/^[a-zA-Z0-9_-]+\.json$/), sha256: hash, mediaType: z.literal('application/json') }),
  requestId: id.nullable(), cizId: id.nullable(), entity: entity.nullable(),
  observedAt: z.iso.datetime()
});

export const VerdictPolicy = z.strictObject({
  schemaVersion: version, runId: id, manifestSha256: hash,
  verdict: z.enum(['PASS', 'FAIL', 'BLOCKED', 'INCONCLUSIVE']), reasonCode,
  message: z.string().min(1),
  checks: z.array(z.strictObject({ id, status: z.enum(['SATISFIED', 'VIOLATED', 'UNKNOWN', 'NOT_APPLICABLE']), evidenceIds: z.array(id) })),
  ownershipVerified: z.boolean(), integrityVerified: z.boolean(),
  completedAt: z.iso.datetime()
});

export const schemas = { OperationContract, ScenarioSchema, RunProtocol, EvidenceSchema, VerdictPolicy, FixtureContract };

// Межполевые ограничения дополняют машинные JSON Schema.
export function validate(name, value) {
  const schema = schemas[name];
  if (!schema) throw new Error('Неизвестный контракт');
  const result = schema.parse(value);
  const reject = message => { throw new Error(message); };
  const unique = values => new Set(values).size === values.length;
  if (name === 'OperationContract') {
    if (!unique(result.effects.map(e => e.id))) reject('Повтор идентификатора проверки');
    if (!result.effects.some(e => e.required && !e.appliesWhen)) reject('Нет безусловной обязательной проверки');
    if (result.effects.some(e => e.intervalMs > e.deadlineMs)) reject('Интервал больше срока ожидания');
  }
  if (name === 'ScenarioSchema') {
    if ((result.status === 'APPROVED') !== Boolean(result.approval)) reject('Утверждение не соответствует статусу');
    if (!unique(result.nodes.map(n => n.id))) reject('Повтор идентификатора узла');
    // Ядро 0.1 поддерживает только явно упорядоченную цепочку, не делает вид, что исполняет DAG.
    if (result.edges.length !== result.nodes.length - 1 || result.edges.some((e, i) => e.from !== result.nodes[i].id || e.to !== result.nodes[i + 1].id)) reject('Граф не поддерживается ядром 0.1');
    if (result.nodes.at(-1).action.type !== 'verify') reject('Сценарий должен завершаться независимой проверкой');
    if (result.nodes.filter(n => n.action.type === 'click' && n.action.mutation).length !== 1) reject('Ядро 0.1 требует одну бизнес-мутацию');
    for (const node of result.nodes.filter(n => n.action.type === 'click')) {
      if (!node.action.mutation) reject('Ядро 0.1 не поддерживает произвольные клики вне бизнес-мутации');
      if (node.action.operationId !== result.operation.id || !node.action.mutationName) reject('Мутация не связана с операцией');
    }
    if (result.nodes.filter(n => n.action.type === 'verify').length !== 1 || result.nodes.at(-1).action.operationId !== result.operation.id) reject('Проверка должна ссылаться на операцию сценария');
  }
  if (name === 'FixtureContract' && result.ownership.value !== result.fixtureId) reject('Маркер владения не совпадает с fixtureId');
  if (name === 'RunProtocol') {
    const url = new URL(result.environment.baseUrl);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.search || url.hash || url.pathname !== '/') reject('Ядро 0.1 разрешает только явный localhost стенд 127.0.0.1');
  }
  if (name === 'EvidenceSchema') {
    const producers = { request: 'browser', response: 'browser', observation: 'browser', 'mutation-intent': 'control', 'independent-read': 'verification', verdict: 'verification' };
    if (result.producer !== producers[result.kind]) reject('Источник не соответствует типу доказательства');
    if (!unique(result.checkIds)) reject('Повтор привязки проверки');
    if (!['independent-read', 'verdict'].includes(result.kind) && result.checkIds.length) reject('Браузерное событие не закрывает бизнес-проверку');
    if (['request', 'response'].includes(result.kind) && !result.requestId) reject('Нет идентификатора реального запроса');
    if (['response', 'independent-read'].includes(result.kind) && !result.entity) reject('Нет идентичности сущности');
  }
  if (name === 'VerdictPolicy') {
    if ((result.verdict === 'PASS') !== (result.reasonCode === 'NONE')) reject('Причина не соответствует вердикту');
    if (!unique(result.checks.map(c => c.id))) reject('Повтор результата проверки');
    if (result.verdict === 'PASS' && (!result.ownershipVerified || !result.integrityVerified || !result.checks.some(c => c.status === 'SATISFIED') || result.checks.some(c => !['SATISFIED', 'NOT_APPLICABLE'].includes(c.status) || (c.status === 'SATISFIED' && c.evidenceIds.length === 0)))) reject('Недостаточно доказательств для PASS');
    if (result.verdict === 'FAIL' && (result.reasonCode !== 'BUSINESS_INVARIANT_VIOLATED' || !result.ownershipVerified || !result.integrityVerified || !result.checks.some(c => c.status === 'VIOLATED') || result.checks.some(c => c.status === 'UNKNOWN' || (['SATISFIED', 'VIOLATED'].includes(c.status) && c.evidenceIds.length === 0)))) reject('Недостаточно доказательств для FAIL');
  }
  return result;
}

export const IntentCommand = z.strictObject({
  type: z.literal('INTENT'), commandId: id, runId: id,
  payload: z.strictObject({ intentId: id, stepId: id, operationId: id, mutationName: id, inputsSha256: hash, fixtureId: id })
});
export const IntentAck = z.strictObject({ type: z.literal('ACK'), commandId: id, runId: id, intentId: id, evidenceId: id, durable: z.literal(true) });

// Формат независимого локального чтения; production adapter получает собственную версию.
export const IndependentRead = z.strictObject({
  method: z.literal('GET'), path: z.literal('/records'),
  fixtureId: id, entity: entity, fields,
  environmentFingerprint: id, requestId: id,
  httpStatus: z.literal(200), observedAt: z.iso.datetime()
});

// Вызывается ДО browser dispatch. Hash/approval проверяются core дополнительно.
export function validateBundleLinks({ scenario, operation, fixture, manifest }) {
  validate('ScenarioSchema', scenario); validate('OperationContract', operation);
  validate('FixtureContract', fixture); validate('RunProtocol', manifest);
  const same = (a, b) => JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort());
  if (scenario.status !== 'APPROVED') throw new Error('Черновик нельзя исполнять');
  if (scenario.operation.id !== operation.id || scenario.operation.version !== operation.version || manifest.operation.id !== operation.id || manifest.operation.version !== operation.version || manifest.scenario.id !== scenario.id || manifest.scenario.version !== scenario.version) throw new Error('Ссылки версий не согласованы');
  if (!same(scenario.inputs, operation.inputs)) throw new Error('Входы сценария отличаются от утверждённой операции');
  const mutation = scenario.nodes.find(n => n.action.type === 'click').action;
  if (mutation.mutationName !== operation.mutation.name) throw new Error('Неизвестная мутация');
  if (fixture.runId !== manifest.runId || fixture.environmentId !== manifest.environment.id || fixture.ownership.field !== operation.mutation.ownershipField || !fixture.allowedMutations.includes(operation.mutation.name) || operation.roles.some(role => !fixture.accounts.some(a => a.role === role))) throw new Error('Fixture не разрешает эту операцию');
  if (!operation.verification.identityFields.includes(operation.mutation.ownershipField)) throw new Error('Проверка не включает маркер владения');
}

// Не заменяет проверку происхождения: вызывается после независимого чтения artifact bytes.
export function validateVerdictCoverage(verdict, operation, reads) {
  validate('VerdictPolicy', verdict); validate('OperationContract', operation);
  if (verdict.checks.length !== operation.effects.length || operation.effects.some(e => !verdict.checks.some(c => c.id === e.id))) throw new Error('Неполный набор проверок');
  for (const check of verdict.checks) {
    const effect = operation.effects.find(e => e.id === check.id);
    const conditionKnown = !effect.appliesWhen || Object.hasOwn(operation.inputs, effect.appliesWhen.field);
    const applicable = !effect.appliesWhen || operation.inputs[effect.appliesWhen.field] === effect.appliesWhen.equals;
    if (check.status === 'NOT_APPLICABLE' && (!conditionKnown || applicable)) throw new Error('Неподтверждённое исключение проверки');
    if (['SATISFIED', 'VIOLATED'].includes(check.status)) {
      if (!conditionKnown || !applicable) throw new Error('Условие проверки не подтверждено');
      if (!check.evidenceIds.some(eid => {
        const read = reads.find(r => r.envelope.evidenceId === eid);
        if (!read) return false;
        validate('EvidenceSchema', read.envelope); IndependentRead.parse(read.artifact);
        return read.envelope.kind === 'independent-read' && read.envelope.runId === verdict.runId && read.envelope.manifestSha256 === verdict.manifestSha256 && read.envelope.checkIds.includes(check.id) && Object.hasOwn(read.artifact.fields, effect.field) && (check.status === 'SATISFIED' ? read.artifact.fields[effect.field] === effect.equals : read.artifact.fields[effect.field] !== effect.equals);
      })) throw new Error('Эффект не подтверждён независимым чтением');
    }
  }
  return verdict;
}
