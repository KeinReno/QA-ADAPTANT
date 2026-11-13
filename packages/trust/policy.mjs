// WP-03 Policy Engine: чистый PDP.
// Решение принимается только по заранее собранным фактам. Модуль не читает диск,
// не открывает сеть, не проверяет подписи, не пишет consumption и не создаёт ключи.
// Контракт: docs/harness/BASELINE-AND-CONTRACTS.md §5.3, docs/wp-00/03-CONTRACT-PROPOSALS.md.
import { randomUUID } from 'node:crypto';
import { digest } from '../core/canonical.mjs';

export const PHASES = ['preflight', 'dispatch', 'observe', 'reconcile', 'publish'];
export const EFFECTS = ['ALLOW', 'DENY', 'INDETERMINATE'];
export const OBLIGATIONS = ['consume-dispatch', 'do-not-dispatch'];
export const APPROVAL_STATES = ['issued', 'consumed', 'revoked', 'expired', 'not-yet-valid', 'incomplete', 'missing'];

const readPhases = new Set(['observe', 'reconcile', 'publish']);
const dispatchPhases = new Set(['preflight', 'dispatch']);
const knownRoles = new Set(['owner', 'operator', 'runner', 'anchor-signer', 'verifier', 'agent']);
const revocationReasons = new Set(['owner-revoked', 'environment-revoked', 'principal-revoked']);
const environmentKinds = new Set(['local-stand', 'dev', 'production']);
const environmentStatuses = new Set(['active', 'disabled', 'revoked']);
const isoTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const sha256 = /^[a-f0-9]{64}$/;
const signatureHex = /^[a-f0-9]+$/i;

const factsKeys = ['approval', 'authenticatedSid', 'environment', 'expected', 'issuer', 'now', 'phase', 'principal', 'registry', 'run', 'trustStore'];
const expectedKeys = ['effects', 'environmentGeneration', 'environmentId', 'fixtureId', 'inputs', 'operation', 'resource', 'scenarioContentSha256'];
const approvalFactsKeys = ['body', 'consumption', 'error', 'revocation', 'state'];
const principalFactsKeys = ['body', 'error'];
const trustStoreKeys = ['available', 'code'];
const environmentFactsKeys = ['attestation', 'error', 'record'];
const attestationKeys = ['body', 'error', 'ok'];
const runKeys = ['canceled', 'mutationRecorded', 'runId'];
const registryKeys = ['effectsMatch', 'operationAllowed'];
const consumptionKeys = ['approvalId', 'consumedAt', 'decisionId', 'environmentGeneration', 'inputsHash', 'runId'];

// Коды причин, которые PDP возвращает вызывающему. Таблица: docs/wp-00/03-CONTRACT-PROPOSALS.md.
const authReasons = new Set(['TRUST_STORE_UNAVAILABLE', 'PRINCIPAL_UNKNOWN', 'PRINCIPAL_REVOKED', 'CALLER_UNAUTHENTICATED', 'APPROVAL_SIGNATURE_INVALID', 'CONSUMPTION_INCOMPLETE']);
const contractReasons = new Set(['ROLE_DENIED', 'APPROVAL_MISSING', 'APPROVAL_MISMATCH', 'APPROVAL_EXPIRED', 'APPROVAL_REVOKED', 'APPROVAL_REPLAY', 'APPROVAL_CONSUMED', 'ENVIRONMENT_KIND_DENIED', 'CONTRACT_INVALID', 'MUTATION_ALREADY_RECORDED']);
const environmentReasons = new Set(['ENVIRONMENT_UNKNOWN', 'ENVIRONMENT_REVOKED', 'ENVIRONMENT_ATTESTATION_FAILED', 'ENVIRONMENT_UNAVAILABLE']);
const anchorReasons = new Set(['ANCHOR_MISSING', 'PUBLICATION_PENDING', 'ANCHOR_UNLINKED']);
const integrityReasons = new Set(['ANCHOR_CONFLICT', 'ANCHOR_SIGNATURE_INVALID', 'ANCHOR_BINDING_REJECTED']);

function fail(code, message) {
  throw Object.assign(new Error(message), { policyCode: code });
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isId(value) {
  return typeof value === 'string' && value.length >= 1 && value.length <= 160;
}

function isHash(value) {
  return typeof value === 'string' && sha256.test(value);
}

function isTime(value) {
  return typeof value === 'string' && isoTime.test(value) && !Number.isNaN(Date.parse(value));
}

function isGeneration(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

function isScalar(value) {
  return value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value));
}

// Ошибка сборщика фактов: строка кода либо объект с полем code.
function errorCodeOf(error) {
  if (error === null || error === undefined) return null;
  if (typeof error === 'string') return error;
  if (isPlainObject(error) && typeof error.code === 'string') return error.code;
  return 'CONTRACT_INVALID';
}

function validErrorField(error) {
  return error === null || error === undefined || typeof error === 'string' || (isPlainObject(error) && typeof error.code === 'string');
}

function assertShape(condition, message) {
  if (!condition) fail('CONTRACT_INVALID', message);
}

function assertAllowedEffects(effects, message) {
  assertShape(Array.isArray(effects) && effects.length > 0, message);
  for (const effect of effects) {
    assertShape(exactKeys(effect, ['equals', 'field', 'id']), message);
    assertShape(isId(effect.id) && isId(effect.field) && isScalar(effect.equals), message);
  }
}

function validateFacts(facts) {
  assertShape(exactKeys(facts, factsKeys), 'Форма facts не совпадает с контрактом §5.3');
  assertShape(PHASES.includes(facts.phase), 'Фаза решения вне контракта');
  assertShape(isTime(facts.now), 'Поле now не является временем UTC');
  assertShape(facts.authenticatedSid === null || typeof facts.authenticatedSid === 'string', 'authenticatedSid должен быть строкой или null');

  assertShape(exactKeys(facts.trustStore, trustStoreKeys), 'Форма trustStore не совпадает с контрактом');
  assertShape(typeof facts.trustStore.available === 'boolean', 'trustStore.available должен быть boolean');
  assertShape(facts.trustStore.code === null || typeof facts.trustStore.code === 'string', 'trustStore.code должен быть null или строкой');

  for (const [name, part] of [['principal', facts.principal], ['issuer', facts.issuer]]) {
    assertShape(exactKeys(part, principalFactsKeys), `Форма ${name} не совпадает с контрактом`);
    assertShape(part.body === null || isPlainObject(part.body), `${name}.body должен быть объектом или null`);
    assertShape(validErrorField(part.error), `${name}.error имеет неверную форму`);
  }

  assertShape(exactKeys(facts.approval, approvalFactsKeys), 'Форма approval не совпадает с контрактом');
  assertShape(APPROVAL_STATES.includes(facts.approval.state), 'Состояние approval вне контракта');
  assertShape(facts.approval.body === null || isPlainObject(facts.approval.body), 'approval.body должен быть объектом или null');
  assertShape(validErrorField(facts.approval.error), 'approval.error имеет неверную форму');
  assertShape(facts.approval.consumption === null || isPlainObject(facts.approval.consumption), 'approval.consumption должен быть объектом или null');
  assertShape(facts.approval.revocation === null || isPlainObject(facts.approval.revocation), 'approval.revocation должен быть объектом или null');

  const expected = facts.expected;
  assertShape(exactKeys(expected, expectedKeys), 'Форма expected не совпадает с контрактом');
  assertShape(isPlainObject(expected.operation), 'expected.operation должен быть объектом');
  assertShape(isId(expected.operation.id) && isId(expected.operation.version), 'expected.operation не содержит id/version');
  assertShape(isPlainObject(expected.inputs), 'expected.inputs должен быть объектом');
  for (const [key, value] of Object.entries(expected.inputs)) assertShape(isId(key) && isScalar(value), 'expected.inputs содержит недопустимое значение');
  assertAllowedEffects(expected.effects, 'expected.effects не совпадает с формой разрешённых эффектов');
  assertShape(isHash(expected.scenarioContentSha256), 'expected.scenarioContentSha256 не SHA-256');
  assertShape(isId(expected.fixtureId), 'expected.fixtureId вне границы 1…160');
  assertShape(isId(expected.environmentId), 'expected.environmentId вне границы 1…160');
  assertShape(isGeneration(expected.environmentGeneration), 'expected.environmentGeneration не целое ≥ 1');
  assertShape(exactKeys(expected.resource, ['method', 'path']) && typeof expected.resource.method === 'string' && typeof expected.resource.path === 'string', 'expected.resource не {method,path}');

  assertShape(exactKeys(facts.environment, environmentFactsKeys), 'Форма environment не совпадает с контрактом');
  assertShape(facts.environment.record === null || isPlainObject(facts.environment.record), 'environment.record должен быть объектом или null');
  assertShape(validErrorField(facts.environment.error), 'environment.error имеет неверную форму');
  assertShape(exactKeys(facts.environment.attestation, attestationKeys), 'Форма environment.attestation не совпадает с контрактом');
  assertShape(typeof facts.environment.attestation.ok === 'boolean', 'environment.attestation.ok должен быть boolean');
  assertShape(facts.environment.attestation.body === null || isPlainObject(facts.environment.attestation.body), 'environment.attestation.body должен быть объектом или null');
  assertShape(validErrorField(facts.environment.attestation.error), 'environment.attestation.error имеет неверную форму');

  assertShape(exactKeys(facts.run, runKeys), 'Форма run не совпадает с контрактом');
  assertShape(isId(facts.run.runId), 'run.runId вне границы 1…160');
  assertShape(typeof facts.run.canceled === 'boolean' && typeof facts.run.mutationRecorded === 'boolean', 'run.canceled и run.mutationRecorded должны быть boolean');

  assertShape(exactKeys(facts.registry, registryKeys), 'Форма registry не совпадает с контрактом');
  assertShape(typeof facts.registry.operationAllowed === 'boolean' && typeof facts.registry.effectsMatch === 'boolean', 'registry содержит не boolean');
}

function validatePrincipalCard(body, name) {
  assertShape(body.domain === 'principal' || body.domain === undefined, `${name}.body не является карточкой Principal`);
  assertShape(isId(body.principalId), `${name}.body.principalId вне границы 1…160`);
  assertShape(Array.isArray(body.roles) && body.roles.length > 0 && body.roles.every(role => knownRoles.has(role)), `${name}.body.roles содержит неизвестную роль`);
  assertShape(body.status === 'active' || body.status === 'revoked', `${name}.body.status вне контракта`);
  assertShape(body.windowsSid === null || body.windowsSid === undefined || typeof body.windowsSid === 'string', `${name}.body.windowsSid имеет неверную форму`);
}

function validateApprovalBody(body) {
  assertShape(isPlainObject(body), 'approval.body должен быть объектом');
  assertShape(body.schemaVersion === '0.2.0' && body.domain === 'approval', 'approval.body не документ approval 0.2');
  for (const key of ['approvalId', 'issuerPrincipalId', 'subjectPrincipalId', 'operationId', 'operationVersion', 'fixtureId', 'targetEnvironmentId']) {
    assertShape(isId(body[key]), `approval.body.${key} вне границы 1…160`);
  }
  for (const key of ['approvedInputsHash', 'operationSha256', 'scenarioContentSha256']) {
    assertShape(isHash(body[key]), `approval.body.${key} не SHA-256`);
  }
  assertShape(isGeneration(body.environmentGeneration), 'approval.body.environmentGeneration не целое ≥ 1');
  assertShape(isTime(body.issuedAt) && isTime(body.expiresAt), 'approval.body.issuedAt/expiresAt не UTC');
  assertShape(Date.parse(body.expiresAt) > Date.parse(body.issuedAt), 'approval.body.expiresAt не позже issuedAt');
  assertShape(exactKeys(body.targetResource, ['method', 'path']) && typeof body.targetResource.method === 'string' && typeof body.targetResource.path === 'string', 'approval.body.targetResource не {method,path}');
  assertAllowedEffects(body.allowedEffects, 'approval.body.allowedEffects имеет неверную форму');
  // Подпись проверена сборщиком фактов; здесь проверяется только её назначение и форма.
  if (body.signatureAlgorithm !== 'Ed25519') fail('APPROVAL_SIGNATURE_INVALID', 'approval.body.signatureAlgorithm не Ed25519');
  if (typeof body.signature !== 'string' || !signatureHex.test(body.signature)) fail('APPROVAL_SIGNATURE_INVALID', 'approval.body.signature отсутствует');
  if (!isHash(body.keyId)) fail('APPROVAL_SIGNATURE_INVALID', 'approval.body.keyId не SHA-256');
}

function validateRevocation(revocation, approvalId) {
  if (revocation === null || revocation === undefined) return null;
  assertShape(isPlainObject(revocation), 'approval.revocation должен быть объектом');
  assertShape(revocation.approvalId === approvalId, 'approval.revocation относится к другому approval');
  assertShape(revocationReasons.has(revocation.reason), 'approval.revocation.reason вне закрытого списка');
  assertShape(typeof revocation.revokedAt === 'string', 'approval.revocation.revokedAt отсутствует');
  return revocation;
}

function inspectConsumption(consumption) {
  if (consumption === null || consumption === undefined) return { status: 'missing', body: null };
  if (!isPlainObject(consumption)) return { status: 'incomplete', body: null };
  const keys = Object.keys(consumption);
  const extra = keys.filter(key => !consumptionKeys.includes(key) && key !== 'bodySha256');
  if (extra.length) return { status: 'incomplete', body: null };
  for (const key of consumptionKeys) if (!Object.hasOwn(consumption, key)) return { status: 'incomplete', body: null };
  const body = {};
  for (const key of consumptionKeys) body[key] = consumption[key];
  if (!isId(body.approvalId) || !isId(body.runId) || !isId(body.decisionId)) return { status: 'incomplete', body: null };
  if (!isHash(body.inputsHash) || !isTime(body.consumedAt) || !isGeneration(body.environmentGeneration)) return { status: 'incomplete', body: null };
  // D-3: полное тело расхода обязано содержать сходящийся bodySha256 (03-CONTRACT-PROPOSALS, approval.mjs).
  if (!Object.hasOwn(consumption, 'bodySha256')) return { status: 'incomplete', body: null };
  if (!isHash(consumption.bodySha256) || consumption.bodySha256 !== digest(body)) return { status: 'incomplete', body: null };
  return { status: 'complete', body };
}

function validateEnvironmentRecord(record) {
  assertShape(isPlainObject(record), 'environment.record должен быть объектом');
  assertShape(isId(record.environmentId), 'environment.record.environmentId вне границы 1…160');
  assertShape(isGeneration(record.generation), 'environment.record.generation не целое ≥ 1');
  assertShape(environmentKinds.has(record.kind), 'environment.record.kind вне контракта');
  assertShape(environmentStatuses.has(record.status), 'environment.record.status вне контракта');
  assertShape(typeof record.origin === 'string' && record.origin.length > 0, 'environment.record.origin отсутствует');
  assertShape(isHash(record.standKeyId), 'environment.record.standKeyId не SHA-256');
  assertShape(record.credentialRef === null || record.credentialRef === undefined || typeof record.credentialRef === 'string', 'environment.record.credentialRef имеет неверную форму');
}

function validateAttestation(attestation, record) {
  const code = errorCodeOf(attestation.error);
  if (code) {
    if (code === 'ENVIRONMENT_ATTESTATION_FAILED' || code === 'ENVIRONMENT_UNAVAILABLE') fail(code, 'Аттестация среды не прошла');
    fail('CONTRACT_INVALID', 'environment.attestation.error имеет неизвестный код');
  }
  if (attestation.ok !== true) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда не подтвердила свежий challenge');
  const body = attestation.body;
  assertShape(isPlainObject(body), 'environment.attestation.body должен быть объектом при ok=true');
  assertShape(body.domain === 'environment-attest' || body.domain === undefined, 'environment.attestation.body имеет чужой domain');
  assertShape(isGeneration(body.generation), 'environment.attestation.body.generation не целое ≥ 1');
  assertShape(typeof body.origin === 'string' && body.origin.length > 0, 'environment.attestation.body.origin отсутствует');
  assertShape(isHash(body.keyId), 'environment.attestation.body.keyId не SHA-256');
  assertShape(body.challenge === undefined || typeof body.challenge === 'string', 'environment.attestation.body.challenge имеет неверную форму');
  assertShape(body.pid === undefined || (Number.isSafeInteger(body.pid) && body.pid > 0), 'environment.attestation.body.pid имеет неверную форму');
  // Смысловые расхождения аттестации с реестром — провал аттестации, а не ошибка формы.
  if (body.environmentId !== record.environmentId) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Идентификатор аттестации не совпал с реестром');
  if (body.generation !== record.generation) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Поколение аттестации не совпало с реестром');
  if (body.origin !== record.origin) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Origin аттестации не совпал с реестром');
  if (body.keyId !== record.standKeyId) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестация подписана не ключом стенда реестра');
}

function decisionFor(facts, phase, effect, reasonCode) {
  const expected = isPlainObject(facts?.expected) ? facts.expected : {};
  let inputsHash = null;
  if (isPlainObject(expected.inputs)) {
    try { inputsHash = digest(expected.inputs); } catch { inputsHash = null; }
  }
  const approvalBody = isPlainObject(facts?.approval?.body) ? facts.approval.body : {};
  const approvalId = isId(approvalBody.approvalId) ? approvalBody.approvalId : null;
  if (inputsHash === null && isHash(approvalBody.approvedInputsHash)) inputsHash = approvalBody.approvedInputsHash;
  const authenticatedSid = typeof facts?.authenticatedSid === 'string' ? facts.authenticatedSid : null;
  return {
    decisionId: randomUUID(),
    effect,
    phase,
    reasonCode,
    approvalId,
    inputsHash,
    environmentId: isId(expected.environmentId) ? expected.environmentId : null,
    environmentGeneration: isGeneration(expected.environmentGeneration) ? expected.environmentGeneration : null,
    authenticatedSid,
    obligations: readPhases.has(phase) ? 'do-not-dispatch' : dispatchPhases.has(phase) ? 'consume-dispatch' : 'do-not-dispatch',
    evaluatedAt: isTime(facts?.now) ? facts.now : new Date().toISOString()
  };
}

function bestPhase(facts) {
  return PHASES.includes(facts?.phase) ? facts.phase : 'preflight';
}

function evaluate(facts) {
  validateFacts(facts);
  const phase = facts.phase;
  const dispatchLike = dispatchPhases.has(phase);

  // 1. Недоступный корень доверия — неопределённость, не разрешение.
  if (facts.trustStore.available !== true || facts.trustStore.code !== null) {
    fail('TRUST_STORE_UNAVAILABLE', 'Корень доверия недоступен');
  }

  // 2. Субъект (Principal) и его состояние. Отзыв субъекта проверяется до SID.
  const principal = facts.principal.body;
  if (principal === null) fail('PRINCIPAL_UNKNOWN', 'Карточка субъекта не загружена');
  if (errorCodeOf(facts.principal.error)) fail('PRINCIPAL_UNKNOWN', 'Карточка субъекта не проверена');
  validatePrincipalCard(principal, 'principal');
  if (principal.status !== 'active') fail('PRINCIPAL_REVOKED', 'Субъект отозван');

  // 3. Аутентификация вызывающего до авторизации роли (§5.3: SID раньше ROLE_DENIED).
  // SID читается у процесса, а не берётся из строки пользовательского ввода.
  if (typeof facts.authenticatedSid !== 'string' || facts.authenticatedSid.length === 0) fail('CALLER_UNAUTHENTICATED', 'SID вызывающего не прочитан');
  if (principal.roles.includes('operator') && typeof principal.windowsSid !== 'string') fail('CALLER_UNAUTHENTICATED', 'У оператора нет windowsSid в карточке');
  if (principal.windowsSid !== facts.authenticatedSid) fail('CALLER_UNAUTHENTICATED', 'SID вызывающего не совпал с карточкой субъекта');

  // 4. Роль субъекта: только после подтверждённого SID.
  if (principal.roles.includes('owner') && principal.roles.includes('runner')) fail('ROLE_DENIED', 'Owner и runner не совмещаются');
  if (principal.roles.includes('owner') && principal.roles.includes('anchor-signer')) fail('ROLE_DENIED', 'Owner и anchor-signer не совмещаются');
  if (!principal.roles.includes('owner') && !principal.roles.includes('operator')) fail('ROLE_DENIED', 'Роль не позволяет вызывать доверенный вход');

  // 5. Реестр операций 0.1: без записи в реестре доверенный путь не расширяется.
  if (facts.registry.operationAllowed !== true) fail('CONTRACT_INVALID', 'Операция вне доверенного реестра 0.1');
  if (facts.registry.effectsMatch !== true) fail('APPROVAL_MISMATCH', 'Ожидаемые эффекты не входят в реестр операции');

  // 5. Approval присутствует и действителен.
  const approval = facts.approval;
  if (errorCodeOf(approval.error)) {
    const code = errorCodeOf(approval.error);
    if (code === 'TRUST_STORE_UNAVAILABLE') fail('TRUST_STORE_UNAVAILABLE', 'Корень доверия недоступен при чтении approval');
    if (authReasons.has(code) || contractReasons.has(code) || code === 'CONTRACT_INVALID') fail(code, 'Approval не прошёл проверку сборщика фактов');
    fail('CONTRACT_INVALID', 'approval.error имеет неизвестный код');
  }
  if (approval.body === null || approval.state === 'missing') fail('APPROVAL_MISSING', 'Approval отсутствует');

  // 6. Издатель approval — действующий owner с ключом этого документа.
  const issuer = facts.issuer.body;
  if (issuer === null) fail('PRINCIPAL_UNKNOWN', 'Карточка издателя не загружена');
  if (errorCodeOf(facts.issuer.error)) fail('PRINCIPAL_UNKNOWN', 'Карточка издателя не проверена');
  validatePrincipalCard(issuer, 'issuer');
  if (issuer.status !== 'active') fail('PRINCIPAL_REVOKED', 'Издатель approval отозван');
  if (!issuer.roles.includes('owner')) fail('ROLE_DENIED', 'Approval подписан не owner');
  if (issuer.keyId === null || issuer.keyId === undefined) fail('ROLE_DENIED', 'У издателя нет ключа подписи');
  if (issuer.keyId !== approval.body.keyId) fail('APPROVAL_SIGNATURE_INVALID', 'keyId approval не принадлежит издателю');

  validateApprovalBody(approval.body);
  const approvalBody = approval.body;
  if (approvalBody.subjectPrincipalId !== principal.principalId) fail('ROLE_DENIED', 'Approval выписан другому субъекту');

  // 7. Состояние approval из сборщика фактов.
  const revocation = validateRevocation(approval.revocation, approvalBody.approvalId);
  if (approval.state === 'incomplete') fail('CONSUMPTION_INCOMPLETE', 'Расход approval неполон');
  if (approval.state === 'revoked') fail('APPROVAL_REVOKED', 'Отзыв approval подтверждён');
  if (approval.state === 'expired') fail('APPROVAL_EXPIRED', 'Срок approval истёк до расхода');
  if (approval.state === 'not-yet-valid') fail('CONTRACT_INVALID', 'Момент решения раньше issuedAt');
  if (revocation && approval.state !== 'consumed') fail('APPROVAL_REVOKED', 'Отзыв approval подтверждён');

  // 8. Связка approval с фактически замороженными входами.
  const expected = facts.expected;
  if (expected.operation.id !== approvalBody.operationId || expected.operation.version !== approvalBody.operationVersion || digest(expected.operation) !== approvalBody.operationSha256) fail('APPROVAL_MISMATCH', 'Операция не совпала с approval');
  if (digest(expected.inputs) !== approvalBody.approvedInputsHash) fail('APPROVAL_MISMATCH', 'Входы не совпали с approval');
  if (expected.scenarioContentSha256 !== approvalBody.scenarioContentSha256) fail('APPROVAL_MISMATCH', 'Сценарий не совпал с approval');
  if (expected.fixtureId !== approvalBody.fixtureId) fail('APPROVAL_MISMATCH', 'Fixture не совпал с approval');
  if (expected.environmentId !== approvalBody.targetEnvironmentId || expected.environmentGeneration !== approvalBody.environmentGeneration) fail('APPROVAL_MISMATCH', 'Среда не совпала с approval');
  if (digest(expected.effects) !== digest(approvalBody.allowedEffects)) fail('APPROVAL_MISMATCH', 'Эффекты не совпали с approval');
  if (expected.resource.method !== approvalBody.targetResource.method || expected.resource.path !== approvalBody.targetResource.path) fail('APPROVAL_MISMATCH', 'Ресурс не совпал с approval');

  // 9. Расход: неполный, повторный dispatch и чтение связанного прогона.
  const consumption = inspectConsumption(approval.consumption);
  if (consumption.status === 'incomplete') fail('CONSUMPTION_INCOMPLETE', 'Файл расхода повреждён или неполон');
  if (approval.state === 'consumed') {
    if (consumption.status !== 'complete') fail('CONSUMPTION_INCOMPLETE', 'Состояние consumed без полного файла расхода');
    if (consumption.body.runId !== facts.run.runId) fail('APPROVAL_REPLAY', 'Approval уже связан с другим runId');
    if (consumption.body.inputsHash !== approvalBody.approvedInputsHash || consumption.body.environmentGeneration !== approvalBody.environmentGeneration) fail('CONSUMPTION_INCOMPLETE', 'Полный расход не совпал с approval');
    if (dispatchLike) fail('APPROVAL_CONSUMED', 'Повторный dispatch по израсходованному approval');
  } else if (consumption.status === 'complete') {
    fail('CONTRACT_INVALID', 'Полный расход при состоянии approval, отличном от consumed');
  }

  // 10. Состояние прогона: отмена и уже записанный intent.
  if (dispatchLike && facts.run.canceled) fail('RUN_CANCELED', 'Отмена до dispatch');
  if (dispatchLike && facts.run.mutationRecorded) fail('MUTATION_ALREADY_RECORDED', 'Intent уже записан, новый dispatch не нужен');

  // 11. Среда: реестр читается для любой фазы, живая аттестация — только перед dispatch.
  const environment = facts.environment;
  const environmentError = errorCodeOf(environment.error);
  if (environmentError) {
    if (environmentError === 'ENVIRONMENT_UNKNOWN' || environmentError === 'ENVIRONMENT_REVOKED' || environmentError === 'ENVIRONMENT_UNAVAILABLE' || environmentError === 'ENVIRONMENT_ATTESTATION_FAILED') fail(environmentError, 'Среда не подтверждена сборщиком фактов');
    fail('CONTRACT_INVALID', 'environment.error имеет неизвестный код');
  }
  // D-4: неизвестный код ошибки аттестации отвергается во всех фазах, включая чтение.
  const attestationError = errorCodeOf(environment.attestation.error);
  if (attestationError && attestationError !== 'ENVIRONMENT_ATTESTATION_FAILED' && attestationError !== 'ENVIRONMENT_UNAVAILABLE') {
    fail('CONTRACT_INVALID', 'environment.attestation.error имеет неизвестный код');
  }
  if (environment.record === null) fail('ENVIRONMENT_UNKNOWN', 'Запись реестра сред отсутствует');
  validateEnvironmentRecord(environment.record);
  const record = environment.record;
  if (record.environmentId !== expected.environmentId) fail('ENVIRONMENT_UNKNOWN', 'Запись реестра относится к другой среде');
  if (record.status !== 'active') fail('ENVIRONMENT_REVOKED', 'Среда не active');
  if (record.kind !== 'local-stand') fail('ENVIRONMENT_KIND_DENIED', 'Доверенный dispatch 0.2 только для local-stand');
  // Поколение и живая аттестация относятся к праву на dispatch. Чтение уже связанного
  // прогона не зависит от перезапуска стенда, но требует известной активной local-stand среды.
  if (dispatchLike && record.generation !== expected.environmentGeneration) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Поколение среды сменилось');
  if (dispatchLike) validateAttestation(environment.attestation, record);

  return { effect: 'ALLOW', reasonCode: 'TRUST_OK' };
}

export function decide(facts) {
  const phase = bestPhase(facts);
  try {
    const result = evaluate(facts);
    return decisionFor(facts, phase, result.effect, result.reasonCode);
  } catch (error) {
    if (error && typeof error.policyCode === 'string') {
      const effect = error.policyCode === 'TRUST_STORE_UNAVAILABLE' ? 'INDETERMINATE' : 'DENY';
      return decisionFor(facts, phase, effect, error.policyCode);
    }
    // Любая неожиданная ошибка на некорректной форме facts не превращается в TypeError.
    return decisionFor(facts, phase, 'DENY', 'CONTRACT_INVALID');
  }
}

// Проекция TrustDecision в verdict 0.1. Таблица: docs/wp-00/03-CONTRACT-PROPOSALS.md,
// раздел «Проекция в verdict 0.1». Для ALLOW проекции нет: решение PDP не является verdict.
export function projectToVerdict(decision) {
  if (!isPlainObject(decision) || !EFFECTS.includes(decision.effect) || !PHASES.includes(decision.phase) || typeof decision.reasonCode !== 'string') {
    return { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' };
  }
  if (decision.effect === 'ALLOW') return null;
  const beforeIntent = dispatchPhases.has(decision.phase);
  const code = decision.reasonCode;
  if (code === 'TRUST_OK') return { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' };
  if (code === 'RUN_CANCELED') return { verdict: beforeIntent ? 'BLOCKED' : 'INCONCLUSIVE', reasonCode: 'CANCELED' };
  if (environmentReasons.has(code)) return { verdict: beforeIntent ? 'BLOCKED' : 'INCONCLUSIVE', reasonCode: 'ENVIRONMENT_CHANGED' };
  if (authReasons.has(code)) {
    if (decision.effect === 'INDETERMINATE' && !beforeIntent) return { verdict: 'INCONCLUSIVE', reasonCode: 'AUTH_UNAVAILABLE' };
    return { verdict: 'BLOCKED', reasonCode: 'AUTH_UNAVAILABLE' };
  }
  if (contractReasons.has(code)) return { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' };
  if (anchorReasons.has(code)) return { verdict: 'INCONCLUSIVE', reasonCode: 'EVIDENCE_MISSING' };
  if (integrityReasons.has(code)) return { verdict: 'BLOCKED', reasonCode: 'INTEGRITY_ERROR' };
  return { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' };
}
