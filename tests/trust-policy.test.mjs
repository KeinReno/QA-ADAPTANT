// WP-03 Policy: table-driven проверки PDP по 06-ACCEPTANCE-MATRIX.md.
// Каждая строка фиксирует фазу, ожидаемый effect и точный reasonCode.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest } from '../packages/core/canonical.mjs';
import { decide, projectToVerdict } from '../packages/trust/policy.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const SID = 'S-1-5-21-1001';
const RUN_ID = 'run-1';
const OWNER_KEY_ID = 'a'.repeat(64);
const STAND_KEY_ID = 'b'.repeat(64);
const ENV_ID = 'env-local-1';
const ORIGIN = 'http://127.0.0.1:43117';
const ISSUED_AT = '2026-11-13T00:00:00.000Z';
const EXPIRES_AT = '2026-11-13T00:10:00.000Z';
const NOW = '2026-11-13T00:01:00.000Z';

const operation = {
  schemaVersion: '0.1.0',
  id: 'local-create-record',
  version: '1.0.0',
  description: 'Создать запись на локальном стенде',
  roles: ['local-test-harness'],
  preconditions: [],
  inputs: { comment: 'комментарий', executorId: 'executor-1', title: 'заголовок' },
  entityKind: 'record',
  effects: [
    { id: 'title-saved', field: 'title', equals: 'заголовок', required: true, source: 'independent-read', deadlineMs: 1000, intervalMs: 50 },
    { id: 'executor-saved', field: 'executorId', equals: 'executor-1', required: true, source: 'independent-read', deadlineMs: 1000, intervalMs: 50 },
    { id: 'comment-saved', field: 'comment', equals: 'комментарий', required: true, source: 'independent-read', deadlineMs: 1000, intervalMs: 50 }
  ],
  mutation: { name: 'create-record', repeat: 'never-after-dispatch', ownershipField: 'title' },
  verification: { adapter: 'local', readMethod: 'GET', lookupBy: 'fixtureId', identityFields: ['title'] }
};
const inputs = operation.inputs;
const allowedEffects = operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals }));

function principal(over = {}) {
  return {
    schemaVersion: '0.2.0',
    domain: 'principal',
    principalId: 'local-operator',
    roles: ['operator'],
    keyId: null,
    windowsSid: SID,
    status: 'active',
    ...over
  };
}

function owner(over = {}) {
  return {
    schemaVersion: '0.2.0',
    domain: 'principal',
    principalId: 'local-owner',
    roles: ['owner'],
    keyId: OWNER_KEY_ID,
    windowsSid: SID,
    status: 'active',
    ...over
  };
}

function approvalBody(over = {}) {
  return {
    schemaVersion: '0.2.0',
    domain: 'approval',
    approvalId: 'approval-1',
    issuerPrincipalId: 'local-owner',
    subjectPrincipalId: 'local-operator',
    operationId: operation.id,
    operationVersion: operation.version,
    scenarioContentSha256: 'c'.repeat(64),
    operationSha256: digest(operation),
    approvedInputsHash: digest(inputs),
    fixtureId: 'fixture-1',
    targetEnvironmentId: ENV_ID,
    environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    approvalNonce: 'd'.repeat(64),
    keyId: OWNER_KEY_ID,
    signature: 'e'.repeat(128),
    signatureAlgorithm: 'Ed25519',
    ...over
  };
}

function environmentRecord(over = {}) {
  return {
    schemaVersion: '0.2.0',
    domain: 'environment-record',
    environmentId: ENV_ID,
    generation: 1,
    kind: 'local-stand',
    status: 'active',
    origin: ORIGIN,
    standKeyId: STAND_KEY_ID,
    credentialRef: null,
    keyId: OWNER_KEY_ID,
    signature: 'f'.repeat(128),
    signatureAlgorithm: 'Ed25519',
    ...over
  };
}

function attestationBody(over = {}) {
  return {
    schemaVersion: '0.2.0',
    domain: 'environment-attest',
    environmentId: ENV_ID,
    generation: 1,
    origin: ORIGIN,
    pid: 4242,
    challenge: '1'.repeat(64),
    keyId: STAND_KEY_ID,
    signature: '2'.repeat(128),
    signatureAlgorithm: 'Ed25519',
    ...over
  };
}

function consumptionBody(over = {}) {
  const body = {
    approvalId: 'approval-1',
    runId: RUN_ID,
    decisionId: 'decision-previous',
    inputsHash: digest(inputs),
    environmentGeneration: 1,
    consumedAt: '2026-11-13T00:00:05.000Z',
    ...over
  };
  return { ...body, bodySha256: digest(body) };
}

function revocationBody(over = {}) {
  return {
    schemaVersion: '0.2.0',
    domain: 'revocation',
    approvalId: 'approval-1',
    revokedAt: '2026-11-13T00:00:07.000Z',
    reason: 'owner-revoked',
    keyId: OWNER_KEY_ID,
    signature: '3'.repeat(128),
    signatureAlgorithm: 'Ed25519',
    ...over
  };
}

function baseFacts(over = {}) {
  const facts = {
    phase: 'dispatch',
    now: NOW,
    authenticatedSid: SID,
    trustStore: { available: true, code: null },
    principal: { body: principal(), error: null },
    issuer: { body: owner(), error: null },
    approval: { body: approvalBody(), state: 'issued', error: null, consumption: null, revocation: null },
    expected: {
      operation,
      inputs,
      effects: allowedEffects,
      scenarioContentSha256: 'c'.repeat(64),
      fixtureId: 'fixture-1',
      environmentId: ENV_ID,
      environmentGeneration: 1,
      resource: { method: 'POST', path: '/records' }
    },
    environment: { record: environmentRecord(), error: null, attestation: { ok: true, body: attestationBody(), error: null } },
    run: { runId: RUN_ID, canceled: false, mutationRecorded: false },
    registry: { operationAllowed: true, effectsMatch: true }
  };
  return deepMerge(structuredClone(facts), over);
}

function deepMerge(target, patch) {
  if (!isPlainObject(patch)) return patch;
  for (const [key, value] of Object.entries(patch)) {
    if (isPlainObject(value) && isPlainObject(target[key])) deepMerge(target[key], value);
    else target[key] = structuredClone(value);
  }
  return target;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function decisionShape(decision) {
  return {
    keys: Object.keys(decision).sort(),
    effect: decision.effect,
    phase: decision.phase,
    reasonCode: decision.reasonCode,
    approvalId: decision.approvalId,
    inputsHash: decision.inputsHash,
    environmentId: decision.environmentId,
    environmentGeneration: decision.environmentGeneration,
    authenticatedSid: decision.authenticatedSid,
    obligations: decision.obligations,
    evaluatedAt: decision.evaluatedAt
  };
}

const decisionKeys = ['approvalId', 'authenticatedSid', 'decisionId', 'effect', 'environmentGeneration', 'environmentId', 'evaluatedAt', 'inputsHash', 'obligations', 'phase', 'reasonCode'];

test('TrustDecision имеет ровно замороженный набор полей', () => {
  const decision = decide(baseFacts());
  assert.deepEqual(Object.keys(decision).sort(), decisionKeys);
  for (const key of ['decisionId', 'effect', 'phase', 'reasonCode', 'obligations', 'evaluatedAt']) assert.equal(typeof decision[key], 'string');
  assert.equal(decision.phase, 'dispatch');
  assert.equal(decision.evaluatedAt, NOW);
});

test('счастливый путь dispatch: ALLOW TRUST_OK и consume-dispatch', () => {
  const decision = decide(baseFacts());
  assert.equal(decision.effect, 'ALLOW');
  assert.equal(decision.reasonCode, 'TRUST_OK');
  assert.equal(decision.obligations, 'consume-dispatch');
  assert.equal(decision.approvalId, 'approval-1');
  assert.equal(decision.inputsHash, digest(inputs));
  assert.equal(decision.environmentId, ENV_ID);
  assert.equal(decision.environmentGeneration, 1);
  assert.equal(decision.authenticatedSid, SID);
});

for (const phase of ['observe', 'reconcile', 'publish']) {
  test(`счастливый путь ${phase}: ALLOW TRUST_OK и do-not-dispatch`, () => {
    const decision = decide(baseFacts({ phase }));
    assert.equal(decision.effect, 'ALLOW');
    assert.equal(decision.reasonCode, 'TRUST_OK');
    assert.equal(decision.phase, phase);
    assert.equal(decision.obligations, 'do-not-dispatch');
  });
}

test('чтение связанного прогона по полному расходу: ALLOW do-not-dispatch', () => {
  const decision = decide(baseFacts({ phase: 'observe', approval: { state: 'consumed', consumption: consumptionBody() } }));
  assert.equal(decision.effect, 'ALLOW');
  assert.equal(decision.reasonCode, 'TRUST_OK');
  assert.equal(decision.obligations, 'do-not-dispatch');
});

test('отзыв после расхода не отменяет чтение результата', () => {
  const decision = decide(baseFacts({ phase: 'reconcile', approval: { state: 'consumed', consumption: consumptionBody(), revocation: revocationBody() } }));
  assert.equal(decision.effect, 'ALLOW');
  assert.equal(decision.reasonCode, 'TRUST_OK');
});

test('отмена после dispatch не мешает чтению, но запрещает dispatch', () => {
  const read = decide(baseFacts({ phase: 'observe', run: { canceled: true } }));
  assert.equal(read.effect, 'ALLOW');
  assert.equal(read.obligations, 'do-not-dispatch');
  const dispatch = decide(baseFacts({ run: { canceled: true } }));
  assert.equal(dispatch.effect, 'DENY');
  assert.equal(dispatch.reasonCode, 'RUN_CANCELED');
});

test('чтение не требует живой аттестации, но требует запись реестра среды', () => {
  const attestationFailed = decide(baseFacts({ phase: 'observe', environment: { attestation: { ok: false, body: null, error: 'ENVIRONMENT_ATTESTATION_FAILED' } } }));
  assert.equal(attestationFailed.effect, 'ALLOW');
  const recordMissing = decide(baseFacts({ phase: 'observe', environment: { record: null } }));
  assert.equal(recordMissing.effect, 'DENY');
  assert.equal(recordMissing.reasonCode, 'ENVIRONMENT_UNKNOWN');
});

const table = [
  // Авторизация и Principal.
  { name: 'неизвестный Principal', patch: { principal: { body: null } }, effect: 'DENY', reasonCode: 'PRINCIPAL_UNKNOWN' },
  { name: 'карточка Principal не проверена', patch: { principal: { error: 'PRINCIPAL_UNKNOWN' } }, effect: 'DENY', reasonCode: 'PRINCIPAL_UNKNOWN' },
  { name: 'отозванный Principal', patch: { principal: { body: principal({ status: 'revoked' }) } }, effect: 'DENY', reasonCode: 'PRINCIPAL_REVOKED' },
  { name: 'несовпадение SID вызывающего', patch: { authenticatedSid: 'S-1-5-21-9999' }, effect: 'DENY', reasonCode: 'CALLER_UNAUTHENTICATED' },
  { name: 'SID вызывающего не прочитан', patch: { authenticatedSid: null }, effect: 'DENY', reasonCode: 'CALLER_UNAUTHENTICATED' },
  { name: 'у оператора нет windowsSid в карточке', patch: { principal: { body: principal({ windowsSid: null }) } }, effect: 'DENY', reasonCode: 'CALLER_UNAUTHENTICATED' },
  { name: 'запрещённая роль', patch: { principal: { body: principal({ roles: ['verifier'] }) } }, effect: 'DENY', reasonCode: 'ROLE_DENIED' },
  { name: 'совмещение owner и runner', patch: { principal: { body: principal({ roles: ['owner', 'runner'], keyId: OWNER_KEY_ID }) } }, effect: 'DENY', reasonCode: 'ROLE_DENIED' },
  { name: 'approval выписан другому субъекту', patch: { approval: { body: approvalBody({ subjectPrincipalId: 'local-other' }) } }, effect: 'DENY', reasonCode: 'ROLE_DENIED' },
  { name: 'неизвестный издатель approval', patch: { issuer: { body: null } }, effect: 'DENY', reasonCode: 'PRINCIPAL_UNKNOWN' },
  { name: 'отозванный издатель approval', patch: { issuer: { body: owner({ status: 'revoked' }) } }, effect: 'DENY', reasonCode: 'PRINCIPAL_REVOKED' },
  { name: 'approval подписан не owner', patch: { issuer: { body: owner({ roles: ['verifier'] }) } }, effect: 'DENY', reasonCode: 'ROLE_DENIED' },
  { name: 'keyId approval не принадлежит издателю', patch: { issuer: { body: owner({ keyId: '9'.repeat(64) }) } }, effect: 'DENY', reasonCode: 'APPROVAL_SIGNATURE_INVALID' },
  { name: 'неверная подпись approval', patch: { approval: { error: 'APPROVAL_SIGNATURE_INVALID' } }, effect: 'DENY', reasonCode: 'APPROVAL_SIGNATURE_INVALID' },

  // Approval: наличие, срок, отзыв, повтор, расход.
  { name: 'approval отсутствует', patch: { approval: { body: null, state: 'missing' } }, effect: 'DENY', reasonCode: 'APPROVAL_MISSING' },
  { name: 'approval отсутствует без состояния missing', patch: { approval: { body: null } }, effect: 'DENY', reasonCode: 'APPROVAL_MISSING' },
  { name: 'просроченный approval', patch: { approval: { state: 'expired' } }, effect: 'DENY', reasonCode: 'APPROVAL_EXPIRED' },
  { name: 'отозванный approval', patch: { approval: { state: 'revoked', revocation: revocationBody() } }, effect: 'DENY', reasonCode: 'APPROVAL_REVOKED' },
  { name: 'отзыв в обход состояния', patch: { approval: { state: 'issued', revocation: revocationBody() } }, effect: 'DENY', reasonCode: 'APPROVAL_REVOKED' },
  { name: 'повторный dispatch того же runId', patch: { approval: { state: 'consumed', consumption: consumptionBody() } }, effect: 'DENY', reasonCode: 'APPROVAL_CONSUMED' },
  { name: 'approval связан с другим runId', patch: { approval: { state: 'consumed', consumption: consumptionBody({ runId: 'run-other' }) } }, effect: 'DENY', reasonCode: 'APPROVAL_REPLAY' },
  { name: 'неполный расход', patch: { approval: { state: 'incomplete' } }, effect: 'DENY', reasonCode: 'CONSUMPTION_INCOMPLETE' },
  { name: 'consumed без файла расхода', patch: { approval: { state: 'consumed', consumption: null } }, effect: 'DENY', reasonCode: 'CONSUMPTION_INCOMPLETE' },
  { name: 'повреждённый bodySha256 расхода', patch: { approval: { state: 'consumed', consumption: { ...consumptionBody(), bodySha256: '0'.repeat(64) } } }, effect: 'DENY', reasonCode: 'CONSUMPTION_INCOMPLETE' },
  { name: 'расход не совпал с входными данными approval', patch: { approval: { state: 'consumed', consumption: consumptionBody({ inputsHash: '1'.repeat(64) }) } }, effect: 'DENY', reasonCode: 'CONSUMPTION_INCOMPLETE' },
  { name: 'расход не совпал с поколением среды', patch: { approval: { state: 'consumed', consumption: consumptionBody({ environmentGeneration: 2 }) } }, effect: 'DENY', reasonCode: 'CONSUMPTION_INCOMPLETE' },
  { name: 'not-yet-valid approval', patch: { approval: { state: 'not-yet-valid' } }, effect: 'DENY', reasonCode: 'CONTRACT_INVALID' },

  // Связка approval с замороженными входами.
  { name: 'изменены входы', patch: { expected: { inputs: { ...inputs, title: 'другой заголовок' } } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },
  { name: 'изменена операция', patch: { expected: { operation: { ...operation, version: '1.0.1' } } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },
  { name: 'изменены ожидаемые эффекты', patch: { expected: { effects: [{ ...allowedEffects[0], equals: 'другой' }, allowedEffects[1], allowedEffects[2]] } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },
  { name: 'изменён сценарий', patch: { expected: { scenarioContentSha256: '8'.repeat(64) } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },
  { name: 'изменён fixture', patch: { expected: { fixtureId: 'fixture-2' } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },
  { name: 'изменён ресурс', patch: { expected: { resource: { method: 'POST', path: '/other' } } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },
  { name: 'изменена среда в approval', patch: { expected: { environmentId: 'env-other' } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },
  { name: 'изменено поколение среды в approval', patch: { expected: { environmentGeneration: 2 } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },

  // Реестр операций.
  { name: 'операция вне реестра 0.1', patch: { registry: { operationAllowed: false } }, effect: 'DENY', reasonCode: 'CONTRACT_INVALID' },
  { name: 'эффекты не совпали с реестром операции', patch: { registry: { effectsMatch: false } }, effect: 'DENY', reasonCode: 'APPROVAL_MISMATCH' },

  // Среда.
  { name: 'неизвестная среда', patch: { environment: { record: null } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_UNKNOWN' },
  { name: 'среда в реестре не активна', patch: { environment: { record: environmentRecord({ status: 'disabled' }) } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_REVOKED' },
  { name: 'среда вида dev', patch: { environment: { record: environmentRecord({ kind: 'dev' }) } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_KIND_DENIED' },
  { name: 'среда недоступна', patch: { environment: { error: 'ENVIRONMENT_UNAVAILABLE' } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_UNAVAILABLE' },
  { name: 'неподтверждённая аттестация', patch: { environment: { attestation: { ok: false, body: null, error: null } } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_ATTESTATION_FAILED' },
  { name: 'поколение аттестации не совпало с реестром', patch: { environment: { attestation: { body: attestationBody({ generation: 2 }) } } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_ATTESTATION_FAILED' },
  { name: 'аттестация подписана не ключом стенда', patch: { environment: { attestation: { body: attestationBody({ keyId: '7'.repeat(64) }) } } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_ATTESTATION_FAILED' },
  { name: 'origin аттестации не совпал с реестром', patch: { environment: { attestation: { body: attestationBody({ origin: 'http://127.0.0.1:49999' }) } } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_ATTESTATION_FAILED' },
  { name: 'поколение среды сменилось', patch: { environment: { record: environmentRecord({ generation: 2 }) } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_ATTESTATION_FAILED' },
  { name: 'запись реестра относится к другой среде', patch: { environment: { record: environmentRecord({ environmentId: 'env-other' }) } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_UNKNOWN' },
  { name: 'аттестация не получена', patch: { environment: { attestation: { ok: false, body: null, error: 'ENVIRONMENT_UNAVAILABLE' } } }, effect: 'DENY', reasonCode: 'ENVIRONMENT_UNAVAILABLE' },

  // Неопределённость.
  { name: 'недоступный trust root', patch: { trustStore: { available: false, code: 'TRUST_STORE_UNAVAILABLE' } }, effect: 'INDETERMINATE', reasonCode: 'TRUST_STORE_UNAVAILABLE' },
  { name: 'код недоступности trust root без флага', patch: { trustStore: { available: true, code: 'TRUST_STORE_UNAVAILABLE' } }, effect: 'INDETERMINATE', reasonCode: 'TRUST_STORE_UNAVAILABLE' },

  // Жизненный цикл.
  { name: 'отмена до dispatch', patch: { run: { canceled: true } }, effect: 'DENY', reasonCode: 'RUN_CANCELED' },
  { name: 'intent уже записан', patch: { run: { mutationRecorded: true } }, effect: 'DENY', reasonCode: 'MUTATION_ALREADY_RECORDED' },
  { name: 'отмена до dispatch на preflight', patch: { phase: 'preflight', run: { canceled: true } }, effect: 'DENY', reasonCode: 'RUN_CANCELED' }
];

for (const row of table) {
  test(`решение: ${row.name} → ${row.effect} ${row.reasonCode}`, () => {
    const facts = baseFacts(row.patch);
    const decision = decide(facts);
    assert.equal(decision.effect, row.effect, `effect для строки «${row.name}»`);
    assert.equal(decision.reasonCode, row.reasonCode, `reasonCode для строки «${row.name}»`);
    assert.deepEqual(Object.keys(decision).sort(), decisionKeys);
    const expectedObligations = ['observe', 'reconcile', 'publish'].includes(decision.phase) ? 'do-not-dispatch' : 'consume-dispatch';
    assert.equal(decision.obligations, expectedObligations);
    if (decision.effect !== 'ALLOW') assert.notEqual(decision.reasonCode, 'TRUST_OK');
  });
}

test('PDP не бросает исключений на некорректной форме facts, а возвращает CONTRACT_INVALID', () => {
  const malformed = [null, undefined, {}, 'facts', 42, [], { phase: 'dispatch' }, baseFacts({ phase: 'unknown' }), baseFacts({ now: 'вчера' })];
  const missingInputs = baseFacts();
  delete missingInputs.expected.inputs;
  malformed.push(missingInputs);
  const extraField = baseFacts();
  extraField.extra = true;
  malformed.push(extraField);
  const badApprovalDomain = baseFacts();
  badApprovalDomain.approval.body.domain = 'revocation';
  malformed.push(badApprovalDomain);
  const badRegistry = baseFacts();
  badRegistry.registry.effectsMatch = 'yes';
  malformed.push(badRegistry);
  for (const facts of malformed) {
    let decision;
    assert.doesNotThrow(() => { decision = decide(facts); });
    assert.equal(decision.effect, 'DENY');
    assert.equal(decision.reasonCode, 'CONTRACT_INVALID');
    assert.deepEqual(Object.keys(decision).sort(), decisionKeys);
  }
});

test('детерминизм: одинаковые facts дают одинаковый effect/reasonCode и решение', () => {
  const facts = baseFacts();
  const first = decide(facts);
  const second = decide(structuredClone(facts));
  assert.deepEqual({ ...first, decisionId: null }, { ...second, decisionId: null });
  assert.notEqual(first.decisionId, second.decisionId);
  assert.equal(first.phase, second.phase);
  assert.equal(first.evaluatedAt, NOW);
});

test('facts не мутируются и решение не зависит от внешнего состояния', () => {
  const facts = baseFacts();
  const before = structuredClone(facts);
  Object.freeze(facts);
  const decision = decide(facts);
  assert.equal(decision.effect, 'ALLOW');
  assert.deepEqual(facts, before);
});

test('PDP не пишет на диск и не содержит сетевого или файлового кода', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-policy-no-side-effects-'));
  const before = fs.readdirSync(dir, { recursive: true });
  const decision = decide(baseFacts());
  assert.equal(decision.effect, 'ALLOW');
  assert.deepEqual(fs.readdirSync(dir, { recursive: true }), before);
  const source = fs.readFileSync(path.join(repoRoot, 'packages', 'trust', 'policy.mjs'), 'utf8');
  assert.equal(/from\s+'node:(?:fs|net|http|https|tls|child_process)(?:\/[^']*)?'/.test(source), false, 'policy.mjs не импортирует диск, сеть или процессы');
  assert.equal(/\b(?:sign|verify|createHash|createPrivateKey|createPublicKey|generateKeyPairSync|readFileSync|writeFileSync|appendFileSync|consumeDispatch)\s*\(/.test(source), false, 'policy.mjs не вызывает подпись, ключи и файловые записи');
});

test('obligations ограничены двумя значениями из контракта', () => {
  const values = new Set();
  for (const phase of ['preflight', 'dispatch', 'observe', 'reconcile', 'publish']) values.add(decide(baseFacts({ phase })).obligations);
  assert.deepEqual([...values].sort(), ['consume-dispatch', 'do-not-dispatch']);
});

test('изменение одного поля approval меняет inputsHash решения', () => {
  const first = decide(baseFacts());
  const second = decide(baseFacts({ expected: { inputs: { ...inputs, comment: 'другой комментарий' } } }));
  assert.notEqual(first.inputsHash, second.inputsHash);
  assert.equal(second.reasonCode, 'APPROVAL_MISMATCH');
});

// Проекция в verdict 0.1.
const projectionTable = [
  { name: 'ALLOW dispatch не даёт verdict', decision: { effect: 'ALLOW', phase: 'dispatch', reasonCode: 'TRUST_OK' }, expected: null },
  { name: 'ALLOW observe не даёт verdict', decision: { effect: 'ALLOW', phase: 'observe', reasonCode: 'TRUST_OK' }, expected: null },
  { name: 'CONTRACT_INVALID до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'CONTRACT_INVALID' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'ROLE_DENIED до intent', decision: { effect: 'DENY', phase: 'preflight', reasonCode: 'ROLE_DENIED' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'APPROVAL_MISMATCH до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'APPROVAL_MISMATCH' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'APPROVAL_REPLAY до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'APPROVAL_REPLAY' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'APPROVAL_EXPIRED до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'APPROVAL_EXPIRED' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'APPROVAL_REVOKED до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'APPROVAL_REVOKED' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'ENVIRONMENT_KIND_DENIED до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'ENVIRONMENT_KIND_DENIED' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'неверная подпись approval', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'APPROVAL_SIGNATURE_INVALID' }, expected: { verdict: 'BLOCKED', reasonCode: 'AUTH_UNAVAILABLE' } },
  { name: 'SID не совпал', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'CALLER_UNAUTHENTICATED' }, expected: { verdict: 'BLOCKED', reasonCode: 'AUTH_UNAVAILABLE' } },
  { name: 'отозванный Principal', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'PRINCIPAL_REVOKED' }, expected: { verdict: 'BLOCKED', reasonCode: 'AUTH_UNAVAILABLE' } },
  { name: 'неполный расход', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'CONSUMPTION_INCOMPLETE' }, expected: { verdict: 'BLOCKED', reasonCode: 'AUTH_UNAVAILABLE' } },
  { name: 'trust root недоступен до intent', decision: { effect: 'INDETERMINATE', phase: 'dispatch', reasonCode: 'TRUST_STORE_UNAVAILABLE' }, expected: { verdict: 'BLOCKED', reasonCode: 'AUTH_UNAVAILABLE' } },
  { name: 'trust root недоступен после intent', decision: { effect: 'INDETERMINATE', phase: 'reconcile', reasonCode: 'TRUST_STORE_UNAVAILABLE' }, expected: { verdict: 'INCONCLUSIVE', reasonCode: 'AUTH_UNAVAILABLE' } },
  { name: 'среда не подтвердилась до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'ENVIRONMENT_ATTESTATION_FAILED' }, expected: { verdict: 'BLOCKED', reasonCode: 'ENVIRONMENT_CHANGED' } },
  { name: 'поколение среды сменилось после intent', decision: { effect: 'DENY', phase: 'reconcile', reasonCode: 'ENVIRONMENT_ATTESTATION_FAILED' }, expected: { verdict: 'INCONCLUSIVE', reasonCode: 'ENVIRONMENT_CHANGED' } },
  { name: 'отмена до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'RUN_CANCELED' }, expected: { verdict: 'BLOCKED', reasonCode: 'CANCELED' } },
  { name: 'отмена после intent', decision: { effect: 'DENY', phase: 'reconcile', reasonCode: 'RUN_CANCELED' }, expected: { verdict: 'INCONCLUSIVE', reasonCode: 'CANCELED' } },
  { name: 'конфликт анкера', decision: { effect: 'DENY', phase: 'publish', reasonCode: 'ANCHOR_CONFLICT' }, expected: { verdict: 'BLOCKED', reasonCode: 'INTEGRITY_ERROR' } },
  { name: 'анкер отсутствует', decision: { effect: 'DENY', phase: 'publish', reasonCode: 'ANCHOR_MISSING' }, expected: { verdict: 'INCONCLUSIVE', reasonCode: 'EVIDENCE_MISSING' } },
  { name: 'ENVIRONMENT_REVOKED до intent', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'ENVIRONMENT_REVOKED' }, expected: { verdict: 'BLOCKED', reasonCode: 'ENVIRONMENT_CHANGED' } },
  { name: 'ENVIRONMENT_REVOKED после intent', decision: { effect: 'DENY', phase: 'reconcile', reasonCode: 'ENVIRONMENT_REVOKED' }, expected: { verdict: 'INCONCLUSIVE', reasonCode: 'ENVIRONMENT_CHANGED' } },
  { name: 'неизвестный код не даёт PASS', decision: { effect: 'DENY', phase: 'dispatch', reasonCode: 'SOMETHING_ELSE' }, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } },
  { name: 'некорректное решение', decision: null, expected: { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' } }
];

for (const row of projectionTable) {
  test(`проекция: ${row.name} → ${row.expected ? row.expected.verdict + ' ' + row.expected.reasonCode : 'нет verdict'}`, () => {
    assert.deepEqual(projectToVerdict(row.decision), row.expected);
  });
}

test('счастливый путь preflight: ALLOW TRUST_OK и consume-dispatch', () => {
  const decision = decide(baseFacts({ phase: 'preflight' }));
  assert.equal(decision.effect, 'ALLOW');
  assert.equal(decision.reasonCode, 'TRUST_OK');
  assert.equal(decision.obligations, 'consume-dispatch');
});

test('недоступность trust root при чтении approval даёт INDETERMINATE, а не ALLOW', () => {
  const decision = decide(baseFacts({ approval: { error: 'TRUST_STORE_UNAVAILABLE' } }));
  assert.equal(decision.effect, 'INDETERMINATE');
  assert.equal(decision.reasonCode, 'TRUST_STORE_UNAVAILABLE');
});

test('неверный алгоритм или отсутствие подписи approval — APPROVAL_SIGNATURE_INVALID', () => {
  const badAlgorithm = decide(baseFacts({ approval: { body: approvalBody({ signatureAlgorithm: 'RSA' }) } }));
  assert.equal(badAlgorithm.reasonCode, 'APPROVAL_SIGNATURE_INVALID');
  const noSignature = decide(baseFacts({ approval: { body: approvalBody({ signature: '' }) } }));
  assert.equal(noSignature.reasonCode, 'APPROVAL_SIGNATURE_INVALID');
});

test('повреждённый отзыв не принимается как основание', () => {
  const decision = decide(baseFacts({ approval: { state: 'revoked', revocation: revocationBody({ reason: 'unknown-reason' }) } }));
  assert.equal(decision.effect, 'DENY');
  assert.equal(decision.reasonCode, 'CONTRACT_INVALID');
});

test('неизвестный код ошибки сборщика фактов не даёт ALLOW', () => {
  for (const patch of [
    { approval: { error: 'SOMETHING_NEW' } },
    { environment: { error: 'SOMETHING_NEW' } },
    { environment: { attestation: { ok: false, body: null, error: 'SOMETHING_NEW' } } }
  ]) {
    const decision = decide(baseFacts(patch));
    assert.notEqual(decision.effect, 'ALLOW');
    assert.equal(decision.reasonCode, 'CONTRACT_INVALID');
  }
});

test('approval без subjectPrincipalId не проходит форму', () => {
  const facts = baseFacts();
  delete facts.approval.body.subjectPrincipalId;
  const decision = decide(facts);
  assert.equal(decision.effect, 'DENY');
  assert.equal(decision.reasonCode, 'CONTRACT_INVALID');
});

test('чтение не блокируется сменой поколения стенда, dispatch — блокируется', () => {
  const read = decide(baseFacts({ phase: 'observe', environment: { record: environmentRecord({ generation: 2 }) } }));
  assert.equal(read.effect, 'ALLOW');
  const dispatch = decide(baseFacts({ environment: { record: environmentRecord({ generation: 2 }) } }));
  assert.equal(dispatch.effect, 'DENY');
  assert.equal(dispatch.reasonCode, 'ENVIRONMENT_ATTESTATION_FAILED');
});

test('D-1: SID проверяется раньше роли — CALLER_UNAUTHENTICATED, а не ROLE_DENIED', () => {
  const cases = [
    ['чужая роль', { authenticatedSid: 'S-1-5-21-9999', principal: { body: principal({ roles: ['verifier'] }) } }],
    ['null SID', { authenticatedSid: null, principal: { body: principal({ roles: ['verifier'] }) } }],
    ['owner+runner', { authenticatedSid: 'S-1-5-21-9999', principal: { body: principal({ roles: ['owner', 'runner'], keyId: OWNER_KEY_ID }) } }]
  ];
  for (const [name, patch] of cases) {
    const decision = decide(baseFacts(patch));
    assert.equal(decision.effect, 'DENY', name);
    assert.equal(decision.reasonCode, 'CALLER_UNAUTHENTICATED', name);
  }
  // Отзыв Principal остаётся раньше SID и роли.
  const revoked = decide(baseFacts({ authenticatedSid: 'S-1-5-21-9999', principal: { body: principal({ status: 'revoked' }) } }));
  assert.equal(revoked.reasonCode, 'PRINCIPAL_REVOKED');
});

test('D-2: revoked/disabled среда запрещает и доверенное чтение в 0.2', () => {
  for (const phase of ['observe', 'reconcile', 'publish']) {
    for (const status of ['revoked', 'disabled']) {
      const decision = decide(baseFacts({ phase, environment: { record: environmentRecord({ status }) } }));
      assert.equal(decision.effect, 'DENY', phase + '/' + status);
      assert.equal(decision.reasonCode, 'ENVIRONMENT_REVOKED', phase + '/' + status);
    }
    const fromError = decide(baseFacts({ phase, environment: { error: 'ENVIRONMENT_REVOKED' } }));
    assert.equal(fromError.effect, 'DENY');
    assert.equal(fromError.reasonCode, 'ENVIRONMENT_REVOKED');
  }
  const dispatch = decide(baseFacts({ environment: { record: environmentRecord({ status: 'revoked' }) } }));
  assert.equal(dispatch.reasonCode, 'ENVIRONMENT_REVOKED');
});

test('D-3: consumption без bodySha256 не является полным и не даёт ALLOW в чтении', () => {
  const { bodySha256, ...withoutHash } = consumptionBody();
  assert.equal(typeof bodySha256, 'string');
  for (const phase of ['observe', 'reconcile']) {
    const decision = decide(baseFacts({ phase, approval: { state: 'consumed', consumption: withoutHash } }));
    assert.equal(decision.effect, 'DENY', phase);
    assert.equal(decision.reasonCode, 'CONSUMPTION_INCOMPLETE', phase);
  }
  const dispatch = decide(baseFacts({ approval: { state: 'consumed', consumption: withoutHash } }));
  assert.equal(dispatch.reasonCode, 'CONSUMPTION_INCOMPLETE');
});

test('D-4: неизвестный environment.attestation.error отвергается во всех фазах', () => {
  for (const phase of ['dispatch', 'preflight', 'observe', 'reconcile', 'publish']) {
    const decision = decide(baseFacts({ phase, environment: { attestation: { ok: false, body: null, error: 'SOMETHING_NEW' } } }));
    assert.equal(decision.effect, 'DENY', phase);
    assert.equal(decision.reasonCode, 'CONTRACT_INVALID', phase);
  }
  // Известная ошибка аттестации в чтении не требуется (живая аттестация нужна только перед dispatch).
  const read = decide(baseFacts({ phase: 'observe', environment: { attestation: { ok: false, body: null, error: 'ENVIRONMENT_ATTESTATION_FAILED' } } }));
  assert.equal(read.effect, 'ALLOW');
  assert.equal(read.reasonCode, 'TRUST_OK');
});

test('D-5: projectToVerdict отображает ENVIRONMENT_REVOKED в ENVIRONMENT_CHANGED до и после intent', () => {
  const before = decide(baseFacts({ phase: 'dispatch', environment: { record: environmentRecord({ status: 'revoked' }) } }));
  assert.equal(before.reasonCode, 'ENVIRONMENT_REVOKED');
  assert.deepEqual(projectToVerdict(before), { verdict: 'BLOCKED', reasonCode: 'ENVIRONMENT_CHANGED' });
  const after = decide(baseFacts({ phase: 'reconcile', environment: { record: environmentRecord({ status: 'revoked' }) } }));
  assert.equal(after.reasonCode, 'ENVIRONMENT_REVOKED');
  assert.deepEqual(projectToVerdict(after), { verdict: 'INCONCLUSIVE', reasonCode: 'ENVIRONMENT_CHANGED' });
});

test('проекция берёт реальные решения decide: DENY даёт BLOCKED, INDETERMINATE — INCONCLUSIVE', () => {
  const denied = decide(baseFacts({ approval: { body: null, state: 'missing' } }));
  assert.deepEqual(projectToVerdict(denied), { verdict: 'BLOCKED', reasonCode: 'CONTRACT_INVALID' });
  const unknown = decide(baseFacts({ trustStore: { available: false, code: 'TRUST_STORE_UNAVAILABLE' } }));
  assert.deepEqual(projectToVerdict(unknown), { verdict: 'BLOCKED', reasonCode: 'AUTH_UNAVAILABLE' });
  const allowed = decide(baseFacts());
  assert.equal(projectToVerdict(allowed), null);
});