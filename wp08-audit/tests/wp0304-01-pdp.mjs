// WP-08 независимый аудит WP-03: чистый PDP.
// Проверки: отсутствие I/O, матрица разрешений (невозможен ALLOW без approval/attestation/активного
// principal), порядок проверок и reasonCode, fail-closed на противоречивых фактах, граница доверия
// PDP (подпись/аттестацию проверяет сборщик фактов), R-09.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import http from 'node:http';
import { loadModules, repoRoot } from './wp0304-lib.mjs';

const modules = await loadModules();
const { decide, projectToVerdict, PHASES, EFFECTS } = modules.policy;
const digest = modules.digest;

const SID = 'S-1-5-21-111111111-222222222-333333333-1001';
const T0 = '2026-11-13T07:00:00.000Z';
const T1 = '2026-11-13T08:00:00.000Z';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const ORIGIN = 'http://127.0.0.1:45678/';

function clone(value) { return JSON.parse(JSON.stringify(value)); }

function validConsumption(updates = {}) {
  const body = {
    approvalId: 'approval-1', runId: 'run-1', decisionId: 'decision-1',
    inputsHash: digest({ title: 'T', executorId: 'operator' }),
    environmentGeneration: 1, consumedAt: T0, ...updates
  };
  return { ...body, bodySha256: digest(body) };
}

export function validFacts(overrides = {}) {
  const operation = { id: 'local-create-record', version: '1.0.0' };
  const inputs = { title: 'T', executorId: 'operator' };
  const effects = [{ id: 'title-saved', field: 'title', equals: 'T' }];
  const record = {
    environmentId: 'env-1', generation: 1, kind: 'local-stand', status: 'active',
    origin: ORIGIN, standKeyId: SHA_C, credentialRef: ''
  };
  const approvalBody = {
    schemaVersion: '0.2.0', domain: 'approval', approvalId: 'approval-1',
    issuerPrincipalId: 'owner-1', subjectPrincipalId: 'operator-1',
    operationId: operation.id, operationVersion: operation.version,
    approvedInputsHash: digest(inputs), operationSha256: digest(operation),
    scenarioContentSha256: SHA_A, fixtureId: 'fixture-1',
    targetEnvironmentId: 'env-1', environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: effects, issuedAt: T0, expiresAt: T1,
    approvalNonce: 'ab'.repeat(32), keyId: SHA_B,
    signature: 'cd'.repeat(64), signatureAlgorithm: 'Ed25519'
  };
  const base = {
    phase: 'dispatch',
    now: '2026-11-13T07:30:00.000Z',
    authenticatedSid: SID,
    trustStore: { available: true, code: null },
    principal: { body: { domain: 'principal', principalId: 'operator-1', roles: ['operator'], status: 'active', windowsSid: SID }, error: null },
    issuer: { body: { domain: 'principal', principalId: 'owner-1', roles: ['owner'], status: 'active', windowsSid: SID, keyId: SHA_B }, error: null },
    approval: { body: approvalBody, state: 'issued', error: null, consumption: null, revocation: null },
    expected: {
      operation, inputs, effects, scenarioContentSha256: SHA_A, fixtureId: 'fixture-1',
      environmentId: 'env-1', environmentGeneration: 1, resource: { method: 'POST', path: '/records' }
    },
    environment: {
      record,
      error: null,
      attestation: { ok: true, error: null, body: { domain: 'environment-attest', environmentId: 'env-1', generation: 1, origin: ORIGIN, keyId: SHA_C, challenge: 'd'.repeat(64), pid: 4242 } }
    },
    run: { runId: 'run-1', canceled: false, mutationRecorded: false },
    registry: { operationAllowed: true, effectsMatch: true }
  };
  const facts = clone(base);
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete facts[key];
    else if (value && typeof value === 'object' && !Array.isArray(value) && facts[key] && typeof facts[key] === 'object') facts[key] = { ...facts[key], ...value };
    else facts[key] = value;
  }
  return facts;
}

function effectOf(facts) {
  const decision = decide(facts);
  return { effect: decision.effect, reasonCode: decision.reasonCode, decision };
}

// --- 1. Чистота PDP -------------------------------------------------------------------------
test('PDP: policy.mjs не импортирует I/O-модули и не вызывает сеть/диск', () => {
  const source = fs.readFileSync(repoRoot + '\\packages\\trust\\policy.mjs', 'utf8');
  const imports = [...source.matchAll(/from\s+'([^']+)'/g)].map(match => match[1]);
  for (const spec of imports) {
    assert.ok(!/^node:(fs|net|http|https|tls|child_process)$/.test(spec), 'запрещённый импорт: ' + spec);
    assert.ok(!/^node:fs\//.test(spec), 'запрещённый импорт: ' + spec);
  }
  for (const forbidden of ['readFileSync', 'writeFileSync', 'openSync', 'fetch(', 'execFile', 'createSign', 'generateKeyPair', 'net.connect', 'http.request', 'require(']) {
    assert.ok(!source.includes(forbidden), 'PDP содержит запрещённый вызов: ' + forbidden);
  }
});

test('PDP: decide работает при заглушенных fs/net/http/fetch (никакого I/O)', () => {
  const saved = {
    readFileSync: fs.readFileSync, writeFileSync: fs.writeFileSync, openSync: fs.openSync,
    existsSync: fs.existsSync, readdirSync: fs.readdirSync, mkdirSync: fs.mkdirSync,
    connect: net.Socket.prototype.connect, request: http.request, get: http.get,
    fetch: globalThis.fetch
  };
  const boom = name => () => { throw new Error('PDP выполнил I/O: ' + name); };
  fs.readFileSync = boom('fs.readFileSync'); fs.writeFileSync = boom('fs.writeFileSync');
  fs.openSync = boom('fs.openSync'); fs.existsSync = boom('fs.existsSync');
  fs.readdirSync = boom('fs.readdirSync'); fs.mkdirSync = boom('fs.mkdirSync');
  net.Socket.prototype.connect = boom('net.connect'); http.request = boom('http.request'); http.get = boom('http.get');
  globalThis.fetch = boom('fetch');
  try {
    const result = effectOf(validFacts());
    assert.equal(result.effect, 'ALLOW');
    assert.equal(result.reasonCode, 'TRUST_OK');
  } finally {
    fs.readFileSync = saved.readFileSync; fs.writeFileSync = saved.writeFileSync;
    fs.openSync = saved.openSync; fs.existsSync = saved.existsSync;
    fs.readdirSync = saved.readdirSync; fs.mkdirSync = saved.mkdirSync;
    net.Socket.prototype.connect = saved.connect; http.request = saved.request; http.get = saved.get;
    globalThis.fetch = saved.fetch;
  }
});

test('PDP: decisions/obligations по фазам, ALLOW не проецируется в verdict', () => {
  const expected = { preflight: 'consume-dispatch', dispatch: 'consume-dispatch', observe: 'do-not-dispatch', reconcile: 'do-not-dispatch', publish: 'do-not-dispatch' };
  for (const phase of PHASES) {
    const facts = validFacts({ phase });
    if (phase === 'observe' || phase === 'reconcile' || phase === 'publish') {
      facts.environment.attestation = { ok: false, body: null, error: 'ENVIRONMENT_UNAVAILABLE' };
      facts.approval.state = 'consumed';
      facts.approval.consumption = validConsumption();
      facts.run.canceled = true;
      facts.run.mutationRecorded = true;
    }
    const result = effectOf(facts);
    assert.equal(result.effect, 'ALLOW', 'фаза ' + phase + ': ' + result.reasonCode);
    assert.equal(result.reasonCode, 'TRUST_OK');
    assert.equal(result.decision.obligations, expected[phase], phase);
    assert.equal(projectToVerdict(result.decision), null, phase);
    assert.equal(result.decision.phase, phase);
    assert.equal(typeof result.decision.decisionId, 'string');
  }
});

// --- 2. Матрица запретов ALLOW ---------------------------------------------------------------
test('PDP: невозможен ALLOW без approval', () => {
  for (const [label, facts] of [
    ['approval.body=null,state=missing', (() => { const f = validFacts(); f.approval = { ...f.approval, body: null, state: 'missing', error: 'APPROVAL_MISSING' }; return f; })()],
    ['approval.error=APPROVAL_MISSING', (() => { const f = validFacts(); f.approval.error = 'APPROVAL_MISSING'; return f; })()],
    ['approval.state=revoked', validFacts({ approval: { state: 'revoked' } })],
    ['approval.state=expired', validFacts({ approval: { state: 'expired' } })],
    ['approval.state=not-yet-valid', validFacts({ approval: { state: 'not-yet-valid' } })],
    ['approval.state=incomplete', validFacts({ approval: { state: 'incomplete' } })],
    ['approval signatureAlgorithm=HMAC', validFacts({ approval: { body: { ...validFacts().approval.body, signatureAlgorithm: 'HMAC' } } })],
    ['approval keyId не издателя', validFacts({ issuer: { body: { ...validFacts().issuer.body, keyId: SHA_A } } })]
  ]) {
    const result = effectOf(facts);
    assert.notEqual(result.effect, 'ALLOW', label);
    assert.ok(['DENY', 'INDETERMINATE'].includes(result.effect), label);
  }
  const missing = effectOf(validFacts({ approval: { body: null, state: 'missing', error: 'APPROVAL_MISSING' } }));
  assert.equal(missing.reasonCode, 'APPROVAL_MISSING');
});

test('PDP: невозможен ALLOW без attestation и при чужой среде', () => {
  const cases = [
    ['attestation.ok=false', validFacts({ environment: { attestation: { ok: false, body: null, error: 'ENVIRONMENT_ATTESTATION_FAILED' } } }), 'ENVIRONMENT_ATTESTATION_FAILED'],
    ['attestation.body.generation != record.generation', (() => { const f = validFacts(); f.environment.attestation.body.generation = 2; return f; })(), 'ENVIRONMENT_ATTESTATION_FAILED'],
    ['attestation.body.keyId != standKeyId', (() => { const f = validFacts(); f.environment.attestation.body.keyId = SHA_A; return f; })(), 'ENVIRONMENT_ATTESTATION_FAILED'],
    ['attestation.body.origin != record.origin', (() => { const f = validFacts(); f.environment.attestation.body.origin = 'http://127.0.0.1:9999/'; return f; })(), 'ENVIRONMENT_ATTESTATION_FAILED'],
    ['attestation.body.environmentId != record', (() => { const f = validFacts(); f.environment.attestation.body.environmentId = 'env-2'; return f; })(), 'ENVIRONMENT_ATTESTATION_FAILED'],
    ['record.generation != expected (поколение сменилось)', validFacts({ environment: { record: { ...validFacts().environment.record, generation: 2 } } }), 'ENVIRONMENT_ATTESTATION_FAILED'],
    ['record=null', validFacts({ environment: { record: null } }), 'ENVIRONMENT_UNKNOWN'],
    ['record.status=revoked', validFacts({ environment: { record: { ...validFacts().environment.record, status: 'revoked' } } }), 'ENVIRONMENT_REVOKED'],
    ['record.kind=dev', validFacts({ environment: { record: { ...validFacts().environment.record, kind: 'dev' } } }), 'ENVIRONMENT_KIND_DENIED'],
    ['record.kind=production', validFacts({ environment: { record: { ...validFacts().environment.record, kind: 'production' } } }), 'ENVIRONMENT_KIND_DENIED'],
    ['environment.error=ENVIRONMENT_UNKNOWN', validFacts({ environment: { error: 'ENVIRONMENT_UNKNOWN' } }), 'ENVIRONMENT_UNKNOWN'],
    ['environment.error=ENVIRONMENT_UNAVAILABLE', validFacts({ environment: { error: 'ENVIRONMENT_UNAVAILABLE' } }), 'ENVIRONMENT_UNAVAILABLE']
  ];
  for (const [label, facts, code] of cases) {
    const result = effectOf(facts);
    assert.notEqual(result.effect, 'ALLOW', label);
    assert.equal(result.reasonCode, code, label);
  }
});

test('PDP: невозможен ALLOW при отозванном/чужом principal и слабой аутентификации', () => {
  const cases = [
    ['principal revoked', validFacts({ principal: { body: { ...validFacts().principal.body, status: 'revoked' } } }), 'PRINCIPAL_REVOKED'],
    ['principal body=null', validFacts({ principal: { body: null, error: 'PRINCIPAL_UNKNOWN' } }), 'PRINCIPAL_UNKNOWN'],
    ['principal windowSid чужой', validFacts({ principal: { body: { ...validFacts().principal.body, windowsSid: 'S-1-5-21-9-9-9-1002' } } }), 'CALLER_UNAUTHENTICATED'],
    ['authenticatedSid=null', validFacts({ authenticatedSid: null }), 'CALLER_UNAUTHENTICATED'],
    ['issuer revoked', validFacts({ issuer: { body: { ...validFacts().issuer.body, status: 'revoked' } } }), 'PRINCIPAL_REVOKED'],
    ['issuer не owner', validFacts({ issuer: { body: { ...validFacts().issuer.body, roles: ['operator'] } } }), 'ROLE_DENIED'],
    ['approval.subjectPrincipalId чужой', validFacts({ approval: { body: { ...validFacts().approval.body, subjectPrincipalId: 'operator-2' } } }), 'ROLE_DENIED'],
    ['principal только verifier', validFacts({ principal: { body: { ...validFacts().principal.body, roles: ['verifier'] } } }), 'ROLE_DENIED'],
    ['owner+runner', validFacts({ principal: { body: { ...validFacts().principal.body, roles: ['owner', 'runner'], windowsSid: SID } } }), 'ROLE_DENIED']
  ];
  for (const [label, facts, code] of cases) {
    const result = effectOf(facts);
    assert.notEqual(result.effect, 'ALLOW', label);
    assert.equal(result.reasonCode, code, label);
  }
});

test('PDP: связка approval с входами/операцией/эффектами/ресурсом/fixture', () => {
  const cases = [
    ['inputs', validFacts({ expected: { inputs: { title: 'Другое', executorId: 'operator' } } })],
    ['operation.version', validFacts({ expected: { operation: { id: 'local-create-record', version: '2.0.0' } } })],
    ['scenarioContentSha256', validFacts({ expected: { scenarioContentSha256: SHA_B } })],
    ['fixtureId', validFacts({ expected: { fixtureId: 'fixture-2' } })],
    ['environmentId', validFacts({ expected: { environmentId: 'env-2' } })],
    ['environmentGeneration', validFacts({ expected: { environmentGeneration: 2 } })],
    ['effects', validFacts({ expected: { effects: [{ id: 'title-saved', field: 'title', equals: 'X' }] } })],
    ['resource.path', validFacts({ expected: { resource: { method: 'POST', path: '/other' } } })],
    ['effects пустой', validFacts({ expected: { effects: [] } })]
  ];
  for (const [label, facts] of cases) {
    const result = effectOf(facts);
    assert.notEqual(result.effect, 'ALLOW', label);
    assert.ok(['APPROVAL_MISMATCH'].includes(result.reasonCode) || result.reasonCode === 'CONTRACT_INVALID', label + ' -> ' + result.reasonCode);
  }
});

// --- 3. Порядок проверок и reasonCode ----------------------------------------------------
test('PDP: порядок проверок (revoked principal раньше SID; missing approval раньше среды)', () => {
  const revokedBadSid = validFacts({ principal: { body: { ...validFacts().principal.body, status: 'revoked', windowsSid: 'S-1-5-21-9-9-9-1002' } } });
  assert.equal(effectOf(revokedBadSid).reasonCode, 'PRINCIPAL_REVOKED');
  const badSidBadRole = validFacts({ principal: { body: { ...validFacts().principal.body, roles: ['verifier'], windowsSid: 'S-1-5-21-9-9-9-1002' } } });
  assert.equal(effectOf(badSidBadRole).reasonCode, 'CALLER_UNAUTHENTICATED');
  const missingApprovalBadEnv = validFacts({ approval: { body: null, state: 'missing', error: 'APPROVAL_MISSING' }, environment: { record: null, error: 'ENVIRONMENT_UNKNOWN' } });
  assert.equal(effectOf(missingApprovalBadEnv).reasonCode, 'APPROVAL_MISSING');
  const noRegistryNoApproval = validFacts({ registry: { operationAllowed: false, effectsMatch: false }, approval: { body: null, state: 'missing', error: 'APPROVAL_MISSING' } });
  assert.equal(effectOf(noRegistryNoApproval).reasonCode, 'CONTRACT_INVALID');
});

test('PDP: trustStore недоступен -> INDETERMINATE TRUST_STORE_UNAVAILABLE', () => {
  for (const trustStore of [{ available: false, code: null }, { available: true, code: 'TRUST_STORE_UNAVAILABLE' }, { available: false, code: 'BROKEN' }]) {
    const result = effectOf(validFacts({ trustStore }));
    assert.equal(result.effect, 'INDETERMINATE');
    assert.equal(result.reasonCode, 'TRUST_STORE_UNAVAILABLE');
    const projection = projectToVerdict(result.decision);
    assert.equal(projection.verdict, 'BLOCKED');
    assert.equal(projection.reasonCode, 'AUTH_UNAVAILABLE');
  }
});

test('PDP: fail-closed на противоречивых фактах (ошибка при валидном теле)', () => {
  const contradictions = [
    ['approval.body есть, approval.error есть', validFacts({ approval: { error: 'APPROVAL_SIGNATURE_INVALID' } }), 'APPROVAL_SIGNATURE_INVALID'],
    ['principal.body есть, principal.error есть', validFacts({ principal: { error: 'PRINCIPAL_UNKNOWN' } }), 'PRINCIPAL_UNKNOWN'],
    ['issuer.body есть, issuer.error есть', validFacts({ issuer: { error: 'ROLE_DENIED' } }), 'PRINCIPAL_UNKNOWN'],
    ['attestation.ok=true, attestation.error=CONTRACT_INVALID', validFacts({ environment: { attestation: { ok: true, error: 'CONTRACT_INVALID', body: validFacts().environment.attestation.body } } }), 'CONTRACT_INVALID'],
    ['attestation.ok=true, attestation.error=ENVIRONMENT_UNAVAILABLE', validFacts({ environment: { attestation: { ok: true, error: 'ENVIRONMENT_UNAVAILABLE', body: validFacts().environment.attestation.body } } }), 'ENVIRONMENT_UNAVAILABLE'],
    ['environment.attestation.error неизвестный', validFacts({ environment: { attestation: { ok: false, error: 'SOMETHING_ELSE', body: null } } }), 'CONTRACT_INVALID'],
    ['record.active + environment.error=ENVIRONMENT_REVOKED', validFacts({ environment: { error: 'ENVIRONMENT_REVOKED' } }), 'ENVIRONMENT_REVOKED'],
    ['approval.error неизвестный код', validFacts({ approval: { error: 'WEIRD' } }), 'CONTRACT_INVALID'],
    ['unknown reason в revocation', validFacts({ approval: { revocation: { approvalId: 'approval-1', reason: 'other', revokedAt: T0 } } }), 'CONTRACT_INVALID']
  ];
  for (const [label, facts, code] of contradictions) {
    const result = effectOf(facts);
    assert.notEqual(result.effect, 'ALLOW', label);
    assert.equal(result.reasonCode, code, label);
  }
});

test('PDP: форма facts строгая, на некорректной форме DENY CONTRACT_INVALID без TypeError', () => {
  assert.equal(effectOf(validFacts({ phase: 'unknown-phase' })).effect, 'DENY');
  assert.equal(effectOf(validFacts({ phase: 'unknown-phase' })).reasonCode, 'CONTRACT_INVALID');
  for (const broken of [null, {}, [], 'facts', 42, validFacts({ now: 'not-a-time' }), validFacts({ extra: true })]) {
    const decision = decide(broken);
    assert.equal(decision.effect, 'DENY');
    assert.equal(decision.reasonCode, 'CONTRACT_INVALID');
  }
});

// --- 4. Расход и состояние ----------------------------------------------------------------
test('PDP: расход approval — replay/consumed/incomplete', () => {
  const replay = validFacts({ approval: { state: 'consumed', consumption: validConsumption({ runId: 'run-2' }) }, run: { runId: 'run-1' } });
  assert.equal(effectOf(replay).reasonCode, 'APPROVAL_REPLAY');
  const consumed = validFacts({ approval: { state: 'consumed', consumption: validConsumption() } });
  assert.equal(effectOf(consumed).reasonCode, 'APPROVAL_CONSUMED');
  const incomplete = validFacts({ approval: { state: 'incomplete', consumption: { approvalId: 'approval-1' } } });
  assert.equal(effectOf(incomplete).reasonCode, 'CONSUMPTION_INCOMPLETE');
  const completeButIssued = validFacts({ approval: { state: 'issued', consumption: validConsumption() } });
  assert.equal(effectOf(completeButIssued).reasonCode, 'CONTRACT_INVALID');
  const badBodyHash = validFacts({ approval: { state: 'consumed', consumption: { ...validConsumption(), bodySha256: SHA_A } } });
  assert.equal(effectOf(badBodyHash).reasonCode, 'CONSUMPTION_INCOMPLETE');
  const consumedRevoked = validFacts({ phase: 'observe', approval: { state: 'consumed', consumption: validConsumption(), revocation: { approvalId: 'approval-1', reason: 'owner-revoked', revokedAt: T0 } } });
  assert.equal(effectOf(consumedRevoked).effect, 'ALLOW');
  const issuedRevoked = validFacts({ approval: { revocation: { approvalId: 'approval-1', reason: 'owner-revoked', revokedAt: T0 } } });
  assert.equal(effectOf(issuedRevoked).reasonCode, 'APPROVAL_REVOKED');
  const canceled = validFacts({ run: { canceled: true } });
  assert.equal(effectOf(canceled).reasonCode, 'RUN_CANCELED');
  const mutationRecorded = validFacts({ run: { mutationRecorded: true } });
  assert.equal(effectOf(mutationRecorded).reasonCode, 'MUTATION_ALREADY_RECORDED');
  const canceledRead = validFacts({ phase: 'observe', approval: { state: 'consumed', consumption: validConsumption() }, run: { runId: 'run-1', canceled: true, mutationRecorded: true } });
  assert.equal(effectOf(canceledRead).effect, 'ALLOW');
});

test('PDP: реестр операций 0.1 обязателен', () => {
  assert.equal(effectOf(validFacts({ registry: { operationAllowed: false, effectsMatch: true } })).reasonCode, 'CONTRACT_INVALID');
  assert.equal(effectOf(validFacts({ registry: { operationAllowed: true, effectsMatch: false } })).reasonCode, 'APPROVAL_MISMATCH');
});

// --- 5. Граница доверия PDP: проверки подписи/аттестации не выполняются --------------------
test('ГРАНИЦА: PDP выдаёт ALLOW на вручную собранных facts без проверки подписи approval и аттестации', () => {
  const facts = validFacts();
  facts.approval.body.signature = 'ff'.repeat(64); // подпись не соответствует ни одному ключу
  facts.approval.body.signatureAlgorithm = 'Ed25519';
  delete facts.environment.attestation.body.challenge;
  delete facts.environment.attestation.body.pid;
  facts.environment.attestation.body.keyId = facts.environment.record.standKeyId;
  const result = effectOf(facts);
  assert.equal(result.effect, 'ALLOW', 'PDP сам по себе не проверяет подпись/аттестацию: ' + result.reasonCode);
  assert.equal(result.reasonCode, 'TRUST_OK');
});

// --- 6. R-09: поколение в PDP для фаз чтения не сверяется ---------------------------------
test('R-09 подтверждён: чтение ALLOW при поколении реестра != ожидаемого и без живой аттестации', () => {
  for (const phase of ['observe', 'reconcile', 'publish']) {
    const facts = validFacts({ phase });
    facts.approval.state = 'consumed';
    facts.approval.consumption = validConsumption();
    facts.expected.environmentGeneration = 1;
    facts.environment.record.generation = 7;
    facts.environment.attestation = { ok: false, body: null, error: 'ENVIRONMENT_UNAVAILABLE' };
    const result = effectOf(facts);
    assert.equal(result.effect, 'ALLOW', phase + ': чтение блокируется поколением, чего контракт не требует');
  }
  const dispatch = validFacts({ phase: 'dispatch' });
  dispatch.environment.record.generation = 7;
  assert.equal(effectOf(dispatch).reasonCode, 'ENVIRONMENT_ATTESTATION_FAILED');
});

// --- 7. Проекция в verdict 0.1 ------------------------------------------------------------
test('Проекция: точные коды 0.1 по таблице контракта', () => {
  const cases = [
    ['TRUST_STORE_UNAVAILABLE', 'INDETERMINATE', 'preflight', 'BLOCKED', 'AUTH_UNAVAILABLE'],
    ['CALLER_UNAUTHENTICATED', 'DENY', 'preflight', 'BLOCKED', 'AUTH_UNAVAILABLE'],
    ['APPROVAL_MISMATCH', 'DENY', 'dispatch', 'BLOCKED', 'CONTRACT_INVALID'],
    ['APPROVAL_REVOKED', 'DENY', 'dispatch', 'BLOCKED', 'CONTRACT_INVALID'],
    ['ENVIRONMENT_ATTESTATION_FAILED', 'DENY', 'dispatch', 'BLOCKED', 'ENVIRONMENT_CHANGED'],
    ['ENVIRONMENT_ATTESTATION_FAILED', 'DENY', 'observe', 'INCONCLUSIVE', 'ENVIRONMENT_CHANGED'],
    ['ENVIRONMENT_KIND_DENIED', 'DENY', 'dispatch', null, null],
    ['RUN_CANCELED', 'DENY', 'dispatch', 'BLOCKED', 'CANCELED'],
    ['RUN_CANCELED', 'DENY', 'observe', 'INCONCLUSIVE', 'CANCELED'],
    ['ANCHOR_MISSING', 'DENY', 'publish', 'INCONCLUSIVE', 'EVIDENCE_MISSING'],
    ['ANCHOR_CONFLICT', 'DENY', 'publish', 'BLOCKED', 'INTEGRITY_ERROR'],
    ['TRUST_OK', 'DENY', 'dispatch', 'BLOCKED', 'CONTRACT_INVALID'],
    ['НЕИЗВЕСТНЫЙ', 'DENY', 'dispatch', 'BLOCKED', 'CONTRACT_INVALID']
  ];
  for (const [reasonCode, effect, phase, verdict, projected] of cases) {
    const decision = { decisionId: 'x', effect, phase, reasonCode, approvalId: null, inputsHash: null, environmentId: null, environmentGeneration: null, authenticatedSid: null, obligations: 'do-not-dispatch', evaluatedAt: T0 };
    const projection = projectToVerdict(decision);
    if (verdict === null) {
      assert.ok(projection !== null, reasonCode);
      // ENVIRONMENT_KIND_DENIED: контракт (03-CONTRACT-PROPOSALS, строка «вид среды») -> BLOCKED CONTRACT_INVALID.
      assert.equal(projection.verdict, 'BLOCKED', reasonCode);
      assert.equal(projection.reasonCode, 'CONTRACT_INVALID', reasonCode);
      continue;
    }
    assert.equal(projection.verdict, verdict, reasonCode);
    assert.equal(projection.reasonCode, projected, reasonCode);
  }
});

// --- 8. Facts не мутируются, каждая фаза в EFFECTS --------------------------------
test('PDP: facts не мутируются и phase входит в контракт', () => {
  const facts = validFacts();
  const before = JSON.stringify(facts);
  const decision = decide(facts);
  assert.equal(JSON.stringify(facts), before, 'PDP изменил facts');
  assert.ok(EFFECTS.includes(decision.effect));
  assert.ok(PHASES.includes(decision.phase));
  assert.equal(decision.environmentId, 'env-1');
  assert.equal(decision.environmentGeneration, 1);
  assert.equal(decision.inputsHash, digest(facts.expected.inputs));
});
