import fs from 'node:fs';
import path from 'node:path';
import { digest } from '../core/canonical.mjs';
import { loadTrustRoot, signTrustedDocument, verifyTrustedDocument, verifyAndAssertPrincipal } from './identity.mjs';

const approvalKeys = [
  'allowedEffects', 'approvalId', 'approvalNonce', 'approvedInputsHash', 'domain', 'environmentGeneration',
  'expiresAt', 'fixtureId', 'issuedAt', 'issuerPrincipalId', 'keyId', 'operationId', 'operationSha256',
  'operationVersion', 'scenarioContentSha256', 'schemaVersion', 'signature', 'signatureAlgorithm',
  'subjectPrincipalId', 'targetEnvironmentId', 'targetResource'
];
const consumptionKeys = ['approvalId', 'consumedAt', 'decisionId', 'environmentGeneration', 'inputsHash', 'runId'];
const revocationReasons = new Set(['owner-revoked', 'environment-revoked', 'principal-revoked']);
const maxLifetimeMs = 15 * 60 * 1000;

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('CONTRACT_INVALID', 'Документ approval не объект');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('CONTRACT_INVALID', 'Поле approval не из контракта 0.2');
}

function assertId(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 160) fail('CONTRACT_INVALID', 'Идентификатор вне границы 1…160');
  if (value !== path.win32.basename(value) || value !== path.posix.basename(value) || value.includes('..')) fail('CONTRACT_INVALID', 'Идентификатор нельзя использовать как путь');
}

function assertHash(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('CONTRACT_INVALID', 'Хеш не является SHA-256');
}

function assertTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) || Number.isNaN(Date.parse(value))) fail('CONTRACT_INVALID', 'Время не в UTC');
}

function assertEffects(effects) {
  if (!Array.isArray(effects) || effects.length === 0) fail('CONTRACT_INVALID', 'Список эффектов пуст');
  for (const effect of effects) {
    exactKeys(effect, ['equals', 'field', 'id']);
    assertId(effect.id);
    assertId(effect.field);
  }
}

function assertApprovalBody(body) {
  exactKeys(body, approvalKeys);
  if (body.schemaVersion !== '0.2.0' || body.domain !== 'approval' || body.signatureAlgorithm !== 'Ed25519') fail('CONTRACT_INVALID', 'Версия или домен approval не 0.2');
  for (const key of ['approvalId', 'issuerPrincipalId', 'subjectPrincipalId', 'operationId', 'operationVersion', 'fixtureId', 'targetEnvironmentId']) assertId(body[key]);
  for (const key of ['approvedInputsHash', 'operationSha256', 'scenarioContentSha256', 'keyId']) assertHash(body[key]);
  if (typeof body.signature !== 'string' || !/^[a-f0-9]+$/i.test(body.signature)) fail('APPROVAL_SIGNATURE_INVALID', 'Подпись approval отсутствует');
  if (typeof body.approvalNonce !== 'string' || !/^[a-f0-9]{64}$/.test(body.approvalNonce)) fail('CONTRACT_INVALID', 'approvalNonce не равен 32 байтам');
  if (!Number.isSafeInteger(body.environmentGeneration) || body.environmentGeneration < 1) fail('CONTRACT_INVALID', 'Поколение среды не целое');
  exactKeys(body.targetResource, ['method', 'path']);
  if (body.targetResource.method !== 'POST' || body.targetResource.path !== '/records') fail('CONTRACT_INVALID', 'Ресурс 0.2 только POST /records');
  assertEffects(body.allowedEffects);
  assertTime(body.issuedAt);
  assertTime(body.expiresAt);
  const lifetime = Date.parse(body.expiresAt) - Date.parse(body.issuedAt);
  if (!(lifetime > 0 && lifetime <= maxLifetimeMs)) fail('CONTRACT_INVALID', 'Срок approval не укладывается в 15 минут');
}

function storeFile(trustRoot, folder, approvalId) {
  assertId(approvalId);
  const directory = path.resolve(trustRoot, folder);
  const file = path.resolve(directory, `${approvalId}.json`);
  if (path.dirname(file) !== directory) fail('CONTRACT_INVALID', 'Файл approval выходит из своего каталога');
  return { directory, file };
}

function syncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, 'r');
    fs.fsyncSync(fd);
    return 'synced';
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EINVAL' || error.code === 'EISDIR') return error.code;
    fail('CONSUMPTION_INCOMPLETE', 'Каталог расхода не синхронизирован');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function inspectConsumption(trustRoot, approvalId) {
  const { file } = storeFile(trustRoot, 'consumption', approvalId);
  if (!fs.existsSync(file)) return { status: 'missing', file };
  let value;
  try { value = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return { status: 'incomplete', file }; }
  const keys = value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value).sort() : [];
  const expected = [...consumptionKeys, 'bodySha256'].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return { status: 'incomplete', file };
  const body = {};
  for (const key of consumptionKeys) body[key] = value[key];
  if (value.bodySha256 !== digest(body)) return { status: 'incomplete', file };
  if (body.approvalId !== approvalId || !Number.isSafeInteger(body.environmentGeneration)) return { status: 'incomplete', file };
  for (const key of ['runId', 'decisionId']) {
    try { assertId(body[key]); }
    catch { return { status: 'incomplete', file }; }
  }
  try { assertHash(body.inputsHash); assertTime(body.consumedAt); }
  catch { return { status: 'incomplete', file }; }
  return { status: 'complete', file, body };
}

function readRevocation(trust, trustRoot, approvalId) {
  const { file } = storeFile(trustRoot, 'revocations', approvalId);
  if (!fs.existsSync(file)) return null;
  let document;
  try { document = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('APPROVAL_SIGNATURE_INVALID', 'Файл отзыва не читается'); }
  const body = verifyTrustedDocument(trust, document);
  exactKeys(document, ['approvalId', 'domain', 'keyId', 'reason', 'revokedAt', 'schemaVersion', 'signature', 'signatureAlgorithm']);
  if (body.domain !== 'revocation' || body.schemaVersion !== '0.2.0' || body.approvalId !== approvalId || !revocationReasons.has(body.reason)) fail('APPROVAL_SIGNATURE_INVALID', 'Отзыв не относится к этому approval');
  assertTime(body.revokedAt);
  return body;
}

function assertBindings(body, expected) {
  if (!expected || typeof expected !== 'object' || !expected.operation || !expected.inputs || !expected.effects) fail('APPROVAL_MISMATCH', 'Фактические входы расхода не переданы');
  const operation = expected.operation;
  if (operation.id !== body.operationId || operation.version !== body.operationVersion || digest(operation) !== body.operationSha256) fail('APPROVAL_MISMATCH', 'Операция не совпала с approval');
  if (digest(expected.inputs) !== body.approvedInputsHash) fail('APPROVAL_MISMATCH', 'Входы не совпали с approval');
  if (expected.scenarioContentSha256 !== body.scenarioContentSha256 || expected.fixtureId !== body.fixtureId) fail('APPROVAL_MISMATCH', 'Сценарий или fixture не совпали с approval');
  if (expected.environmentId !== body.targetEnvironmentId || expected.environmentGeneration !== body.environmentGeneration) fail('APPROVAL_MISMATCH', 'Среда не совпала с approval');
  if (digest(expected.effects) !== digest(body.allowedEffects)) fail('APPROVAL_MISMATCH', 'Эффекты не совпали с approval');
  const resource = expected.resource || { method: 'POST', path: '/records' };
  if (resource.method !== body.targetResource.method || resource.path !== body.targetResource.path) fail('APPROVAL_MISMATCH', 'Ресурс не совпал с approval');
}

function assertCaller(trust, body, issuer, subject, windowsSid, requireSid) {
  if (!issuer) fail('PRINCIPAL_UNKNOWN', 'Карточка издателя не передана');
  const issuerPrincipal = verifyAndAssertPrincipal(trust, issuer, { role: 'owner', domain: 'approval' });
  if (issuerPrincipal.principalId !== body.issuerPrincipalId || issuerPrincipal.keyId !== body.keyId) fail('ROLE_DENIED', 'Издатель approval не owner этого ключа');
  if (!subject) fail('PRINCIPAL_UNKNOWN', 'Карточка субъекта не передана');
  const subjectPrincipal = verifyAndAssertPrincipal(trust, subject, requireSid || windowsSid !== undefined ? { windowsSid } : {});
  if (subjectPrincipal.principalId !== body.subjectPrincipalId) fail('ROLE_DENIED', 'Субъект не владеет этим approval');
  if (!subjectPrincipal.roles.includes('owner') && !subjectPrincipal.roles.includes('operator')) fail('ROLE_DENIED', 'Субъект не может запустить прогон');
  if (requireSid && (typeof windowsSid !== 'string' || windowsSid.length === 0)) fail('CALLER_UNAUTHENTICATED', 'SID вызывающего не передан');
  return { issuerPrincipal, subjectPrincipal };
}

function stateOf(consumption, revocation, body, now) {
  if (consumption.status === 'incomplete') return 'incomplete';
  if (consumption.status === 'complete') return 'consumed';
  if (revocation) return 'revoked';
  if (Date.parse(now) < Date.parse(body.issuedAt)) return 'not-yet-valid';
  if (Date.parse(now) >= Date.parse(body.expiresAt)) return 'expired';
  return 'issued';
}

function trustedNow(purpose, testNow) {
  if (purpose === 'view' && testNow !== undefined) {
    assertTime(testNow);
    return testNow;
  }
  return new Date().toISOString();
}

function writeExclusive(file, payload) {
  let fd;
  try { fd = fs.openSync(file, 'wx'); }
  catch (error) {
    if (error.code === 'EEXIST') return 'exists';
    fail('TRUST_STORE_UNAVAILABLE', 'Имя в корне доверия не создано');
  }
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  return 'created';
}

function readStoredApproval(trust, trustRoot, approvalId) {
  const { file } = storeFile(trustRoot, 'approvals', approvalId);
  if (!fs.existsSync(file)) fail('APPROVAL_MISSING', 'Закреплённый approval отсутствует');
  let document;
  try { document = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('APPROVAL_SIGNATURE_INVALID', 'Закреплённый approval не читается'); }
  verifyTrustedDocument(trust, document);
  assertApprovalBody(document);
  if (document.approvalId !== approvalId) fail('CONTRACT_INVALID', 'Имя файла approval не совпало с документом');
  return document;
}

function withGuard(trustRoot, approvalId, fn) {
  assertId(approvalId);
  const directory = path.resolve(trustRoot, 'guards');
  const guardFile = path.resolve(directory, `${approvalId}.lock`);
  if (path.dirname(guardFile) !== directory) fail('CONTRACT_INVALID', 'Блокировка выходит из каталога');
  fs.mkdirSync(directory, { recursive: true });
  const deadline = Date.now() + 5000;
  for (;;) {
    let fd;
    try { fd = fs.openSync(guardFile, 'wx'); }
    catch (error) {
      if (error.code !== 'EEXIST') fail('CONSUMPTION_INCOMPLETE', 'Блокировка approval не создана');
      if (Date.now() > deadline) fail('CONSUMPTION_INCOMPLETE', 'Отзыв и расход не дождались очереди');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
      continue;
    }
    try { return fn(); }
    finally {
      fs.closeSync(fd);
      fs.rmSync(guardFile, { force: true });
    }
  }
}

function pauseBeforeGuard(request) {
  if (request.fault !== 'before-guard') return;
  fs.writeFileSync(request.readyFile, 'paused');
  const deadline = Date.now() + 20000;
  while (!fs.existsSync(request.releaseFile)) {
    if (Date.now() > deadline) fail('CONSUMPTION_INCOMPLETE', 'Ожидание подтверждённого отзыва прервано');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
  }
}

export function signApproval(privateKey, fields, trust, trustRoot) {
  const body = { ...fields, schemaVersion: '0.2.0', domain: 'approval', signature: '00', signatureAlgorithm: 'Ed25519' };
  assertApprovalBody(body);
  delete body.signature;
  delete body.signatureAlgorithm;
  const signed = signTrustedDocument(privateKey, body);
  return trustRoot ? commitApproval(trust, trustRoot, signed) : signed;
}

export function commitApproval(trust, trustRoot, document) {
  verifyTrustedDocument(trust, document);
  assertApprovalBody(document);
  const payload = `${JSON.stringify(document)}\n`;
  const { directory, file } = storeFile(trustRoot, 'approvals', document.approvalId);
  fs.mkdirSync(directory, { recursive: true });
  if (writeExclusive(file, payload) === 'exists') {
    const existing = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (digest(existing) !== digest(document)) fail('CONTRACT_INVALID', 'approvalId уже закреплён с другим содержимым');
    return existing;
  }
  if (fs.readFileSync(file, 'utf8') !== payload) fail('TRUST_STORE_UNAVAILABLE', 'Закреплённый approval не сошёлся при чтении');
  return document;
}

export function verifyApproval(trust, approval, options = {}) {
  const approvalId = approval?.approvalId || options.approvalId;
  if (approval) {
    verifyTrustedDocument(trust, approval);
    assertApprovalBody(approval);
  }
  const stored = readStoredApproval(trust, options.trustRoot, approvalId);
  if (approval && digest(approval) !== digest(stored)) fail('CONTRACT_INVALID', 'Переданный approval не совпадает с закреплённым документом');
  const now = trustedNow(options.purpose, options.testNow);
  assertCaller(trust, stored, options.issuer, options.subject, options.windowsSid, options.purpose === 'dispatch');
  if (options.expected || options.purpose === 'dispatch') assertBindings(stored, options.expected);
  const revocation = readRevocation(trust, options.trustRoot, stored.approvalId);
  const consumption = inspectConsumption(options.trustRoot, stored.approvalId);
  const state = stateOf(consumption, revocation, stored, now);
  if (options.purpose === 'dispatch') {
    if (state === 'incomplete') fail('CONSUMPTION_INCOMPLETE', 'Файл расхода занят и неполон');
    if (state === 'revoked') fail('APPROVAL_REVOKED', 'Отзыв подтверждён до расхода');
    if (state === 'not-yet-valid') fail('CONTRACT_INVALID', 'Момент расхода раньше issuedAt');
    if (state === 'expired') fail('APPROVAL_EXPIRED', 'Срок approval истёк до расхода');
    if (state === 'consumed' && consumption.body.runId !== options.runId) fail('APPROVAL_REPLAY', 'Approval уже связан с другим runId');
    if (state === 'consumed' && (consumption.body.inputsHash !== stored.approvedInputsHash || consumption.body.environmentGeneration !== stored.environmentGeneration)) fail('CONSUMPTION_INCOMPLETE', 'Полный расход не совпал с approval');
  }
  return { body: stored, state, ack: false, consumption: consumption.status === 'complete' ? consumption.body : null, revocation, code: state === 'incomplete' ? 'CONSUMPTION_INCOMPLETE' : null };
}

export function readApprovalState(trust, approval, options = {}) {
  // P2-02: путь «только approvalId» обязан читать закреплённый документ из trust root,
  // а не терять идентификатор и отказывать с CONTRACT_INVALID.
  return verifyApproval(trust, approval, { issuer: options.issuer, subject: options.subject, windowsSid: options.windowsSid, trustRoot: options.trustRoot, expected: options.expected, testNow: options.testNow, approvalId: options.approvalId, purpose: 'view' });
}

export function revokeApproval(privateKey, trustRoot, fields) {
  assertId(fields.approvalId);
  if (!revocationReasons.has(fields.reason)) fail('CONTRACT_INVALID', 'Причина отзыва вне списка');
  assertTime(fields.revokedAt);
  const signed = signTrustedDocument(privateKey, {
    schemaVersion: '0.2.0',
    domain: 'revocation',
    approvalId: fields.approvalId,
    revokedAt: fields.revokedAt,
    reason: fields.reason,
    keyId: fields.keyId
  });
  return withGuard(trustRoot, fields.approvalId, () => {
    const { directory, file } = storeFile(trustRoot, 'revocations', fields.approvalId);
    fs.mkdirSync(directory, { recursive: true });
    const payload = `${JSON.stringify(signed)}\n`;
    if (writeExclusive(file, payload) === 'exists') fail('APPROVAL_REVOKED', 'Файл отзыва уже существует и не заменяется');
    if (fs.readFileSync(file, 'utf8') !== payload) fail('APPROVAL_SIGNATURE_INVALID', 'Отзыв не сошёлся при повторном чтении');
    return signed;
  });
}

export function consumeDispatch(request) {
  pauseBeforeGuard(request);
  const trust = request.trust || loadTrustRoot(request.trustRoot);
  const approvalId = request.approval?.approvalId || request.approvalId;
  return withGuard(request.trustRoot, approvalId, () => dispatchLocked(trust, request));
}

function dispatchLocked(trust, request) {
  const viewed = verifyApproval(trust, request.approval, {
    trustRoot: request.trustRoot,
    issuer: request.issuer,
    subject: request.subject,
    windowsSid: request.windowsSid,
    expected: request.expected,
    runId: request.runId,
    approvalId: request.approvalId,
    purpose: 'dispatch'
  });
  if (viewed.state === 'consumed') return { ...viewed, ack: false, code: 'APPROVAL_CONSUMED' };
  const consumedAt = new Date().toISOString();
  if (Date.parse(consumedAt) < Date.parse(viewed.body.issuedAt)) fail('CONTRACT_INVALID', 'Момент расхода раньше issuedAt');
  if (Date.parse(consumedAt) >= Date.parse(viewed.body.expiresAt)) fail('APPROVAL_EXPIRED', 'Срок approval истёк до расхода');
  const body = {
    approvalId: viewed.body.approvalId,
    runId: request.runId,
    decisionId: request.decisionId,
    inputsHash: viewed.body.approvedInputsHash,
    environmentGeneration: viewed.body.environmentGeneration,
    consumedAt
  };
  assertId(body.runId);
  assertId(body.decisionId);
  assertTime(body.consumedAt);
  const record = { ...body, bodySha256: digest(body) };
  const { directory, file } = storeFile(request.trustRoot, 'consumption', body.approvalId);
  fs.mkdirSync(directory, { recursive: true });
  if (readRevocation(trust, request.trustRoot, body.approvalId)) fail('APPROVAL_REVOKED', 'Отзыв подтверждён до расхода');
  let fd;
  try {
    fd = fs.openSync(file, 'wx');
  } catch (error) {
    if (error.code !== 'EEXIST') fail('CONSUMPTION_INCOMPLETE', 'Имя расхода не создано');
    return finishExisting(trust, request);
  }
  try {
    if (readRevocation(trust, request.trustRoot, body.approvalId)) fail('APPROVAL_REVOKED', 'Отзыв подтверждён до расхода');
    if (request.fault === 'after-create') {
      fs.writeSync(fd, '{');
      fail('CONSUMPTION_INCOMPLETE', 'Обрыв после CREATE_NEW и до полного bodySha256');
    }
    fs.writeFileSync(fd, `${JSON.stringify(record)}\n`);
    fs.fsyncSync(fd);
  } catch (error) {
    if (error.code === 'CONSUMPTION_INCOMPLETE' || error.code === 'CONTRACT_INVALID' || error.code === 'APPROVAL_REVOKED') throw error;
    fail('CONSUMPTION_INCOMPLETE', 'Запись расхода оборвана');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  const directorySync = syncDirectory(directory);
  if (readRevocation(trust, request.trustRoot, body.approvalId)) fail('APPROVAL_REVOKED', 'Отзыв подтверждён до расхода');
  const written = inspectConsumption(request.trustRoot, body.approvalId);
  if (written.status !== 'complete' || written.body.runId !== request.runId || digest(written.body) !== record.bodySha256) fail('CONSUMPTION_INCOMPLETE', 'Повторное чтение расхода не сошлось');
  if (written.body.inputsHash !== viewed.body.approvedInputsHash) fail('CONSUMPTION_INCOMPLETE', 'Расход не связан с закреплённым approval');
  return { body: viewed.body, state: 'consumed', ack: true, consumption: written.body, revocation: null, code: 'TRUST_OK', directorySync };
}

function finishExisting(trust, request) {
  const checked = verifyApproval(trust, request.approval, {
    trustRoot: request.trustRoot, issuer: request.issuer, subject: request.subject,
    windowsSid: request.windowsSid, expected: request.expected, runId: request.runId,
    approvalId: request.approvalId, purpose: 'dispatch'
  });
  if (checked.state === 'incomplete') fail('CONSUMPTION_INCOMPLETE', 'Занятое имя расхода неполно и не заменяется');
  if (checked.state === 'consumed' && checked.consumption.runId === request.runId) return { ...checked, ack: false, code: 'APPROVAL_CONSUMED' };
  if (checked.state === 'consumed') fail('APPROVAL_REPLAY', 'Approval уже связан с другим runId');
  fail('CONSUMPTION_INCOMPLETE', 'Занятое имя расхода не подтвердилось');
}
