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
  if (Date.parse(now) >= Date.parse(body.expiresAt)) return 'expired';
  return 'issued';
}

export function signApproval(privateKey, fields) {
  const body = { ...fields, schemaVersion: '0.2.0', domain: 'approval', signature: '00', signatureAlgorithm: 'Ed25519' };
  assertApprovalBody(body);
  delete body.signature;
  delete body.signatureAlgorithm;
  return signTrustedDocument(privateKey, body);
}

export function verifyApproval(trust, approval, options = {}) {
  const unsigned = verifyTrustedDocument(trust, approval);
  assertApprovalBody(approval);
  const now = options.now || new Date().toISOString();
  assertTime(now);
  assertCaller(trust, unsigned, options.issuer, options.subject, options.windowsSid, options.purpose === 'dispatch');
  if (options.expected || options.purpose === 'dispatch') assertBindings(unsigned, options.expected);
  const revocation = readRevocation(trust, options.trustRoot, unsigned.approvalId);
  const consumption = inspectConsumption(options.trustRoot, unsigned.approvalId);
  const state = stateOf(consumption, revocation, unsigned, now);
  if (options.purpose === 'dispatch') {
    if (state === 'incomplete') fail('CONSUMPTION_INCOMPLETE', 'Файл расхода занят и неполон');
    if (state === 'revoked') fail('APPROVAL_REVOKED', 'Approval отозван до расхода');
    if (state === 'expired') fail('APPROVAL_EXPIRED', 'Срок approval истёк до расхода');
    if (state === 'consumed' && consumption.body.runId !== options.runId) fail('APPROVAL_REPLAY', 'Approval уже связан с другим runId');
    if (state === 'consumed' && (consumption.body.inputsHash !== unsigned.approvedInputsHash || consumption.body.environmentGeneration !== unsigned.environmentGeneration)) fail('CONSUMPTION_INCOMPLETE', 'Полный расход не совпал с approval');
  }
  return { body: unsigned, state, ack: false, consumption: consumption.status === 'complete' ? consumption.body : null, revocation, code: state === 'incomplete' ? 'CONSUMPTION_INCOMPLETE' : null };
}

export function readApprovalState(trust, approval, options = {}) {
  return verifyApproval(trust, approval, { ...options, purpose: 'view' });
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
  const { directory, file } = storeFile(trustRoot, 'revocations', fields.approvalId);
  fs.mkdirSync(directory, { recursive: true });
  try {
    fs.writeFileSync(file, `${JSON.stringify(signed)}\n`, { flag: 'wx' });
  } catch (error) {
    if (error.code === 'EEXIST') fail('APPROVAL_REVOKED', 'Файл отзыва уже существует и не заменяется');
    throw error;
  }
  return signed;
}

export function consumeDispatch(request) {
  const trust = request.trust || loadTrustRoot(request.trustRoot);
  const viewed = verifyApproval(trust, request.approval, { ...request, purpose: 'dispatch' });
  if (viewed.state === 'consumed') return { ...viewed, ack: false, code: 'APPROVAL_CONSUMED' };
  const body = {
    approvalId: viewed.body.approvalId,
    runId: request.runId,
    decisionId: request.decisionId,
    inputsHash: viewed.body.approvedInputsHash,
    environmentGeneration: viewed.body.environmentGeneration,
    consumedAt: request.consumedAt || request.now || new Date().toISOString()
  };
  assertId(body.runId);
  assertId(body.decisionId);
  assertTime(body.consumedAt);
  const record = { ...body, bodySha256: digest(body) };
  const { directory, file } = storeFile(request.trustRoot, 'consumption', body.approvalId);
  fs.mkdirSync(directory, { recursive: true });
  let fd;
  try {
    fd = fs.openSync(file, 'wx');
  } catch (error) {
    if (error.code !== 'EEXIST') fail('CONSUMPTION_INCOMPLETE', 'Имя расхода не создано');
    return finishExisting(trust, request);
  }
  try {
    if (request.fault === 'after-create') {
      fs.writeSync(fd, '{');
      fail('CONSUMPTION_INCOMPLETE', 'Обрыв после CREATE_NEW и до полного bodySha256');
    }
    fs.writeFileSync(fd, `${JSON.stringify(record)}\n`);
    fs.fsyncSync(fd);
  } catch (error) {
    if (error.code === 'CONSUMPTION_INCOMPLETE' || error.code === 'CONTRACT_INVALID') throw error;
    fail('CONSUMPTION_INCOMPLETE', 'Запись расхода оборвана');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  const directorySync = syncDirectory(directory);
  const written = inspectConsumption(request.trustRoot, body.approvalId);
  if (written.status !== 'complete' || written.body.runId !== request.runId || digest(written.body) !== record.bodySha256) fail('CONSUMPTION_INCOMPLETE', 'Повторное чтение расхода не сошлось');
  return { body: viewed.body, state: 'consumed', ack: true, consumption: written.body, revocation: viewed.revocation, code: 'TRUST_OK', directorySync };
}

function finishExisting(trust, request) {
  const checked = verifyApproval(trust, request.approval, { ...request, purpose: 'dispatch' });
  if (checked.state === 'incomplete') fail('CONSUMPTION_INCOMPLETE', 'Занятое имя расхода неполно и не заменяется');
  if (checked.state === 'consumed' && checked.consumption.runId === request.runId) return { ...checked, ack: false, code: 'APPROVAL_CONSUMED' };
  if (checked.state === 'consumed') fail('APPROVAL_REPLAY', 'Approval уже связан с другим runId');
  fail('CONSUMPTION_INCOMPLETE', 'Занятое имя расхода не подтвердилось');
}
