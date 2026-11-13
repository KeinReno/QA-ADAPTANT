import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { canonical } from '../core/canonical.mjs';
import { publicKeyId, signTrustedDocument, verifyTrustedDocument } from './identity.mjs';

// WP-04: реестр сред и challenge-response аттестация локального стенда.
// Контракт: docs/wp-00/03-CONTRACT-PROPOSALS.md (EnvironmentRecord), §5.1 baseline 0.2.
export const DEFAULT_ATTEST_TIMEOUT_MS = 2000;

const schemaVersion = '0.2.0';
const kinds = new Set(['local-stand', 'dev', 'production']);
const statuses = new Set(['active', 'disabled', 'revoked']);
const recordKeys = [
  'schemaVersion', 'domain', 'environmentId', 'generation', 'kind', 'status', 'origin',
  'standKeyId', 'credentialRef', 'keyId', 'signature', 'signatureAlgorithm'
];
const unsignedRecordKeys = recordKeys.filter(key => key !== 'signature' && key !== 'signatureAlgorithm');
const attestationKeys = [
  'schemaVersion', 'domain', 'environmentId', 'generation', 'origin', 'pid', 'challenge',
  'keyId', 'signature', 'signatureAlgorithm'
];
const loopbackOrigin = /^http:\/\/127\.0\.0\.1:(\d{1,5})\/$/;
const hex64 = /^[a-f0-9]{64}$/;
const hex = /^[a-f0-9]+$/i;
const maxAttestationBytes = 65_536;
const maxReadBytes = 1_048_576;
// AUD-P0-02: аутентифицированный канал чтений. Заголовки совпадают с adapters/local/server.mjs.
export const STAND_CHALLENGE_HEADER = 'x-qa-stand-challenge';
export const STAND_RESPONSE_HEADER = 'x-qa-stand-response';
const standResponseVersion = '0.2.1';
const standResponseKeys = [
  'schemaVersion', 'domain', 'environmentId', 'generation', 'origin', 'standKeyId', 'challenge',
  'method', 'path', 'status', 'bodySha256', 'pid', 'issuedAt', 'keyId', 'signature', 'signatureAlgorithm'
];
const httpMethod = /^[A-Z]{1,16}$/;
const hashCanonical = value => createHash('sha256').update(canonical(value), 'utf8').digest('hex');
// Метка «тело уже проверено подписью owner»: не даёт аттестовать неподписанную запись, собранную вызывающим.
const verifiedRecord = Symbol('qa-adaptant-environment-record-verified');

function markVerified(body) {
  Object.defineProperty(body, verifiedRecord, { value: true, enumerable: false });
  return body;
}

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('CONTRACT_INVALID', 'Документ среды не объект');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('CONTRACT_INVALID', 'Поле документа среды не из контракта 0.2');
}

function assertId(value, label) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 160) fail('CONTRACT_INVALID', label + ' вне границы 1…160');
  if (value !== path.win32.basename(value) || value !== path.posix.basename(value) || value.includes('..')) fail('CONTRACT_INVALID', label + ' нельзя использовать как путь');
}

function assertGeneration(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) fail('CONTRACT_INVALID', 'Поколение среды не целое от 1');
}

function assertOrigin(origin, kind) {
  if (typeof origin !== 'string' || origin.length < 1 || origin.length > 200) fail('CONTRACT_INVALID', 'origin среды не строка');
  if (kind === 'local-stand') {
    const match = loopbackOrigin.exec(origin);
    if (!match) fail('CONTRACT_INVALID', 'origin local-stand обязан быть http://127.0.0.1:<port>/');
    const port = Number(match[1]);
    if (!(port >= 1 && port <= 65_535)) fail('CONTRACT_INVALID', 'Порт local-stand вне диапазона');
    return;
  }
  let parsed;
  try { parsed = new URL(origin); }
  catch { fail('CONTRACT_INVALID', 'origin среды не URL'); }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') fail('CONTRACT_INVALID', 'origin среды не http(s)');
  if (parsed.username || parsed.password) fail('CONTRACT_INVALID', 'origin среды не содержит учётных данных');
  if (parsed.search || parsed.hash) fail('CONTRACT_INVALID', 'origin среды не содержит query или fragment');
  if (!parsed.hostname) fail('CONTRACT_INVALID', 'origin среды без хоста');
}

function assertCredentialRef(value) {
  if (typeof value !== 'string' || value.length > 200) fail('CONTRACT_INVALID', 'credentialRef вне границы 0…200');
  if (/[\u0000-\u001f\u007f]/.test(value)) fail('CONTRACT_INVALID', 'credentialRef содержит управляющие символы');
}

function assertAttestationPid(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) fail('CONTRACT_INVALID', 'pid аттестации не целое от 1');
}

function assertRecordContent(body) {
  if (body.schemaVersion !== schemaVersion || body.domain !== 'environment-record') fail('CONTRACT_INVALID', 'Версия или домен записи среды не 0.2');
  assertId(body.environmentId, 'environmentId');
  assertGeneration(body.generation);
  if (!kinds.has(body.kind)) fail('CONTRACT_INVALID', 'kind среды вне списка');
  if (!statuses.has(body.status)) fail('CONTRACT_INVALID', 'status среды вне списка');
  assertOrigin(body.origin, body.kind);
  if (typeof body.standKeyId !== 'string' || !hex64.test(body.standKeyId)) fail('CONTRACT_INVALID', 'standKeyId не SHA-256');
  assertCredentialRef(body.credentialRef);
  if (typeof body.keyId !== 'string' || !hex64.test(body.keyId)) fail('CONTRACT_INVALID', 'keyId записи среды не SHA-256');
}

function assertAttestationContent(body) {
  if (body.schemaVersion !== schemaVersion || body.domain !== 'environment-attest') fail('CONTRACT_INVALID', 'Версия или домен аттестации не 0.2');
  assertId(body.environmentId, 'environmentId аттестации');
  assertGeneration(body.generation);
  if (typeof body.origin !== 'string' || body.origin.length > 200) fail('CONTRACT_INVALID', 'origin аттестации не строка');
  assertAttestationPid(body.pid);
  if (typeof body.challenge !== 'string' || !hex64.test(body.challenge)) fail('CONTRACT_INVALID', 'challenge аттестации не 32 байта hex');
  if (typeof body.keyId !== 'string' || !hex64.test(body.keyId)) fail('CONTRACT_INVALID', 'keyId аттестации не SHA-256');
}

function unsigned(document) {
  const body = { ...document };
  delete body.signature;
  delete body.signatureAlgorithm;
  return body;
}

function publicKeyObject(value) {
  if (!value) return null;
  try {
    if (typeof value === 'object' && typeof value.export === 'function' && value.type === 'public') return value;
    if (typeof value === 'string') {
      if (value.startsWith('-----BEGIN')) return createPublicKey(value);
      return createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return createPublicKey({ key: Buffer.from(value), format: 'der', type: 'spki' });
    if (value && typeof value === 'object' && typeof value.spki === 'string') return createPublicKey({ key: Buffer.from(value.spki, 'base64'), format: 'der', type: 'spki' });
    if (value && typeof value === 'object' && value.publicKey) return publicKeyObject(value.publicKey);
  } catch {
    return null;
  }
  return null;
}

function standPublicKey(trust, body, options) {
  let value = options && options.standPublicKey;
  if (!value && trust && typeof trust === 'object') {
    for (const mapName of ['stands', 'standKeys']) {
      const map = trust[mapName];
      if (map instanceof Map) value = map.get(body.standKeyId);
      else if (map && typeof map === 'object') value = map[body.standKeyId];
      if (value) break;
    }
    if (!value && trust[body.standKeyId]) value = trust[body.standKeyId];
    if (!value && trust['stand-key']) value = trust['stand-key'];
  }
  const key = publicKeyObject(value);
  if (!key) return null;
  if (publicKeyId(key) !== body.standKeyId) return null;
  return key;
}

export function createStandKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { standKeyId: publicKeyId(publicKey), publicKey, privateKey };
}

export function newChallenge() {
  return randomBytes(32).toString('hex');
}

export function signEnvironmentRecord(ownerPrivateKey, fields) {
  const keyId = publicKeyId(createPublicKey(ownerPrivateKey));
  const body = {
    credentialRef: '',
    ...fields,
    schemaVersion,
    domain: 'environment-record',
    keyId,
    signature: '00',
    signatureAlgorithm: 'Ed25519'
  };
  exactKeys(body, recordKeys);
  assertRecordContent(body);
  if (typeof body.signature !== 'string' || !hex.test(body.signature)) fail('CONTRACT_INVALID', 'Подпись записи среды отсутствует');
  const signed = signTrustedDocument(ownerPrivateKey, body);
  return signed;
}

export function verifyEnvironmentRecord(trust, record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) fail('CONTRACT_INVALID', 'Запись среды не объект');
  // D-03: повторная проверка уже проверенного тела идемпотентна по Symbol-метке.
  if (record[verifiedRecord]) {
    exactKeys(record, unsignedRecordKeys);
    assertRecordContent(record);
    return markVerified({ ...record });
  }
  if (typeof record.signature !== 'string') fail('CONTRACT_INVALID', 'Неподписанная запись среды не проходила проверку подписи');
  const body = verifyTrustedDocument(trust, record);
  exactKeys(record, recordKeys);
  assertRecordContent(record);
  if (!hex.test(record.signature)) fail('CONTRACT_INVALID', 'Подпись записи среды отсутствует');
  if (body.domain !== 'environment-record') fail('CONTRACT_INVALID', 'Документ не является записью среды');
  return markVerified(body);
}

function recordBody(trust, record) {
  return verifyEnvironmentRecord(trust, record);
}

function syncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, 'r');
    fs.fsyncSync(fd);
    return 'synced';
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EINVAL' || error.code === 'EISDIR') return error.code;
    fail('TRUST_STORE_UNAVAILABLE', 'Каталог реестра сред не синхронизирован');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

// D-01 (решение Lead, docs/changes/005): поколенческая раскладка
// trustRoot/environments/<environmentId>/<generation>.json. Отдельный CREATE_NEW-файл на поколение.
function environmentDirectory(trustRoot, environmentId) {
  assertId(environmentId, 'environmentId');
  const root = path.resolve(trustRoot, 'environments');
  const directory = path.resolve(root, environmentId);
  if (path.dirname(directory) !== root) fail('CONTRACT_INVALID', 'Каталог среды выходит из реестра');
  return { root, directory };
}

function generationFile(directory, generation) {
  assertGeneration(generation);
  const file = path.resolve(directory, generation + '.json');
  if (path.dirname(file) !== directory) fail('CONTRACT_INVALID', 'Файл поколения среды выходит из каталога');
  return file;
}

function existingGenerations(directory) {
  let entries;
  try { entries = fs.readdirSync(directory, { withFileTypes: true }); }
  catch { fail('CONTRACT_INVALID', 'Каталог среды не читается'); }
  const generations = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const match = /^([1-9]\d*)\.json$/.exec(entry.name);
    if (!match) continue;
    generations.push(Number(match[1]));
  }
  generations.sort((left, right) => left - right);
  return generations;
}

function readGeneration(trust, directory, environmentId, generation) {
  const file = generationFile(directory, generation);
  let document;
  try { document = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('CONTRACT_INVALID', 'Запись поколения среды не читается'); }
  const body = verifyEnvironmentRecord(trust, document);
  if (body.environmentId !== environmentId) fail('CONTRACT_INVALID', 'environmentId записи не совпал с каталогом');
  if (body.generation !== generation) fail('CONTRACT_INVALID', 'generation записи не совпала с именем файла');
  return { file, document, body };
}

export function commitEnvironmentRecord(trust, trustRoot, record) {
  const body = verifyEnvironmentRecord(trust, record);
  const payload = JSON.stringify(record) + '\n';
  const { directory } = environmentDirectory(trustRoot, body.environmentId);
  fs.mkdirSync(directory, { recursive: true });
  const file = generationFile(directory, body.generation);
  if (fs.existsSync(file)) {
    const existing = readGeneration(trust, directory, body.environmentId, body.generation);
    if (canonical(existing.document) !== canonical(record)) fail('CONTRACT_INVALID', 'Поколение среды уже опубликовано с другим содержимым');
    return existing.document;
  }
  const before = existingGenerations(directory);
  const maximum = before.length === 0 ? 0 : before[before.length - 1];
  if (body.generation < maximum) fail('CONTRACT_INVALID', 'Публикация поколения ниже уже существующего максимума');
  let fd;
  try {
    fd = fs.openSync(file, 'wx');
  } catch (error) {
    if (error.code !== 'EEXIST') fail('TRUST_STORE_UNAVAILABLE', 'Файл поколения среды не создан');
    const existing = readGeneration(trust, directory, body.environmentId, body.generation);
    if (canonical(existing.document) !== canonical(record)) fail('CONTRACT_INVALID', 'Поколение среды уже опубликовано с другим содержимым');
    return existing.document;
  }
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);
  } catch {
    fail('TRUST_STORE_UNAVAILABLE', 'Поколение среды не сохранено');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  syncDirectory(directory);
  if (fs.readFileSync(file, 'utf8') !== payload) fail('TRUST_STORE_UNAVAILABLE', 'Опубликованное поколение среды не сошлось при чтении');
  const after = existingGenerations(directory);
  const latest = after.length === 0 ? 0 : after[after.length - 1];
  if (latest > body.generation) {
    fs.rmSync(file, { force: true });
    fail('CONTRACT_INVALID', 'Публикация поколения ниже уже существующего максимума');
  }
  return record;
}

export function loadEnvironmentRecord(trust, trustRoot, environmentId) {
  const { directory } = environmentDirectory(trustRoot, environmentId);
  let isDirectory = false;
  try { isDirectory = fs.statSync(directory).isDirectory(); }
  catch { isDirectory = false; }
  if (!isDirectory) fail('ENVIRONMENT_UNKNOWN', 'Среда отсутствует в реестре');
  const generations = existingGenerations(directory);
  if (generations.length === 0) fail('ENVIRONMENT_UNKNOWN', 'Среда отсутствует в реестре');
  let latest = null;
  for (const generation of generations) latest = readGeneration(trust, directory, environmentId, generation);
  const body = latest.body;
  if (body.status === 'revoked') fail('ENVIRONMENT_REVOKED', 'Среда отозвана');
  return markVerified(body);
}

function requireAttestable(body) {
  if (body.kind !== 'local-stand') fail('ENVIRONMENT_KIND_DENIED', 'Аттестуется только local-stand');
  if (body.status === 'revoked') fail('ENVIRONMENT_REVOKED', 'Среда отозвана');
  if (body.status !== 'active') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда не активна');
}

export function signEnvironmentAttestation(standPrivateKey, fields) {
  const keyId = publicKeyId(createPublicKey(standPrivateKey));
  const body = {
    ...fields,
    schemaVersion,
    domain: 'environment-attest',
    keyId
  };
  exactKeys({ ...body, signature: '00', signatureAlgorithm: 'Ed25519' }, attestationKeys);
  assertAttestationContent(body);
  const signature = sign(null, Buffer.from(canonical(body), 'utf8'), standPrivateKey).toString('hex');
  return { ...body, signature, signatureAlgorithm: 'Ed25519' };
}

export function verifyEnvironmentAttestation(trust, record, attestation, options = {}) {
  const recordFields = recordBody(trust, record);
  requireAttestable(recordFields);
  if (typeof options.challenge !== 'string' || !hex64.test(options.challenge)) fail('CONTRACT_INVALID', 'Свежий challenge не передан');
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) fail('CONTRACT_INVALID', 'Аттестация не объект');
  exactKeys(attestation, attestationKeys);
  assertAttestationContent(attestation);
  // D-02: неверный алгоритм/пустая/не-hex подпись — провал аттестации, а не формы документа.
  if (attestation.signatureAlgorithm !== 'Ed25519') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Алгоритм подписи аттестации не Ed25519');
  if (typeof attestation.signature !== 'string' || !hex.test(attestation.signature)) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись аттестации отсутствует или не hex');
  if (attestation.environmentId !== recordFields.environmentId) fail('ENVIRONMENT_ATTESTATION_FAILED', 'environmentId аттестации не совпал с реестром');
  if (attestation.generation !== recordFields.generation) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Поколение среды изменилось');
  if (attestation.origin !== recordFields.origin) fail('ENVIRONMENT_ATTESTATION_FAILED', 'origin аттестации не совпал с реестром');
  if (attestation.keyId !== recordFields.standKeyId) fail('ENVIRONMENT_ATTESTATION_FAILED', 'standKeyId аттестации не совпал с реестром');
  if (attestation.challenge !== options.challenge) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестация не несёт свежий challenge');
  const key = standPublicKey(trust, recordFields, options);
  if (!key) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Неизвестный ключ стенда: standKeyId не разрешается');
  const body = unsigned(attestation);
  const ok = verify(null, Buffer.from(canonical(body), 'utf8'), key, Buffer.from(attestation.signature, 'hex'));
  if (!ok) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись challenge не сошлась');
  return body;
}

function assertStandResponseContent(body) {
  if (body.schemaVersion !== standResponseVersion || body.domain !== 'stand-response') fail('CONTRACT_INVALID', 'Версия или домен подписи ответа стенда не 0.2.1');
  assertId(body.environmentId, 'environmentId ответа стенда');
  assertGeneration(body.generation);
  if (typeof body.origin !== 'string' || body.origin.length < 1 || body.origin.length > 200) fail('CONTRACT_INVALID', 'origin ответа стенда не строка');
  if (typeof body.standKeyId !== 'string' || !hex64.test(body.standKeyId)) fail('CONTRACT_INVALID', 'standKeyId ответа стенда не SHA-256');
  if (typeof body.challenge !== 'string' || !hex64.test(body.challenge)) fail('CONTRACT_INVALID', 'challenge ответа стенда не 32 байта hex');
  if (typeof body.method !== 'string' || !httpMethod.test(body.method)) fail('CONTRACT_INVALID', 'method ответа стенда не HTTP-метод');
  if (typeof body.path !== 'string' || body.path.length < 1 || body.path.length > 200 || body.path[0] !== '/') fail('CONTRACT_INVALID', 'path ответа стенда не путь');
  if (!Number.isSafeInteger(body.status) || body.status < 100 || body.status > 599) fail('CONTRACT_INVALID', 'status ответа стенда вне диапазона');
  if (typeof body.bodySha256 !== 'string' || !hex64.test(body.bodySha256)) fail('CONTRACT_INVALID', 'bodySha256 ответа стенда не SHA-256');
  assertAttestationPid(body.pid);
  if (typeof body.issuedAt !== 'string' || body.issuedAt.length < 20 || body.issuedAt.length > 40 || !Number.isFinite(Date.parse(body.issuedAt))) fail('CONTRACT_INVALID', 'issuedAt ответа стенда не ISO-8601');
  if (typeof body.keyId !== 'string' || !hex64.test(body.keyId)) fail('CONTRACT_INVALID', 'keyId ответа стенда не SHA-256');
}

function standResponseStatement(signature) {
  if (signature && typeof signature === 'object' && !Array.isArray(signature)) return signature;
  if (typeof signature === 'string' && signature.length > 0) {
    const text = signature.trim().startsWith('{') ? signature : Buffer.from(signature, 'base64url').toString('utf8');
    try { return JSON.parse(text); }
    catch { fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись ответа стенда не разбирается'); }
  }
  fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись ответа стенда отсутствует');
}

function responseBodySha256({ body, responseBytes }) {
  if (responseBytes !== undefined) {
    let parsed = body;
    if (parsed === undefined) {
      let text;
      if (typeof responseBytes === 'string') text = responseBytes;
      else if (Buffer.isBuffer(responseBytes) || responseBytes instanceof Uint8Array) text = Buffer.from(responseBytes).toString('utf8');
      else fail('CONTRACT_INVALID', 'responseBytes не строка и не байты');
      try { parsed = JSON.parse(text); }
      catch { fail('ENVIRONMENT_ATTESTATION_FAILED', 'Тело ответа стенда не JSON'); }
    }
    return hashCanonical(parsed);
  }
  if (body === undefined) fail('CONTRACT_INVALID', 'Тело ответа стенда не передано');
  return hashCanonical(body);
}

// AUD-P0-02: проверка подписи ответа стенда ключом из доверенной регистрации (record подписан owner).
// Сверяются environmentId/generation/origin/standKeyId/challenge/method/path/status/bodySha256/pid/keyId,
// затем Ed25519-подпись по каноническому JSON без signature/signatureAlgorithm.
export function verifyStandResponse({
  trust, record, challenge, body, responseBytes, signature,
  method, path: responsePath, status, pid, standPublicKey: publicKey
} = {}) {
  const recordFields = recordBody(trust, record);
  requireAttestable(recordFields);
  if (typeof challenge !== 'string' || !hex64.test(challenge)) fail('CONTRACT_INVALID', 'Свежий challenge не передан');
  const statement = standResponseStatement(signature);
  exactKeys(statement, standResponseKeys);
  assertStandResponseContent(statement);
  if (statement.signatureAlgorithm !== 'Ed25519') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Алгоритм подписи ответа стенда не Ed25519');
  if (typeof statement.signature !== 'string' || !hex.test(statement.signature)) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись ответа стенда отсутствует или не hex');
  if (statement.environmentId !== recordFields.environmentId) fail('ENVIRONMENT_ATTESTATION_FAILED', 'environmentId ответа стенда не совпал с реестром');
  if (statement.generation !== recordFields.generation) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Поколение среды в ответе стенда изменилось');
  if (statement.origin !== recordFields.origin) fail('ENVIRONMENT_ATTESTATION_FAILED', 'origin ответа стенда не совпал с реестром');
  if (statement.standKeyId !== recordFields.standKeyId) fail('ENVIRONMENT_ATTESTATION_FAILED', 'standKeyId ответа стенда не совпал с реестром');
  if (statement.keyId !== recordFields.standKeyId) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ стенда подписан не ключом стенда');
  if (statement.challenge !== challenge) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ стенда не несёт свежий challenge');
  if (method !== undefined && statement.method !== String(method).toUpperCase()) fail('ENVIRONMENT_ATTESTATION_FAILED', 'method ответа стенда не совпал с запросом');
  if (responsePath !== undefined && statement.path !== responsePath) fail('ENVIRONMENT_ATTESTATION_FAILED', 'path ответа стенда не совпал с запросом');
  if (status !== undefined && statement.status !== status) fail('ENVIRONMENT_ATTESTATION_FAILED', 'status ответа стенда не совпал с прочитанным');
  if (pid !== undefined && statement.pid !== pid) fail('ENVIRONMENT_ATTESTATION_FAILED', 'pid ответа стенда не совпал с аттестованным процессом');
  if (statement.bodySha256 !== responseBodySha256({ body, responseBytes })) fail('ENVIRONMENT_ATTESTATION_FAILED', 'bodySha256 ответа стенда не совпал с телом');
  const key = standPublicKey(trust, recordFields, { standPublicKey: publicKey });
  if (!key) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Неизвестный ключ стенда: standKeyId не разрешается');
  const unsignedStatement = unsigned(statement);
  const ok = verify(null, Buffer.from(canonical(unsignedStatement), 'utf8'), key, Buffer.from(statement.signature, 'hex'));
  if (!ok) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись ответа стенда не сошлась');
  return unsignedStatement;
}

function headerValue(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === 'function') return headers.get(name);
  if (typeof headers === 'object') {
    for (const key of Object.keys(headers)) if (key.toLowerCase() === name) return headers[key];
  }
  return null;
}

// Разбор заголовка подписи ответа: base64url(JSON) либо сам JSON (для тестовых двойников).
export function readStandResponseSignature(headers) {
  const raw = headerValue(headers, STAND_RESPONSE_HEADER);
  if (typeof raw !== 'string' || raw.length === 0) return null;
  const text = raw.trim().startsWith('{') ? raw : Buffer.from(raw, 'base64url').toString('utf8');
  try { return JSON.parse(text); }
  catch { fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись ответа стенда не JSON'); }
}

// AUD-P0-02 / §10.2: закреплённое соединение (pinned keep-alive). Control/Verification один раз
// открывают TCP к аттестованному стенду, аттестуют его на этом же сокете и далее не открывают новых
// соединений: подмена процесса стенда ломает закреплённый сокет, а не уводит запрос на rogue.
export function createPinnedAgent(socket) {
  if (!socket || typeof socket !== 'object' || typeof socket.destroyed !== 'boolean') fail('CONTRACT_INVALID', 'Закреплённый сокет не передан');
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 });
  agent.createConnection = (options, callback) => {
    if (!socket.destroyed) {
      if (typeof callback === 'function') { callback(null, socket); return undefined; }
      return socket;
    }
    // Новое TCP-соединение не открывается принципиально: разрыв закреплённого сокета — отказ.
    const error = Object.assign(new Error('Закреплённое соединение стенда разорвано'), { code: 'ENVIRONMENT_UNAVAILABLE' });
    if (typeof callback === 'function') { callback(error); return undefined; }
    throw error;
  };
  return agent;
}

function transportError(error) {
  if (error && typeof error.code === 'string'
    && (error.code.startsWith('ENVIRONMENT_') || error.code === 'CONTRACT_INVALID')) return error;
  return Object.assign(new Error('Закреплённое соединение стенда недоступно: ' + (error?.message || 'разрыв')), { code: 'ENVIRONMENT_UNAVAILABLE' });
}

// HTTP-запрос строго по уже закреплённому сокету. Новый TCP не открывается никогда.
export function pinnedStandRequest(connection, { method = 'GET', path: requestPath = '/', headers = {}, body, timeoutMs } = {}) {
  if (!connection || !connection.agent || typeof connection.origin !== 'string') fail('CONTRACT_INVALID', 'Закреплённое соединение стенда не передано');
  let target;
  try { target = new URL(requestPath, connection.origin); }
  catch { fail('CONTRACT_INVALID', 'Путь запроса закреплённого соединения не URL'); }
  if (target.origin !== connection.origin) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Запрос уходит за пределы закреплённого origin');
  if (target.protocol !== 'http:') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Закреплённое соединение не по http');
  const payload = body === undefined ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
  const requestHeaders = { accept: 'application/json', ...headers };
  if (payload !== null) {
    requestHeaders['content-type'] = requestHeaders['content-type'] || 'application/json';
    requestHeaders['content-length'] = payload.length;
  }
  const limit = timeoutOf(timeoutMs === undefined ? connection.timeoutMs : timeoutMs);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(transportError(error));
      else resolve(value);
    };
    let request;
    try {
      request = http.request({
        host: target.hostname,
        port: Number(target.port),
        method: String(method).toUpperCase(),
        path: target.pathname + target.search,
        headers: requestHeaders,
        agent: connection.agent,
        timeout: limit
      }, response => {
        const chunks = [];
        let total = 0;
        let tooLarge = false;
        response.on('data', chunk => {
          total += chunk.length;
          if (total > maxReadBytes) { tooLarge = true; response.destroy(); return; }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (tooLarge) return finish(Object.assign(new Error('Ответ закреплённого соединения слишком большой'), { code: 'ENVIRONMENT_ATTESTATION_FAILED' }));
          const responseTextValue = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          try { parsed = responseTextValue.length ? JSON.parse(responseTextValue) : null; }
          catch { parsed = null; }
          finish(null, { status: response.statusCode, headers: response.headers, text: responseTextValue, body: parsed });
        });
        response.on('error', error => finish(error));
      });
    } catch (error) { finish(error); return; }
    request.on('timeout', () => request.destroy(Object.assign(new Error('Таймаут закреплённого соединения стенда'), { code: 'ENVIRONMENT_UNAVAILABLE' })));
    request.on('error', error => finish(error));
    if (payload !== null) request.write(payload);
    request.end();
  });
}

// Свежая аттестация по тому же закреплённому сокету: challenge-response, подпись environment-attest
// и подпись stand-response на тот же challenge и то же тело.
export async function attestPinnedConnection(connection, { trust, record, standPublicKey: publicKey, headers = {}, timeoutMs } = {}) {
  if (!connection || typeof connection.request !== 'function') fail('CONTRACT_INVALID', 'Закреплённое соединение стенда не передано');
  const recordFields = recordBody(trust, record || connection.record);
  requireAttestable(recordFields);
  if (new URL(recordFields.origin).origin !== connection.origin) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Запись среды не совпадает с закреплённым origin');
  const challenge = newChallenge();
  const response = await pinnedStandRequest(connection, {
    method: 'POST', path: '/attest',
    headers: { ...headers, [STAND_CHALLENGE_HEADER]: challenge },
    body: { challenge }, timeoutMs
  });
  if (response.status !== 200) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда ответила ' + response.status);
  if (!response.body || typeof response.body !== 'object' || Array.isArray(response.body)) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестация среды не JSON-объект');
  const attestation = verifyEnvironmentAttestation(trust, recordFields, response.body, { challenge, standPublicKey: publicKey });
  const statement = readStandResponseSignature(response.headers);
  if (!statement) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ аттестации не подписан доменом stand-response');
  const verified = verifyStandResponse({
    trust, record: recordFields, challenge, body: response.body, responseBytes: response.text, signature: statement,
    method: 'POST', path: '/attest', status: 200, standPublicKey: publicKey
  });
  if (verified.pid !== attestation.pid) fail('ENVIRONMENT_ATTESTATION_FAILED', 'pid подписи ответа не совпал с pid аттестации');
  return { challenge, attestation, response: verified };
}

// Control открывает ОДНО соединение к аттестованному стенду и аттестует его на этом же сокете.
// Возвращает { socket, agent, attestation, portOwnerPid, request(), close() }; новых TCP не открывает.
export async function openPinnedStandConnection({ record, trust, standPublicKey: publicKey, headers = {}, timeoutMs } = {}) {
  const recordFields = recordBody(trust, record);
  requireAttestable(recordFields);
  const parsed = new URL(recordFields.origin);
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || !parsed.port) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Закрепляется только локальный http-стенд 127.0.0.1:<port>');
  const port = Number(parsed.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Порт закрепляемого стенда вне диапазона');
  const socket = net.connect({ host: '127.0.0.1', port });
  socket.setNoDelay(true);
  const connected = await new Promise(resolve => {
    socket.once('connect', () => resolve({ ok: true }));
    socket.once('error', error => resolve({ error }));
    socket.setTimeout(timeoutOf(timeoutMs), () => socket.destroy(Object.assign(new Error('Таймаут закреплённого соединения стенда'), { code: 'ENVIRONMENT_UNAVAILABLE' })));
  });
  if (!connected.ok) {
    try { socket.destroy(); } catch { /* уже закрыт */ }
    fail('ENVIRONMENT_UNAVAILABLE', 'Закреплённое соединение со стендом не установлено');
  }
  socket.setTimeout(0);
  const connection = {
    socket,
    record: recordFields,
    origin: parsed.origin,
    timeoutMs: timeoutOf(timeoutMs),
    agent: createPinnedAgent(socket),
    request(options = {}) { return pinnedStandRequest(connection, options); },
    close() {
      try { connection.agent.destroy(); } catch { /* уже уничтожен */ }
      try { socket.destroy(); } catch { /* уже закрыт */ }
    }
  };
  try {
    const attested = await attestPinnedConnection(connection, { trust, record: recordFields, standPublicKey: publicKey, headers, timeoutMs });
    if (!processAlive(attested.attestation.pid)) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Процесс стенда не жив');
    const owner = await portOwnerPid(recordFields.origin);
    if (owner === null) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Владелец локального порта не определён');
    if (owner !== attested.attestation.pid) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Порт обслуживает не аттестованный процесс');
    connection.attestation = attested.attestation;
    connection.attestationResponse = attested.response;
    connection.portOwnerPid = owner;
    return connection;
  } catch (error) {
    connection.close();
    throw error;
  }
}

// AUD-P0-02: Verification сам подтверждает среду — свежая аттестация до и после набора чтений
// на собственном закреплённом соединении; каждое чтение обязано нести подпись стенда.
// read(ctx) — набор чтений вызывающего; ctx.verifiedRead(url, {headers, method}) подписывает каждое чтение.
export async function attestationVerifiedReads({
  trust, record, standPublicKey: publicKey, timeoutMs, headers = {}, read, maxReads = 64
} = {}) {
  if (typeof read !== 'function') fail('CONTRACT_INVALID', 'Набор чтений не передан');
  const recordFields = recordBody(trust, record);
  requireAttestable(recordFields);
  const connection = await openPinnedStandConnection({ record: recordFields, trust, standPublicKey: publicKey, timeoutMs });
  const before = { record: recordFields, attestation: connection.attestation, portOwnerPid: connection.portOwnerPid };
  const identity = {
    environmentId: recordFields.environmentId,
    generation: recordFields.generation,
    origin: recordFields.origin,
    standKeyId: recordFields.standKeyId,
    pid: connection.attestation.pid
  };
  const reads = [];
  const context = {
    environmentId: identity.environmentId,
    generation: identity.generation,
    origin: identity.origin,
    standKeyId: identity.standKeyId,
    pid: identity.pid,
    async verifiedRead(target, options = {}) {
      if (reads.length >= maxReads) fail('CONTRACT_INVALID', 'Превышено число подписанных чтений среды');
      const method = String(options.method || 'GET').toUpperCase();
      let url;
      try { url = new URL(target, identity.origin); }
      catch { fail('CONTRACT_INVALID', 'Адрес чтения среды не URL'); }
      if (url.origin !== connection.origin) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Чтение уходит за пределы закреплённого origin');
      if (url.protocol !== 'http:') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Чтение среды не по http');
      const challenge = newChallenge();
      const response = await connection.request({
        method,
        path: url.pathname + url.search,
        headers: { ...headers, ...(options.headers || {}), [STAND_CHALLENGE_HEADER]: challenge },
        timeoutMs: options.timeoutMs
      });
      if (response.status >= 300 && response.status < 400) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Редирект среды запрещён');
      if (!response.body || typeof response.body !== 'object') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Тело ответа среды не JSON');
      const signature = readStandResponseSignature(response.headers);
      if (!signature) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды не подписан ключом стенда');
      let verified;
      try {
        verified = verifyStandResponse({
          trust, record: recordFields, challenge, body: response.body, responseBytes: response.text, signature,
          method, path: url.pathname, status: response.status, pid: identity.pid, standPublicKey: publicKey
        });
      } catch (error) {
        if (error.code === 'TRUST_STORE_UNAVAILABLE' || error.code === 'ENVIRONMENT_REVOKED' || error.code === 'ENVIRONMENT_ATTESTATION_FAILED') throw error;
        fail('ENVIRONMENT_ATTESTATION_FAILED', 'Подпись ответа среды не подтверждена: ' + error.message);
      }
      reads.push({
        method, path: url.pathname, status: response.status, challenge,
        bodySha256: verified.bodySha256, issuedAt: verified.issuedAt
      });
      return { status: response.status, body: response.body, headers: response.headers, bodySha256: verified.bodySha256, attestation: verified };
    }
  };
  try {
    const result = await read(context);
    const afterAttested = await attestPinnedConnection(connection, { trust, record: recordFields, standPublicKey: publicKey, headers, timeoutMs });
    const after = { record: recordFields, attestation: afterAttested.attestation };
    if (afterAttested.attestation.pid !== identity.pid) fail('ENVIRONMENT_ATTESTATION_FAILED', 'pid среды изменился во время набора чтений');
    if (!processAlive(identity.pid)) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Процесс стенда не жив после набора чтений');
    const owner = await portOwnerPid(recordFields.origin);
    if (owner === null) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Владелец локального порта не определён после набора чтений');
    if (owner !== identity.pid) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Порт обслуживает не аттестованный процесс');
    after.portOwnerPid = owner;
    for (const field of ['environmentId', 'generation', 'origin', 'standKeyId', 'pid']) {
      const afterValue = field === 'pid' ? after.attestation.pid : recordFields[field];
      if (afterValue !== identity[field]) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда изменилась во время набора чтений: ' + field);
    }
    return { result, before, after, reads };
  } finally {
    connection.close();
  }
}
function timeoutOf(value) {
  if (Number.isFinite(value) && value > 0) return Math.floor(value);
  return DEFAULT_ATTEST_TIMEOUT_MS;
}

function responseFailure(error) {
  if (error && typeof error.code === 'string'
    && (error.code.startsWith('ENVIRONMENT_') || error.code === 'CONTRACT_INVALID' || error.code === 'TRUST_STORE_UNAVAILABLE')) return error;
  return null;
}

function declaredContentLength(response) {
  try {
    if (response.headers && typeof response.headers.get === 'function') {
      const value = Number(response.headers.get('content-length'));
      return Number.isFinite(value) ? value : null;
    }
  } catch {
    return null;
  }
  return null;
}

// D-04: читаем поток с капом до буферизации всего тела; content-length проверяется заранее.
async function responseText(response, cap = maxAttestationBytes) {
  if (!response || typeof response.text !== 'function') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды не читается');
  const declared = declaredContentLength(response);
  if (declared !== null && declared > cap) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды слишком большой');
  if (response.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        total += chunk.length;
        if (total > cap) {
          try { await reader.cancel(); } catch { /* поток уже закрыт */ }
          fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды слишком большой');
        }
        chunks.push(chunk);
      }
    } catch (error) {
      const own = responseFailure(error);
      if (own) throw own;
      fail('ENVIRONMENT_UNAVAILABLE', 'Ответ среды оборван');
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  let text;
  try { text = await response.text(); }
  catch { fail('ENVIRONMENT_UNAVAILABLE', 'Ответ среды оборван'); }
  if (typeof text !== 'string') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды не текст');
  if (Buffer.byteLength(text, 'utf8') > cap) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды слишком большой');
  return text;
}

export async function attestEnvironment({ record, trust, challenge, fetchImpl, timeoutMs, standPublicKey: publicKey } = {}) {
  if (typeof challenge !== 'string' || !hex64.test(challenge)) fail('CONTRACT_INVALID', 'challenge обязан быть 32 байтами hex');
  const recordFields = recordBody(trust, record);
  requireAttestable(recordFields);
  const send = fetchImpl || globalThis.fetch;
  if (typeof send !== 'function') fail('ENVIRONMENT_UNAVAILABLE', 'HTTP-клиент не доступен');
  const url = recordFields.origin + 'attest';
  const signal = typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(timeoutOf(timeoutMs)) : undefined;
  let response;
  try {
    response = await send(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ challenge }),
      redirect: 'manual',
      signal
    });
  } catch {
    fail('ENVIRONMENT_UNAVAILABLE', 'Аттестация среды не получена');
  }
  if (!response || !Number.isSafeInteger(response.status)) fail('ENVIRONMENT_UNAVAILABLE', 'Аттестация среды не получена');
  if (response.status >= 300 && response.status < 400) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Редирект среды запрещён');
  if (response.status !== 200) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда ответила ' + response.status);
  const text = await responseText(response);
  let attestation;
  try { attestation = JSON.parse(text); }
  catch { fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестация среды не JSON'); }
  let attestationBody;
  try {
    attestationBody = verifyEnvironmentAttestation(trust, recordFields, attestation, { challenge, standPublicKey: publicKey });
  } catch (error) {
    if (error.code === 'TRUST_STORE_UNAVAILABLE') throw error;
    fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестация среды не подтверждена: ' + error.message);
  }
  return { record: recordFields, attestation: attestationBody };
}

export function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === 'EPERM') return true;
    return false;
  }
}

function runFile(command, args, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { windowsHide: true, timeout: timeoutMs }, (error, stdout) => {
      if (error) reject(error);
      else resolve(String(stdout));
    });
  });
}

function listenerPidsFromNetstat(text, port) {
  const pids = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$/i.exec(line);
    if (!match) continue;
    const host = match[1].toLowerCase();
    if (Number(match[2]) !== port) continue;
    if (host !== '127.0.0.1' && host !== '0.0.0.0' && host !== '[::]' && host !== '[::1]') continue;
    pids.add(Number(match[3]));
  }
  return pids;
}

function listenerPidsFromLsof(text) {
  const pids = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.startsWith('p')) continue;
    const pid = Number(line.slice(1));
    if (Number.isSafeInteger(pid) && pid > 0) pids.add(pid);
  }
  return pids;
}

export async function portOwnerPid(origin) {
  let parsed;
  try { parsed = new URL(origin); }
  catch { return null; }
  if (parsed.protocol !== 'http:') return null;
  if (parsed.hostname !== '127.0.0.1') return null;
  const port = parsed.port ? Number(parsed.port) : 80;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return null;
  let pids;
  try {
    if (process.platform === 'win32') pids = listenerPidsFromNetstat(await runFile('netstat', ['-ano', '-p', 'TCP']), port);
    else pids = listenerPidsFromLsof(await runFile('lsof', ['-nP', '-iTCP:' + port, '-sTCP:LISTEN', '-Fp']), port);
  } catch {
    return null;
  }
  if (pids.size !== 1) return null;
  return [...pids][0];
}

export async function attestLiveEnvironment({ trust, record, fetchImpl, timeoutMs, standPublicKey: publicKey } = {}) {
  const challenge = newChallenge();
  const attested = await attestEnvironment({ record, trust, challenge, fetchImpl, timeoutMs, standPublicKey: publicKey });
  const pid = attested.attestation.pid;
  if (!processAlive(pid)) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Процесс стенда не жив');
  const owner = await portOwnerPid(attested.attestation.origin);
  if (owner === null) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Владелец локального порта не определён');
  if (owner !== pid) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Порт обслуживает не аттестованный процесс');
  return { ...attested, portOwnerPid: owner };
}
