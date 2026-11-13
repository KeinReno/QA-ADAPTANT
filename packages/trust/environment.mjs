import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
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
  const body = verifyTrustedDocument(trust, record);
  exactKeys(record, recordKeys);
  assertRecordContent(record);
  if (typeof record.signature !== 'string' || !hex.test(record.signature)) fail('CONTRACT_INVALID', 'Подпись записи среды отсутствует');
  if (body.domain !== 'environment-record') fail('CONTRACT_INVALID', 'Документ не является записью среды');
  return markVerified(body);
}

function recordBody(trust, record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) fail('CONTRACT_INVALID', 'Запись среды не объект');
  if (typeof record.signature === 'string') return verifyEnvironmentRecord(trust, record);
  // Тело после loadEnvironmentRecord/verifyEnvironmentRecord: подпись уже проверена.
  if (!record[verifiedRecord]) fail('CONTRACT_INVALID', 'Неподписанная запись среды не проходила проверку подписи');
  exactKeys(record, unsignedRecordKeys);
  assertRecordContent(record);
  return markVerified({ ...record });
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

function environmentFile(trustRoot, environmentId) {
  assertId(environmentId, 'environmentId');
  const directory = path.resolve(trustRoot, 'environments');
  const file = path.resolve(directory, environmentId + '.json');
  if (path.dirname(file) !== directory) fail('CONTRACT_INVALID', 'Файл среды выходит из своего каталога');
  return { directory, file };
}

export function commitEnvironmentRecord(trust, trustRoot, record) {
  const body = verifyEnvironmentRecord(trust, record);
  const payload = JSON.stringify(record) + '\n';
  const { directory, file } = environmentFile(trustRoot, body.environmentId);
  fs.mkdirSync(directory, { recursive: true });
  let fd;
  try {
    fd = fs.openSync(file, 'wx');
  } catch (error) {
    if (error.code !== 'EEXIST') fail('TRUST_STORE_UNAVAILABLE', 'Имя записи среды не создано');
    let existing;
    try { existing = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { fail('CONTRACT_INVALID', 'Существующая запись среды не читается'); }
    const existingBody = verifyEnvironmentRecord(trust, existing);
    if (existingBody.environmentId !== body.environmentId) fail('CONTRACT_INVALID', 'Имя файла среды не совпало с документом');
    if (canonical(existing) !== canonical(record)) fail('CONTRACT_INVALID', 'environmentId уже закреплён с другим содержимым');
    return existing;
  }
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);
  } catch {
    fail('TRUST_STORE_UNAVAILABLE', 'Запись среды не сохранена');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  syncDirectory(directory);
  if (fs.readFileSync(file, 'utf8') !== payload) fail('TRUST_STORE_UNAVAILABLE', 'Закреплённая запись среды не сошлась при чтении');
  return record;
}

export function loadEnvironmentRecord(trust, trustRoot, environmentId) {
  const { file } = environmentFile(trustRoot, environmentId);
  if (!fs.existsSync(file)) fail('ENVIRONMENT_UNKNOWN', 'Среда отсутствует в реестре');
  let document;
  try { document = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('CONTRACT_INVALID', 'Запись среды не читается'); }
  const body = verifyEnvironmentRecord(trust, document);
  if (body.environmentId !== environmentId) fail('CONTRACT_INVALID', 'Имя файла среды не совпало с документом');
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
  if (attestation.signatureAlgorithm !== 'Ed25519' || typeof attestation.signature !== 'string' || !hex.test(attestation.signature)) fail('CONTRACT_INVALID', 'Подпись аттестации отсутствует');
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

function timeoutOf(value) {
  if (Number.isFinite(value) && value > 0) return Math.floor(value);
  return DEFAULT_ATTEST_TIMEOUT_MS;
}

async function responseText(response) {
  if (!response || typeof response.text !== 'function') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды не читается');
  let text;
  try { text = await response.text(); }
  catch { fail('ENVIRONMENT_UNAVAILABLE', 'Ответ среды оборван'); }
  if (typeof text !== 'string') fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды не текст');
  if (Buffer.byteLength(text, 'utf8') > maxAttestationBytes) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды слишком большой');
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
  const declared = response.headers && typeof response.headers.get === 'function' ? Number(response.headers.get('content-length')) : NaN;
  if (Number.isFinite(declared) && declared > maxAttestationBytes) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ среды слишком большой');
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
