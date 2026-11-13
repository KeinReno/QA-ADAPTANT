import fs from 'node:fs';
import path from 'node:path';
import { createPrivateKey, createPublicKey, randomUUID, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { digest, canonical, scenarioApprovalHash } from '../core/canonical.mjs';
import { validate, reasonCodes, validateVerdictCoverage } from '../contracts/index.mjs';
import { RunStore } from '../core/store.mjs';
import { verifyFrozenBundle } from '../core/bundle.mjs';
import { assertEvidenceRefs, assertTerminalEvidence } from '../core/evidence-policy.mjs';
import { publicKeyId, verifyTrustedDocument } from './identity.mjs';

export const DEFAULT_ANCHOR_BUDGET_MS = 5000;
export const MIN_ANCHOR_BUDGET_MS = 1;
export const MAX_ANCHOR_BUDGET_MS = 60000;
export const INCONCLUSIVE_MESSAGE = 'Анкер не получен в пределах бюджета: доказательство отсутствует';

const choiceKeys = ['anchorId', 'candidateSha256', 'createdAt', 'discardedCandidateSha256', 'domain', 'outcome', 'schemaVersion'];
const statementBodyKeys = [
  'anchorId', 'approvalId', 'candidateSha256', 'chainHead', 'domain', 'environmentGeneration', 'environmentId',
  'inputsHash', 'keyId', 'manifestSha256', 'publishedAt', 'reasonCode', 'runId', 'schemaVersion', 'verdict',
  // P0-01: заявление анкера связывается с подписанной аттестацией Verification.
  'verificationAttestationSha256', 'verificationKeyId'
];
export const VERIFICATION_ATTESTATION_SCHEMA_VERSION = '0.2.1';
export const VERIFICATION_ATTESTATION_DOMAIN = 'verification-attestation';
const VERIFICATION_RECORD_SCHEMA_VERSION = '0.2.0';
const VERIFICATION_RECORD_DOMAIN = 'verification-attestation-record';
const attestationBodyKeys = [
  'schemaVersion', 'domain', 'runId', 'manifestSha256', 'approvalId', 'candidateSha256', 'readSetSha256',
  'evidenceChainHead', 'decision', 'verificationKeyId', 'pid', 'startedAt', 'nonce', 'keyId'
];
const chainHeadKeys = ['envelopeSha256', 'sequence'];
const decisionKeys = ['reasonCode', 'verdict'];
const attestationKeys = [...attestationBodyKeys, 'signature', 'signatureAlgorithm'];
const verificationRecordKeys = ['schemaVersion', 'domain', 'runId', 'attestation', 'verificationPublicKey'];
const verificationPublicKeyKeys = ['algorithm', 'keyId', 'spki'];
const hex256 = /^[a-f0-9]{64}$/;
const outcomes = new Set(['anchor', 'budget-inconclusive', 'fail-without-anchor', 'inconclusive-without-anchor']);
const verdicts = new Set(['PASS', 'FAIL', 'BLOCKED', 'INCONCLUSIVE']);
const reasonCodeSet = new Set(reasonCodes);

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function exactKeys(value, keys, what) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('CONTRACT_INVALID', what + ' не является объектом');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('CONTRACT_INVALID', what + ' содержит поле вне контракта 0.2');
}

function assertId(value, what) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 160) fail('CONTRACT_INVALID', what + ': идентификатор вне границы 1…160');
  if (value !== path.win32.basename(value) || value !== path.posix.basename(value) || value.includes('..')) fail('CONTRACT_INVALID', what + ': идентификатор нельзя использовать как путь');
}

function assertHash(value, what) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('CONTRACT_INVALID', what + ' не является SHA-256');
}

function assertTime(value, what) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) || Number.isNaN(Date.parse(value))) fail('CONTRACT_INVALID', what + ' не является временем UTC');
}

function jsonBytes(value) {
  return Buffer.from(String(canonical(value)) + '\n', 'utf8');
}

// Publish immutable files only after a complete, flushed temporary file exists.
// Linking within the same directory gives CREATE_NEW semantics without exposing
// a partially written final path if the process is interrupted.
function atomicCreateNew(file, bytes, code, description) {
  const directory = path.dirname(file);
  fs.mkdirSync(directory, { recursive: true });
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.${randomUUID()}.tmp`);
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.linkSync(temp, file);
    let dirFd;
    try {
      dirFd = fs.openSync(directory, 'r');
      fs.fsyncSync(dirFd);
    } catch { /* Directory fsync is not supported on every platform. */ }
    finally { if (dirFd !== undefined) fs.closeSync(dirFd); }
    return true;
  } catch (error) {
    if (error.code === 'EEXIST') return false;
    fail(code, description);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temp); } catch {}
  }
}

// P0-01: домен verification-attestation 0.2.1. Аттестацию подписывает эфемерный ключ
// Verification, живущий только в памяти процесса. Публичный ключ передаётся отдельно,
// а привязка к прогону перепроверяется по durable evidence и записи подписанта.

function assertNonce(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('CONTRACT_INVALID', 'nonce аттестации не 32 байта hex');
}

function coercePublicKey(value) {
  if (!value) return null;
  try {
    if (typeof value === 'object' && typeof value.export === 'function' && value.type === 'public') return value;
    if (typeof value === 'string') {
      if (value.includes('BEGIN')) return createPublicKey(value);
      return createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return createPublicKey({ key: Buffer.from(value), format: 'der', type: 'spki' });
    if (typeof value === 'object' && typeof value.spki === 'string') return createPublicKey({ key: Buffer.from(value.spki, 'base64'), format: 'der', type: 'spki' });
  } catch { return null; }
  return null;
}

function coercePrivateKey(value) {
  if (!value) return null;
  try {
    if (typeof value === 'object' && typeof value.export === 'function' && value.type === 'private') return value;
    if (typeof value === 'string') {
      if (value.includes('BEGIN')) return createPrivateKey(value);
      return createPrivateKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'pkcs8' });
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return createPrivateKey({ key: Buffer.from(value), format: 'der', type: 'pkcs8' });
  } catch { return null; }
  return null;
}

export function verificationPublicKeyRecord(publicKey) {
  const key = coercePublicKey(publicKey);
  if (!key) fail('CONTRACT_INVALID', 'Публичный ключ Verification не разбирается');
  return { algorithm: 'Ed25519', keyId: publicKeyId(key), spki: key.export({ type: 'spki', format: 'der' }).toString('base64') };
}

function verificationPublicKeyObject(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) fail('VERIFICATION_ATTESTATION_INVALID', 'Запись публичного ключа Verification не объект');
  exactKeys(record, verificationPublicKeyKeys, 'verificationPublicKey');
  if (record.algorithm !== 'Ed25519') fail('VERIFICATION_ATTESTATION_INVALID', 'Алгоритм ключа Verification не Ed25519');
  assertHash(record.keyId, 'verificationPublicKey.keyId');
  const key = coercePublicKey(record.spki);
  if (!key) fail('VERIFICATION_ATTESTATION_INVALID', 'SPKI ключа Verification не разбирается');
  if (publicKeyId(key) !== record.keyId) fail('VERIFICATION_ATTESTATION_INVALID', 'keyId не совпал с публичным ключом Verification');
  return key;
}

// readSetSha256 — digest канонического массива пар {evidenceId, artifact.sha256} фактически
// выполненных независимых чтений (kind='independent-read') в порядке журнала.
export function computeReadSetSha256(items) {
  if (!Array.isArray(items)) throw new TypeError('Нужен журнал evidence');
  const entries = [];
  for (const item of items) {
    const envelope = item && item.envelope;
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) fail('CONTRACT_INVALID', 'Элемент журнала evidence не объект');
    if (envelope.kind !== 'independent-read') continue;
    assertId(envelope.evidenceId, 'evidenceId');
    assertHash(envelope.artifact?.sha256, 'artifact.sha256');
    entries.push({ evidenceId: envelope.evidenceId, artifactSha256: envelope.artifact.sha256 });
  }
  return digest(entries);
}

function assertAttestationContent(body) {
  if (body.schemaVersion !== VERIFICATION_ATTESTATION_SCHEMA_VERSION || body.domain !== VERIFICATION_ATTESTATION_DOMAIN) {
    fail('VERIFICATION_ATTESTATION_INVALID', 'Версия или домен аттестации Verification не 0.2.1/verification-attestation');
  }
  assertId(body.runId, 'runId аттестации');
  assertHash(body.manifestSha256, 'manifestSha256 аттестации');
  assertId(body.approvalId, 'approvalId аттестации');
  assertHash(body.candidateSha256, 'candidateSha256 аттестации');
  assertHash(body.readSetSha256, 'readSetSha256 аттестации');
  exactKeys(body.evidenceChainHead, chainHeadKeys, 'evidenceChainHead');
  if (!Number.isSafeInteger(body.evidenceChainHead.sequence) || body.evidenceChainHead.sequence < 1) fail('VERIFICATION_ATTESTATION_INVALID', 'evidenceChainHead.sequence вне границы');
  assertHash(body.evidenceChainHead.envelopeSha256, 'evidenceChainHead.envelopeSha256');
  exactKeys(body.decision, decisionKeys, 'decision аттестации');
  if (!verdicts.has(body.decision.verdict)) fail('VERIFICATION_ATTESTATION_INVALID', 'decision.verdict вне enum 0.1');
  if (!reasonCodeSet.has(body.decision.reasonCode)) fail('VERIFICATION_ATTESTATION_INVALID', 'decision.reasonCode вне enum 0.1');
  assertHash(body.verificationKeyId, 'verificationKeyId аттестации');
  assertHash(body.keyId, 'keyId аттестации');
  if (body.keyId !== body.verificationKeyId) fail('VERIFICATION_ATTESTATION_INVALID', 'keyId и verificationKeyId аттестации расходятся');
  if (!Number.isSafeInteger(body.pid) || body.pid < 1) fail('VERIFICATION_ATTESTATION_INVALID', 'pid аттестации не целое от 1');
  assertTime(body.startedAt, 'startedAt аттестации');
  assertNonce(body.nonce);
}

export function buildVerificationAttestation(privateKey, fields = {}) {
  const key = coercePrivateKey(privateKey);
  if (!key) fail('CONTRACT_INVALID', 'Приватный ключ Verification не разбирается');
  const allowed = new Set(['runId', 'manifestSha256', 'approvalId', 'candidateSha256', 'readSetSha256', 'evidenceChainHead', 'decision', 'pid', 'startedAt', 'nonce']);
  for (const name of Object.keys(fields)) if (!allowed.has(name)) fail('CONTRACT_INVALID', 'Поле аттестации вне контракта: ' + name);
  const verificationKeyId = publicKeyId(createPublicKey(key));
  const body = {
    schemaVersion: VERIFICATION_ATTESTATION_SCHEMA_VERSION,
    domain: VERIFICATION_ATTESTATION_DOMAIN,
    runId: fields.runId,
    manifestSha256: fields.manifestSha256,
    approvalId: fields.approvalId,
    candidateSha256: fields.candidateSha256,
    readSetSha256: fields.readSetSha256,
    evidenceChainHead: fields.evidenceChainHead,
    decision: fields.decision,
    verificationKeyId,
    pid: fields.pid,
    startedAt: fields.startedAt,
    nonce: fields.nonce,
    keyId: verificationKeyId
  };
  exactKeys(body, attestationBodyKeys, 'verification-attestation');
  assertAttestationContent(body);
  const signature = cryptoSign(null, Buffer.from(canonical(body), 'utf8'), key).toString('hex');
  return { ...body, signature, signatureAlgorithm: 'Ed25519' };
}

export function verifyVerificationAttestation(attestation, options = {}) {
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация Verification не объект');
  exactKeys(attestation, attestationKeys, 'verification-attestation');
  if (attestation.signatureAlgorithm !== 'Ed25519') fail('VERIFICATION_ATTESTATION_INVALID', 'Алгоритм подписи аттестации не Ed25519');
  if (typeof attestation.signature !== 'string' || !/^[a-f0-9]+$/i.test(attestation.signature)) fail('VERIFICATION_ATTESTATION_INVALID', 'Подпись аттестации отсутствует или не hex');
  const body = { ...attestation };
  delete body.signature;
  delete body.signatureAlgorithm;
  assertAttestationContent(body);
  const key = coercePublicKey(options.publicKey);
  if (!key) fail('VERIFICATION_ATTESTATION_INVALID', 'Публичный ключ Verification не передан');
  if (publicKeyId(key) !== body.verificationKeyId) fail('VERIFICATION_ATTESTATION_INVALID', 'verificationKeyId не совпал с публичным ключом Verification');
  if (options.expectedKeyId !== undefined && options.expectedKeyId !== body.verificationKeyId) fail('VERIFICATION_ATTESTATION_INVALID', 'verificationKeyId не совпал с зарегистрированным ключом');
  const ok = cryptoVerify(null, Buffer.from(canonical(body), 'utf8'), key, Buffer.from(attestation.signature, 'hex'));
  if (!ok) fail('VERIFICATION_ATTESTATION_INVALID', 'Подпись аттестации Verification не сошлась');
  return body;
}

export function verificationAttestationSha256(attestation) {
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) fail('CONTRACT_INVALID', 'Аттестация Verification не объект');
  return digest(attestation);
}

function verificationDirectory(trustRoot) {
  if (typeof trustRoot !== 'string' || trustRoot.length === 0) throw new TypeError('Нужен каталог trust root');
  return path.resolve(trustRoot, 'verification');
}

function verificationFile(trustRoot, runId) {
  assertId(runId, 'runId');
  const directory = verificationDirectory(trustRoot);
  const file = path.resolve(directory, runId + '.json');
  if (path.dirname(file) !== directory) fail('CONTRACT_INVALID', 'Файл аттестации выходит из каталога verification');
  return { directory, file };
}

function validateVerificationRecord(record, runId) {
  exactKeys(record, verificationRecordKeys, 'verification-attestation-record');
  if (record.schemaVersion !== VERIFICATION_RECORD_SCHEMA_VERSION || record.domain !== VERIFICATION_RECORD_DOMAIN) {
    fail('VERIFICATION_ATTESTATION_INVALID', 'Файл аттестации Verification не является записью 0.2.0');
  }
  assertId(record.runId, 'runId записи аттестации');
  if (record.runId !== runId) fail('VERIFICATION_ATTESTATION_INVALID', 'Запись аттестации относится к другому runId');
  const publicKey = verificationPublicKeyObject(record.verificationPublicKey);
  const body = verifyVerificationAttestation(record.attestation, { publicKey, expectedKeyId: record.verificationPublicKey.keyId });
  if (body.runId !== runId) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация относятся к другому runId');
  return { body, publicKey };
}

// Подписант — единственный писатель trustRoot/verification/<runId>.json.
export function publishVerificationRecord(trustRoot, { runId, attestation, verificationPublicKey } = {}) {
  const { directory, file } = verificationFile(trustRoot, runId);
  const publicKey = coercePublicKey(typeof verificationPublicKey === 'string' || Buffer.isBuffer(verificationPublicKey) ? verificationPublicKey : verificationPublicKey?.spki);
  if (!publicKey) fail('CONTRACT_INVALID', 'Публичный ключ Verification не передан');
  const expectedKeyId = publicKeyId(publicKey);
  const body = verifyVerificationAttestation(attestation, { publicKey, expectedKeyId });
  if (body.runId !== runId) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация относится к другому runId');
  const record = {
    schemaVersion: VERIFICATION_RECORD_SCHEMA_VERSION,
    domain: VERIFICATION_RECORD_DOMAIN,
    runId,
    attestation,
    verificationPublicKey: verificationPublicKeyRecord(publicKey)
  };
  const bytes = jsonBytes(record);
  if (fs.existsSync(file)) {
    let existing;
    try { existing = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { fail('ANCHOR_CONFLICT', 'Существующая аттестация Verification не читается и не заменяется'); }
    const previous = validateVerificationRecord(existing, runId);
    const sameAttestation = digest(existing.attestation) === digest(attestation);
    if (!sameAttestation || previous.body.verificationKeyId !== body.verificationKeyId) {
      fail('ANCHOR_CONFLICT', 'Для этого runId уже сохранена другая аттестация Verification');
    }
    return { record: existing, attestation: previous.body, created: false };
  }
  if (!atomicCreateNew(file, bytes, 'TRUST_STORE_UNAVAILABLE', 'Аттестация Verification не сохранена')) {
    return publishVerificationRecord(trustRoot, { runId, attestation, verificationPublicKey });
  }
  if (!fs.readFileSync(file).equals(bytes)) fail('INTEGRITY_ERROR', 'Повторное чтение аттестации Verification не сошлось');
  return { record, attestation: body, created: true };
}


function assertRunDir(runDir) {
  if (typeof runDir !== 'string' || runDir.length === 0) throw new TypeError('Нужен каталог прогона');
  if (!path.isAbsolute(runDir)) fail('CONTRACT_INVALID', 'Каталог прогона должен быть абсолютным');
}

function trustDir(runDir) { return path.join(runDir, 'trust'); }

function readManifestValue(runDir) {
  const file = path.join(runDir, 'manifest.json');
  if (!fs.existsSync(file)) fail('CONTRACT_INVALID', 'Замороженный манифест прогона отсутствует');
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('INTEGRITY_ERROR', 'Замороженный манифест прогона не читается'); }
}

function validateVerdictBody(candidate, what = 'candidate') {
  let parsed;
  try { parsed = validate('VerdictPolicy', candidate); }
  catch (error) { fail('CONTRACT_INVALID', what + ' не является VerdictPolicy 0.1: ' + error.message); }
  return parsed;
}

function validateChoice(choice) {
  exactKeys(choice, choiceKeys, 'terminal-choice');
  if (choice.schemaVersion !== '0.2.0' || choice.domain !== 'terminal-choice') fail('CONTRACT_INVALID', 'Версия или домен terminal-choice не 0.2');
  if (!outcomes.has(choice.outcome)) fail('CONTRACT_INVALID', 'Исход terminal-choice вне контракта');
  assertHash(choice.candidateSha256, 'candidateSha256');
  assertTime(choice.createdAt, 'createdAt');
  if (choice.outcome === 'anchor') {
    assertId(choice.anchorId, 'anchorId');
    if (choice.discardedCandidateSha256 !== null) fail('CONTRACT_INVALID', 'Исход anchor не отбрасывает candidate');
  } else if (choice.anchorId !== null) {
    fail('CONTRACT_INVALID', 'Исход без анкера не содержит anchorId');
  }
  if (choice.outcome === 'budget-inconclusive') {
    assertHash(choice.discardedCandidateSha256, 'discardedCandidateSha256');
  } else if (choice.discardedCandidateSha256 !== null) {
    fail('CONTRACT_INVALID', 'Исход без отброшенного PASS не содержит discardedCandidateSha256');
  }
  return choice;
}

function validateStatementBody(body) {
  exactKeys(body, statementBodyKeys, 'anchor-statement');
  if (body.schemaVersion !== '0.2.0' || body.domain !== 'anchor-statement') fail('CONTRACT_INVALID', 'Версия или домен анкера не 0.2');
  assertId(body.anchorId, 'anchorId');
  assertId(body.runId, 'runId');
  assertId(body.approvalId, 'approvalId');
  assertId(body.environmentId, 'environmentId');
  assertHash(body.manifestSha256, 'manifestSha256');
  assertHash(body.candidateSha256, 'candidateSha256');
  assertHash(body.inputsHash, 'inputsHash');
  assertHash(body.keyId, 'keyId');
  assertHash(body.verificationAttestationSha256, 'verificationAttestationSha256');
  assertHash(body.verificationKeyId, 'verificationKeyId');
  assertTime(body.publishedAt, 'publishedAt');
  if (!verdicts.has(body.verdict)) fail('CONTRACT_INVALID', 'Вердикт анкера вне enum 0.1');
  if (!reasonCodeSet.has(body.reasonCode)) fail('CONTRACT_INVALID', 'reasonCode анкера вне enum 0.1');
  if (!Number.isSafeInteger(body.environmentGeneration) || body.environmentGeneration < 1) fail('CONTRACT_INVALID', 'Поколение среды анкера не целое');
  exactKeys(body.chainHead, ['envelopeSha256', 'sequence'], 'chainHead');
  if (!Number.isSafeInteger(body.chainHead.sequence) || body.chainHead.sequence < 0) fail('CONTRACT_INVALID', 'sequence цепочки вне границы');
  assertHash(body.chainHead.envelopeSha256, 'envelopeSha256');
  return body;
}

export function readVerificationRecord(trustRoot, runId) {
  const { file } = verificationFile(trustRoot, runId);
  if (!fs.existsSync(file)) return null;
  let record;
  try { record = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('VERIFICATION_ATTESTATION_INVALID', 'Запись аттестации Verification не читается'); }
  const validated = validateVerificationRecord(record, runId);
  return {
    record,
    attestation: record.attestation,
    attestationBody: validated.body,
    verificationPublicKey: record.verificationPublicKey,
    attestationSha256: digest(record.attestation)
  };
}

// Наблюдатель и подписант проверяют аттестацию одинаково: файл в trust root, подпись,
// привязка keyId к заявлению анкера, runId/manifest/candidate и пересчёт readSet по durable evidence.
export function assertVerificationAttestation({ trustRoot, runId, manifestSha256, approvalId, candidateSha256, readSetSha256, evidenceChainHead, decision, statement } = {}) {
  if (!statement || typeof statement !== 'object') fail('CONTRACT_INVALID', 'Нужно заявление анкера');
  assertHash(statement.verificationAttestationSha256, 'verificationAttestationSha256');
  assertHash(statement.verificationKeyId, 'verificationKeyId');
  const loaded = readVerificationRecord(trustRoot, runId);
  if (!loaded) fail('VERIFICATION_ATTESTATION_MISSING', 'Аттестация Verification для этого прогона отсутствует');
  if (loaded.attestationSha256 !== statement.verificationAttestationSha256) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация Verification не совпала с заявлением анкера');
  if (loaded.attestationBody.verificationKeyId !== statement.verificationKeyId) fail('VERIFICATION_ATTESTATION_INVALID', 'verificationKeyId анкера и аттестации расходятся');
  if (loaded.attestationBody.runId !== runId) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация относится к другому runId');
  if (manifestSha256 !== undefined && loaded.attestationBody.manifestSha256 !== manifestSha256) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация относится к другому манифесту');
  if (candidateSha256 !== undefined && loaded.attestationBody.candidateSha256 !== candidateSha256) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация подписана на другой candidateSha256');
  if (readSetSha256 !== undefined && loaded.attestationBody.readSetSha256 !== readSetSha256) fail('VERIFICATION_ATTESTATION_INVALID', 'readSetSha256 не совпал с durable evidence');
  if (approvalId !== undefined && loaded.attestationBody.approvalId !== approvalId) fail('VERIFICATION_ATTESTATION_INVALID', 'Аттестация относится к другому approvalId');
  if (evidenceChainHead !== undefined) {
    if (loaded.attestationBody.evidenceChainHead?.sequence !== evidenceChainHead?.sequence ||
        loaded.attestationBody.evidenceChainHead?.envelopeSha256 !== evidenceChainHead?.envelopeSha256) {
      fail('VERIFICATION_ATTESTATION_INVALID', 'evidenceChainHead не совпал с головой цепочки');
    }
  }
  if (decision !== undefined) {
    if (loaded.attestationBody.decision?.verdict !== decision?.verdict ||
        loaded.attestationBody.decision?.reasonCode !== decision?.reasonCode) {
      fail('VERIFICATION_ATTESTATION_INVALID', 'decision аттестации не совпал с candidate');
    }
  }
  return { attestation: loaded.attestationBody, attestationSha256: loaded.attestationSha256, verificationKeyId: loaded.attestationBody.verificationKeyId };
}

export function loadAnchorBudgetMs(trustRoot) {
  if (typeof trustRoot !== 'string' || trustRoot.length === 0) throw new TypeError('Нужен каталог trust root');
  const file = path.join(trustRoot, 'profile.json');
  if (!fs.existsSync(file)) return DEFAULT_ANCHOR_BUDGET_MS;
  let profile;
  try { profile = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('TRUST_STORE_UNAVAILABLE', 'Профиль trust root не читается'); }
  if (!profile || profile.schemaVersion !== '0.2.0' || profile.domain !== 'trust-profile') fail('TRUST_STORE_UNAVAILABLE', 'Профиль trust root не является профилем 0.2');
  if (!Number.isSafeInteger(profile.anchorBudgetMs) || profile.anchorBudgetMs < MIN_ANCHOR_BUDGET_MS || profile.anchorBudgetMs > MAX_ANCHOR_BUDGET_MS) {
    fail('TRUST_STORE_UNAVAILABLE', 'anchorBudgetMs вне диапазона 1…60000');
  }
  return profile.anchorBudgetMs;
}

export function buildCandidate({ frozen, verdict, reasonCode, message, checks, completedAt, ownershipVerified, integrityVerified } = {}) {
  if (!frozen || !frozen.manifest || typeof frozen.manifestSha256 !== 'string') fail('CONTRACT_INVALID', 'Нужен замороженный bundle прогона');
  if (!verdicts.has(verdict)) fail('CONTRACT_INVALID', 'Вердикт candidate вне enum 0.1');
  if (!reasonCodeSet.has(reasonCode)) fail('CONTRACT_INVALID', 'reasonCode candidate вне enum 0.1');
  const body = {
    schemaVersion: '0.1.0',
    runId: frozen.manifest.runId,
    manifestSha256: frozen.manifestSha256,
    verdict,
    reasonCode,
    message,
    checks: checks || frozen.operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] })),
    ownershipVerified: ownershipVerified === undefined ? ['PASS', 'FAIL'].includes(verdict) : Boolean(ownershipVerified),
    integrityVerified: integrityVerified === undefined ? true : Boolean(integrityVerified),
    completedAt: completedAt || new Date().toISOString()
  };
  return validateVerdictBody(body);
}

export function buildInconclusiveCandidate({ frozen, completedAt } = {}) {
  return buildCandidate({
    frozen,
    verdict: 'INCONCLUSIVE',
    reasonCode: 'EVIDENCE_MISSING',
    message: INCONCLUSIVE_MESSAGE,
    checks: frozen.operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] })),
    completedAt,
    ownershipVerified: false,
    integrityVerified: true
  });
}

function candidateBodyFile(runDir, candidateSha256) {
  assertHash(candidateSha256, 'candidateSha256');
  const directory = path.resolve(trustDir(runDir), 'candidates');
  const file = path.resolve(directory, candidateSha256 + '.json');
  if (path.dirname(file) !== directory) fail('CONTRACT_INVALID', 'Файл candidate выходит из своего каталога');
  return { directory, file };
}

export function readCandidateBody(runDir, candidateSha256) {
  assertRunDir(runDir);
  const { file } = candidateBodyFile(runDir, candidateSha256);
  if (!fs.existsSync(file)) return null;
  let raw;
  try { raw = fs.readFileSync(file); }
  catch { fail('INTEGRITY_ERROR', 'Тело candidate не читается'); }
  let candidate;
  try { candidate = JSON.parse(raw.toString('utf8')); }
  catch { fail('INTEGRITY_ERROR', 'Тело candidate не разбирается'); }
  const validated = validateVerdictBody(candidate);
  if (digest(validated) !== candidateSha256) fail('INTEGRITY_ERROR', 'Имя тела candidate не совпало с его digest');
  if (!raw.equals(jsonBytes(validated))) fail('INTEGRITY_ERROR', 'Байты тела candidate не канонические');
  return { candidate: validated, candidateSha256, bytes: jsonBytes(validated) };
}

// Тело каждого опубликованного кандидата лежит под своим хешем; выбор исхода ссылается на него.
export function publishCandidateBody(runDir, candidate) {
  assertRunDir(runDir);
  const validated = validateVerdictBody(candidate);
  const candidateSha256 = digest(validated);
  const { directory, file } = candidateBodyFile(runDir, candidateSha256);
  const bytes = jsonBytes(validated);
  if (!atomicCreateNew(file, bytes, 'CANDIDATE_INCOMPLETE', 'Тело candidate не создано')) {
    const existing = readCandidateBody(runDir, candidateSha256);
    if (existing) return { candidateSha256, created: false };
    fail('CANDIDATE_INCOMPLETE', 'Занятое имя тела candidate не подтвердилось');
  }
  if (!fs.readFileSync(file).equals(bytes)) fail('INTEGRITY_ERROR', 'Повторное чтение тела candidate не сошлось');
  return { candidateSha256, created: true };
}

export function buildBudgetInconclusiveChoice({ runDir, frozen, createdAt } = {}) {
  assertRunDir(runDir);
  const existing = readCandidate(runDir);
  if (!existing) fail('CONTRACT_INVALID', 'Нет durable PASS-candidate, который можно отбросить по бюджету');
  if (existing.candidate.verdict !== 'PASS') fail('CONTRACT_INVALID', 'Бюджет анкера относится только к PASS-candidate');
  const at = createdAt || new Date().toISOString();
  const candidate = buildInconclusiveCandidate({ frozen, completedAt: at });
  publishCandidateBody(runDir, candidate);
  const choice = validateChoice({
    schemaVersion: '0.2.0',
    domain: 'terminal-choice',
    outcome: 'budget-inconclusive',
    candidateSha256: digest(candidate),
    discardedCandidateSha256: existing.candidateSha256,
    anchorId: null,
    createdAt: at
  });
  return { candidate, choice, candidateSha256: digest(candidate) };
}

export function publishBudgetInconclusiveOutcome({ runDir, frozen, createdAt } = {}) {
  assertRunDir(runDir);
  const existingChoice = readTerminalChoice(runDir);
  if (existingChoice) return { choice: existingChoice, created: false, candidateSha256: existingChoice.candidateSha256 };
  const { candidate, choice } = buildBudgetInconclusiveChoice({ runDir, frozen, createdAt });
  const published = publishTerminalChoice(runDir, choice);
  return { candidate, choice: published.choice, created: published.created, candidateSha256: digest(candidate) };
}

export function readCandidate(runDir) {
  assertRunDir(runDir);
  const file = path.join(trustDir(runDir), 'candidate.json');
  if (!fs.existsSync(file)) return null;
  let raw;
  try { raw = fs.readFileSync(file); }
  catch { fail('CANDIDATE_INCOMPLETE', 'Durable candidate не читается'); }
  let candidate;
  try { candidate = JSON.parse(raw.toString('utf8')); }
  catch { fail('CANDIDATE_INCOMPLETE', 'Durable candidate не разбирается'); }
  const validated = validateVerdictBody(candidate);
  const expected = jsonBytes(validated);
  if (!raw.equals(expected)) fail('INTEGRITY_ERROR', 'Байты durable candidate не совпадают с каноническим телом');
  return { candidate: validated, candidateSha256: digest(validated), bytes: expected };
}

export function publishCandidate(runDir, candidate) {
  assertRunDir(runDir);
  const validated = validateVerdictBody(candidate);
  const manifest = readManifestValue(runDir);
  if (validated.runId !== manifest.runId || validated.manifestSha256 !== digest(manifest)) fail('CONTRACT_INVALID', 'Candidate не принадлежит этому прогону');
  const candidateSha256 = digest(validated);
  const directory = trustDir(runDir);
  const file = path.join(directory, 'candidate.json');
  const bytes = jsonBytes(validated);
  if (!atomicCreateNew(file, bytes, 'CANDIDATE_INCOMPLETE', 'Durable candidate не создан')) {
    const existing = readCandidate(runDir);
    if (existing && existing.candidateSha256 === candidateSha256) {
      publishCandidateBody(runDir, validated);
      return { candidateSha256, created: false };
    }
    fail('CANDIDATE_CONFLICT', 'Durable candidate уже занят другим телом и не заменяется');
  }
  const reread = fs.readFileSync(file);
  if (!reread.equals(bytes)) fail('INTEGRITY_ERROR', 'Повторное чтение durable candidate не сошлось');
  publishCandidateBody(runDir, validated);
  return { candidateSha256, created: true };
}

export function buildTerminalChoice({ outcome, candidateSha256, discardedCandidateSha256 = null, anchorId = null, createdAt } = {}) {
  return validateChoice({
    schemaVersion: '0.2.0',
    domain: 'terminal-choice',
    outcome,
    candidateSha256,
    discardedCandidateSha256,
    anchorId,
    createdAt: createdAt || new Date().toISOString()
  });
}

export function readTerminalChoice(runDir) {
  assertRunDir(runDir);
  const file = path.join(trustDir(runDir), 'terminal-choice.json');
  if (!fs.existsSync(file)) return null;
  let raw;
  try { raw = fs.readFileSync(file); }
  catch { fail('TERMINAL_CHOICE_INCOMPLETE', 'terminal-choice не читается'); }
  let choice;
  try { choice = JSON.parse(raw.toString('utf8')); }
  catch { fail('TERMINAL_CHOICE_INCOMPLETE', 'terminal-choice записан не полностью'); }
  const validated = validateChoice(choice);
  if (!raw.equals(jsonBytes(validated))) fail('TERMINAL_CHOICE_INCOMPLETE', 'Байты terminal-choice не совпадают с каноническим телом');
  return validated;
}

export function publishTerminalChoice(runDir, choice) {
  assertRunDir(runDir);
  const validated = validateChoice(choice);
  const directory = trustDir(runDir);
  const file = path.join(directory, 'terminal-choice.json');
  const bytes = jsonBytes(validated);
  if (!atomicCreateNew(file, bytes, 'TERMINAL_CHOICE_INCOMPLETE', 'terminal-choice не создан')) {
    const existing = readTerminalChoice(runDir);
    if (!existing) fail('TERMINAL_CHOICE_INCOMPLETE', 'Занятое имя terminal-choice не подтвердилось');
    return { choice: existing, created: false };
  }
  const reread = fs.readFileSync(file);
  if (!reread.equals(bytes)) fail('INTEGRITY_ERROR', 'Повторное чтение terminal-choice не сошлось');
  return { choice: validated, created: true };
}

export function evidenceChainHead(store, runDir) {
  if (!store || typeof store.readEvidence !== 'function') throw new TypeError('Нужен RunStore');
  assertRunDir(runDir);
  const items = store.readEvidence(runDir);
  if (!items.length) return null;
  const last = items.at(-1).envelope;
  return { sequence: last.sequence, envelopeSha256: digest(last) };
}

function resolveChosenCandidate({ runDir, frozen, choice }) {
  const chosen = readCandidateBody(runDir, choice.candidateSha256);
  if (!chosen) {
    if (choice.outcome === 'anchor') fail('ANCHOR_MISSING', 'Выбран исход anchor, но тело выбранного candidate отсутствует');
    fail('EVIDENCE_MISSING', 'Тело выбранного candidate отсутствует; байты verdict не пересчитываются');
  }
  if (choice.outcome === 'budget-inconclusive') {
    if (chosen.candidate.verdict !== 'INCONCLUSIVE' || chosen.candidate.reasonCode !== 'EVIDENCE_MISSING') fail('INTEGRITY_ERROR', 'Выбор budget-inconclusive не указывает на INCONCLUSIVE/EVIDENCE_MISSING');
    if (choice.discardedCandidateSha256 !== null) {
      const discarded = readCandidate(runDir);
      if (!discarded) fail('INTEGRITY_ERROR', 'Отброшенный PASS-candidate исчез из каталога прогона');
      if (discarded.candidateSha256 !== choice.discardedCandidateSha256) fail('INTEGRITY_ERROR', 'Отброшенный PASS-candidate не совпал с выбором');
      const discardedBody = readCandidateBody(runDir, choice.discardedCandidateSha256);
      if (!discardedBody) fail('INTEGRITY_ERROR', 'Тело отброшенного PASS-candidate исчезло');
    }
    return chosen.candidate;
  }
  const business = readCandidate(runDir);
  if (!business || business.candidateSha256 !== choice.candidateSha256) fail('INTEGRITY_ERROR', 'Выбранный candidate не совпал с durable бизнес-candidate');
  if (choice.outcome === 'fail-without-anchor' && chosen.candidate.verdict !== 'FAIL') fail('CONTRACT_INVALID', 'Исход fail-without-anchor относится только к бизнес-FAIL');
  if (choice.outcome === 'inconclusive-without-anchor' && chosen.candidate.verdict !== 'INCONCLUSIVE') fail('CONTRACT_INVALID', 'Исход inconclusive-without-anchor относится только к бизнес-INCONCLUSIVE');
  return chosen.candidate;
}

// D-01: исход anchor публикуется только при годном анкере на выбранный candidate.
// Проверка выполняется до записи verdict и повторно в ветке уже записанного verdict.
function assertAnchoredPublication({ store, runDir, frozen, trust, trustRoot, choice, verdictItem = null }) {
  if (!trust || !trustRoot) fail('ANCHOR_MISSING', 'Для исхода anchor нужны trust и trustRoot: анкер не проверен');
  const statement = loadAnchor(trustRoot, choice.anchorId);
  const body = verifyAnchorStatement(trust, statement);
  if (body.anchorId !== choice.anchorId) fail('ANCHOR_CONFLICT', 'Заявление анкера не совпало с anchorId выбора');
  if (body.candidateSha256 !== choice.candidateSha256) fail('ANCHOR_CONFLICT', 'Анкер подписан на другой candidateSha256');
  if (body.runId !== frozen.manifest.runId || body.manifestSha256 !== frozen.manifestSha256) fail('ANCHOR_CONFLICT', 'Анкер относится к другому прогону или манифесту');
  if (body.verdict !== 'PASS' && body.verdict !== 'FAIL') fail('ANCHOR_CONFLICT', 'Исход anchor относится только к PASS или FAIL');
  const chosen = readCandidateBody(runDir, choice.candidateSha256);
  if (!chosen) fail('EVIDENCE_MISSING', 'Тело выбранного candidate отсутствует; verdict не пишется');
  if (chosen.candidate.verdict !== body.verdict || chosen.candidate.reasonCode !== body.reasonCode) fail('ANCHOR_CONFLICT', 'Анкер относится к другому вердикту candidate');
  const binding = inspectEvidenceBinding({ trust, trustRoot, runDir, approvalId: body.approvalId, mode: verdictItem ? 'terminal' : 'pre-verdict' });
  verifyAnchorAgainstBinding({ trustRoot, trust, statement: body, binding, verdictItem });
  return body;
}

function assertUnanchoredPublication({ runDir, choice, artifact }) {
  const chosen = readCandidateBody(runDir, choice.candidateSha256);
  if (!chosen) fail('EVIDENCE_MISSING', 'Тело выбранного candidate отсутствует; verdict не пересчитывается');
  if (choice.outcome === 'fail-without-anchor' && (chosen.candidate.verdict !== 'FAIL' || artifact.verdict !== 'FAIL')) fail('INTEGRITY_ERROR', 'Исход fail-without-anchor не указывает на FAIL');
  if (choice.outcome === 'inconclusive-without-anchor' && (chosen.candidate.verdict !== 'INCONCLUSIVE' || artifact.verdict !== 'INCONCLUSIVE')) fail('INTEGRITY_ERROR', 'Исход inconclusive-without-anchor не указывает на INCONCLUSIVE');
  if (choice.outcome === 'budget-inconclusive' && (chosen.candidate.verdict !== 'INCONCLUSIVE' || chosen.candidate.reasonCode !== 'EVIDENCE_MISSING' || artifact.reasonCode !== 'EVIDENCE_MISSING')) fail('INTEGRITY_ERROR', 'Исход budget-inconclusive не указывает на INCONCLUSIVE/EVIDENCE_MISSING');
  return chosen.candidate;
}

export function publishTerminalVerdict({ store, runDir, frozen, trust = null, trustRoot = null } = {}) {
  if (!store || !frozen || !frozen.manifest || !frozen.scenario || !frozen.fixture) throw new TypeError('Нужны store, runDir и замороженный bundle');
  assertRunDir(runDir);
  const choice = readTerminalChoice(runDir);
  if (!choice) fail('PUBLICATION_PENDING', 'Выбор исхода ещё не сделан; терминальный verdict не пишется');
  const items = store.readEvidence(runDir);
  const existing = items.filter(item => item.envelope.kind === 'verdict');
  if (existing.length > 1) fail('INTEGRITY_ERROR', 'В журнале больше одного терминального verdict');
  if (existing.length === 1) {
    const artifact = existing[0].artifact;
    if (digest(artifact) !== choice.candidateSha256) fail('INTEGRITY_ERROR', 'Терминальный verdict не совпал с выбором исхода');
    if (choice.outcome === 'anchor') assertAnchoredPublication({ store, runDir, frozen, trust, trustRoot, choice, verdictItem: existing[0] });
    else assertUnanchoredPublication({ runDir, choice, artifact });
    return { verdict: artifact, evidenceId: existing[0].envelope.evidenceId, created: false };
  }
  if (choice.outcome === 'anchor') assertAnchoredPublication({ store, runDir, frozen, trust, trustRoot, choice, verdictItem: null });
  const verdict = resolveChosenCandidate({ runDir, frozen, choice });
  const final = store.appendEvidence(runDir, {
    runId: frozen.manifest.runId,
    manifestSha256: frozen.manifestSha256,
    fixtureId: frozen.fixture.fixtureId,
    stepId: frozen.scenario.nodes.at(-1).id,
    producer: 'verification',
    kind: 'verdict',
    artifact: verdict,
    parentEvidenceIds: items.map(item => item.envelope.evidenceId),
    checkIds: verdict.checks.filter(check => ['SATISFIED', 'VIOLATED'].includes(check.status)).map(check => check.id)
  });
  if (digest(verdict) !== choice.candidateSha256) fail('INTEGRITY_ERROR', 'Записанный verdict не совпал с выбранным candidate');
  return { verdict, evidenceId: final.evidenceId, created: true };
}

export function verifyAnchorStatement(trust, statement) {
  if (!statement || typeof statement !== 'object' || Array.isArray(statement)) fail('CONTRACT_INVALID', 'Заявление анкера не объект');
  let body;
  try { body = verifyTrustedDocument(trust, statement); }
  catch (error) {
    if (error.code === 'TRUST_STORE_UNAVAILABLE') throw error;
    fail('ANCHOR_SIGNATURE_INVALID', error.message);
  }
  return validateStatementBody(body);
}

// D-06: возвращает только разобранный файл; вызывающий обязан проверить его verifyAnchorStatement.
export function loadAnchor(trustRoot, anchorId) {
  if (typeof trustRoot !== 'string' || trustRoot.length === 0) throw new TypeError('Нужен каталог trust root');
  assertId(anchorId, 'anchorId');
  const directory = path.resolve(trustRoot, 'anchors');
  const file = path.resolve(directory, anchorId + '.json');
  if (path.dirname(file) !== directory) fail('CONTRACT_INVALID', 'Файл анкера выходит из своего каталога');
  if (!fs.existsSync(file)) fail('ANCHOR_MISSING', 'Заявление анкера отсутствует');
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('ANCHOR_SIGNATURE_INVALID', 'Заявление анкера не читается'); }
}

function listAnchors(trustRoot) {
  const directory = path.resolve(trustRoot, 'anchors');
  if (!fs.existsSync(directory)) return [];
  const result = [];
  for (const name of fs.readdirSync(directory).filter(item => item.endsWith('.json')).sort()) {
    try { result.push(JSON.parse(fs.readFileSync(path.join(directory, name), 'utf8'))); }
    catch { /* повреждённый файл не становится годным анкером и не переписывается */ }
  }
  return result;
}

// D-05: ANCHOR_UNLINKED сообщается только по заявлению с годной подписью anchor-signer.
function findUnlinkedAnchor(trust, trustRoot, runId, candidateSha256) {
  if (!candidateSha256 || !trust) return null;
  for (const anchor of listAnchors(trustRoot)) {
    let body;
    try { body = verifyAnchorStatement(trust, anchor); }
    catch { continue; }
    if (body.runId === runId && body.candidateSha256 === candidateSha256) return body.anchorId || null;
  }
  return null;
}

function reducedEffects(effects) {
  return effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals }));
}

function assertSnapshots(store, runDir, frozen, approval, consumption) {
  if (frozen.operation.id !== approval.operationId || frozen.operation.version !== approval.operationVersion || digest(frozen.operation) !== approval.operationSha256) fail('APPROVAL_MISMATCH', 'Операция не совпала с approval');
  if (digest(frozen.operation.inputs) !== approval.approvedInputsHash) fail('APPROVAL_MISMATCH', 'Входы не совпали с approval');
  if (scenarioApprovalHash(frozen.scenario) !== approval.scenarioContentSha256) fail('APPROVAL_MISMATCH', 'Сценарий не совпал с approval');
  if (frozen.fixture.fixtureId !== approval.fixtureId) fail('APPROVAL_MISMATCH', 'Fixture не совпал с approval');
  if (frozen.manifest.environment.id !== approval.targetEnvironmentId) fail('APPROVAL_MISMATCH', 'Среда не совпала с approval');
  if (digest(reducedEffects(frozen.operation.effects)) !== digest(approval.allowedEffects)) fail('APPROVAL_MISMATCH', 'Эффекты не совпали с approval');
  if (consumption.runId !== frozen.manifest.runId) fail('APPROVAL_MISMATCH', 'Расход связан с другим runId');
  if (consumption.inputsHash !== approval.approvedInputsHash) fail('APPROVAL_MISMATCH', 'Расход не связан с хешем входов approval');
  if (consumption.environmentGeneration !== approval.environmentGeneration) fail('APPROVAL_MISMATCH', 'Расход не связан с поколением approval');
  void store;
  void runDir;
}

function readApprovalForSigner(trust, trustRoot, approvalId) {
  assertId(approvalId, 'approvalId');
  const file = path.join(path.resolve(trustRoot, 'approvals'), approvalId + '.json');
  if (!fs.existsSync(file)) fail('APPROVAL_MISSING', 'Закреплённый approval отсутствует');
  let document;
  try { document = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('APPROVAL_SIGNATURE_INVALID', 'Закреплённый approval не читается'); }
  try { verifyTrustedDocument(trust, document); }
  catch (error) { if (error.code === 'TRUST_STORE_UNAVAILABLE') throw error; fail('APPROVAL_SIGNATURE_INVALID', error.message); }
  if (document.schemaVersion !== '0.2.0' || document.domain !== 'approval' || document.approvalId !== approvalId) fail('APPROVAL_SIGNATURE_INVALID', 'Документ не является approval этого идентификатора');
  if (document.targetResource?.method !== 'POST' || document.targetResource?.path !== '/records') fail('APPROVAL_MISMATCH', 'Ресурс approval вне локального контракта');
  assertHash(document.approvedInputsHash, 'approvedInputsHash');
  assertHash(document.operationSha256, 'operationSha256');
  assertHash(document.scenarioContentSha256, 'scenarioContentSha256');
  assertId(document.fixtureId, 'fixtureId');
  assertId(document.targetEnvironmentId, 'targetEnvironmentId');
  if (!Number.isSafeInteger(document.environmentGeneration) || document.environmentGeneration < 1) fail('CONTRACT_INVALID', 'Поколение approval не целое');
  return document;
}

function readConsumptionForSigner(trustRoot, approvalId) {
  const file = path.join(path.resolve(trustRoot, 'consumption'), approvalId + '.json');
  if (!fs.existsSync(file)) fail('CONSUMPTION_INCOMPLETE', 'Файл расхода отсутствует');
  let value;
  try { value = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('CONSUMPTION_INCOMPLETE', 'Файл расхода не разбирается'); }
  const keys = ['approvalId', 'consumedAt', 'decisionId', 'environmentGeneration', 'inputsHash', 'runId', 'bodySha256'];
  exactKeys(value, keys, 'consumption');
  const body = { approvalId: value.approvalId, runId: value.runId, decisionId: value.decisionId, inputsHash: value.inputsHash, environmentGeneration: value.environmentGeneration, consumedAt: value.consumedAt };
  if (digest(body) !== value.bodySha256) fail('CONSUMPTION_INCOMPLETE', 'bodySha256 расхода не сходится');
  if (value.approvalId !== approvalId) fail('CONSUMPTION_INCOMPLETE', 'Расход относится к другому approvalId');
  assertId(body.runId, 'runId'); assertId(body.decisionId, 'decisionId');
  assertHash(body.inputsHash, 'inputsHash'); assertTime(body.consumedAt, 'consumedAt');
  if (!Number.isSafeInteger(body.environmentGeneration)) fail('CONSUMPTION_INCOMPLETE', 'Поколение расхода не целое');
  return body;
}

function readRevocationForSigner(trust, trustRoot, approvalId) {
  const file = path.join(path.resolve(trustRoot, 'revocations'), approvalId + '.json');
  if (!fs.existsSync(file)) return null;
  let document;
  try { document = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { fail('APPROVAL_SIGNATURE_INVALID', 'Файл отзыва не читается'); }
  try { verifyTrustedDocument(trust, document); }
  catch (error) { if (error.code === 'TRUST_STORE_UNAVAILABLE') throw error; fail('APPROVAL_SIGNATURE_INVALID', error.message); }
  if (document.domain !== 'revocation' || document.approvalId !== approvalId) fail('APPROVAL_SIGNATURE_INVALID', 'Отзыв не относится к этому approval');
  return document;
}

// Подписант и наблюдатель читают связку сами: хеш или verdict от вызывающего здесь не принимается.
export function inspectEvidenceBinding({ trust, trustRoot, runDir, approvalId, mode = 'pre-verdict', candidate: suppliedCandidate = null } = {}) {
  assertRunDir(runDir);
  if (!trustRoot) throw new TypeError('Нужен каталог trust root');
  if (mode !== 'pre-verdict' && mode !== 'terminal') throw new TypeError('Неизвестный режим проверки связки');
  const store = new RunStore(path.dirname(path.dirname(path.resolve(runDir))));
  const frozen = verifyFrozenBundle(store, runDir);
  const approval = readApprovalForSigner(trust, trustRoot, approvalId);
  const consumption = readConsumptionForSigner(trustRoot, approvalId);
  const revocation = readRevocationForSigner(trust, trustRoot, approvalId);
  if (revocation && Date.parse(revocation.revokedAt) <= Date.parse(consumption.consumedAt)) fail('APPROVAL_REVOKED', 'Отзыв подтверждён до расхода approval');
  if (Date.parse(consumption.consumedAt) < Date.parse(approval.issuedAt) || Date.parse(consumption.consumedAt) >= Date.parse(approval.expiresAt)) fail('CONSUMPTION_INCOMPLETE', 'Расход не укладывается в срок approval');
  assertSnapshots(store, runDir, frozen, approval, consumption);
  const candidateRecord = suppliedCandidate
    ? { candidate: validateVerdictBody(suppliedCandidate), candidateSha256: digest(validateVerdictBody(suppliedCandidate)) }
    : readCandidate(runDir);
  if (!candidateRecord) fail('ANCHOR_BINDING_REJECTED', 'Durable candidate отсутствует');
  if (candidateRecord.candidate.runId !== frozen.manifest.runId || candidateRecord.candidate.manifestSha256 !== frozen.manifestSha256) fail('APPROVAL_MISMATCH', 'Candidate принадлежит другому прогону');
  const items = store.readEvidence(runDir);
  const found = items.filter(item => item.envelope.kind === 'verdict');
  let chainHead;
  if (mode === 'pre-verdict') {
    if (found.length) fail('PUBLICATION_PENDING', 'В evidence уже есть терминальный verdict');
    chainHead = items.length ? { sequence: items.at(-1).envelope.sequence, envelopeSha256: digest(items.at(-1).envelope) } : null;
  } else {
    if (found.length > 1) fail('INTEGRITY_ERROR', 'В журнале больше одного verdict');
    if (found.length === 1) {
      const verdictItem = found[0];
      if (digest(verdictItem.artifact) !== candidateRecord.candidateSha256) fail('INTEGRITY_ERROR', 'Байты verdict не совпадают с durable candidate');
      if (verdictItem.envelope.previousSha256 !== null) {
        const previous = items.find(item => item.envelope.sequence === verdictItem.envelope.sequence - 1);
        if (!previous || digest(previous.envelope) !== verdictItem.envelope.previousSha256) fail('INTEGRITY_ERROR', 'Голова цепочки не совпадает с предыдущим коммитом');
        chainHead = { sequence: previous.envelope.sequence, envelopeSha256: digest(previous.envelope) };
      } else {
        chainHead = { sequence: 0, envelopeSha256: null };
      }
    } else {
      chainHead = items.length ? { sequence: items.at(-1).envelope.sequence, envelopeSha256: digest(items.at(-1).envelope) } : null;
    }
  }
  if (!chainHead) fail('EVIDENCE_MISSING', 'Цепочка evidence пуста: анкер на пустой цепочке не выпускается');
  return { frozen, approval, consumption, candidate: candidateRecord, chainHead, evidence: items };
}

function verifyAnchorAgainstBinding({ trustRoot, trust, statement, binding, verdictItem }) {
  if (statement.runId !== binding.frozen.manifest.runId) fail('ANCHOR_CONFLICT', 'Анкер относится к другому runId');
  if (statement.manifestSha256 !== binding.frozen.manifestSha256) fail('ANCHOR_CONFLICT', 'Анкер относится к другому манифесту');
  if (statement.candidateSha256 !== binding.candidate.candidateSha256) fail('ANCHOR_CONFLICT', 'Анкер подписан на другой candidateSha256');
  if (statement.approvalId !== binding.approval.approvalId) fail('ANCHOR_CONFLICT', 'Анкер относится к другому approvalId');
  if (statement.inputsHash !== binding.approval.approvedInputsHash) fail('ANCHOR_CONFLICT', 'Анкер относится к другим входам');
  if (statement.environmentId !== binding.approval.targetEnvironmentId || statement.environmentGeneration !== binding.approval.environmentGeneration) fail('ANCHOR_CONFLICT', 'Анкер относится к другой среде');
  if (statement.verdict !== binding.candidate.candidate.verdict || statement.reasonCode !== binding.candidate.candidate.reasonCode) fail('ANCHOR_CONFLICT', 'Анкер относится к другому вердикту');
  if (!binding.chainHead || statement.chainHead.sequence !== binding.chainHead.sequence || statement.chainHead.envelopeSha256 !== binding.chainHead.envelopeSha256) fail('ANCHOR_CONFLICT', 'Анкер подписан на другую голову цепочки');
  if (verdictItem) {
    if (verdictItem.envelope.sequence - 1 !== statement.chainHead.sequence) fail('ANCHOR_CONFLICT', 'Анкер не предшествует терминальному verdict');
    if (verdictItem.envelope.previousSha256 !== statement.chainHead.envelopeSha256) fail('ANCHOR_CONFLICT', 'Анкер не связан с коммитом перед verdict');
  }
  void trustRoot;
  void trust;
}

function verificationReason(error) {
  if (error && ['VERIFICATION_ATTESTATION_MISSING', 'VERIFICATION_ATTESTATION_INVALID'].includes(error.code)) return error.code;
  if (error && ['TRUST_STORE_UNAVAILABLE', 'ANCHOR_CONFLICT', 'ANCHOR_BINDING_REJECTED', 'EVIDENCE_MISSING'].includes(error.code)) return error.code;
  return 'INTEGRITY_ERROR';
}

// P0-01/P1-01: доверенный путь обязан иметь паритет с 0.1 по evidence и покрытию verdict.
// Ошибки не глушатся: вызывающий переводит прогон в inconsistent и PASS не показывает.
function assertEvidenceParity(items, frozen, { candidate = null, terminal = false } = {}) {
  if (terminal) { assertTerminalEvidence(items, frozen); return; }
  assertEvidenceRefs(items, frozen, { requireMutation: true });
  const reads = items.filter(item => item.envelope.kind === 'independent-read');
  if (candidate) {
    validateVerdictCoverage(candidate, frozen.operation, reads);
    if (['PASS', 'FAIL'].includes(candidate.verdict)) {
      const response = items.find(item => item.envelope.kind === 'response');
      if (!response || reads.length === 0) fail('INTEGRITY_ERROR', 'PASS/FAIL без подтверждённого ответа и независимых чтений не публикуется');
    }
  }
}

function assertVerificationLink({ trustRoot, statement, binding, items }) {
  const readSetSha256 = computeReadSetSha256(items);
  return assertVerificationAttestation({
    trustRoot,
    runId: binding.frozen.manifest.runId,
    manifestSha256: binding.frozen.manifestSha256,
    approvalId: binding.approval.approvalId,
    candidateSha256: binding.candidate.candidateSha256,
    readSetSha256,
    evidenceChainHead: binding.chainHead,
    decision: { verdict: binding.candidate.candidate.verdict, reasonCode: binding.candidate.candidate.reasonCode },
    statement
  });
}

function analyze({ store, runDir, frozen, trust, trustRoot }) {
  const result = { state: 'collecting', trusted: false, verdict: null, choice: null, candidate: null, head: null, anchorId: null, anchorStatement: null, anchorStatus: null, reasonCode: null, unlinkedAnchorId: null };
  if (!store || typeof store.readEvidence !== 'function') throw new TypeError('Нужен RunStore');
  assertRunDir(runDir);
  if (!fs.existsSync(runDir)) return result;
  let current = frozen;
  if (!current) current = verifyFrozenBundle(store, runDir);
  else {
    const manifest = store.readSnapshot(runDir, 'manifest').value;
    if (digest(manifest) !== current.manifestSha256) fail('INTEGRITY_ERROR', 'Манифест прогона не совпадает с замороженным bundle');
  }
  result.candidate = readCandidate(runDir);
  result.choice = readTerminalChoice(runDir);
  const items = store.readEvidence(runDir);
  const verdictItems = items.filter(item => item.envelope.kind === 'verdict');
  if (verdictItems.length > 1) fail('INTEGRITY_ERROR', 'В журнале больше одного терминального verdict');
  if (!verdictItems.length) {
    if (!result.choice) {
      result.state = result.candidate ? 'candidate-ready' : 'collecting';
      result.reasonCode = result.candidate ? 'PUBLICATION_PENDING' : null;
      return result;
    }
    const choice = result.choice;
    result.anchorId = choice.anchorId;
    if (choice.outcome === 'anchor') {
      if (!result.candidate || result.candidate.candidateSha256 !== choice.candidateSha256) fail('INTEGRITY_ERROR', 'Выбор anchor не совпал с durable candidate');
      let statement;
      try { statement = loadAnchor(trustRoot, choice.anchorId); }
      catch (error) { if (error.code === 'ANCHOR_MISSING') { result.state = 'inconsistent'; result.reasonCode = 'ANCHOR_MISSING'; result.anchorStatus = 'ANCHOR_MISSING'; return result; } throw error; }
      const body = verifyAnchorStatement(trust, statement);
      result.anchorStatement = statement;
      const binding = inspectEvidenceBinding({ trust, trustRoot, runDir, approvalId: body.approvalId, mode: 'pre-verdict' });
      verifyAnchorAgainstBinding({ trustRoot, trust, statement: body, binding, verdictItem: null });
      try {
        assertEvidenceParity(binding.evidence, current, { candidate: binding.candidate.candidate });
        result.verification = assertVerificationLink({ trustRoot, statement: body, binding, items: binding.evidence });
      } catch (error) {
        result.state = 'inconsistent';
        result.reasonCode = verificationReason(error);
        result.anchorStatus = result.reasonCode;
        return result;
      }
      result.head = binding.chainHead;
      result.state = 'anchor-held';
      result.reasonCode = 'PUBLICATION_PENDING';
      result.anchorStatus = 'ANCHOR_OK';
      return result;
    }
    if (choice.outcome === 'budget-inconclusive') {
      const chosen = readCandidateBody(runDir, choice.candidateSha256);
      if (!chosen || chosen.candidate.verdict !== 'INCONCLUSIVE' || chosen.candidate.reasonCode !== 'EVIDENCE_MISSING') fail('INTEGRITY_ERROR', 'Выбор budget-inconclusive не указывает на durable INCONCLUSIVE');
      if (choice.discardedCandidateSha256 !== null) {
        if (!result.candidate || result.candidate.candidateSha256 !== choice.discardedCandidateSha256) fail('INTEGRITY_ERROR', 'Отброшенный PASS-candidate не совпал с выбором');
        if (!readCandidateBody(runDir, choice.discardedCandidateSha256)) fail('INTEGRITY_ERROR', 'Тело отброшенного PASS-candidate исчезло');
      }
      result.state = 'candidate-ready';
      result.reasonCode = 'PUBLICATION_PENDING';
      result.unlinkedAnchorId = findUnlinkedAnchor(trust, trustRoot, current.manifest.runId, choice.discardedCandidateSha256);
      if (result.unlinkedAnchorId) { result.anchorStatus = 'ANCHOR_UNLINKED'; result.reasonCode = 'ANCHOR_UNLINKED'; }
      return result;
    }
    if (choice.outcome === 'fail-without-anchor') {
      if (!result.candidate || result.candidate.candidateSha256 !== choice.candidateSha256 || result.candidate.candidate.verdict !== 'FAIL') fail('INTEGRITY_ERROR', 'Выбор fail-without-anchor не совпал с бизнес-FAIL');
    } else {
      if (!result.candidate || result.candidate.candidateSha256 !== choice.candidateSha256 || result.candidate.candidate.verdict !== 'INCONCLUSIVE') fail('INTEGRITY_ERROR', 'Выбор inconclusive-without-anchor не совпал с бизнес-INCONCLUSIVE');
    }
    result.state = 'candidate-ready';
    result.reasonCode = 'PUBLICATION_PENDING';
    result.anchorStatus = 'ANCHOR_MISSING';
    return result;
  }
  const verdictItem = verdictItems[0];
  let artifact;
  try { artifact = validateVerdictBody(verdictItem.artifact, 'verdict'); }
  catch { fail('INTEGRITY_ERROR', 'Артефакт verdict не является VerdictPolicy 0.1'); }
  if (!result.choice) fail('INTEGRITY_ERROR', 'Терминальный verdict опубликован без выбора исхода');
  const choice = result.choice;
  if (digest(artifact) !== choice.candidateSha256) fail('INTEGRITY_ERROR', 'Байты verdict не равны выбранному candidateSha256');
  result.anchorId = choice.anchorId;
  result.verdict = artifact;
  if (choice.outcome === 'anchor') {
    let statement;
    try { statement = loadAnchor(trustRoot, choice.anchorId); }
    catch (error) { if (error.code === 'ANCHOR_MISSING') { result.state = 'inconsistent'; result.reasonCode = 'ANCHOR_MISSING'; result.anchorStatus = 'ANCHOR_MISSING'; return result; } throw error; }
    let body;
    try { body = verifyAnchorStatement(trust, statement); }
    catch (error) { result.state = 'inconsistent'; result.reasonCode = error.code === 'ANCHOR_SIGNATURE_INVALID' ? 'ANCHOR_SIGNATURE_INVALID' : 'INTEGRITY_ERROR'; result.anchorStatus = result.reasonCode; return result; }
    result.anchorStatement = statement;
    let binding;
    try { binding = inspectEvidenceBinding({ trust, trustRoot, runDir, approvalId: body.approvalId, mode: 'terminal' }); }
    catch (error) { result.state = 'inconsistent'; result.reasonCode = error.code === 'TRUST_STORE_UNAVAILABLE' ? 'TRUST_STORE_UNAVAILABLE' : (error.code === 'ANCHOR_BINDING_REJECTED' ? 'ANCHOR_BINDING_REJECTED' : (error.code === 'APPROVAL_MISSING' ? 'ANCHOR_MISSING' : 'ANCHOR_BINDING_REJECTED')); result.anchorStatus = result.reasonCode; result.verdict = null; return result; }
    try { verifyAnchorAgainstBinding({ trustRoot, trust, statement: body, binding, verdictItem }); }
    catch (error) { result.state = 'inconsistent'; result.reasonCode = error.code === 'ANCHOR_CONFLICT' ? 'ANCHOR_CONFLICT' : 'INTEGRITY_ERROR'; result.anchorStatus = result.reasonCode; result.verdict = null; return result; }
    try {
      assertEvidenceParity(items, current, { terminal: true });
      result.verification = assertVerificationLink({ trustRoot, statement: body, binding, items });
    } catch (error) {
      result.state = 'inconsistent';
      result.reasonCode = verificationReason(error);
      result.anchorStatus = result.reasonCode;
      result.verdict = null;
      return result;
    }
    result.state = 'terminal';
    result.trusted = true;
    result.anchorStatus = 'ANCHOR_OK';
    result.reasonCode = null;
    return result;
  }
  if (choice.outcome === 'fail-without-anchor' || choice.outcome === 'inconclusive-without-anchor') {
    const expectedVerdict = choice.outcome === 'fail-without-anchor' ? 'FAIL' : 'INCONCLUSIVE';
    if (artifact.verdict !== expectedVerdict) { result.state = 'inconsistent'; result.reasonCode = 'INTEGRITY_ERROR'; result.verdict = null; return result; }
    result.state = 'terminal';
    result.trusted = true;
    result.anchorStatus = 'ANCHOR_MISSING';
    result.reasonCode = artifact.reasonCode;
    return result;
  }
  if (artifact.verdict !== 'INCONCLUSIVE' || artifact.reasonCode !== 'EVIDENCE_MISSING') { result.state = 'inconsistent'; result.reasonCode = 'INTEGRITY_ERROR'; result.verdict = null; return result; }
  const chosenBody = readCandidateBody(runDir, choice.candidateSha256);
  if (!chosenBody || digest(chosenBody.candidate) !== choice.candidateSha256) { result.state = 'inconsistent'; result.reasonCode = 'INTEGRITY_ERROR'; result.verdict = null; return result; }
  result.state = 'terminal';
  result.trusted = true;
  result.anchorStatus = null;
  result.reasonCode = 'EVIDENCE_MISSING';
  result.unlinkedAnchorId = findUnlinkedAnchor(trust, trustRoot, current.manifest.runId, choice.discardedCandidateSha256);
  if (result.unlinkedAnchorId) { result.anchorStatus = 'ANCHOR_UNLINKED'; result.reasonCode = 'ANCHOR_UNLINKED'; }
  return result;
}

export function publicationState({ store, runDir, trust, trustRoot }) {
  if (!store || !runDir || !trustRoot) throw new TypeError('Нужны store, runDir и trustRoot');
  try {
    const state = analyze({ store, runDir, frozen: null, trust, trustRoot }).state;
    return state;
  } catch {
    return 'inconsistent';
  }
}

export function observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot }) {
  if (!store || !runDir || !trustRoot) throw new TypeError('Нужны store, runDir и trustRoot');
  let analysis;
  try {
    analysis = analyze({ store, runDir, frozen: frozen || null, trust, trustRoot });
  } catch (error) {
    return { runId: null, runDir, state: 'inconsistent', trusted: false, passed: false, verdict: null, outcome: null, candidateSha256: null, anchorId: null, anchor: null, anchorStatus: null, reasonCode: error.code || 'INTEGRITY_ERROR', unlinkedAnchorId: null };
  }
  const passed = Boolean(analysis.trusted && analysis.verdict && analysis.verdict.verdict === 'PASS');
  return {
    runId: analysis.verdict?.runId || analysis.candidate?.candidate.runId || null,
    runDir,
    state: analysis.state,
    trusted: analysis.trusted,
    passed,
    verdict: analysis.trusted ? analysis.verdict : null,
    outcome: analysis.choice?.outcome || null,
    candidateSha256: analysis.choice?.candidateSha256 || analysis.candidate?.candidateSha256 || null,
    anchorId: analysis.anchorId,
    anchor: analysis.anchorStatement,
    anchorStatus: analysis.anchorStatus,
    reasonCode: analysis.reasonCode,
    unlinkedAnchorId: analysis.unlinkedAnchorId,
    // P0-01: сведения об аттестации Verification добавляются только в конец результата.
    verification: analysis.verification || null
  };
}

export function anchorWithinBudget({ signer, trustRoot, runDir, approvalId, anchorId, attestation = null, lease = null } = {}) {
  if (!signer || typeof signer.sign !== 'function') throw new TypeError('Нужен подключённый подписант');
  if (!trustRoot || !runDir || !approvalId || !anchorId) throw new TypeError('Нужны trustRoot, runDir, approvalId и anchorId');
  const budgetMs = loadAnchorBudgetMs(trustRoot);
  const request = signer.sign({ runDir, approvalId, anchorId, ...(attestation ? { attestation } : {}), ...(lease ? { lease } : {}) });
  let timer;
  const timeout = new Promise(resolve => { timer = setTimeout(() => resolve({ timeout: true }), budgetMs); });
  return Promise.race([request.then(statement => ({ statement })).catch(error => ({ error })), timeout]).then(async outcome => {
    if (outcome.timeout) return { ok: false, code: 'ANCHOR_TIMEOUT', budgetMs };
    if (outcome.error) return { ok: false, code: outcome.error.code || 'ANCHOR_UNAVAILABLE', budgetMs };
    return { ok: true, statement: outcome.statement, budgetMs };
  }).finally(() => clearTimeout(timer));
}
