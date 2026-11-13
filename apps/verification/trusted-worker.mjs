// WP-08 P0-01: доверенный Verification Worker.
//
// Не переиспользует замороженный apps/verification/worker.mjs. Генерирует эфемерную пару
// Ed25519 только в памяти, сам выполняет независимые чтения, сам считает readSetSha256 по
// фактическим независимым чтениям журнала и подписывает verification-attestation вместе с
// candidate. Управляется только Control по fork IPC; на диск ключ не пишет, публичный канал
// не открывает. Приватный ключ никогда не покидает процесс: по IPC идут только публичный
// ключ, аттестация и результаты.
import path from 'node:path';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { validateVerdictCoverage } from '../../packages/contracts/index.mjs';
import { assertEvidenceRefs } from '../../packages/core/evidence-policy.mjs';
import { buildCandidate, buildVerificationAttestation, computeReadSetSha256, verificationPublicKeyRecord } from '../../packages/trust/anchor.mjs';
import { loadEnvironmentRecord } from '../../packages/trust/environment.mjs';
import * as environment from '../../packages/trust/environment.mjs';
import { loadTrustRoot } from '../../packages/trust/identity.mjs';

const runDir = path.resolve(process.argv[2] || '');
const expectedManifestHash = process.argv[3] || '';
const trustRoot = process.env.QA_ADAPTANT_TRUST_ROOT || process.env.QA_TRUST_ROOT || '';
const approvalId = process.env.QA_ADAPTANT_APPROVAL_ID || process.env.QA_TRUSTED_APPROVAL_ID || '';
const standPublicKey = process.env.QA_ADAPTANT_STAND_PUBLIC_KEY || process.env.QA_STAND_PUBLIC_KEY || '';
const fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '';
const authorization = process.env.QA_ADAPTANT_AUTHORIZATION || (fixtureToken ? 'Bearer ' + fixtureToken : '');
const canceled = process.env.QA_ADAPTANT_CANCELED === '1';
const browserUncertain = process.env.QA_ADAPTANT_BROWSER_UNCERTAIN === '1';
const expectedGeneration = process.env.QA_ADAPTANT_ENVIRONMENT_GENERATION || '';
const now = () => new Date().toISOString();

const send = message => new Promise((resolve, reject) => {
  if (!process.connected) return reject(new Error('IPC_DISCONNECTED'));
  process.send(message, error => error ? reject(error) : resolve());
});
function exitSoon(code) {
  setImmediate(() => {
    process.exitCode = code;
    try { if (process.connected) process.disconnect(); } catch { /* уже отключён */ }
  });
}

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function authorizationHeaders() {
  if (!authorization) fail('ENVIRONMENT_UNAVAILABLE', 'Токен стенда не передан доверенному Verification Worker');
  return { authorization };
}

function verdictBase(frozen, checks, verdict, reasonCode, ownershipVerified, integrityVerified, message) {
  return buildCandidate({ frozen, verdict, reasonCode, message, checks, ownershipVerified, integrityVerified });
}

function unknownChecks(operation) {
  return operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] }));
}

async function performReadCycle(store, frozen, channel) {
  const { manifest, operation, fixture, manifestSha256 } = frozen;
  const base = new URL(manifest.environment.baseUrl);
  const started = Date.now();
  const absoluteDeadline = started + manifest.budget.deadlineMs;
  const envBefore = await channel.environmentRead(Math.min(3000, manifest.budget.deadlineMs));
  if (envBefore.status !== 200 || !envBefore.body || envBefore.body.environmentId !== manifest.environment.id || envBefore.body.environmentId !== fixture.environmentId || envBefore.body.fingerprint !== manifest.environment.fingerprint) fail('ENVIRONMENT_BEFORE');
  const existing = store.readEvidence(runDir);
  const response = existing.find(item => item.envelope.kind === 'response');

  const statuses = new Map();
  for (const effect of operation.effects) {
    if (effect.appliesWhen) {
      if (!Object.hasOwn(operation.inputs, effect.appliesWhen.field)) statuses.set(effect.id, 'UNKNOWN');
      else if (operation.inputs[effect.appliesWhen.field] !== effect.appliesWhen.equals) statuses.set(effect.id, 'NOT_APPLICABLE');
    }
  }
  const active = operation.effects.filter(effect => !statuses.has(effect.id));
  const overallEnd = Math.min(absoluteDeadline, Date.now() + Math.max(...active.map(effect => effect.deadlineMs), 0));
  let readAttempts = 0;
  const lastProofByEffect = new Map();
  let identityFailure = false;
  const reads = [];
  let ownershipVerified = false;

  while (active.some(effect => !['SATISFIED', 'UNKNOWN'].includes(statuses.get(effect.id))) || active.some(effect => !statuses.has(effect.id))) {
    const pending = active.filter(effect => !statuses.has(effect.id));
    if (!pending.length || Date.now() >= overallEnd || readAttempts >= manifest.budget.maxReadAttempts) break;
    const timeoutMs = Math.max(100, Math.min(3000, overallEnd - Date.now()));
    let result = null;
    try { result = await channel.recordsRead(timeoutMs, fixture.fixtureId); }
    catch (error) { if (String(error?.code || '').startsWith('ENVIRONMENT_')) throw error; result = null; }
    readAttempts++;
    const readable = result && result.status === 200 && Array.isArray(result.body?.records);
    if (!readable) {
      const wait = Math.min(...pending.map(effect => effect.intervalMs), 1000);
      await new Promise(resolve => setTimeout(resolve, Math.min(wait, Math.max(0, overallEnd - Date.now()))));
      continue;
    }
    const matches = result.body.records.filter(record => record?.fixtureId === fixture.fixtureId);
    if (result.body.records.length > 0 && matches.length !== result.body.records.length) { identityFailure = true; break; }
    if (matches.length > 1) { identityFailure = true; break; }
    const record = matches[0];
    if (record && (record.id !== response.envelope.entity?.id || record.id !== response.artifact.entity?.id)) { identityFailure = true; break; }
    if (record) {
      const responseMatches = record.id === response.envelope.entity.id && response.envelope.entity.kind === operation.entityKind;
      const identityValid = responseMatches && record.fixtureId === fixture.fixtureId &&
        operation.verification.identityFields.every(field => Object.hasOwn(record, field) && record[field] === (field === fixture.ownership.field ? fixture.ownership.value : operation.inputs[field]));
      if (!identityValid) { identityFailure = true; break; }
      ownershipVerified = true;
      const readRequestId = randomUUID();
      const fields = Object.fromEntries([...Object.keys(operation.inputs), ...operation.verification.identityFields]
        .filter((value, index, array) => array.indexOf(value) === index)
        .filter(key => Object.hasOwn(record, key) && (record[key] === null || ['string', 'number', 'boolean'].includes(typeof record[key])))
        .map(key => [key, record[key]]));
      const artifact = { method: 'GET', path: '/records', fixtureId: fixture.fixtureId, entity: { kind: operation.entityKind, id: record.id }, fields, environmentFingerprint: envBefore.body.fingerprint, requestId: readRequestId, httpStatus: 200, observedAt: now() };
      const checkIds = pending.filter(effect => Object.hasOwn(fields, effect.field)).map(effect => effect.id);
      const envelope = store.appendEvidence(runDir, { runId: manifest.runId, manifestSha256, fixtureId: fixture.fixtureId,
        stepId: frozen.scenario.nodes.find(node => node.action.type === 'verify').id, producer: 'verification', kind: 'independent-read',
        artifact, requestId: readRequestId, entity: artifact.entity, parentEvidenceIds: [response.envelope.evidenceId], checkIds });
      reads.push({ envelope, artifact });
      for (const effect of pending) {
        if (!Object.hasOwn(fields, effect.field)) continue;
        if (fields[effect.field] === effect.equals) { statuses.set(effect.id, 'SATISFIED'); lastProofByEffect.set(effect.id, envelope.evidenceId); }
        else lastProofByEffect.set(effect.id, envelope.evidenceId);
      }
    }
    if (active.some(effect => !statuses.has(effect.id))) {
      const wait = Math.min(...active.filter(effect => !statuses.has(effect.id)).map(effect => effect.intervalMs), 1000);
      await new Promise(resolve => setTimeout(resolve, Math.min(wait, Math.max(0, overallEnd - Date.now()))));
    }
  }

  const envAfter = await channel.environmentRead(Math.min(3000, Math.max(100, absoluteDeadline - Date.now()))).catch(() => null);
  if (!envAfter || envAfter.status !== 200 || envAfter.body?.environmentId !== manifest.environment.id || envAfter.body?.fingerprint !== envBefore.body.fingerprint) fail('ENVIRONMENT_AFTER');
  const completedDeadline = Date.now() >= overallEnd || readAttempts >= manifest.budget.maxReadAttempts;
  const checks = operation.effects.map(effect => {
    let status = statuses.get(effect.id);
    if (!status) {
      if (effect.appliesWhen && !Object.hasOwn(operation.inputs, effect.appliesWhen.field)) status = 'UNKNOWN';
      else if (effect.appliesWhen && operation.inputs[effect.appliesWhen.field] !== effect.appliesWhen.equals) status = 'NOT_APPLICABLE';
      else if (completedDeadline && lastProofByEffect.has(effect.id)) status = 'VIOLATED';
      else status = 'UNKNOWN';
    }
    return { id: effect.id, status, evidenceIds: ['SATISFIED', 'VIOLATED'].includes(status) ? [lastProofByEffect.get(effect.id)] : [] };
  });
  let verdict;
  let reasonCode;
  let message;
  if (identityFailure) { verdict = 'INCONCLUSIVE'; reasonCode = 'RESULT_UNCONFIRMED'; message = 'Независимое чтение не удалось связать с подтверждённым ответом мутации'; }
  else if (checks.some(check => check.status === 'UNKNOWN')) { verdict = 'INCONCLUSIVE'; reasonCode = 'EVIDENCE_MISSING'; message = 'Для завершения обязательных проверок недостаточно независимых данных'; }
  else if (checks.some(check => check.status === 'VIOLATED')) { verdict = 'FAIL'; reasonCode = 'BUSINESS_INVARIANT_VIOLATED'; message = 'Независимое чтение подтвердило нарушение ожидаемого эффекта'; }
  else { verdict = 'PASS'; reasonCode = 'NONE'; message = 'Все обязательные эффекты подтверждены независимым чтением'; }
  const built = verdictBase(frozen, checks, verdict, reasonCode, ownershipVerified, true, message);
  validateVerdictCoverage(built, operation, reads);
  return { verdict: built, reads };
}

async function execute() {
  const store = new RunStore(path.dirname(path.dirname(runDir)));
  const frozen = verifyFrozenBundle(store, runDir);
  const { manifest, operation, fixture, manifestSha256 } = frozen;
  if (manifestSha256 !== expectedManifestHash || digest(manifest) !== expectedManifestHash) fail('INTEGRITY_ERROR', 'MANIFEST_HASH');
  if (typeof approvalId !== 'string' || approvalId.length === 0) fail('INTEGRITY_ERROR', 'APPROVAL_ID_MISSING');
  const base = new URL(manifest.environment.baseUrl);
  if (base.protocol !== 'http:' || base.hostname !== '127.0.0.1' || !base.port || base.pathname !== '/' || base.search || base.hash || base.username || base.password) fail('INTEGRITY_ERROR', 'ORIGIN');
  // Durable цепочка мутации перепроверяется до любых чтений: происхождение candidate опирается на неё.
  const existing = store.readEvidence(runDir);
  assertEvidenceRefs(existing, frozen, { requireMutation: true });
  if (existing.some(item => item.envelope.kind === 'verdict')) fail('INTEGRITY_ERROR', 'В журнале уже есть терминальный verdict');
  const response = existing.find(item => item.envelope.kind === 'response');
  if (!response) return { verdict: verdictBase(frozen, unknownChecks(operation), 'INCONCLUSIVE', 'RESULT_UNCONFIRMED', false, true, 'Независимое чтение не удалось связать с подтверждённым ответом мутации'), reads: [] };
  if (response.artifact.status !== 201) return { verdict: verdictBase(frozen, unknownChecks(operation), 'INCONCLUSIVE', 'RESULT_UNCONFIRMED', false, true, 'Ответ не является доказательством создания'), reads: [] };

  // P0-02: совместимого режима без подписи стенда нет. Отсутствие канала — fail-closed (INCONCLUSIVE).
  if (typeof environment.attestationVerifiedReads !== 'function' || typeof environment.openPinnedStandConnection !== 'function') {
    fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестованный канал стенда недоступен: доверенные чтения невозможны');
  }
  if (!trustRoot) fail('TRUST_STORE_UNAVAILABLE', 'Доверенному worker не передан trust root');
  const trust = loadTrustRoot(trustRoot);
  const record = loadEnvironmentRecord(trust, trustRoot, manifest.environment.id);
  let captured = null;
  // R-B: возвращается ровно read(ctx); метаданные канала — readResult.standReads.
  // /environment отдельно не читается: идентичность среды берётся из подписанной аттестации ctx.
  const readResult = await environment.attestationVerifiedReads({
    trust,
    record,
    standPublicKey: standPublicKey || undefined,
    headers: authorizationHeaders(),
    timeoutMs: 3000,
    read: async context => {
      if (context.environmentId !== manifest.environment.id) fail('ENVIRONMENT_ATTESTATION_FAILED', 'environmentId аттестации не совпал с манифестом');
      if (expectedGeneration && String(context.generation) !== String(expectedGeneration)) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Поколение среды изменилось');
      captured = await performReadCycle(store, frozen, {
        environmentRead: async () => ({
          status: 200,
          body: { environmentId: context.environmentId, fingerprint: manifest.environment.fingerprint }
        }),
        recordsRead: (timeoutMs, fixtureId) => {
          const url = new URL('/records', base);
          url.searchParams.set('fixtureId', fixtureId);
          return context.verifiedRead(url, { method: 'GET', timeoutMs });
        }
      });
      return captured;
    }
  });
  if (!captured) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестованный канал не выполнил независимые чтения');
  void readResult;
  return captured;
}

// P0-01: session nonce приходит ТОЛЬКО по fork IPC от Control. Он входит в подписанную
// аттестацию как поле nonce, поэтому чужой процесс с тем же образом, но без IPC-сеанса,
// не может предъявить подпись.
async function waitForSessionNonce() {
  const timeoutMs = 5000;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => finish(null, Object.assign(new Error('IPC-сеанс Control не открыт: session nonce не получен'), { code: 'SESSION_MISSING' })), timeoutMs);
    const onMessage = message => {
      if (!message || typeof message !== 'object') return;
      if (message.type !== 'SESSION') return;
      if (typeof message.sessionNonce !== 'string' || !/^[a-f0-9]{64}$/.test(message.sessionNonce)) {
        finish(null, Object.assign(new Error('session nonce имеет неверную форму'), { code: 'SESSION_INVALID' }));
        return;
      }
      process.removeListener('message', onMessage);
      finish(message.sessionNonce);
    };
    process.on('message', onMessage);
    process.once('disconnect', () => finish(null, Object.assign(new Error('IPC-сеанс Control закрыт до передачи session nonce'), { code: 'SESSION_MISSING' })));
  });
}

async function runAndAttest(sessionNonce) {
  // Эфемерная пара Verification: только в памяти, на диск не пишется.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const startedAt = now();
  const nonce = sessionNonce;
  const store = new RunStore(path.dirname(path.dirname(runDir)));
  let result;
  try {
    result = await execute();
    if (canceled || browserUncertain) {
      const frozenForFlags = verifyFrozenBundle(store, runDir);
      const checks = frozenForFlags.operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] }));
      result = {
        verdict: verdictBase(frozenForFlags, checks, 'INCONCLUSIVE', canceled ? 'CANCELED' : 'WORKER_LOST', false, true,
          canceled ? 'Прогон отменён; повторная мутация не выполняется' : 'Browser Worker завершился без подтверждения полного выполнения'),
        reads: result.reads || []
      };
    }
  } catch (error) {
    if (process.env.QA_ADAPTANT_DEBUG === '1') console.error(error);
    let runId = 'verification';
    let manifestSha256 = /^[a-f0-9]{64}$/.test(expectedManifestHash) ? expectedManifestHash : '0'.repeat(64);
    let operation = null;
    try { runId = store.readSnapshot(runDir, 'manifest').value.runId; operation = store.readSnapshot(runDir, 'operation').value; } catch { /* прогон недоступен */ }
    const environmentChanged = ['ENVIRONMENT_BEFORE', 'ENVIRONMENT_AFTER'].includes(error.message) || String(error.code || '').startsWith('ENVIRONMENT_');
    const integrityError = /INTEGRITY|RESPONSE_INVALID|REQUEST_INVALID|INTENT_INVALID|EVIDENCE_SCOPE|EVIDENCE_STEP|EVIDENCE_CHAIN|READ_|VERDICT_/.test(error.message);
    const reasonCode = environmentChanged ? 'ENVIRONMENT_CHANGED' : (integrityError ? 'INTEGRITY_ERROR' : 'EVIDENCE_MISSING');
    const checks = operation?.effects?.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] })) || [];
    try {
      const verdict = verdictBase({ manifest: { runId, environment: { baseUrl: 'http://127.0.0.1:1/', id: 'unknown', fingerprint: 'unknown' }, budget: { deadlineMs: 1000, maxReadAttempts: 1 } }, manifestSha256, operation: operation || { effects: [] } }, checks, 'INCONCLUSIVE', reasonCode, false, !integrityError, 'Проверка не завершена; подробности доступны только в локальном журнале процесса');
      result = { verdict, reads: [] };
    } catch {
      await send({ type: 'ERROR', code: error.code || 'TRUSTED_WORKER_ERROR', message: error.message });
      return;
    }
  }
  const frozen = verifyFrozenBundle(store, runDir);
  const items = store.readEvidence(runDir);
  const head = items.at(-1)?.envelope;
  const attestation = buildVerificationAttestation(privateKey, {
    runId: frozen.manifest.runId,
    manifestSha256: frozen.manifestSha256,
    approvalId,
    candidateSha256: digest(result.verdict),
    readSetSha256: computeReadSetSha256(items),
    evidenceChainHead: head ? { sequence: head.sequence, envelopeSha256: digest(head) } : null,
    decision: { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode },
    pid: process.pid,
    startedAt,
    nonce
  });
  await send({
    type: 'RESULT',
    runId: frozen.manifest.runId,
    payload: { verdict: result.verdict, reads: result.reads, attestation, verificationPublicKey: verificationPublicKeyRecord(publicKey) }
  });
}

try {
  const sessionNonce = await waitForSessionNonce();
  await runAndAttest(sessionNonce);
} catch (error) {
  if (process.env.QA_ADAPTANT_DEBUG === '1') console.error(error);
  try { await send({ type: 'ERROR', code: error.code || 'TRUSTED_WORKER_ERROR', message: error.message }); } catch { /* канал закрыт */ }
}

// Остаёмся живыми до STOP от Control: подписант проверяет живость процесса в момент подписи.
await new Promise(resolve => {
  const stop = () => resolve();
  process.once('message', message => { if (message && message.type === 'STOP') stop(); });
  process.once('disconnect', stop);
});
exitSoon(0);
