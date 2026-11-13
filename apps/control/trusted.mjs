// WP-06: доверенный вход Control Plane.
//
// Два входа остаются раздельными: старый start()/observe()/cancel()/reconcile() не знает
// про trust root и не выпускает доверенный PASS, а *_Trusted проходит PEP в точках T-A…T-E.
// Второго исполнителя мутаций нет: оба входа сходятся в одном run().
import fs from 'node:fs';
import path from 'node:path';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID } from 'node:crypto';
import { RunStore } from '../../packages/core/store.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { withFileMutex } from '../../packages/core/file-mutex.mjs';
import { assertApprovedOperation } from '../../packages/core/approved-registry.mjs';
import { assertEvidenceRefs } from '../../packages/core/evidence-policy.mjs';
import { validateVerdictCoverage } from '../../packages/contracts/index.mjs';
import { loadTrustRoot, verifyTrustedDocument } from '../../packages/trust/identity.mjs';
import { consumeDispatch } from '../../packages/trust/approval.mjs';
import { attestLiveEnvironment } from '../../packages/trust/environment.mjs';
import * as environment from '../../packages/trust/environment.mjs';
import { decide, projectToVerdict } from '../../packages/trust/policy.mjs';
import {
  anchorWithinBudget, buildTerminalChoice, observeTrustedVerdict, publishBudgetInconclusiveOutcome, publishCandidate,
  publishTerminalChoice, publishTerminalVerdict, readCandidate, readCandidateBody, readTerminalChoice, verifyAnchorStatement,
  verifyVerificationAttestation, computeReadSetSha256, verificationPublicKeyRecord
} from '../../packages/trust/anchor.mjs';
import { queryTrustedProcessIdentity, spawnAnchorSigner } from '../../packages/trust/anchor-signer.mjs';
import { currentUserSid } from '../../packages/trust/windows-sid.mjs';
import { approvalFact, buildFacts, environmentFact, expectedFromFrozen, principalFact, resolveCredential } from '../../packages/trust/facts.mjs';
import { cancel, cancelTrustedInternal, reconcileTrustedInternal, startTrustedInternal } from './run.mjs';

// run.mjs accepts a trusted context only when it was minted by the guarded
// startTrusted/reconcileTrusted entrypoints below. Contexts returned by the
// diagnostic/exported createTrustContext() factory are intentionally unbranded.
const trustedRunnerContexts = new WeakSet();

export function isTrustedRunnerContext(context) {
  return Boolean(context && typeof context === 'object' && trustedRunnerContexts.has(context));
}

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function nowIso() {
  return new Date().toISOString();
}

async function publishTerminalChoiceWithCancellationBoundary(runDir, choice) {
  const lockFile = path.join(runDir, 'trust', 'publication.lock');
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  return withFileMutex(lockFile, () => {
    if (choice.outcome === 'anchor') {
      try { fs.lstatSync(path.join(runDir, 'cancel.request')); fail('CANCEL_REQUESTED', 'Отменённый run не может получить trusted PASS'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    return publishTerminalChoice(runDir, choice);
  });
}

async function recordSignerProcessIdentity(store, runDir, signerHandle) {
  if (!signerHandle?.pid) return null;
  const identity = await queryTrustedProcessIdentity(signerHandle.pid);
  if (!identity || identity.parentPid !== process.pid || path.win32.basename(identity.executablePath).toLowerCase() !== 'node.exe') {
    fail('ANCHOR_UNAVAILABLE', 'OS не подтвердил process identity дочернего подписанта');
  }
  store.appendEvent(runDir, { type: 'ANCHOR_SIGNER_STARTED', processIdentity: identity, controlPid: process.pid, at: nowIso() });
  return identity;
}

// Проекция точного кода отказа в замороженный enum 0.1. Значение проверяется validate().
function verdictCodeOf(code) {
  if (['CALLER_UNAUTHENTICATED', 'PRINCIPAL_UNKNOWN', 'PRINCIPAL_REVOKED', 'TRUST_STORE_UNAVAILABLE', 'CONSUMPTION_INCOMPLETE', 'APPROVAL_SIGNATURE_INVALID'].includes(code)) return 'AUTH_UNAVAILABLE';
  if (['ENVIRONMENT_ATTESTATION_FAILED', 'ENVIRONMENT_UNKNOWN', 'ENVIRONMENT_UNAVAILABLE', 'ENVIRONMENT_KIND_DENIED', 'ENVIRONMENT_REVOKED'].includes(code)) return 'ENVIRONMENT_CHANGED';
  if (code === 'RUN_CANCELED') return 'CANCELED';
  if (code === 'INTEGRITY_ERROR') return 'INTEGRITY_ERROR';
  return 'CONTRACT_INVALID';
}

function denialOf(decision) {
  const projection = projectToVerdict(decision);
  return {
    phase: decision.phase,
    reasonCode: decision.reasonCode,
    decisionId: decision.decisionId,
    verdictCode: projection?.reasonCode || verdictCodeOf(decision.reasonCode),
    message: 'Доверенный PEP отказал: ' + decision.reasonCode
  };
}

function errorDenial(error, phase) {
  const code = error?.code || 'CONTRACT_INVALID';
  return { phase, reasonCode: code, verdictCode: verdictCodeOf(code), message: error?.message || 'Доверенная проверка не прошла' };
}

function registryFact(frozen) {
  try {
    assertApprovedOperation(frozen.operation, frozen.scenario);
    return { operationAllowed: true, effectsMatch: true };
  } catch {
    return { operationAllowed: false, effectsMatch: false };
  }
}

function persistDecision(runDir, decision) {
  const directory = path.join(runDir, 'trust', 'decisions');
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, decision.phase + '-' + decision.decisionId + '.json');
  let fd;
  try {
    fd = fs.openSync(file, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(decision) + '\n');
    fs.fsyncSync(fd);
  } catch { /* решение не является доказательством мутации; журнал evidence не затрагивается */ }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}

function standChannelAvailable() {
  return typeof environment.attestationVerifiedReads === 'function' && typeof environment.openPinnedStandConnection === 'function';
}

function publicKeyBase64(value) {
  if (!value) return '';
  if (typeof value === 'string') return value;
  if (value.export) return Buffer.from(value.export({ type: 'spki', format: 'der' })).toString('base64');
  return Buffer.from(value).toString('base64');
}

// Окружение доверенного Verification Worker (имена зафиксированы в интеграции R-B/Lead).
export function buildVerificationEnv({ trustRoot, environmentId = '', environmentGeneration = 0, standPublicKey = null, fixtureToken = '', approvalId = '' } = {}) {
  return {
    QA_ADAPTANT_TRUSTED_VERIFIER: '1',
    QA_ADAPTANT_TRUST_ROOT: trustRoot,
    QA_ADAPTANT_ENVIRONMENT_ID: environmentId,
    QA_ADAPTANT_ENVIRONMENT_GENERATION: String(environmentGeneration || ''),
    QA_ADAPTANT_STAND_PUBLIC_KEY: publicKeyBase64(standPublicKey),
    QA_ADAPTANT_APPROVAL_ID: approvalId,
    QA_ADAPTANT_AUTHORIZATION: fixtureToken ? 'Bearer ' + fixtureToken : '',
    QA_ADAPTANT_FIXTURE_TOKEN: fixtureToken
  };
}

// Control запускает доверенный Verification Worker как дочерний процесс и принимает
// аттестацию и публичный ключ только по fork IPC. Приватный ключ Verification по IPC
// не передаётся: Worker подписывает аттестацию у себя и отдаёт только результат.
export async function verifyWithTrustedWorker({ runDir, frozen, trustRoot, approvalId, fixtureToken = '', standPublicKey = null, timeoutMs, canceled = false, browserUncertain = false, environmentId = null, environmentGeneration = null } = {}) {
  if (!runDir || !frozen || !trustRoot || !approvalId) throw new TypeError('Нужны runDir, frozen, trustRoot и approvalId');
  const store = new RunStore(path.dirname(path.dirname(path.resolve(runDir))));
  const entry = fileURLToPath(new URL('../verification/trusted-worker.mjs', import.meta.url));
  if (!standChannelAvailable()) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестованный канал стенда недоступен: доверенный Verification невозможен');
  const env = buildVerificationEnv({
    trustRoot,
    environmentId: environmentId || frozen.manifest.environment.id,
    environmentGeneration: environmentGeneration || frozen.manifest.environment.generation || 1,
    standPublicKey,
    fixtureToken,
    approvalId
  });
  if (canceled) env.QA_ADAPTANT_CANCELED = '1';
  if (browserUncertain) env.QA_ADAPTANT_BROWSER_UNCERTAIN = '1';
  const child = fork(entry, [runDir, frozen.manifestSha256], {
    stdio: ['ignore', 'ignore', process.env.QA_ADAPTANT_DEBUG === '1' ? 'inherit' : 'ignore', 'ipc'],
    env: { ...process.env, ...env }
  });
  const processIdentity = await queryTrustedProcessIdentity(child.pid);
  if (!processIdentity || processIdentity.parentPid !== process.pid || path.win32.basename(processIdentity.executablePath).toLowerCase() !== 'node.exe') {
    try { child.kill(); } catch { /* уже завершён */ }
    fail('WORKER_LOST', 'OS process identity Verification не удалось подтвердить до открытия IPC-сеанса');
  }
  store.appendEvent(runDir, { type: 'VERIFICATION_WORKER_STARTED', processIdentity, controlPid: process.pid, at: nowIso() });
  // Session nonce Control→Worker: 32 случайных байта hex, передаются РЕБЁНКУ ТОЛЬКО по fork IPC
  // (не env/argv/файл). Он входит в подписанные байты verification-attestation (поле nonce).
  const sessionNonce = randomBytes(32).toString('hex');
  try { child.send({ type: 'SESSION', sessionNonce }); }
  catch (error) { try { child.kill(); } catch { /* уже завершён */ } throw fail('WORKER_LOST', 'Не удалось передать session nonce Verification Worker: ' + error.message); }
  const budget = Number.isSafeInteger(timeoutMs) && timeoutMs > 0 ? timeoutMs : Math.max(15000, (frozen.manifest.budget?.deadlineMs || 5000) + 5000);
  let workerPid = child.pid;
  const close = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    try { child.send({ type: 'STOP' }); } catch { /* канал уже закрыт */ }
    await new Promise(resolve => {
      let timer;
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        resolve();
      };
      child.once('exit', finish);
      if (child.exitCode !== null || child.signalCode !== null) { finish(); return; }
      timer = setTimeout(() => { try { child.kill(); } catch { /* уже завершён */ } }, 1500);
    });
  };
  try {
    const message = await new Promise((resolve, reject) => {
      let settled = false;
      const finish = (value, error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(value);
      };
      const timer = setTimeout(() => { try { child.kill(); } catch { /* уже завершён */ } finish(null, fail('WORKER_LOST', 'Доверенный Verification Worker не прислал результат')); }, budget);
      child.on('message', value => {
        if (!value || typeof value !== 'object') return;
        if (value.type === 'RESULT') finish(value);
        else if (value.type === 'ERROR') finish(null, fail(value.code || 'WORKER_LOST', value.message || 'Доверенный Verification Worker отказал'));
      });
      child.once('error', error => finish(null, error));
      child.once('exit', code => { if (code !== null && !settled) finish(null, fail('WORKER_LOST', 'Доверенный Verification Worker завершился без результата: exit=' + code)); });
    });
    if (message.runId !== frozen.manifest.runId) fail('INTEGRITY_ERROR', 'Доверенный Verification Worker вернул другой runId');
    const payload = message.payload || {};
    const publicKey = verificationPublicKeyRecord(payload.verificationPublicKey);
    const attestationBody = verifyVerificationAttestation(payload.attestation, { publicKey, expectedKeyId: publicKey.keyId });
    if (attestationBody.nonce !== sessionNonce) fail('INTEGRITY_ERROR', 'nonce аттестации не совпал с session nonce IPC-сеанса Control');
    const items = store.readEvidence(runDir);
    if (attestationBody.runId !== frozen.manifest.runId || attestationBody.manifestSha256 !== frozen.manifestSha256) fail('INTEGRITY_ERROR', 'Аттестация Verification относится к другому прогону');
    if (attestationBody.approvalId !== approvalId) fail('INTEGRITY_ERROR', 'Аттестация Verification относится к другому approvalId');
    if (digest(payload.verdict) !== attestationBody.candidateSha256) fail('INTEGRITY_ERROR', 'candidateSha256 не совпал с байтами candidate Verification');
    const readSetSha256 = computeReadSetSha256(items);
    if (attestationBody.readSetSha256 !== readSetSha256) fail('INTEGRITY_ERROR', 'readSetSha256 аттестации не совпал с durable evidence');
    const head = items.at(-1)?.envelope;
    if (!head || attestationBody.evidenceChainHead?.sequence !== head.sequence || attestationBody.evidenceChainHead?.envelopeSha256 !== digest(head)) {
      fail('INTEGRITY_ERROR', 'evidenceChainHead аттестации не совпал с головой цепочки');
    }
    if (attestationBody.decision?.verdict !== payload.verdict?.verdict || attestationBody.decision?.reasonCode !== payload.verdict?.reasonCode) {
      fail('INTEGRITY_ERROR', 'decision аттестации не совпал с verdict Verification');
    }
    if (!Array.isArray(payload.reads)) fail('INTEGRITY_ERROR', 'Verification Worker не вернул независимые чтения');
    for (const returned of payload.reads) {
      const durable = items.find(item => item.envelope.evidenceId === returned?.envelope?.evidenceId);
      if (!durable || digest(durable.artifact) !== digest(returned.artifact)) fail('INTEGRITY_ERROR', 'IPC read не совпал с durable evidence');
    }
    const durableReads = items.filter(item => item.envelope.kind === 'independent-read');
    validateVerdictCoverage(payload.verdict, frozen.operation, durableReads);
    assertEvidenceRefs(items, frozen, { requireMutation: true });
    if (payload.verdict.verdict === 'PASS' && durableReads.length === 0) fail('INTEGRITY_ERROR', 'PASS Verification без независимых чтений');
    return { payload, attestation: payload.attestation, verificationPublicKey: publicKey, verificationPid: workerPid, processIdentity, sessionNonce, close };
  } catch (error) {
    await close();
    throw error;
  }
}

export function createTrustContext(options = {}) {
  const {
    trust, trustRoot, approvalId, approval = null, issuer, subject, sid, standPublicKey,
    signer = null, anchorKeyPath = null, credentials = null, fixtureToken = null, workerTimeoutMs
  } = options;
  if (!trust || !trustRoot || !approvalId) throw new TypeError('Нужны trust, trustRoot и approvalId');
  let currentEnvironment = null;
  let trustStoreUnavailable = false;
  let lastDecision = null;
  // Закреплённое соединение Control→стенд и PINNED_JOB для доверенного Browser Worker (P0-02).
  let pinned = null;
  // E-04: секрет среды, разрешённый по credentialRef подписанной записи.
  let credential = null;
  function resolvedCredentialSecret() {
    return credential && credential.ok && typeof credential.secret === 'string' ? credential.secret : '';
  }

  async function refreshEnvironment(runId, frozen) {
    const expected = expectedFromFrozen(frozen);
    const environment = environmentFact({ trust, trustRoot, environmentId: expected.environmentId, origin: frozen.manifest.environment.baseUrl, generation: null });
    // Повреждённый реестр — недоступность корня доверия (E-05), а не «просто неизвестная среда».
    trustStoreUnavailable = ['CONTRACT_INVALID', 'TRUST_STORE_UNAVAILABLE'].includes(environment.error);
    if (trustStoreUnavailable) {
      currentEnvironment = { record: null, error: 'ENVIRONMENT_UNKNOWN', attestation: { ok: false, body: null, error: 'ENVIRONMENT_UNAVAILABLE' } };
      return expected;
    }
    if (!environment.record) { currentEnvironment = { record: null, error: environment.error, attestation: { ok: false, body: null, error: environment.error } }; return expected; }
    const generation = environment.record.generation;
    let attestation = { ok: false, body: null, error: 'ENVIRONMENT_ATTESTATION_FAILED' };
    // Аттестуется только активный local-stand: dev/production и неактивные записи отсекает PDP по записи.
    if (environment.record.status === 'active' && environment.record.kind === 'local-stand') {
      try {
        const live = await attestLiveEnvironment({ trust, record: environment.record, standPublicKey });
        attestation = { ok: true, body: live.attestation, error: null };
      } catch (error) {
        const code = error?.code;
        attestation = { ok: false, body: null, error: code === 'ENVIRONMENT_UNAVAILABLE' ? 'ENVIRONMENT_UNAVAILABLE' : 'ENVIRONMENT_ATTESTATION_FAILED' };
      }
    }
    // E-04: секрет среды выдаётся только по credentialRef из подписанной записи реестра.
    const resolved = resolveCredential({ credentialRef: environment.record.credentialRef, credentials, fixtureToken });
    credential = resolved;
    if (!resolved.ok) {
      attestation = { ok: false, body: null, error: resolved.code || 'ENVIRONMENT_ATTESTATION_FAILED' };
    }
    currentEnvironment = { record: environment.record, error: null, attestation };
    expected.environmentGeneration = generation;
    return expected;
  }

  function factsFor(phase, { runId, frozen, expected, approvalState, canceled = false, mutationRecorded = false }) {
    return buildFacts({
      phase,
      now: nowIso(),
      authenticatedSid: sid,
      trustStore: trustStoreUnavailable ? { available: false, code: 'TRUST_STORE_UNAVAILABLE' } : { available: true, code: null },
      principal: principalFact(trust, subject, { windowsSid: sid }),
      issuer: principalFact(trust, issuer, { role: 'owner', domain: 'approval' }),
      approval: approvalState,
      expected,
      environment: currentEnvironment || { record: null, error: 'ENVIRONMENT_UNKNOWN', attestation: { ok: false, body: null, error: 'ENVIRONMENT_UNAVAILABLE' } },
      run: { runId, canceled, mutationRecorded },
      registry: registryFact(frozen)
    });
  }

  function approvalState(expected) {
    return approvalFact({ trust, trustRoot, approvalId, approval, issuer, subject, windowsSid: sid, expected, runId: null });
  }

  // Доверенная топология: если пайплайн не передал готового клиента, Control сам запускает
  // подписанта дочерним процессом с приватным fork IPC. Путь к anchor.key идёт только в env ребёнка.
  async function openSigner(existingSigner, anchorKeyPath, root) {
    if (existingSigner) return existingSigner;
    if (anchorKeyPath) return spawnAnchorSigner({ trustRoot: root, anchorKeyPath });
    return null;
  }

  function requirePinnedChannel(what) {
    if (!standChannelAvailable()) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Аттестованный канал стенда недоступен: ' + what);
    if (!currentEnvironment?.record) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда не подтверждена: ' + what);
    return currentEnvironment.record;
  }

  // P0-02: Control открывает закреплённое соединение после T-A и аттестует его на этом же сокете.
  // Сокет и PINNED_JOB уходят доверенному Browser Worker одним сообщением; новых TCP на origin нет.
  async function preparePinnedDispatch({ frozen, token, child } = {}) {
    if (!frozen || !frozen.manifest) throw new TypeError('Нужен замороженный bundle');
    if (!child || typeof child.send !== 'function') throw new TypeError('Нужен дочерний процесс Browser Worker');
    if (pinned?.connection) { try { await pinned.connection.close(); } catch { /* уже закрыто */ } pinned = null; }
    let connection = null;
    try {
      const record = requirePinnedChannel('подготовка dispatch');
      if (typeof token !== 'string' || token.length === 0) fail('CONTRACT_INVALID', 'Нужен токен стенда для закреплённого соединения');
      connection = await environment.openPinnedStandConnection({
        record, trust, standPublicKey, headers: { authorization: 'Bearer ' + token }, timeoutMs: 3000
      });
      const { manifest, operation, fixture, scenario } = frozen;
      const clickNode = scenario.nodes.find(node => node.action.type === 'click' && node.action.mutation);
      if (!clickNode) fail('CONTRACT_INVALID', 'В сценарии нет узла мутации');
      const job = {
        type: 'PINNED_JOB',
        runId: manifest.runId,
        manifestSha256: frozen.manifestSha256,
        stepId: clickNode.id,
        intentId: manifest.runId + ':' + clickNode.id,
        operationId: operation.id,
        mutationName: operation.mutation.name,
        inputsSha256: digest(operation.inputs),
        fixtureId: fixture.fixtureId,
        entityKind: operation.entityKind,
        origin: connection.origin || record.origin || manifest.environment.baseUrl,
        token,
        fields: { ...operation.inputs, fixtureId: fixture.fixtureId },
        // Worker сам переаттестует закреплённый сокет непосредственно перед POST.
        trustRoot,
        standPublicKey: typeof standPublicKey === 'string' ? standPublicKey : Buffer.from(standPublicKey.export({ type: 'spki', format: 'der' })).toString('base64'),
        // Подписанный документ записи среды: по IPC Symbol-маркер проверенного тела не переживает сериализацию.
        environmentRecord: JSON.parse(fs.readFileSync(path.join(trustRoot, 'environments', record.environmentId, record.generation + '.json'), 'utf8')),
        timeoutMs: manifest.budget.deadlineMs
      };
      // handle net.Socket и Bearer уходят одним сообщением; после передачи родитель сокет не использует.
      child.send(job, connection.socket);
      pinned = { connection, job, token };
      return { allow: true };
    } catch (error) {
      if (connection) { try { await connection.close(); } catch { /* уже закрыто */ } }
      pinned = null;
      return { allow: false, denial: errorDenial(error, 'dispatch') };
    }
  }

  // Control-side проверка подписанного ответа POST до записи evidence/публикации.
  function verifyDispatchResponse({ payload, connection = null } = {}) {
    try {
      const record = requirePinnedChannel('проверка ответа POST');
      if (typeof environment.verifyStandResponse !== 'function') fail('ENVIRONMENT_ATTESTATION_FAILED', 'verifyStandResponse недоступна');
      const target = connection || pinned?.connection || null;
      const responseBody = payload?.responseBody;
      const signature = payload?.responseSignature;
      const challenge = payload?.responseChallenge;
      if (!responseBody || !signature || !challenge) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ POST не подписан ключом стенда');
      // Переаттестация закреплённого соединения, выполненная Worker'ом непосредственно перед POST.
      if (typeof environment.verifyEnvironmentAttestation === 'function') {
        if (!payload?.prePostAttestation || !payload?.prePostSignature) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Нет переаттестации закреплённого соединения перед POST');
        environment.verifyEnvironmentAttestation(trust, record, payload.prePostAttestation, { challenge: payload.prePostChallenge, standPublicKey });
        environment.verifyStandResponse({
          trust, record, challenge: payload.prePostChallenge, body: payload.prePostAttestation,
          signature: payload.prePostSignature, method: 'POST', path: '/attest', status: 200, standPublicKey
        });
      }
      const body = environment.verifyStandResponse({
        trust,
        record,
        challenge,
        body: responseBody,
        signature,
        method: 'POST',
        path: '/records',
        status: payload.status,
        pid: target?.attestation?.pid,
        standPublicKey
      });
      return { allow: true, body };
    } catch (error) {
      if (process.env.QA_ADAPTANT_DEBUG === '1') console.error('verifyDispatchResponse', error.code, error.message, error.stack);
      return { allow: false, denial: errorDenial(error, 'dispatch'), body: null };
    }
  }

  // Окружение для доверенного Verification Worker / Browser Worker (имена из интеграции).
  function verificationEnv() {
    return buildVerificationEnv({
      trustRoot,
      environmentId: currentEnvironment?.record?.environmentId || '',
      environmentGeneration: currentEnvironment?.record?.generation || 0,
      standPublicKey,
      fixtureToken: resolvedCredentialSecret(),
      approvalId
    });
  }

  async function closePinnedConnection() {
    if (!pinned) return;
    const connection = pinned.connection;
    pinned = null;
    try { await connection.close(); } catch { /* уже закрыто */ }
  }

  return {
    trust,
    trustRoot,
    approvalId,
    get signer() { return signer; },
    get lastDecision() { return lastDecision; },
    preparePinnedDispatch,
    verifyDispatchResponse,
    verificationEnv,
    async close() { await closePinnedConnection(); },
    // E-04: выданный секрет (null, если среда не привязала credentialRef и секрет не нужен).
    credentialSecret() {
      return credential && credential.ok ? credential.secret : null;
    },

    async recoverPendingPublication({ store, runDir, frozen, lease }) {
      const choice = readTerminalChoice(runDir);
      const events = store.readEvents(runDir);
      const priorSigner = [...events].reverse().find(event => event.type === 'ANCHOR_SIGNER_STARTED');
      if (priorSigner?.processIdentity) {
        const currentSigner = await queryTrustedProcessIdentity(priorSigner.processIdentity.pid);
        if (currentSigner && digest(currentSigner) === digest(priorSigner.processIdentity)) {
          fail('PUBLICATION_PENDING', 'Предыдущий подписант ещё обрабатывает команду; recovery ждёт его завершения');
        }
        if (!currentSigner && environment.processAlive(priorSigner.processIdentity.pid)) {
          fail('PUBLICATION_PENDING', 'Состояние предыдущего подписанта неизвестно; receipt status не запрашивается');
        }
      }
      const signerHandle = await openSigner(signer, anchorKeyPath, trustRoot);
      if (!signerHandle || typeof signerHandle.verificationReceiptStatus !== 'function') {
        if (choice) fail('PUBLICATION_PENDING', 'Выбор terminal outcome нельзя подтвердить без receipt status подписанта');
      }
      try {
        // Record each newly spawned recovery signer before its first status/finalize request.
        // The next reconcile can then prove that this exact process has stopped before retrying.
        await recordSignerProcessIdentity(store, runDir, signerHandle);
      } catch (error) {
        if (signerHandle !== signer && typeof signerHandle?.close === 'function') await signerHandle.close();
        throw error;
      }
      let durableReceipt = null;
      if (signerHandle && typeof signerHandle.verificationReceiptStatus === 'function') {
        durableReceipt = await signerHandle.verificationReceiptStatus({ runDir, runId: frozen.manifest.runId,
          lease: { runId: frozen.manifest.runId, pid: process.pid, token: lease?.token } });
      }
      if (choice && signerHandle !== signer && typeof signerHandle?.close === 'function') await signerHandle.close();
      if (durableReceipt && choice && choice.outcome !== 'anchor') {
        fail('PUBLICATION_PENDING', 'Signed PASS receipt конфликтует с terminal-choice; требуется подписанный tombstone');
      }
      if (choice?.outcome === 'anchor' && !durableReceipt) {
        fail('PUBLICATION_PENDING', 'Anchor terminal-choice без signed verification receipt не подтверждает PASS');
      }
      if (choice) {
        if (choice.outcome === 'anchor') {
          try { fs.lstatSync(path.join(runDir, 'cancel.request')); fail('PUBLICATION_PENDING', 'Отменённый run не может быть восстановлен как PASS'); }
          catch (error) { if (error.code !== 'ENOENT') throw error; }
        }
        const body = readCandidateBody(runDir, choice.candidateSha256);
        if (!body) fail('EVIDENCE_MISSING', 'Тело выбранного candidate отсутствует; verdict не пересчитывается');
        if (durableReceipt && (choice.outcome !== 'anchor' || choice.anchorId !== verifyTrustedDocument(trust, durableReceipt).anchorId ||
            choice.candidateSha256 !== verifyTrustedDocument(trust, durableReceipt).candidateSha256)) {
          fail('PUBLICATION_PENDING', 'Terminal choice не совпадает с подписанным verification receipt');
        }
        const published = publishTerminalVerdict({ store, runDir, frozen, trust, trustRoot });
        store.appendEvent(runDir, { type: 'TRUST_VERDICT_DURABLE', evidenceId: published.evidenceId, verdict: published.verdict.verdict, anchorId: choice.anchorId || null });
        store.appendEvent(runDir, { type: 'STATE', state: 'FINISHED', verdict: published.verdict.verdict, reasonCode: published.verdict.reasonCode });
        return { runId: frozen.manifest.runId, runDir, verdict: published.verdict, evidenceIds: store.readEvidence(runDir).map(item => item.envelope.evidenceId) };
      }
      const started = [...events].reverse().find(event => event.type === 'VERIFICATION_WORKER_STARTED');
      if (started?.processIdentity) {
        const current = await queryTrustedProcessIdentity(started.processIdentity.pid);
        if (current && digest(current) === digest(started.processIdentity)) fail('PUBLICATION_PENDING', 'Verification Worker ещё жив; recovery ожидает его завершения');
        if (!current && environment.processAlive(started.processIdentity.pid)) fail('PUBLICATION_PENDING', 'Verification Worker process identity неизвестна; receipt status пока не запрашивается');
      }
      if (!signerHandle || typeof signerHandle.verificationReceiptStatus !== 'function') fail('PUBLICATION_PENDING', 'Подписант недоступен для receipt status');
      try {
        const receiptDocument = durableReceipt;
        if (!receiptDocument) {
          if (readCandidate(runDir)) fail('PUBLICATION_PENDING', 'Durable candidate без подписанного verification receipt не используется для recovery');
          return null;
        }
        const receipt = verifyTrustedDocument(trust, receiptDocument);
        const evidence = store.readEvidence(runDir);
        const head = evidence.at(-1)?.envelope;
        const headValue = head ? { sequence: head.sequence, envelopeSha256: digest(head) } : null;
        if (receipt.schemaVersion !== '0.2.2' || receipt.domain !== 'verification-recovery-receipt' ||
            receipt.runId !== frozen.manifest.runId || receipt.manifestSha256 !== frozen.manifestSha256 ||
            receipt.approvalId !== approvalId || receipt.receiptId !== digest({ runId: receipt.runId, approvalId: receipt.approvalId, anchorId: receipt.anchorId }) ||
            digest(receipt.candidate) !== receipt.candidateSha256 || digest(headValue) !== digest(receipt.evidenceChainHead) ||
            computeReadSetSha256(evidence) !== receipt.readSetSha256 || !started?.processIdentity ||
            digest(started.processIdentity) !== digest(receipt.processIdentity) ||
            receipt.processIdentity?.pid !== receipt.verificationPid ||
            receipt.processIdentity?.parentPid !== receipt.provenance?.prepareControlPid ||
            receipt.processIdentity?.creationTimeUtc !== receipt.provenance?.workerCreationTimeUtc ||
            typeof receipt.provenance?.prepareLeaseToken !== 'string' || receipt.provenance.prepareLeaseToken.length < 16) {
          fail('INTEGRITY_ERROR', 'Receipt не совпадает с durable run/evidence/process identity');
        }
        const attestation = verifyVerificationAttestation(receipt.attestation, { publicKey: receipt.verificationPublicKey, expectedKeyId: receipt.verificationPublicKey?.keyId });
        if (attestation.pid !== receipt.verificationPid || attestation.verificationKeyId !== receipt.verificationPublicKey?.keyId ||
            attestation.candidateSha256 !== receipt.candidateSha256 || attestation.approvalId !== receipt.approvalId) fail('INTEGRITY_ERROR', 'Receipt attestation key/PID binding не прошёл проверку');
        const existingCandidate = readCandidate(runDir);
        if (existingCandidate && existingCandidate.candidateSha256 !== receipt.candidateSha256) fail('CANDIDATE_CONFLICT', 'Durable candidate расходится с подписанным receipt');
        // candidate.json may have reached disk before its hash-addressed body when Control crashed.
        // Re-publishing the exact receipt body is idempotent and repairs that durable split state.
        publishCandidate(runDir, receipt.candidate);
        store.appendEvent(runDir, { type: 'STATE', state: 'PUBLICATION_RECOVERING', candidateSha256: receipt.candidateSha256, outcome: 'receipt' });
        const outcome = await anchorWithinBudget({ signer: signerHandle, trustRoot, runDir, approvalId, anchorId: receipt.anchorId,
          attestation: receipt.attestation, lease: { runId: frozen.manifest.runId, pid: process.pid, token: lease?.token } });
        if (!outcome.ok) fail('PUBLICATION_PENDING', 'Finalize receipt не подтверждён; terminal-choice не записан');
        const anchor = verifyAnchorStatement(trust, outcome.statement);
        if (anchor.anchorId !== receipt.anchorId || anchor.candidateSha256 !== receipt.candidateSha256) fail('ANCHOR_BINDING_REJECTED', 'Finalize anchor не совпал с receipt');
        await publishTerminalChoiceWithCancellationBoundary(runDir, buildTerminalChoice({ outcome: 'anchor', candidateSha256: receipt.candidateSha256, anchorId: receipt.anchorId }));
        const published = publishTerminalVerdict({ store, runDir, frozen, trust, trustRoot });
        store.appendEvent(runDir, { type: 'TRUST_VERDICT_DURABLE', evidenceId: published.evidenceId, verdict: published.verdict.verdict, anchorId: receipt.anchorId });
        store.appendEvent(runDir, { type: 'STATE', state: 'FINISHED', verdict: published.verdict.verdict, reasonCode: published.verdict.reasonCode });
        return { runId: frozen.manifest.runId, runDir, verdict: published.verdict, evidenceIds: store.readEvidence(runDir).map(item => item.envelope.evidenceId) };
      } finally {
        if (signerHandle !== signer && typeof signerHandle.close === 'function') await signerHandle.close();
      }
    },
    // Разрешение секрета для доверенного чтения (reconcile): без живой аттестации стенда,
    // но только по подписанной записи реестра и точному credentialRef.
    async ensureCredential({ frozen }) {
      const expected = expectedFromFrozen(frozen);
      const environment = environmentFact({ trust, trustRoot, environmentId: expected.environmentId, origin: frozen.manifest.environment.baseUrl, generation: null });
      if (!environment.record) fail(environment.error || 'ENVIRONMENT_UNKNOWN', 'Среда не разрешена для выдачи секрета');
      if (environment.record.environmentId !== expected.environmentId) fail('ENVIRONMENT_UNKNOWN', 'Запись реестра относится к другой среде');
      const resolved = resolveCredential({ credentialRef: environment.record.credentialRef, credentials, fixtureToken });
      if (!resolved.ok) fail(resolved.code || 'ENVIRONMENT_ATTESTATION_FAILED', resolved.message);
      credential = resolved;
      return resolved.secret;
    },

    async preflight({ runDir, frozen }) {
      const expected = await refreshEnvironment(frozen.manifest.runId, frozen);
      // Поколение для сверки связки берётся из самого approval: без него форма facts неполна.
      const probe = approvalFact({ trust, trustRoot, approvalId, approval, issuer, subject, windowsSid: sid, expected: null, runId: null });
      if (probe.body) expected.environmentGeneration = probe.body.environmentGeneration;
      const approvalStateValue = probe.body ? approvalState(expected) : probe;
      const facts = factsFor('preflight', { runId: frozen.manifest.runId, frozen, expected, approvalState: approvalStateValue });
      const decision = decide(facts);
      lastDecision = decision;
      persistDecision(runDir, decision);
      return decision.effect === 'ALLOW' ? { allow: true, decision } : { allow: false, denial: denialOf(decision) };
    },

    async dispatch({ runDir, frozen, intent }) {
      const expected = await refreshEnvironment(frozen.manifest.runId, frozen);
      const probe = approvalFact({ trust, trustRoot, approvalId, approval, issuer, subject, windowsSid: sid, expected: null, runId: null });
      if (probe.body) expected.environmentGeneration = probe.body.environmentGeneration;
      const approvalStateValue = probe.body ? approvalState(expected) : probe;
      const facts = factsFor('dispatch', { runId: frozen.manifest.runId, frozen, expected, approvalState: approvalStateValue, mutationRecorded: false });
      const decision = decide(facts);
      lastDecision = decision;
      persistDecision(runDir, decision);
      if (decision.effect !== 'ALLOW') return { allow: false, denial: denialOf(decision) };
      try {
        const consumed = consumeDispatch({
          trust, trustRoot, approval, approvalId, issuer, subject, windowsSid: sid, expected,
          runId: frozen.manifest.runId, decisionId: decision.decisionId
        });
        if (consumed.ack !== true) {
          return { allow: false, denial: { phase: 'dispatch', reasonCode: consumed.code || 'APPROVAL_CONSUMED', verdictCode: 'CONTRACT_INVALID', message: 'Расход approval не подтверждён; ACK не выдаётся' } };
        }
      } catch (error) {
        return { allow: false, denial: errorDenial(error, 'dispatch') };
      }
      return { allow: true, decision };
    },

    async beforeRequestAck({ frozen }) {
      try {
        if (pinned?.connection) {
          // Сокет уже передан Worker'у: в родителе он закрыт. Control проверяет живость процесса и владельца
          // порта, а повторную аттестацию самого закреплённого соединения выполняет Worker перед POST.
          const record = requirePinnedChannel('подтверждение перед POST');
          const pid = pinned.connection.attestation?.pid;
          if (!environment.processAlive(pid)) fail('ENVIRONMENT_CHANGED', 'Процесс стенда не жив перед отправкой POST');
          const owner = await environment.portOwnerPid(record.origin);
          if (owner === null) fail('ENVIRONMENT_CHANGED', 'Владелец локального порта не определён перед POST');
          if (owner !== pid) fail('ENVIRONMENT_CHANGED', 'Порт обслуживает не аттестованный процесс');
          return { allow: true };
        }
        const record = currentEnvironment?.record;
        if (!record) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда не подтверждена до отправки');
        await attestLiveEnvironment({ trust, record, standPublicKey });
        return { allow: true };
      } catch (error) {
        return { allow: false, denial: errorDenial(error, 'dispatch') };
      }
    },

    async publish({ store, runDir, frozen, verdict = null, canceled = false, browserUncertain = false, lease = null, fault = null }) {
      const existing = readTerminalChoice(runDir);
      let worker = null;
      let signerHandle = null;
      try {
        let chosen = verdict;
        const items = store.readEvidence(runDir);
        const mutationKnown = items.some(item => item.envelope.kind === 'mutation-intent');
        if (!existing && mutationKnown) {
          // P0-01: кандидат принимается только вместе с подписанной аттестацией доверенного Verification.
          worker = await verifyWithTrustedWorker({
            runDir, frozen, trustRoot, approvalId, fixtureToken: resolvedCredentialSecret(), standPublicKey,
            timeoutMs: workerTimeoutMs, canceled, browserUncertain,
            environmentId: currentEnvironment?.record?.environmentId || null,
            environmentGeneration: currentEnvironment?.record?.generation || null
          });
          chosen = worker.payload.verdict;
          if (canceled && chosen.verdict === 'PASS') fail('INTEGRITY_ERROR', 'PASS запрещён для отменённого прогона');
        }
        if (!chosen) fail('INTEGRITY_ERROR', 'Нет доверенного кандидата для публикации');
        if (!existing) {
          if (chosen.verdict === 'PASS') {
            let anchored = null;
            signerHandle = await openSigner(signer, anchorKeyPath, trustRoot);
            await recordSignerProcessIdentity(store, runDir, signerHandle);
            // Подписант без регистрации ключа Verification не может подтвердить происхождение: анкера нет.
            if (signerHandle && worker && typeof signerHandle.prepareVerificationReceipt === 'function') {
              const anchorId = 'anchor-' + randomUUID();
              const receiptDocument = await signerHandle.prepareVerificationReceipt({
                runDir, approvalId, anchorId, candidate: chosen,
                publicKey: worker.verificationPublicKey, verificationPid: worker.verificationPid,
                sessionNonce: worker.sessionNonce, attestation: worker.attestation,
                processIdentity: worker.processIdentity,
                lease: { runId: frozen.manifest.runId, pid: process.pid, token: lease?.token }
              });
              const receiptBody = verifyTrustedDocument(trust, receiptDocument);
              if (fault === 'afterVerificationReceiptBeforeCandidate') {
                store.appendEvent(runDir, { type: 'STATE', state: 'RECEIPT_DURABLE_BEFORE_CANDIDATE' });
                await new Promise(resolve => setTimeout(resolve, 30000));
              }
              if (fault === 'throwAfterVerificationReceiptBeforeCandidate') {
                fail('ANCHOR_CONFLICT', 'Имитированный сбой публикации после durable receipt');
              }
              await worker.close();
              worker = null;
              const evidenceAfterStop = store.readEvidence(runDir);
              const headAfterStop = evidenceAfterStop.at(-1)?.envelope;
              if (!headAfterStop) fail('PUBLICATION_PENDING', 'Evidence head отсутствует после остановки Verification Worker');
              // Receipt подписывает голову, проверенную до candidate; новые evidence запрещены.
              if (receiptBody.evidenceChainHead?.sequence !== headAfterStop.sequence || receiptBody.evidenceChainHead?.envelopeSha256 !== digest(headAfterStop)) {
                fail('PUBLICATION_PENDING', 'Evidence head изменился после подготовки verification receipt');
              }
              publishCandidate(runDir, chosen);
              // Ключ Verification регистрируется только по приватному каналу Control→подписант,
              // вместе с pid процесса, происхождение которого подписант подтверждает сам.
              // prepareVerificationReceipt уже зарегистрировал и подписал provenance.
              const outcome = await anchorWithinBudget({
                signer: signerHandle, trustRoot, runDir, approvalId, anchorId, attestation: receiptBody.attestation,
                lease: { runId: frozen.manifest.runId, pid: process.pid, token: lease?.token }
              });
              if (outcome.ok) {
                try {
                  const body = verifyAnchorStatement(trust, outcome.statement);
                  if (body.candidateSha256 !== digest(chosen)) fail('ANCHOR_BINDING_REJECTED', 'Анкер относится к другому candidate');
                  anchored = { anchorId: body.anchorId };
                } catch { anchored = null; }
              }
              if (anchored && fault === 'afterAnchorBeforeTerminalChoice') {
                store.appendEvent(runDir, { type: 'STATE', state: 'ANCHOR_DURABLE_BEFORE_TERMINAL_CHOICE', anchorId: anchored.anchorId });
                await new Promise(resolve => setTimeout(resolve, 30000));
              }
              if (anchored && fault === 'pauseAfterAnchorBeforeTerminalChoiceForCancelTest') {
                store.appendEvent(runDir, { type: 'STATE', state: 'ANCHOR_DURABLE_BEFORE_TERMINAL_CHOICE', anchorId: anchored.anchorId });
                await new Promise(resolve => setTimeout(resolve, 1500));
              }
              if (!anchored) fail('PUBLICATION_PENDING', 'Durable PASS receipt существует, finalize не подтверждён; reconcile обязан продолжить тот же anchorId');
            } else {
              publishCandidate(runDir, chosen);
            }
            if (anchored) {
              await publishTerminalChoiceWithCancellationBoundary(runDir, {
                schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'anchor',
                candidateSha256: digest(chosen), discardedCandidateSha256: null, anchorId: anchored.anchorId, createdAt: nowIso()
              });
            } else {
              publishBudgetInconclusiveOutcome({ runDir, frozen });
            }
          } else if (chosen.verdict === 'FAIL') {
            publishCandidate(runDir, chosen);
            await publishTerminalChoiceWithCancellationBoundary(runDir, {
              schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'fail-without-anchor',
              candidateSha256: digest(chosen), discardedCandidateSha256: null, anchorId: null, createdAt: nowIso()
            });
          } else {
            publishCandidate(runDir, chosen);
            await publishTerminalChoiceWithCancellationBoundary(runDir, {
              schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'inconclusive-without-anchor',
              candidateSha256: digest(chosen), discardedCandidateSha256: null, anchorId: null, createdAt: nowIso()
            });
          }
        }
        if (fault === 'afterTerminalChoiceBeforeVerdict') {
          store.appendEvent(runDir, { type: 'STATE', state: 'TERMINAL_CHOICE_DURABLE_BEFORE_VERDICT' });
          await new Promise(resolve => setTimeout(resolve, 30000));
        }
        // Проверка анкера для исхода anchor выполняется внутри publishTerminalVerdict (WP-05 D-01).
        const published = publishTerminalVerdict({ store, runDir, frozen, trust, trustRoot });
        store.appendEvent(runDir, { type: 'TRUST_VERDICT_DURABLE', evidenceId: published.evidenceId, verdict: published.verdict.verdict, anchorId: readTerminalChoice(runDir)?.anchorId || null });
        store.appendEvent(runDir, { type: 'STATE', state: 'FINISHED', verdict: published.verdict.verdict, reasonCode: published.verdict.reasonCode });
        return {
          runId: frozen.manifest.runId,
          runDir,
          verdict: published.verdict,
          evidenceIds: store.readEvidence(runDir).map(item => item.envelope.evidenceId)
        };
      } finally {
        if (signerHandle && signerHandle !== signer && typeof signerHandle.close === 'function') await signerHandle.close();
        if (worker && typeof worker.close === 'function') await worker.close();
      }
    }
  };
}

function createTrustedRunnerContext(options) {
  const context = createTrustContext(options);
  trustedRunnerContexts.add(context);
  return context;
}

function createTrustedCancelCapability() {
  const capability = Object.freeze({});
  trustedRunnerContexts.add(capability);
  return capability;
}

function assertTrustedOptions(options, required) {
  for (const key of required) {
    if (!options || options[key] === undefined || options[key] === null || options[key] === '') throw fail('CONTRACT_INVALID', 'Доверенный вход требует ' + key);
  }
}

function assertSignerConfigured(options) {
  if (options?.signerPipe) fail('CONTRACT_INVALID', 'Legacy signerPipe не поддерживает receipt-протокол; используйте Anchor-Signer через anchorKeyPath');
  if (!options?.anchorKeyPath) fail('CONTRACT_INVALID', 'Доверенный прогон требует Anchor-Signer через anchorKeyPath до запуска мутации');
}

// PASS из общего терминального результата не считается доверенным, пока не подтверждён анкером.
// Это закрывает показ подложного PASS через start/reconcile и через adopt существующего прогона.
function assertTrustedPass(result, { root, trustRoot, trust }) {
  if (!result || !result.verdict || result.verdict.verdict !== 'PASS') return result;
  const store = new RunStore(root);
  const runDir = store.runPath(result.runId);
  const frozen = verifyFrozenBundle(store, runDir);
  const anchored = observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot });
  if (!anchored.trusted || !anchored.passed) throw fail('INTEGRITY_ERROR', 'PASS доверенного прогона не подтверждён анкером');
  return result;
}

async function signerFor(options) {
  if (options.signerPipe) fail('CONTRACT_INVALID', 'Legacy signerPipe не поддерживает receipt-протокол');
  return null;
}

export async function startTrusted(bundle, options = {}) {
  assertTrustedOptions(options, ['root', 'trustRoot', 'approvalId', 'issuer', 'subject']);
  assertSignerConfigured(options);
  const trust = loadTrustRoot(options.trustRoot);
  const sid = currentUserSid();
  const signer = await signerFor(options);
  const fixtureToken = options.fixtureToken || process.env.QA_ADAPTANT_FIXTURE_TOKEN || '';
  const context = createTrustedRunnerContext({
    trust, trustRoot: options.trustRoot, approvalId: options.approvalId, approval: options.approval || null,
    issuer: options.issuer, subject: options.subject, sid, standPublicKey: options.standPublicKey || null,
    signer, anchorKeyPath: options.anchorKeyPath || null,
    credentials: options.credentials || null, fixtureToken,
    workerTimeoutMs: options.workerTimeoutMs
  });
  try {
    const result = await startTrustedInternal(bundle, { root: options.root, headed: options.headed || false, fault: options.fault || null, fixtureToken }, context);
    return assertTrustedPass(result, { root: options.root, trustRoot: options.trustRoot, trust });
  } finally {
    try { await context.close(); } catch { /* соединение уже закрыто */ }
    if (signer && typeof signer.close === 'function') signer.close();
  }
}

export async function observeTrusted({ root, trustRoot, runId, approvalId = null } = {}) {
  assertTrustedOptions({ root, trustRoot, runId }, ['root', 'trustRoot', 'runId']);
  // P2-02: наблюдение не требует документа approval; approvalId принимается как необязательная ссылка.
  if (approvalId !== null && (typeof approvalId !== 'string' || approvalId.length === 0)) throw fail('CONTRACT_INVALID', 'approvalId наблюдения имеет неверную форму');
  const trust = loadTrustRoot(trustRoot);
  const store = new RunStore(root);
  const runDir = store.runPath(runId);
  const frozen = verifyFrozenBundle(store, runDir);
  const evidence = store.readEvidence(runDir);
  const events = store.readEvents(runDir);
  const anchored = observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot });
  const base = {
    runId,
    runDir,
    manifestSha256: frozen.manifestSha256,
    state: [...events].reverse().find(event => event.state)?.state || frozen.manifest.state,
    verdict: null,
    evidenceIds: evidence.map(item => item.envelope.evidenceId),
    events
  };
  return {
    ...base,
    verdict: anchored.trusted ? anchored.verdict : null,
    trusted: anchored.trusted,
    passed: anchored.passed,
    publication: anchored.state,
    anchorId: anchored.anchorId,
    anchorStatus: anchored.anchorStatus,
    reasonCode: anchored.reasonCode,
    unlinkedAnchorId: anchored.unlinkedAnchorId
  };
}

export async function cancelTrusted({ root, trustRoot, runId, subject, approvalId = null } = {}) {
  assertTrustedOptions({ root, trustRoot, runId, subject }, ['root', 'trustRoot', 'runId', 'subject']);
  // P2-02: отмена не требует документа approval; approvalId принимается как необязательная ссылка.
  if (approvalId !== null && (typeof approvalId !== 'string' || approvalId.length === 0)) throw fail('CONTRACT_INVALID', 'approvalId отмены имеет неверную форму');
  const trust = loadTrustRoot(trustRoot);
  const sid = currentUserSid();
  const card = principalFact(trust, subject, { windowsSid: sid });
  if (!card.body) fail(card.error || 'CALLER_UNAUTHENTICATED', 'Вызывающий не аутентифицирован для отмены');
  return cancelTrustedInternal({ root, runId }, createTrustedCancelCapability());
}

export async function reconcileTrusted({ root, trustRoot, approvalId, approval = null, issuer, subject, standPublicKey = null, signerPipe = null, anchorKeyPath = null, credentials = null, fixtureToken = null, workerTimeoutMs, runId, fault = null } = {}) {
  assertTrustedOptions({ root, trustRoot, approvalId, issuer, subject, runId }, ['root', 'trustRoot', 'approvalId', 'issuer', 'subject', 'runId']);
  assertSignerConfigured({ signerPipe, anchorKeyPath });
  const trust = loadTrustRoot(trustRoot);
  const sid = currentUserSid();
  const signer = await signerFor({ trustRoot, anchorKeyPath, signerPipe });
  const context = createTrustedRunnerContext({
    trust, trustRoot, approvalId, approval, issuer, subject, sid, standPublicKey, signer,
    anchorKeyPath, credentials, workerTimeoutMs,
    fixtureToken: fixtureToken || process.env.QA_ADAPTANT_FIXTURE_TOKEN || ''
  });
  try {
    const result = await reconcileTrustedInternal({ root, runId, fault }, context);
    return assertTrustedPass(result, { root, trustRoot, trust });
  } finally {
    try { await context.close(); } catch { /* соединение уже закрыто */ }
    if (signer && typeof signer.close === 'function') signer.close();
  }
}
