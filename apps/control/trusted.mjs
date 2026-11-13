// WP-06: доверенный вход Control Plane.
//
// Два входа остаются раздельными: старый start()/observe()/cancel()/reconcile() не знает
// про trust root и не выпускает доверенный PASS, а *_Trusted проходит PEP в точках T-A…T-E.
// Второго исполнителя мутаций нет: оба входа сходятся в одном run().
import fs from 'node:fs';
import path from 'node:path';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { RunStore } from '../../packages/core/store.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { assertApprovedOperation } from '../../packages/core/approved-registry.mjs';
import { assertEvidenceRefs } from '../../packages/core/evidence-policy.mjs';
import { validateVerdictCoverage } from '../../packages/contracts/index.mjs';
import { loadTrustRoot } from '../../packages/trust/identity.mjs';
import { consumeDispatch } from '../../packages/trust/approval.mjs';
import { attestLiveEnvironment } from '../../packages/trust/environment.mjs';
import * as environment from '../../packages/trust/environment.mjs';
import { decide, projectToVerdict } from '../../packages/trust/policy.mjs';
import {
  anchorWithinBudget, observeTrustedVerdict, publishBudgetInconclusiveOutcome, publishCandidate,
  publishTerminalChoice, publishTerminalVerdict, readTerminalChoice, verifyAnchorStatement,
  verifyVerificationAttestation, computeReadSetSha256, verificationPublicKeyRecord
} from '../../packages/trust/anchor.mjs';
import { connectAnchorSigner, spawnAnchorSigner } from '../../packages/trust/anchor-signer.mjs';
import { currentUserSid } from '../../packages/trust/windows-sid.mjs';
import { approvalFact, buildFacts, environmentFact, expectedFromFrozen, principalFact } from '../../packages/trust/facts.mjs';
import { cancel, observe, reconcile, start } from './run.mjs';

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function nowIso() {
  return new Date().toISOString();
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
  const budget = Number.isSafeInteger(timeoutMs) && timeoutMs > 0 ? timeoutMs : Math.max(15000, (frozen.manifest.budget?.deadlineMs || 5000) + 5000);
  let workerPid = child.pid;
  const close = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    try { child.send({ type: 'STOP' }); } catch { /* канал уже закрыт */ }
    await new Promise(resolve => {
      const timer = setTimeout(() => { try { child.kill(); } catch { /* уже завершён */ } resolve(); }, 1500);
      child.once('exit', () => { clearTimeout(timer); resolve(); });
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
    return { payload, attestation: payload.attestation, verificationPublicKey: publicKey, verificationPid: workerPid, close };
  } catch (error) {
    await close();
    throw error;
  }
}

export function createTrustContext(options = {}) {
  const {
    trust, trustRoot, approvalId, approval = null, issuer, subject, sid, standPublicKey,
    signer = null, anchorKeyPath = null, fixtureToken = '', workerTimeoutMs
  } = options;
  if (!trust || !trustRoot || !approvalId) throw new TypeError('Нужны trust, trustRoot и approvalId');
  let currentEnvironment = null;
  let trustStoreUnavailable = false;
  let lastDecision = null;
  // Закреплённое соединение Control→стенд и PINNED_JOB для доверенного Browser Worker (P0-02).
  let pinned = null;

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
    if (!anchorKeyPath) return null;
    return spawnAnchorSigner({ trustRoot: root, anchorKeyPath });
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
        if (!payload?.prePostAttestation) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Нет переаттестации закреплённого соединения перед POST');
        environment.verifyEnvironmentAttestation(trust, record, payload.prePostAttestation, { challenge: payload.prePostAttestation.challenge, standPublicKey });
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
      fixtureToken,
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

    async publish({ store, runDir, frozen, verdict = null, canceled = false, browserUncertain = false }) {
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
            runDir, frozen, trustRoot, approvalId, fixtureToken, standPublicKey,
            timeoutMs: workerTimeoutMs, canceled, browserUncertain,
            environmentId: currentEnvironment?.record?.environmentId || null,
            environmentGeneration: currentEnvironment?.record?.generation || null
          });
          chosen = worker.payload.verdict;
          if (canceled && chosen.verdict === 'PASS') fail('INTEGRITY_ERROR', 'PASS запрещён для отменённого прогона');
        }
        if (!chosen) fail('INTEGRITY_ERROR', 'Нет доверенного кандидата для публикации');
        if (!existing) {
          publishCandidate(runDir, chosen);
          if (chosen.verdict === 'PASS') {
            let anchored = null;
            signerHandle = await openSigner(signer, anchorKeyPath, trustRoot);
            // Подписант без регистрации ключа Verification не может подтвердить происхождение: анкера нет.
            if (signerHandle && worker && typeof signerHandle.registerVerificationKey === 'function') {
              // Ключ Verification регистрируется только по приватному каналу Control→подписант,
              // вместе с pid процесса, происхождение которого подписант подтверждает сам.
              await signerHandle.registerVerificationKey(frozen.manifest.runId, worker.verificationPublicKey, worker.verificationPid);
              const anchorId = 'anchor-' + randomUUID();
              const outcome = await anchorWithinBudget({
                signer: signerHandle, trustRoot, runDir, approvalId, anchorId, attestation: worker.attestation
              });
              if (outcome.ok) {
                try {
                  const body = verifyAnchorStatement(trust, outcome.statement);
                  if (body.candidateSha256 !== digest(chosen)) fail('ANCHOR_BINDING_REJECTED', 'Анкер относится к другому candidate');
                  anchored = { anchorId: body.anchorId };
                } catch { anchored = null; }
              }
            }
            if (anchored) {
              publishTerminalChoice(runDir, {
                schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'anchor',
                candidateSha256: digest(chosen), discardedCandidateSha256: null, anchorId: anchored.anchorId, createdAt: nowIso()
              });
            } else {
              publishBudgetInconclusiveOutcome({ runDir, frozen });
            }
          } else if (chosen.verdict === 'FAIL') {
            publishTerminalChoice(runDir, {
              schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'fail-without-anchor',
              candidateSha256: digest(chosen), discardedCandidateSha256: null, anchorId: null, createdAt: nowIso()
            });
          } else {
            publishTerminalChoice(runDir, {
              schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'inconclusive-without-anchor',
              candidateSha256: digest(chosen), discardedCandidateSha256: null, anchorId: null, createdAt: nowIso()
            });
          }
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

function assertTrustedOptions(options, required) {
  for (const key of required) {
    if (!options || options[key] === undefined || options[key] === null || options[key] === '') throw fail('CONTRACT_INVALID', 'Доверенный вход требует ' + key);
  }
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
  if (!options.signerPipe) return null;
  return connectAnchorSigner(options.signerPipe);
}

export async function startTrusted(bundle, options = {}) {
  assertTrustedOptions(options, ['root', 'trustRoot', 'approvalId', 'issuer', 'subject']);
  const trust = loadTrustRoot(options.trustRoot);
  const sid = currentUserSid();
  const signer = await signerFor(options);
  const context = createTrustContext({
    trust, trustRoot: options.trustRoot, approvalId: options.approvalId, approval: options.approval || null,
    issuer: options.issuer, subject: options.subject, sid, standPublicKey: options.standPublicKey || null,
    signer, anchorKeyPath: options.anchorKeyPath || null,
    fixtureToken: options.fixtureToken || process.env.QA_ADAPTANT_FIXTURE_TOKEN || '',
    workerTimeoutMs: options.workerTimeoutMs
  });
  try {
    const result = await start(bundle, { root: options.root, headed: options.headed || false, fault: options.fault || null, fixtureToken: options.fixtureToken || process.env.QA_ADAPTANT_FIXTURE_TOKEN || '', trust: context });
    return assertTrustedPass(result, { root: options.root, trustRoot: options.trustRoot, trust });
  } finally {
    try { await context.close(); } catch { /* соединение уже закрыто */ }
    if (signer && typeof signer.close === 'function') signer.close();
  }
}

export async function observeTrusted({ root, trustRoot, runId } = {}) {
  assertTrustedOptions({ root, trustRoot, runId }, ['root', 'trustRoot', 'runId']);
  const trust = loadTrustRoot(trustRoot);
  const base = await observe({ root, runId });
  const store = new RunStore(root);
  const runDir = store.runPath(runId);
  const frozen = verifyFrozenBundle(store, runDir);
  const anchored = observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot });
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

export async function cancelTrusted({ root, trustRoot, runId, subject } = {}) {
  assertTrustedOptions({ root, trustRoot, runId, subject }, ['root', 'trustRoot', 'runId', 'subject']);
  const trust = loadTrustRoot(trustRoot);
  const sid = currentUserSid();
  const card = principalFact(trust, subject, { windowsSid: sid });
  if (!card.body) fail(card.error || 'CALLER_UNAUTHENTICATED', 'Вызывающий не аутентифицирован для отмены');
  return cancel({ root, runId });
}

export async function reconcileTrusted({ root, trustRoot, approvalId, approval = null, issuer, subject, standPublicKey = null, signerPipe = null, anchorKeyPath = null, fixtureToken = '', workerTimeoutMs, runId, fault = null } = {}) {
  assertTrustedOptions({ root, trustRoot, approvalId, issuer, subject, runId }, ['root', 'trustRoot', 'approvalId', 'issuer', 'subject', 'runId']);
  const trust = loadTrustRoot(trustRoot);
  const sid = currentUserSid();
  const signer = await signerFor({ signerPipe });
  const context = createTrustContext({ trust, trustRoot, approvalId, approval, issuer, subject, sid, standPublicKey, signer, anchorKeyPath, fixtureToken, workerTimeoutMs });
  try {
    const result = await reconcile({ root, runId, trust: context, fault });
    return assertTrustedPass(result, { root, trustRoot, trust });
  } finally {
    try { await context.close(); } catch { /* соединение уже закрыто */ }
    if (signer && typeof signer.close === 'function') signer.close();
  }
}
