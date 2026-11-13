// WP-08 AUD-P0-02 (§10.2): доверенный Browser Worker закреплённого соединения.
//
// Отличие от замороженного apps/browser/worker.mjs 0.1: Worker не запускает браузер и не открывает
// новых TCP-соединений. Control передаёт ему по fork IPC handle net.Socket уже аттестованного стенда
// и Bearer в ОДНОМ сообщении. Единственный POST выполняется только по этому сокету; response
// сохраняется как evidence по той же схеме, что 0.1: INTENT → ACK → HTTP_REQUEST → EVIDENCE_ACK →
// POST → HTTP_RESPONSE → EVIDENCE_ACK → DONE. При разрыве сокета POST не повторяется:
// Worker отдаёт HTTP_FAILED/ERROR, Control обязан завершить прогон INCONCLUSIVE.
import { randomUUID } from 'node:crypto';
import {
  attestPinnedConnection, createPinnedAgent, newChallenge, pinnedStandRequest, readStandResponseSignature,
  STAND_CHALLENGE_HEADER
} from '../../packages/trust/environment.mjs';
import { loadTrustRoot } from '../../packages/trust/identity.mjs';

const requestId = randomUUID();
let job = null;
let socket = null;
let shuttingDown = false;
let controlLost = false;
const ackWaiters = new Map();
const evidenceWaiters = new Map();

function exitSoon(code) {
  shuttingDown = true;
  setImmediate(() => {
    process.exitCode = code;
    try { if (process.connected) process.disconnect(); } catch { /* уже отключён */ }
  });
}

function send(message) {
  return new Promise((resolve, reject) => {
    if (!process.connected) return reject(Object.assign(new Error('Control IPC отключён'), { code: 'WORKER_LOST' }));
    process.send(message, error => error ? reject(error) : resolve());
  });
}

function event(type, payload = {}) {
  return send({ type, runId: job?.runId, payload });
}

function waitAck(commandId, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { ackWaiters.delete(commandId); reject(Object.assign(new Error('ACK durable intent не получен'), { code: 'WORKER_LOST' })); }, timeoutMs);
    ackWaiters.set(commandId, ack => { clearTimeout(timer); resolve(ack); });
  });
}

function waitEvidenceAck(id, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { evidenceWaiters.delete(id); reject(Object.assign(new Error('Не получено durable подтверждение HTTP evidence'), { code: 'WORKER_LOST' })); }, timeoutMs);
    evidenceWaiters.set(id, message => { clearTimeout(timer); resolve(message); });
  });
}

function fail(code, message) {
  return Object.assign(new Error(message), { code });
}

function assertJob(value) {
  if (!value || typeof value !== 'object') throw fail('CONTRACT_INVALID', 'PINNED_JOB не объект');
  for (const key of ['runId', 'manifestSha256', 'stepId', 'intentId', 'operationId', 'mutationName', 'inputsSha256', 'fixtureId', 'entityKind', 'origin', 'token']) {
    if (typeof value[key] !== 'string' || value[key].length === 0) throw fail('CONTRACT_INVALID', 'PINNED_JOB без поля ' + key);
  }
  if (!value.fields || typeof value.fields !== 'object' || Array.isArray(value.fields)) throw fail('CONTRACT_INVALID', 'PINNED_JOB.fields не объект');
  if (value.fields.fixtureId !== value.fixtureId) throw fail('CONTRACT_INVALID', 'fields.fixtureId не совпал с PINNED_JOB.fixtureId');
  return value;
}

function pinnedConnection(handle, originText, timeoutMs) {
  const origin = new URL(originText);
  if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || !origin.port) throw fail('CONTRACT_INVALID', 'PINNED_JOB.origin не локальный http-стенд');
  if (!handle || typeof handle.destroyed !== 'boolean') throw fail('CONTRACT_INVALID', 'Handle закреплённого сокета не получен');
  if (handle.destroyed) throw fail('ENVIRONMENT_UNAVAILABLE', 'Закреплённый сокет уже разорван');
  if (String(handle.remoteAddress) !== '127.0.0.1' || Number(handle.remotePort) !== Number(origin.port)) throw fail('ENVIRONMENT_UNAVAILABLE', 'Handle сокета не принадлежит origin среды');
  return {
    socket: handle,
    origin: origin.origin,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? Math.floor(timeoutMs) : 5000,
    agent: createPinnedAgent(handle)
  };
}

async function postMutation() {
  const challenge = newChallenge();
  const headers = {
    authorization: 'Bearer ' + job.token,
    'idempotency-key': job.intentId,
    [STAND_CHALLENGE_HEADER]: challenge
  };
  // Единственный POST: только по переданному handle, без redirect и без повторов.
  const response = await pinnedStandRequest(socket, {
    method: 'POST',
    path: '/records',
    headers,
    body: job.fields,
    timeoutMs: socket.timeoutMs
  });
  const body = response.body;
  const entity = body && body.id ? { kind: job.entityKind, id: String(body.id) } : null;
  const signature = readStandResponseSignature(response.headers);
  return { status: response.status, body, entity, signature, challenge, text: response.text };
}

async function execute(handle) {
  socket = pinnedConnection(handle, job.origin, job.timeoutMs);
  await event('STEP', { stepId: job.stepId, status: 'INTENT_PENDING' });
  const commandId = randomUUID();
  const ackPromise = waitAck(commandId);
  await send({ type: 'INTENT', commandId, runId: job.runId, payload: {
    intentId: job.intentId, stepId: job.stepId, operationId: job.operationId,
    mutationName: job.mutationName, inputsSha256: job.inputsSha256, fixtureId: job.fixtureId
  } });
  const ack = await ackPromise;
  if (ack.durable !== true || ack.intentId !== job.intentId) throw fail('INTEGRITY_ERROR', 'ACK не подтверждает durable intent');
  await event('STEP', { stepId: job.stepId, status: 'DISPATCHED' });

  const evidenceAck = waitEvidenceAck(requestId);
  await event('HTTP_REQUEST', {
    requestId, intentId: job.intentId, method: 'POST', path: '/records',
    fixtureId: job.fixtureId, fields: job.fields, operationId: job.operationId
  });
  await evidenceAck;
  if (controlLost || !process.connected) throw fail('WORKER_LOST', 'Control IPC отключён перед POST');

  // T-C в Worker'е: закреплённое соединение переаттестуется на самом сокете непосредственно перед POST.
  const prePost = await attestPinnedConnection(socket, {
    trust: loadTrustRoot(job.trustRoot),
    record: job.environmentRecord,
    standPublicKey: job.standPublicKey
  });

  let posted;
  try {
    posted = await postMutation();
  } catch (error) {
    // POST уже мог уйти: не повторяем. Control обязан дать INCONCLUSIVE.
    try { await event('HTTP_FAILED', { requestId, reason: String(error?.message || error).slice(0, 160), stage: 'post' }); } catch { /* Control потерян */ }
    throw error;
  }

  const responseAck = waitEvidenceAck(requestId);
  await event('HTTP_RESPONSE', {
    requestId,
    status: posted.status,
    responseFixtureId: typeof posted.body?.fixtureId === 'string' ? posted.body.fixtureId : null,
    entity: posted.entity,
    responseSignature: posted.signature,
    responseChallenge: posted.challenge,
    responseBody: posted.body,
    method: 'POST',
    path: '/records',
    prePostAttestation: prePost.attestation
  });
  await responseAck;
  await event('STEP', { stepId: job.stepId, status: 'ACTION_RETURNED' });
  if (!posted.signature) {
    // Ответ без подписи стенда не подтверждает мутацию: PASS запрещён, POST не повторяется.
    throw fail('ENVIRONMENT_ATTESTATION_FAILED', 'Ответ POST не подписан ключом стенда');
  }
  await event('DONE', { status: 'COMPLETED' });
}

process.on('message', (message, handle) => {
  if (message?.type === 'ACK' && message.runId === job?.runId) { ackWaiters.get(message.commandId)?.(message); return; }
  if (message?.type === 'EVIDENCE_ACK' && message.runId === job?.runId) { evidenceWaiters.get(message.requestId)?.(message); return; }
  if (message?.type === 'PINNED_JOB') {
    const running = job !== null;
    try {
      job = assertJob(message.job ?? message);
    } catch (error) {
      try { send({ type: 'ERROR', runId: message?.runId || 'unknown', payload: { code: error.code || 'CONTRACT_INVALID', message: error.message } }); } catch { /* нет IPC */ }
      exitSoon(32);
      return;
    }
    if (running) { try { send({ type: 'ERROR', runId: job.runId, payload: { code: 'CONTRACT_INVALID', message: 'Повторный PINNED_JOB запрещён' } }); } catch { /* нет IPC */ } exitSoon(32); return; }
    execute(handle).then(() => exitSoon(0)).catch(error => {
      const code = error?.code || 'WORKER_LOST';
      send({ type: 'ERROR', runId: job.runId, payload: { code, message: String(error?.message || error).slice(0, 240) } }).catch(() => {}).finally(() => exitSoon(code === 'WORKER_LOST' ? 90 : 32));
    });
    return;
  }
});

process.on('disconnect', () => {
  if (shuttingDown) return;
  controlLost = true;
  exitSoon(90);
});

// Если Control так и не прислал PINNED_JOB — Worker не открывает ничего самостоятельно.
const idleTimer = setTimeout(() => {
  if (job === null) exitSoon(90);
}, 30000);
idleTimer.unref?.();
