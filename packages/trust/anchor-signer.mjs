// Anchor-signer 0.2.1 (WP-08 P0-01).
//
// Новая топология: подписант запускается Control как дочерний процесс и принимает
// заявки только по приватному fork IPC (канал создан доверенным родителем). Путь к
// anchor.key передаётся только через окружение ребёнка; публичного named pipe для
// приёма заявок доверенный путь не открывает.
//
// Совместимый legacy-режим startAnchorSigner/connectAnchorSigner сохранён для тестов
// и старых сценариев, но и он подписывает только при валидной verification-attestation,
// поэтому не является обходом происхождения.
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { execFile, fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { digest } from '../core/canonical.mjs';
import { assertEvidenceRefs } from '../core/evidence-policy.mjs';
import { validateVerdictCoverage } from '../contracts/index.mjs';
import {
  computeReadSetSha256, inspectEvidenceBinding, publishVerificationRecord, readCandidateBody,
  verificationPublicKeyRecord, verifyVerificationAttestation
} from './anchor.mjs';
import { loadTrustRoot, signTrustedDocument, unwrapPrivateKey, verifyTrustedDocument } from './identity.mjs';

const MAX_REQUEST_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 15000;
const signRequestKeys = new Set(['type', 'runDir', 'approvalId', 'anchorId', 'attestation', 'id']);
const registerRequestKeys = new Set(['type', 'runId', 'publicKey', 'verificationPid', 'id']);
const TRUSTED_WORKER_SUFFIX = 'apps' + path.sep + 'verification' + path.sep + 'trusted-worker.mjs';

function powershellPath() {
  const root = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
  return path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === 'EPERM'; }
}

// Происхождение процесса Verification: WMI даёт ParentProcessId/CommandLine без отладки и инъекций.
function queryProcess(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return Promise.resolve(null);
  const script = '$p = Get-CimInstance Win32_Process -Filter "ProcessId=' + String(pid) + '"; if ($p) { $p | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress }';
  return new Promise(resolve => {
    execFile(powershellPath(), ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 5000 }, (error, stdout) => {
      if (error) return resolve(null);
      try { resolve(JSON.parse(String(stdout))); }
      catch { resolve(null); }
    });
  });
}

function normalizedCommandLine(info) {
  const value = String(info?.CommandLine || '').replace(/\//g, '\\');
  return value.toLowerCase();
}

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function assertId(value, what) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 160) fail('CONTRACT_INVALID', what + ': идентификатор вне границы 1…160');
  if (value !== path.win32.basename(value) || value !== path.posix.basename(value) || value.includes('..')) fail('CONTRACT_INVALID', what + ': идентификатор нельзя использовать как путь');
}

function exactKeys(value, keys, what) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('CONTRACT_INVALID', what + ' не объект');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('CONTRACT_INVALID', what + ' содержит поле вне протокола');
}

function anchorFile(trustRoot, anchorId) {
  assertId(anchorId, 'anchorId');
  const directory = path.resolve(trustRoot, 'anchors');
  const file = path.resolve(directory, anchorId + '.json');
  if (path.dirname(file) !== directory) fail('CONTRACT_INVALID', 'Файл анкера выходит из каталога');
  return { directory, file };
}

function listAnchors(trustRoot) {
  const directory = path.resolve(trustRoot, 'anchors');
  if (!fs.existsSync(directory)) return [];
  const items = [];
  for (const name of fs.readdirSync(directory).filter(name => name.endsWith('.json')).sort()) {
    try { items.push(JSON.parse(fs.readFileSync(path.join(directory, name), 'utf8'))); }
    catch { /* повреждённый анкер не становится годным и не переписывается */ }
  }
  return items;
}

function channelCode(code) {
  if (code === 'VERIFICATION_ATTESTATION_INVALID' || code === 'VERIFICATION_ATTESTATION_MISSING') return 'ANCHOR_BINDING_REJECTED';
  if (['ANCHOR_CONFLICT', 'CONTRACT_INVALID', 'TRUST_STORE_UNAVAILABLE', 'INTEGRITY_ERROR', 'ANCHOR_SIGNATURE_INVALID', 'ANCHOR_UNAVAILABLE'].includes(code)) return code;
  return 'ANCHOR_BINDING_REJECTED';
}

function sameStatementSemantics(left, right) {
  return left.runId === right.runId && left.manifestSha256 === right.manifestSha256 &&
    left.candidateSha256 === right.candidateSha256 && left.approvalId === right.approvalId &&
    left.inputsHash === right.inputsHash && left.environmentId === right.environmentId &&
    left.environmentGeneration === right.environmentGeneration && left.verdict === right.verdict &&
    left.reasonCode === right.reasonCode && left.chainHead?.sequence === right.chainHead?.sequence &&
    left.chainHead?.envelopeSha256 === right.chainHead?.envelopeSha256 &&
    left.verificationAttestationSha256 === right.verificationAttestationSha256 &&
    left.verificationKeyId === right.verificationKeyId;
}

// Приватный канал Control→подписант: не публикует сокет и не принимает внешних подключений.
function createSignerSession({ trustRoot, privateKeyPath, privateKey, inProcess = false } = {}) {
  if (typeof trustRoot !== 'string' || trustRoot.length === 0) throw new TypeError('Нужен trustRoot');
  const resolvedTrust = path.resolve(trustRoot);
  const resolvedKeyPath = privateKeyPath ? path.resolve(privateKeyPath) : null;
  if (!resolvedKeyPath && !privateKey) throw new TypeError('Нужен путь к anchor.key или загруженный ключ');
  let anchorKey = privateKey && typeof privateKey === 'object' && privateKey.type === 'private' ? privateKey : null;
  // Ключ Verification регистрируется в этой сессии подписанта на конкретный runId.
  const verificationKeys = new Map();

  async function loadPrivateKey() {
    if (!anchorKey) anchorKey = await unwrapPrivateKey(resolvedKeyPath);
    return anchorKey;
  }

  function registerVerificationKey(request) {
    assertId(request.runId, 'runId');
    if (!Number.isSafeInteger(request.verificationPid) || request.verificationPid < 1) fail('CONTRACT_INVALID', 'Регистрация ключа Verification требует verificationPid');
    const normalized = verificationPublicKeyRecord(request.publicKey);
    const previous = verificationKeys.get(request.runId);
    if (previous && (previous.keyId !== normalized.keyId || previous.verificationPid !== request.verificationPid)) {
      fail('CONTRACT_INVALID', 'Для runId уже зарегистрирован другой ключ или процесс Verification');
    }
    verificationKeys.set(request.runId, { ...normalized, verificationPid: request.verificationPid });
    return { keyId: normalized.keyId };
  }

  // Подписант подтверждает происхождение ключа: зарегистрированный verification-pid — потомок
  // того же Control (process.ppid подписанта), образ — доверенный trusted-worker.mjs, процесс жив.
  async function assertVerificationProvenance(runId, registered) {
    // В доверенной топологии подписант — дочерний процесс Control, поэтому его родитель process.ppid.
    // Legacy named-pipe режим исполняется в процессе Control, там эквивалент родителя — process.pid.
    const controlPid = inProcess ? process.pid : process.ppid;
    const verificationPid = registered.verificationPid;
    if (!processAlive(verificationPid)) fail('ANCHOR_BINDING_REJECTED', 'Процесс Verification не жив на момент подписи');
    const [verificationInfo, controlInfo] = await Promise.all([queryProcess(verificationPid), queryProcess(controlPid)]);
    if (!verificationInfo) fail('ANCHOR_BINDING_REJECTED', 'Происхождение процесса Verification не подтверждено WMI');
    if (Number(verificationInfo.ParentProcessId) !== Number(controlPid)) fail('ANCHOR_BINDING_REJECTED', 'Родитель процесса Verification не является Control этой сессии');
    if (!controlInfo) fail('ANCHOR_BINDING_REJECTED', 'Родитель подписанта (Control) не подтверждён WMI');
    const commandLine = normalizedCommandLine(verificationInfo);
    if (!commandLine.includes(TRUSTED_WORKER_SUFFIX.toLowerCase())) fail('ANCHOR_BINDING_REJECTED', 'Образ процесса Verification не является доверенным apps/verification/trusted-worker.mjs');
    const executable = String(verificationInfo.ExecutablePath || '').toLowerCase();
    if (!executable.endsWith('node.exe')) fail('ANCHOR_BINDING_REJECTED', 'Процесс Verification запущен не доверенным интерпретатором Node');
    void runId;
    return { controlPid, verificationPid };
  }

  function assertNoTerminalChoice(runDir) {
    if (fs.existsSync(path.join(runDir, 'trust', 'terminal-choice.json'))) fail('ANCHOR_BINDING_REJECTED', 'terminal-choice.json уже существует: новая подпись PASS не выпускается');
  }

  function reuseOrConflict(file, expectedBody) {
    let existing;
    try { existing = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { fail('ANCHOR_CONFLICT', 'Существующее заявление анкера не читается и не заменяется'); }
    let body;
    try { body = verifyTrustedDocument(loadTrustRoot(resolvedTrust), existing); }
    catch { fail('ANCHOR_CONFLICT', 'Существующее заявление анкера не проходит подпись и не заменяется'); }
    if (!sameStatementSemantics(body, expectedBody)) fail('ANCHOR_CONFLICT', 'Для этого anchorId уже подписано другое заявление');
    return existing;
  }

  async function signAndPublish(request) {
    const trust = loadTrustRoot(resolvedTrust);
    const key = await loadPrivateKey();
    assertNoTerminalChoice(request.runDir);
    const binding = inspectEvidenceBinding({ trust, trustRoot: resolvedTrust, runDir: request.runDir, approvalId: request.approvalId, mode: 'pre-verdict' });
    const runId = binding.frozen.manifest.runId;
    const registered = verificationKeys.get(runId);
    if (!registered) fail('ANCHOR_BINDING_REJECTED', 'Ключ Verification для этого runId не зарегистрирован в сессии подписанта');
    await assertVerificationProvenance(runId, registered);
    const attestation = request.attestation;
    if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) fail('ANCHOR_BINDING_REJECTED', 'Verification-attestation не передана по приватному каналу');
    // Подписант проверяет подпись аттестации ключом, зарегистрированным в этой сессии.
    const attested = verifyVerificationAttestation(attestation, { publicKey: registered, expectedKeyId: registered.keyId });
    if (attested.runId !== runId) fail('ANCHOR_BINDING_REJECTED', 'Аттестация Verification относится к другому runId');
    if (attested.manifestSha256 !== binding.frozen.manifestSha256) fail('ANCHOR_BINDING_REJECTED', 'Аттестация Verification относится к другому манифесту');
    if (attested.approvalId !== binding.approval.approvalId) fail('ANCHOR_BINDING_REJECTED', 'Аттестация Verification относится к другому approvalId');
    if (attested.candidateSha256 !== binding.candidate.candidateSha256) fail('ANCHOR_BINDING_REJECTED', 'Аттестация Verification подписана на другой candidateSha256');
    if (attested.evidenceChainHead?.sequence !== binding.chainHead?.sequence || attested.evidenceChainHead?.envelopeSha256 !== binding.chainHead?.envelopeSha256) {
      fail('ANCHOR_BINDING_REJECTED', 'evidenceChainHead аттестации не совпал с главой цепочки');
    }
    if (attested.decision?.verdict !== binding.candidate.candidate.verdict || attested.decision?.reasonCode !== binding.candidate.candidate.reasonCode) {
      fail('ANCHOR_BINDING_REJECTED', 'decision аттестации не совпал с candidate');
    }
    const readSetSha256 = computeReadSetSha256(binding.evidence);
    if (attested.readSetSha256 !== readSetSha256) fail('INTEGRITY_ERROR', 'readSetSha256 аттестации не совпал с durable evidence');
    const chosen = readCandidateBody(request.runDir, binding.candidate.candidateSha256);
    if (!chosen) fail('ANCHOR_BINDING_REJECTED', 'Тело candidate не найдено в каталоге прогона');
    // Паритет 0.1 до подписи: ссылки evidence, terminal-инварианты и покрытие verdict.
    assertEvidenceRefs(binding.evidence, binding.frozen, { requireMutation: true });
    const reads = binding.evidence.filter(item => item.envelope.kind === 'independent-read');
    validateVerdictCoverage(chosen.candidate, binding.frozen.operation, reads);
    if (['PASS', 'FAIL'].includes(chosen.candidate.verdict)) {
      const response = binding.evidence.find(item => item.envelope.kind === 'response');
      if (!response || reads.length === 0) fail('INTEGRITY_ERROR', 'PASS/FAIL без подтверждённого ответа и независимых чтений не подписывается');
    }
    const statementBody = {
      schemaVersion: '0.2.0',
      domain: 'anchor-statement',
      anchorId: request.anchorId,
      runId,
      manifestSha256: binding.frozen.manifestSha256,
      chainHead: binding.chainHead,
      candidateSha256: binding.candidate.candidateSha256,
      verdict: chosen.candidate.verdict,
      reasonCode: chosen.candidate.reasonCode,
      approvalId: binding.approval.approvalId,
      inputsHash: binding.approval.approvedInputsHash,
      environmentId: binding.approval.targetEnvironmentId,
      environmentGeneration: binding.approval.environmentGeneration,
      publishedAt: new Date().toISOString(),
      keyId: trust['anchor-signer'].keyId,
      verificationAttestationSha256: digest(attestation),
      verificationKeyId: attested.verificationKeyId
    };
    const target = anchorFile(resolvedTrust, request.anchorId);
    if (fs.existsSync(target.file)) return reuseOrConflict(target.file, statementBody);
    for (const item of listAnchors(resolvedTrust)) {
      if (item.runId === runId && item.anchorId !== request.anchorId) fail('ANCHOR_CONFLICT', 'Для этого runId уже существует другое заявление анкера');
    }
    // Подписант — единственный писатель аттестации Verification в trust root.
    publishVerificationRecord(resolvedTrust, { runId, attestation, verificationPublicKey: registered });
    assertNoTerminalChoice(request.runDir);
    const statement = signTrustedDocument(key, statementBody);
    try {
      fs.mkdirSync(target.directory, { recursive: true });
      // D-03: повторная проверка непосредственно перед CREATE_NEW сужает окно гонки с выбором исхода.
      assertNoTerminalChoice(request.runDir);
      const fd = fs.openSync(target.file, 'wx', 0o600);
      try { fs.writeFileSync(fd, Buffer.from(JSON.stringify(statement) + '\n', 'utf8')); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
    } catch (error) {
      if (error.code !== 'EEXIST') fail('TRUST_STORE_UNAVAILABLE', 'Заявление анкера не записано');
      return reuseOrConflict(target.file, statementBody);
    }
    // D-03: если выбор исхода появился за время записи, подпись не считается выпущенной.
    assertNoTerminalChoice(request.runDir);
    const written = JSON.parse(fs.readFileSync(target.file, 'utf8'));
    const reloaded = verifyTrustedDocument(loadTrustRoot(resolvedTrust), written);
    if (digest(reloaded) !== digest(statementBody)) fail('INTEGRITY_ERROR', 'Повторное чтение анкера не сошлось');
    return written;
  }

  async function handleRequest(raw) {
    if (typeof raw !== 'string' || raw.length > MAX_REQUEST_BYTES) fail('CONTRACT_INVALID', 'Запрос подписанту слишком велик');
    let request;
    try { request = JSON.parse(raw); }
    catch { fail('CONTRACT_INVALID', 'Запрос подписанту не JSON'); }
    if (!request || typeof request !== 'object' || Array.isArray(request)) fail('CONTRACT_INVALID', 'Запрос подписанту не объект');
    if (request.id !== undefined && typeof request.id !== 'number' && typeof request.id !== 'string') fail('CONTRACT_INVALID', 'Служебный id запроса имеет неверную форму');
    if (request.type === 'register-verification-key') {
      for (const name of Object.keys(request)) if (!registerRequestKeys.has(name)) fail('CONTRACT_INVALID', 'Запрос регистрации ключа содержит поле вне протокола');
      return { ok: true, ...registerVerificationKey(request) };
    }
    if (request.type !== 'sign') fail('CONTRACT_INVALID', 'Подписант принимает только типы sign и register-verification-key');
    for (const name of Object.keys(request)) if (!signRequestKeys.has(name)) fail('CONTRACT_INVALID', 'Запрос подписанту содержит поле вне протокола');
    if (typeof request.runDir !== 'string' || !path.isAbsolute(request.runDir)) fail('CONTRACT_INVALID', 'runDir должен быть абсолютным путём');
    assertId(request.approvalId, 'approvalId');
    assertId(request.anchorId, 'anchorId');
    if (request.attestation === undefined) fail('CONTRACT_INVALID', 'Запрос sign обязан нести verification-attestation');
    return { ok: true, statement: await signAndPublish(request) };
  }

  return { signAndPublish, handleRequest, registerVerificationKey };
}

function handleMessage(session, message, respond) {
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    respond({ ok: false, code: 'CONTRACT_INVALID', message: 'Сообщение приватного канала не объект' });
    return;
  }
  const requestId = message.id ?? null;
  const { id, ...payload } = message;
  void id;
  Promise.resolve()
    .then(() => session.handleRequest(JSON.stringify(payload)))
    .then(result => respond({ id: requestId, ...result }))
    .catch(error => respond({ id: requestId, ok: false, code: channelCode(error.code), message: error.message }));
}

// Дочерний процесс подписанта: только приватный IPC, ключ — только из окружения ребёнка.
async function runChildSigner() {
  const trustRoot = process.env.QA_TRUST_ROOT;
  const anchorKeyPath = process.env.QA_ANCHOR_KEY_PATH;
  if (typeof trustRoot !== 'string' || !trustRoot) throw new Error('Подписанту не передан trust root');
  if (typeof anchorKeyPath !== 'string' || !anchorKeyPath) throw new Error('Подписанту не передан путь к anchor.key');
  const session = createSignerSession({ trustRoot, privateKeyPath: anchorKeyPath });
  const respond = payload => { try { if (process.connected) process.send(payload); } catch { /* родитель ушёл */ } };
  process.on('message', message => handleMessage(session, message, respond));
  process.on('disconnect', () => { process.exitCode = 0; });
  await new Promise(resolve => process.once('disconnect', resolve));
}

export function startAnchorSigner({ trustRoot, secretsDir, pipePath } = {}) {
  if (typeof trustRoot !== 'string' || trustRoot.length === 0) throw new TypeError('Нужен trustRoot');
  if (typeof secretsDir !== 'string' || secretsDir.length === 0) throw new TypeError('Нужны secretsDir');
  const resolvedTrust = path.resolve(trustRoot);
  const resolvedSecrets = path.resolve(secretsDir);
  const pipe = pipePath || '\\\\.\\pipe\\qa-adaptant-anchor-' + randomBytes(8).toString('hex');
  const session = createSignerSession({ trustRoot: resolvedTrust, privateKeyPath: path.join(resolvedSecrets, 'anchor.key'), inProcess: true });
  const sockets = new Set();

  const server = net.createServer(socket => {
    sockets.add(socket);
    let buffer = '';
    let queue = Promise.resolve();
    socket.setEncoding('utf8');
    const respond = payload => { try { socket.write(JSON.stringify(payload) + '\n'); } catch { /* соединение уже закрыто */ } };
    socket.on('data', chunk => {
      buffer += chunk;
      if (buffer.length > MAX_REQUEST_BYTES) { respond({ ok: false, code: 'CONTRACT_INVALID', message: 'Запрос подписанту превышает предел' }); buffer = ''; return; }
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (!line.trim()) continue;
        queue = queue.then(async () => {
          let requestId = null;
          try { requestId = JSON.parse(line).id ?? null; } catch { /* ошибка разбора уходит в обработчик */ }
          try { respond({ id: requestId, ...(await session.handleRequest(line)) }); }
          catch (error) { respond({ id: requestId, ok: false, code: channelCode(error.code), message: error.message }); }
        });
      }
    });
    socket.on('error', () => { /* клиент ушёл; сервер остаётся */ });
    socket.on('close', () => sockets.delete(socket));
  });

  let resolveReady;
  let rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  server.once('error', error => rejectReady(error));
  server.listen(pipe, () => resolveReady());

  return {
    pipePath: pipe,
    ready,
    close() {
      for (const socket of sockets) { try { socket.destroy(); } catch { /* уже закрыт */ } }
      sockets.clear();
      return new Promise(resolve => server.close(() => resolve()));
    }
  };
}

// Клиент подписанта для legacy named pipe (совместимость с существующими тестами).
export function connectAnchorSigner(pipePath) {
  if (typeof pipePath !== 'string' || pipePath.length === 0) throw new TypeError('Нужен путь named pipe');
  const socket = net.connect(pipePath);
  socket.setEncoding('utf8');
  const pending = new Map();
  let nextId = 1;
  let connected = false;
  let closed = false;
  let buffer = '';

  socket.on('connect', () => { connected = true; });
  socket.on('data', chunk => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (!line.trim()) continue;
      let message;
      try { message = JSON.parse(line); } catch { continue; }
      const entry = pending.get(message.id);
      if (!entry) continue;
      pending.delete(message.id);
      clearTimeout(entry.timer);
      if (message.ok) entry.resolve(message);
      else entry.reject(Object.assign(new Error(message.message || 'Подписант отказал'), { code: message.code || 'ANCHOR_BINDING_REJECTED' }));
    }
  });
  const rejectAll = error => {
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(error); }
    pending.clear();
  };
  socket.on('error', error => { rejectAll(Object.assign(new Error(error.message), { code: 'ANCHOR_UNAVAILABLE' })); });
  socket.on('close', () => { closed = true; rejectAll(Object.assign(new Error('Канал подписанта закрыт'), { code: 'ANCHOR_UNAVAILABLE' })); });

  function write(request) {
    return new Promise((resolve, reject) => {
      if (closed) { reject(Object.assign(new Error('Канал подписанта закрыт'), { code: 'ANCHOR_UNAVAILABLE' })); return; }
      const id = nextId++;
      const timer = setTimeout(() => { pending.delete(id); reject(Object.assign(new Error('Подписант не ответил'), { code: 'ANCHOR_UNAVAILABLE' })); }, REQUEST_TIMEOUT_MS);
      pending.set(id, { resolve, reject, timer });
      const send = () => {
        try { socket.write(JSON.stringify({ ...request, id }) + '\n'); }
        catch (error) { pending.delete(id); clearTimeout(timer); reject(Object.assign(new Error(error.message), { code: 'ANCHOR_UNAVAILABLE' })); }
      };
      if (connected) send();
      else socket.once('connect', send);
    });
  }

  return {
    async registerVerificationKey(runId, publicKey, verificationPid) {
      assertId(runId, 'runId');
      if (!publicKey) fail('CONTRACT_INVALID', 'Нужен публичный ключ Verification');
      const answer = await write({ type: 'register-verification-key', runId, publicKey: verificationPublicKeyRecord(publicKey), verificationPid });
      return { keyId: answer.keyId };
    },
    sign(payload = {}) {
      const allowed = new Set(['runDir', 'approvalId', 'anchorId', 'attestation']);
      for (const key of Object.keys(payload)) if (!allowed.has(key)) fail('CONTRACT_INVALID', 'sign() не принимает поле вне протокола: ' + key);
      if (!payload.attestation) fail('CONTRACT_INVALID', 'sign() требует verification-attestation');
      return write({ type: 'sign', runDir: payload.runDir, approvalId: payload.approvalId, anchorId: payload.anchorId, attestation: payload.attestation }).then(answer => answer.statement);
    },
    close() {
      closed = true;
      rejectAll(Object.assign(new Error('Канал подписанта закрыт'), { code: 'ANCHOR_UNAVAILABLE' }));
      return new Promise(resolve => { socket.once('close', resolve); socket.end(); setTimeout(resolve, 500); });
    }
  };
}

// Доверенный клиент: подписант запускается как дочерний процесс с приватным fork IPC.
export function spawnAnchorSigner({ trustRoot, anchorKeyPath, timeoutMs } = {}) {
  if (typeof trustRoot !== 'string' || trustRoot.length === 0) throw new TypeError('Нужен trustRoot');
  if (typeof anchorKeyPath !== 'string' || anchorKeyPath.length === 0) throw new TypeError('Нужен путь к anchor.key');
  const entry = fileURLToPath(import.meta.url);
  const child = fork(entry, [], {
    stdio: ['ignore', 'ignore', process.env.QA_ADAPTANT_DEBUG === '1' ? 'inherit' : 'ignore', 'ipc'],
    env: {
      ...process.env,
      QA_ANCHOR_SIGNER_CHILD: '1',
      QA_TRUST_ROOT: path.resolve(trustRoot),
      QA_ANCHOR_KEY_PATH: path.resolve(anchorKeyPath)
    }
  });
  const pending = new Map();
  let nextId = 1;
  let closed = false;
  const deadline = Number.isSafeInteger(timeoutMs) && timeoutMs > 0 ? timeoutMs : REQUEST_TIMEOUT_MS;
  const rejectAll = error => {
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(error); }
    pending.clear();
  };
  child.on('message', message => {
    if (!message || typeof message !== 'object') return;
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);
    clearTimeout(entry.timer);
    if (message.ok) entry.resolve(message);
    else entry.reject(Object.assign(new Error(message.message || 'Подписант отказал'), { code: message.code || 'ANCHOR_BINDING_REJECTED' }));
  });
  child.on('error', error => rejectAll(Object.assign(new Error(error.message), { code: 'ANCHOR_UNAVAILABLE' })));
  child.on('exit', code => {
    closed = true;
    rejectAll(Object.assign(new Error('Приватный канал подписанта закрыт: exit=' + code), { code: 'ANCHOR_UNAVAILABLE' }));
  });

  function request(payload) {
    return new Promise((resolve, reject) => {
      if (closed) { reject(Object.assign(new Error('Приватный канал подписанта закрыт'), { code: 'ANCHOR_UNAVAILABLE' })); return; }
      const id = nextId++;
      const timer = setTimeout(() => { pending.delete(id); reject(Object.assign(new Error('Подписант не ответил'), { code: 'ANCHOR_UNAVAILABLE' })); }, deadline);
      pending.set(id, { resolve, reject, timer });
      try { child.send({ ...payload, id }); }
      catch (error) { pending.delete(id); clearTimeout(timer); reject(Object.assign(new Error(error.message), { code: 'ANCHOR_UNAVAILABLE' })); }
    });
  }

  return {
    pid: child.pid,
    async registerVerificationKey(runId, publicKey, verificationPid) {
      assertId(runId, 'runId');
      if (!publicKey) fail('CONTRACT_INVALID', 'Нужен публичный ключ Verification');
      const answer = await request({ type: 'register-verification-key', runId, publicKey: verificationPublicKeyRecord(publicKey), verificationPid });
      return { keyId: answer.keyId };
    },
    sign(payload = {}) {
      const allowed = new Set(['runDir', 'approvalId', 'anchorId', 'attestation']);
      for (const key of Object.keys(payload)) if (!allowed.has(key)) fail('CONTRACT_INVALID', 'sign() не принимает поле вне протокола: ' + key);
      if (!payload.attestation) fail('CONTRACT_INVALID', 'sign() требует verification-attestation');
      return request({ type: 'sign', runDir: payload.runDir, approvalId: payload.approvalId, anchorId: payload.anchorId, attestation: payload.attestation }).then(answer => answer.statement);
    },
    close() {
      if (closed) return Promise.resolve();
      closed = true;
      rejectAll(Object.assign(new Error('Приватный канал подписанта закрыт'), { code: 'ANCHOR_UNAVAILABLE' }));
      return new Promise(resolve => {
        child.once('exit', resolve);
        try { child.disconnect(); } catch { /* уже отключён */ }
        try { child.kill(); } catch { /* уже завершён */ }
        setTimeout(resolve, 500);
      });
    }
  };
}

if (process.env.QA_ANCHOR_SIGNER_CHILD === '1') {
  await runChildSigner();
}
