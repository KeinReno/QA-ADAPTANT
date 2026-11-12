import fs from 'node:fs';
import path from 'node:path';
import { execFile, execFileSync, fork } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { assertTerminalEvidence } from '../../packages/core/evidence-policy.mjs';
import { assertApprovedOperation } from '../../packages/core/approved-registry.mjs';
import { IntentCommand, IntentAck, reasonCodes, validate, validateVerdictCoverage } from '../../packages/contracts/index.mjs';

const activeBrowsers = new Map();
const cancellations = new Map();
const now = () => new Date().toISOString();
const equal = (a, b) => digest(a) === digest(b);
const fail = (code, message) => Object.assign(new Error(message), { code });

function safeRunId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(value)) throw fail('CONTRACT_INVALID', 'Некорректный runId');
  return value;
}

async function readJson(url, timeoutMs = 2500) {
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json' } });
  if (response.status < 200 || response.status >= 300 || response.headers.has('location')) throw fail('FIXTURE_UNAVAILABLE', `Стенд вернул HTTP ${response.status}`);
  return response.json();
}

function resultVerdict(bundle, verdict, reasonCode, message, { ownershipVerified = false, integrityVerified = true, checks } = {}) {
  return validate('VerdictPolicy', {
    schemaVersion: '0.1.0', runId: bundle.manifest.runId, manifestSha256: bundle.manifestSha256,
    verdict, reasonCode, message,
    checks: checks || bundle.operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] })),
    ownershipVerified, integrityVerified, completedAt: now()
  });
}

function spawnWorker(file, args = [], env = {}) {
  const stderr = process.env.QA_ADAPTANT_DEBUG === '1' ? 'inherit' : 'ignore';
  return fork(file, args, { stdio: ['ignore', 'ignore', stderr, 'ipc'], env: { ...process.env, ...env } });
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === 'EPERM'; }
}

function recordedBrowserPid(runDir) {
  const recorded = readJsonFile(path.join(runDir, 'browser.pid'));
  if (!recorded?.nonce || !pidAlive(recorded.pid)) return null;
  if (process.platform === 'win32') {
    try {
      const output = execFileSync('powershell.exe', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(recorded.pid)}").CommandLine`], { encoding: 'utf8', windowsHide: true, timeout: 3000 });
      if (!output.includes(recorded.nonce)) return null;
    } catch { return null; }
  }
  return recorded.pid;
}

function killTree(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  try { process.kill(pid, 'SIGKILL'); } catch {}
  if (process.platform === 'win32') execFile('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true }, () => {});
}

function readJsonFile(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function leasePath(root, environmentId, fixtureId) {
  return path.join(root, 'leases', `${digest({ environmentId, fixtureId })}.json`);
}

function cancelFile(runDir) { return path.join(runDir, 'cancel.request'); }

function cancelRequested(runDir, runId) {
  return cancellations.has(runId) || fs.existsSync(cancelFile(runDir));
}

function foreignOwnerAlive(runDir) {
  const owner = readJsonFile(path.join(runDir, 'owner.json'));
  return Boolean(owner && owner.pid !== process.pid && pidAlive(owner.pid));
}

function acquireLease(root, environmentId, fixtureId, runId) {
  const file = leasePath(root, environmentId, fixtureId);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const token = randomUUID();
  const body = `${JSON.stringify({ runId, pid: process.pid, token, at: now() })}\n`;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const fd = fs.openSync(file, 'wx', 0o600);
      fs.writeFileSync(fd, body); fs.fsyncSync(fd); fs.closeSync(fd);
      return { file, token };
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const current = readJsonFile(file);
      if (current?.runId === runId && current.pid === process.pid) return { file, token: current.token };
      if (current && pidAlive(current.pid)) throw fail('CONTRACT_INVALID', 'Fixture занят живым прогоном');
      try { fs.unlinkSync(file); } catch {}
    }
  }
  throw fail('CONTRACT_INVALID', 'Не удалось получить владение fixture');
}

function releaseLease(lease, runId) {
  if (!lease) return;
  const current = readJsonFile(lease.file);
  if (current?.runId === runId && current.pid === process.pid && current.token === lease.token) {
    try { fs.unlinkSync(lease.file); } catch {}
  }
}

function assertLease(lease, runId) {
  const current = readJsonFile(lease?.file || '');
  if (!current || current.runId !== runId || current.token !== lease?.token || current.pid !== process.pid) {
    throw fail('INTEGRITY_ERROR', 'Владение fixture потеряно до подтверждения мутации');
  }
}

function mutationEvidenceKnown(store, runId) {
  const runDir = store.runPath(runId);
  if (!fs.existsSync(runDir)) return false;
  try {
    return store.readEvidence(runDir).some(item => ['mutation-intent', 'request', 'response'].includes(item.envelope.kind));
  } catch {
    return true;
  }
}

function canReleaseFixture(store, current) {
  if (!current?.runId) return true;
  const owner = readJsonFile(path.join(store.runPath(current.runId), 'owner.json'));
  if (owner && pidAlive(owner.pid) && owner.pid !== process.pid) return false;
  return !mutationEvidenceKnown(store, current.runId);
}

function claimFixture(store, environmentId, fixtureId, runId) {
  const parent = path.join(store.root, 'fixtures');
  fs.mkdirSync(parent, { recursive: true });
  const dir = path.join(parent, digest({ environmentId, fixtureId }));
  const body = `${JSON.stringify({ runId, environmentId, fixtureId, pid: process.pid, at: now() })}\n`;
  const publish = () => {
    const temp = path.join(parent, `.bind-${process.pid}-${randomUUID()}`);
    fs.mkdirSync(temp);
    const fd = fs.openSync(path.join(temp, 'bind.json'), 'wx', 0o600);
    try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    try { fs.renameSync(temp, dir); }
    catch (error) {
      fs.rmSync(temp, { recursive: true, force: true });
      if (error.code !== 'EEXIST' && error.code !== 'EPERM') throw error;
      return false;
    }
    return true;
  };
  if (fs.existsSync(dir)) {
    const current = readJsonFile(path.join(dir, 'bind.json'));
    if (current?.runId === runId) return dir;
    if (!canReleaseFixture(store, current)) throw fail('CONTRACT_INVALID', 'Fixture уже связан с другим прогоном');
    const released = path.join(store.root, 'quarantine', `fixture-${path.basename(dir)}-${Date.now()}`);
    fs.mkdirSync(path.dirname(released), { recursive: true });
    fs.renameSync(dir, released);
  }
  if (!publish()) {
    const current = readJsonFile(path.join(dir, 'bind.json'));
    if (current?.runId === runId) return dir;
    throw fail('CONTRACT_INVALID', 'Fixture уже связан с другим прогоном');
  }
  return dir;
}

function createLockMarker(lockFile, runId) {
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  const body = `${JSON.stringify({ runId, pid: process.pid, at: now() })}\n`;
  const write = () => {
    const fd = fs.openSync(lockFile, 'wx', 0o600);
    fs.writeFileSync(fd, body); fs.fsyncSync(fd); fs.closeSync(fd);
  };
  try { write(); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const current = readJsonFile(lockFile);
    if (current && pidAlive(current.pid) && current.runId !== runId) throw fail('CONTRACT_INVALID', 'Fixture lock занят');
    try { fs.unlinkSync(lockFile); } catch {}
    write();
  }
}

function runningView(runId, runDir, store) {
  return { runId, runDir, state: 'RUNNING', verdict: null, evidenceIds: store.readEvidence(runDir).map(item => item.envelope.evidenceId) };
}

async function waitForChild(child, timeoutMs = 30000) {
  if (child.exitCode !== null || child.signalCode !== null) return { code: child.exitCode, signal: child.signalCode };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(fail('WORKER_LOST', 'Истёк срок ожидания дочернего процесса')); }, timeoutMs);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', (code, signal) => { clearTimeout(timer); resolve({ code, signal }); });
  });
}

export async function run(bundle, { root, headed = false, fault = null, fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '' } = {}) {
  if (!root) throw new TypeError('Нужен корень локального хранилища');
  let runId;
  let lease = null;
  const store = new RunStore(root);
  let runDir;
  try {
    runId = safeRunId(bundle?.manifest?.runId);
    validate('ScenarioSchema', bundle.scenario); validate('OperationContract', bundle.operation);
    validate('FixtureContract', bundle.fixture); validate('RunProtocol', bundle.manifest);
    try { runDir = store.snapshot(bundle, { runId, pid: process.pid, at: now() }); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      return await adoptExisting(store, runId, bundle);
    }
    const frozen = verifyFrozenBundle(store, runDir);
    const { manifest, operation, scenario, fixture } = frozen;
    assertApprovedOperation(operation, scenario);
    claimFixture(store, manifest.environment.id, fixture.fixtureId, runId);

    store.appendEvent(runDir, { type: 'STATE', state: 'PREFLIGHT' });
    const before = await readJson(new URL('/environment', manifest.environment.baseUrl));
    if (before.environmentId !== manifest.environment.id || before.fingerprint !== manifest.environment.fingerprint) {
      throw fail('FIXTURE_UNAVAILABLE', 'Идентификатор или fingerprint стенда не совпадает с утверждённым окружением');
    }
    const lockFile = path.join(store.root, 'locks', `${digest({ environmentId: manifest.environment.id, fixtureId: fixture.fixtureId })}.lock`);
    lease = acquireLease(store.root, manifest.environment.id, fixture.fixtureId, runId);
    createLockMarker(lockFile, runId);

    try {
      store.appendEvent(runDir, { type: 'STATE', state: 'RUNNING' });
      if (cancelRequested(runDir, runId)) {
        cancellations.set(runId, true);
        return persistVerdict(store, runDir, frozen, resultVerdict(frozen, 'BLOCKED', 'CANCELED', 'Прогон отменён до отправки мутации'));
      }
      if (fault === 'tamperSnapshotBeforeBrowser') {
        const tampered = store.readSnapshot(runDir, 'operation').value;
        tampered.inputs.title = 'Подмена после проверки Control';
        fs.writeFileSync(path.join(runDir, 'operation.json'), `${JSON.stringify(tampered)}\n`);
      }
      const browserFile = new URL('../browser/worker.mjs', import.meta.url);
      const browserNonce = randomUUID();
      const browser = spawnWorker(browserFile, [runDir, frozen.manifestSha256, browserNonce], {
        QA_ADAPTANT_HEADED: headed ? '1' : '0',
        QA_ADAPTANT_FIXTURE_TOKEN: fixtureToken,
        ...(fault ? { QA_ADAPTANT_FAULT: fault } : {})
      });
      activeBrowsers.set(runId, browser);
      fs.writeFileSync(path.join(runDir, 'browser.pid'), `${JSON.stringify({ pid: browser.pid, nonce: browserNonce })}\n`);
      const cancelPoll = setInterval(() => {
        if (cancelRequested(runDir, runId)) { cancellations.set(runId, true); killTree(browser.pid); }
      }, 40);
      cancelPoll.unref();
      let intentRecord = null;
      let requestRecord = null;
      let gotDone = false;
      let workerError = null;
      let eventQueue = Promise.resolve();
      const ack = message => new Promise((resolve, reject) => browser.send(message, error => error ? reject(error) : resolve()));
      browser.on('message', message => {
        eventQueue = eventQueue.then(async () => {
          if (!message || message.runId !== runId || typeof message.type !== 'string') throw fail('INTEGRITY_ERROR', 'Некорректное сообщение Browser IPC');
          if (message.type === 'INTENT') {
            assertLease(lease, runId);
            const command = IntentCommand.parse(message);
            const payload = command.payload;
            const click = scenario.nodes.find(n => n.id === payload.stepId)?.action;
            if (!click || click.type !== 'click' || !click.mutation || payload.operationId !== operation.id || payload.mutationName !== operation.mutation.name || payload.fixtureId !== fixture.fixtureId || payload.inputsSha256 !== digest(operation.inputs)) throw fail('CONTRACT_INVALID', 'INTENT не совпадает с утверждённой мутацией');
            if (intentRecord) {
              if (!equal(intentRecord.artifact, payload)) throw fail('INTEGRITY_ERROR', 'Повторный INTENT содержит другой payload');
            } else {
              const envelope = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: payload.stepId, producer: 'control', kind: 'mutation-intent', artifact: payload, parentEvidenceIds: [] });
              intentRecord = { envelope, artifact: payload };
              store.appendEvent(runDir, { type: 'INTENT_DURABLE', intentId: payload.intentId, evidenceId: envelope.evidenceId });
            }
            const response = IntentAck.parse({ type: 'ACK', commandId: command.commandId, runId, intentId: payload.intentId, evidenceId: intentRecord.envelope.evidenceId, durable: true });
            if (fault !== 'dropIntentAck') await ack(response);
            return;
          }
          if (message.type === 'HTTP_REQUEST') {
            assertLease(lease, runId);
            if (!intentRecord || requestRecord) throw fail('CONTRACT_INVALID', 'POST без intent или повторная мутация отклонены');
            const p = message.payload || {};
            const expectedFields = { ...operation.inputs, fixtureId: fixture.fixtureId };
            if (p.method !== 'POST' || p.path !== '/records' || p.operationId !== operation.id || p.intentId !== intentRecord.artifact.intentId || p.fixtureId !== fixture.fixtureId || !p.requestId || !equal(p.fields, expectedFields)) throw fail('CONTRACT_INVALID', 'Фактический POST не совпадает с замороженными inputs');
            const artifact = { requestId: p.requestId, intentId: p.intentId, operationId: p.operationId, method: p.method, path: p.path, fixtureId: p.fixtureId, fields: p.fields };
            const envelope = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: intentRecord.envelope.stepId, producer: 'browser', kind: 'request', artifact, requestId: p.requestId, parentEvidenceIds: [intentRecord.envelope.evidenceId] });
            requestRecord = { envelope, artifact };
            store.appendEvent(runDir, { type: 'REQUEST_DURABLE', requestId: p.requestId, evidenceId: envelope.evidenceId });
            await ack({ type: 'EVIDENCE_ACK', runId, requestId: p.requestId, durable: true });
            return;
          }
          if (message.type === 'HTTP_RESPONSE') {
            const p = message.payload || {};
            if (!requestRecord || p.requestId !== requestRecord.artifact.requestId || !p.entity?.id || p.responseFixtureId !== fixture.fixtureId) {
              store.appendEvent(runDir, { type: 'RESPONSE_UNCONFIRMED', requestId: p.requestId || null });
            } else if (fault !== 'missingEvidence') {
              const artifact = { requestId: p.requestId, intentId: intentRecord.artifact.intentId, operationId: operation.id, fixtureId: p.responseFixtureId, status: p.status, entity: p.entity };
              const envelope = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: requestRecord.envelope.stepId, producer: 'browser', kind: 'response', artifact, requestId: p.requestId, entity: p.entity, parentEvidenceIds: [requestRecord.envelope.evidenceId] });
              store.appendEvent(runDir, { type: 'RESPONSE_DURABLE', requestId: p.requestId, evidenceId: envelope.evidenceId });
            }
            await ack({ type: 'EVIDENCE_ACK', runId, requestId: p.requestId, durable: fault !== 'missingEvidence' });
            return;
          }
          if (message.type === 'DONE') { gotDone = true; store.appendEvent(runDir, { type: 'BROWSER_DONE', status: message.payload?.status }); return; }
          if (message.type === 'ERROR') { workerError = message.payload; store.appendEvent(runDir, { type: 'BROWSER_ERROR', code: workerError?.code || 'BROWSER_ERROR' }); return; }
          if (['READY', 'STEP', 'HTTP_FAILED'].includes(message.type)) {
            store.appendEvent(runDir, { type: message.type, payload: message.payload || {} });
            return;
          }
          throw fail('CONTRACT_INVALID', `Неизвестное событие Browser: ${message.type}`);
        }).catch(error => { workerError ||= { code: error.code || 'CONTROL_IPC_ERROR', message: error.message }; killTree(browser.pid); });
      });
      let exit;
      try { exit = await waitForChild(browser, manifest.budget.deadlineMs); }
      finally {
        clearInterval(cancelPoll);
        activeBrowsers.delete(runId);
        try { fs.unlinkSync(path.join(runDir, 'browser.pid')); } catch {}
      }
      await eventQueue;
      if (exit.code !== 0 && !workerError) workerError = { code: 'WORKER_LOST', message: `Browser завершился с кодом ${exit.code}` };
      const canceled = cancelRequested(runDir, runId);

      store.appendEvent(runDir, { type: 'STATE', state: 'VERIFYING', intentPersisted: Boolean(intentRecord), browserDone: gotDone });
      if (!intentRecord) {
        const code = canceled ? 'CANCELED' : (workerError?.code || 'CONTRACT_INVALID');
        const blocked = ['ELEMENT_AMBIGUOUS', 'CONTRACT_INVALID', 'CANCELED'].includes(code);
        const verdict = resultVerdict(frozen, blocked ? 'BLOCKED' : 'INCONCLUSIVE', blocked ? code : 'WORKER_LOST', canceled ? 'Прогон отменён до отправки мутации' : (workerError?.message || 'Действие не было подтверждено'));
        cancellations.delete(runId);
        return persistVerdict(store, runDir, frozen, verdict);
      }
      const browserUncertain = Boolean(workerError) || !gotDone || exit.code !== 0;
      cancellations.delete(runId);
      return await verifyAndPersist(store, runDir, { fault, browserUncertain, canceled, fixtureToken });
    } finally {
      try { fs.unlinkSync(lockFile); } catch {}
    }
  } catch (error) {
    activeBrowsers.delete(runId);
    cancellations.delete(runId);
    if (!runDir) throw error;
    if (process.env.QA_ADAPTANT_DEBUG === '1') console.error(error);
    const frozen = verifyFrozenBundle(store, runDir);
    const evidence = store.readEvidence(runDir);
    const possiblyMutated = evidence.some(r => r.envelope.kind === 'mutation-intent');
    const integrity = error.code === 'INTEGRITY_ERROR' || error.message?.includes('INTEGRITY_ERROR');
    const candidate = integrity ? 'INTEGRITY_ERROR' : error.code;
    const reasonCode = reasonCodes.includes(candidate) ? candidate : (possiblyMutated ? 'WORKER_LOST' : 'CONTRACT_INVALID');
    const verdict = resultVerdict(frozen, possiblyMutated ? 'INCONCLUSIVE' : 'BLOCKED', reasonCode, error.message || 'Прогон остановлен', { integrityVerified: !integrity });
    return persistVerdict(store, runDir, frozen, verdict);
  } finally {
    if (runId) releaseLease(lease, runId);
  }
}

async function adoptExisting(store, runId, bundle) {
  const runDir = store.runPath(runId);
  for (let attempt = 0; attempt < 40; attempt++) {
    if (!fs.existsSync(path.join(runDir, 'manifest.json')) || !fs.existsSync(path.join(runDir, 'owner.json'))) {
      await new Promise(resolve => setTimeout(resolve, 25));
      continue;
    }
    const frozen = verifyFrozenBundle(store, runDir);
    if (!equal(frozen.scenario, bundle.scenario) || !equal(frozen.operation, bundle.operation) ||
        !equal(frozen.fixture, bundle.fixture) || !equal(frozen.manifest, bundle.manifest)) {
      throw fail('CONTRACT_INVALID', 'Повторный START содержит другой snapshot для того же runId');
    }
    const finished = terminalResult(store, runDir, frozen);
    if (finished) return finished;
    return runningView(runId, runDir, store);
  }
  throw fail('CONTRACT_INVALID', 'Параллельный START не дождался владельца прогона');
}

function terminalResult(store, runDir, frozen) {
  const evidence = store.readEvidence(runDir);
  const verdict = assertTerminalEvidence(evidence, frozen);
  if (!verdict) return null;
  if (verdict.verdict === 'PASS' || verdict.verdict === 'FAIL') assertApprovedOperation(frozen.operation, frozen.scenario);
  const recorded = [...store.readEvents(runDir)].reverse().find(event => event.type === 'VERDICT_DURABLE' || (event.type === 'STATE' && event.state === 'FINISHED' && event.verdict));
  if (recorded && recorded.verdict !== verdict.verdict) throw fail('INTEGRITY_ERROR', 'INTEGRITY_ERROR: вердикт evidence не совпадает с журналом событий');
  return {
    runId: frozen.manifest.runId,
    runDir,
    verdict,
    evidenceIds: evidence.map(item => item.envelope.evidenceId)
  };
}

async function verifyAndPersist(store, runDir, { fault = null, browserUncertain = true, canceled = false, fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '' } = {}) {
  const frozen = verifyFrozenBundle(store, runDir);
  const finished = terminalResult(store, runDir, frozen);
  if (finished) return finished;
  const verificationFile = new URL('../verification/worker.mjs', import.meta.url);
  const args = [runDir, frozen.manifestSha256];
  if (browserUncertain) args.push('--browser-unconfirmed');
  if (canceled) args.push('--cancellation');
  const verification = spawnWorker(verificationFile, args, { QA_ADAPTANT_FAULT: fault || '', QA_ADAPTANT_FIXTURE_TOKEN: fixtureToken });
  const result = await waitForResult(verification, frozen.manifest.runId, frozen.manifest.budget.deadlineMs);
  const verifierExit = await waitForChild(verification, 5000);
  if (verifierExit.code !== 0) throw fail('WORKER_LOST', 'Verification Worker завершился с ошибкой');
  if (canceled || cancelRequested(runDir, frozen.manifest.runId)) {
    return persistVerdict(store, runDir, frozen, resultVerdict(frozen, 'INCONCLUSIVE', 'CANCELED', 'Прогон отменён после начала мутации; повторная мутация не выполняется'));
  }
  const evidence = store.readEvidence(runDir);
  const actualReads = evidence.filter(item => item.envelope.producer === 'verification' && item.envelope.kind === 'independent-read');
  if (!Array.isArray(result.reads) || !result.reads.every(read => actualReads.some(actual => equal(actual, read)))) {
    throw fail('INTEGRITY_ERROR', 'IPC reads не совпадает с durable storage');
  }
  const verdict = validateVerdictCoverage(result.verdict, frozen.operation, result.reads);
  if (verdict.runId !== frozen.manifest.runId || verdict.manifestSha256 !== frozen.manifestSha256) throw fail('INTEGRITY_ERROR', 'Verifier вернул другой run/manifest');
  const finalEvidence = store.appendEvidence(runDir, {
    runId: frozen.manifest.runId,
    manifestSha256: frozen.manifestSha256,
    fixtureId: frozen.fixture.fixtureId,
    stepId: frozen.scenario.nodes.at(-1).id,
    producer: 'verification',
    kind: 'verdict',
    artifact: verdict,
    parentEvidenceIds: actualReads.map(item => item.envelope.evidenceId),
    checkIds: verdict.checks.filter(check => ['SATISFIED', 'VIOLATED'].includes(check.status)).map(check => check.id)
  });
  store.appendEvent(runDir, { type: 'VERDICT_DURABLE', evidenceId: finalEvidence.evidenceId, verdict: verdict.verdict });
  store.appendEvent(runDir, { type: 'STATE', state: 'FINISHED', verdict: verdict.verdict, reasonCode: verdict.reasonCode });
  return terminalResult(store, runDir, frozen);
}

function preserveIncomplete(store, runId) {
  const runDir = store.runPath(runId);
  const dest = path.join(store.root, 'quarantine', `${runId}-${Date.now()}`);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.renameSync(runDir, dest);
  return dest;
}

function openFrozen(store, runDir) {
  try { return verifyFrozenBundle(store, runDir); }
  catch (error) {
    if (String(error.message || '').startsWith('INCOMPLETE_RUN')) throw fail('INCOMPLETE_RUN', error.message);
    throw error;
  }
}

export async function start(bundle, options = {}) {
  if (!options.root) throw new TypeError('Нужен корень локального хранилища');
  const runId = safeRunId(bundle?.manifest?.runId);
  const store = new RunStore(options.root);
  const runDir = store.runPath(runId);
  if (!fs.existsSync(runDir)) return run(bundle, options);
  let frozen;
  try { frozen = openFrozen(store, runDir); }
  catch (error) {
    if (error.code === 'INCOMPLETE_RUN' && !mutationEvidenceKnown(store, runId)) {
      preserveIncomplete(store, runId);
      return run(bundle, options);
    }
    throw error;
  }
  if (!equal(frozen.scenario, bundle.scenario) || !equal(frozen.operation, bundle.operation) ||
      !equal(frozen.fixture, bundle.fixture) || !equal(frozen.manifest, bundle.manifest)) {
    throw fail('CONTRACT_INVALID', 'Повторный START содержит другой snapshot для того же runId');
  }
  const finished = terminalResult(store, runDir, frozen);
  if (finished) return finished;
  if (foreignOwnerAlive(runDir)) return runningView(runId, runDir, store);
  return reconcile({ root: options.root, runId, fault: options.fault || null, fixtureToken: options.fixtureToken || process.env.QA_ADAPTANT_FIXTURE_TOKEN || '' });
}

export async function observe({ root, runId }) {
  const store = new RunStore(root);
  const safeId = safeRunId(runId);
  const runDir = store.runPath(safeId);
  const frozen = openFrozen(store, runDir);
  const evidence = store.readEvidence(runDir);
  const events = store.readEvents(runDir);
  const terminal = terminalResult(store, runDir, frozen);
  return {
    runId: safeId,
    runDir,
    manifestSha256: frozen.manifestSha256,
    state: [...events].reverse().find(event => event.state)?.state || frozen.manifest.state,
    verdict: terminal?.verdict || null,
    evidenceIds: evidence.map(item => item.envelope.evidenceId),
    events
  };
}

export async function reconcile({ root, runId, fault = null, canceled = false, fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '' } = {}) {
  const store = new RunStore(root);
  const safeId = safeRunId(runId);
  const runDir = store.runPath(safeId);
  const frozen = openFrozen(store, runDir);
  const finished = terminalResult(store, runDir, frozen);
  if (finished) return finished;
  if (foreignOwnerAlive(runDir)) return runningView(safeId, runDir, store);
  const evidence = store.readEvidence(runDir);
  if (!evidence.some(item => item.envelope.kind === 'mutation-intent')) {
    const requested = canceled || cancelRequested(runDir, safeId);
    const verdict = requested
      ? resultVerdict(frozen, 'BLOCKED', 'CANCELED', 'Прогон отменён до отправки мутации')
      : resultVerdict(frozen, 'INCONCLUSIVE', 'WORKER_LOST', 'Control завершился до durable intent; браузер повторно не запускается');
    return persistVerdict(store, runDir, frozen, verdict);
  }
  store.appendEvent(runDir, { type: 'STATE', state: 'RECONCILING' });
  return verifyAndPersist(store, runDir, { fault, browserUncertain: true, canceled, fixtureToken });
}

export async function cancel({ root, runId }) {
  const store = new RunStore(root);
  const safeId = safeRunId(runId);
  const runDir = store.runPath(safeId);
  const frozen = openFrozen(store, runDir);
  const finished = terminalResult(store, runDir, frozen);
  if (finished) return finished;
  fs.writeFileSync(cancelFile(runDir), `${JSON.stringify({ at: now(), pid: process.pid })}\n`);
  cancellations.set(safeId, true);
  const browser = activeBrowsers.get(safeId);
  if (browser) killTree(browser.pid);
  else {
    const pid = recordedBrowserPid(runDir);
    if (pid) killTree(pid);
  }
  return { runId: safeId, runDir, state: 'CANCEL_REQUESTED', verdict: null, evidenceIds: store.readEvidence(runDir).map(item => item.envelope.evidenceId) };
}

export async function cleanup() {
  throw fail('UNSUPPORTED', 'Автоматическая очистка отключена: удаление возможно только после отдельной проверки принадлежности объекта');
}

function waitForResult(child, runId, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(fail('WORKER_LOST', 'Verification Worker не прислал результат')); }, timeoutMs);
    child.on('message', message => {
      if (message?.type === 'RESULT' && message.runId === runId) { clearTimeout(timer); resolve(message.payload); }
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { if (code !== 0) { clearTimeout(timer); reject(fail('WORKER_LOST', 'Verification Worker завершился без результата')); } });
  });
}

function persistVerdict(store, runDir, frozen, verdict) {
  const finished = terminalResult(store, runDir, frozen);
  if (finished) return finished;
  const evidence = store.readEvidence(runDir);
  store.appendEvidence(runDir, { runId: frozen.manifest.runId, manifestSha256: frozen.manifestSha256, fixtureId: frozen.fixture.fixtureId, stepId: frozen.scenario.nodes.at(-1).id, producer: 'verification', kind: 'verdict', artifact: verdict, parentEvidenceIds: evidence.map(r => r.envelope.evidenceId), checkIds: verdict.checks.filter(c => ['SATISFIED', 'VIOLATED'].includes(c.status)).map(c => c.id) });
  store.appendEvent(runDir, { type: 'STATE', state: 'FINISHED', verdict: verdict.verdict, reasonCode: verdict.reasonCode });
  return terminalResult(store, runDir, frozen);
}
