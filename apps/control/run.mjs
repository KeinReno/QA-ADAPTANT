import fs from 'node:fs';
import path from 'node:path';
import { execFile, execFileSync, fork, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { assertTerminalEvidence } from '../../packages/core/evidence-policy.mjs';
import { withFileMutex } from '../../packages/core/file-mutex.mjs';
import { assertApprovedOperation } from '../../packages/core/approved-registry.mjs';
import { IntentCommand, IntentAck, reasonCodes, validate, validateVerdictCoverage } from '../../packages/contracts/index.mjs';
import { isTrustedRunnerContext } from './trusted.mjs';

const activeBrowsers = new Map();
const cancellations = new Map();
const now = () => new Date().toISOString();
const equal = (a, b) => digest(a) === digest(b);
const fail = (code, message) => Object.assign(new Error(message), { code });

// Старый принятый вход не принимает аргументы доверенного режима: иначе появился бы обход PEP.
function assertOldEntryOptions(options) {
  for (const key of ['approvalId', 'approval', 'trustRoot', 'adapter', 'adapterId', 'standPublicKey', 'signerPipe', 'anchorKeyPath', 'trust']) {
    if (options && options[key] !== undefined) throw fail('CONTRACT_INVALID', 'Старый вход не принимает аргумент доверенного режима: ' + key);
  }
}

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

function trustedRunMarker(store, runDir, frozen) {
  const markerFile = path.join(runDir, 'trust', 'trusted-run.json');
  const markers = store.readEvents(runDir).filter(event => event.type === 'TRUSTED_RUN');
  if (markers.length > 1) throw fail('INTEGRITY_ERROR', 'В журнале более одного trusted-run маркера');
  let markerExists = false;
  try { fs.lstatSync(markerFile); markerExists = true; }
  catch (error) {
    if (error.code !== 'ENOENT') throw fail('INTEGRITY_ERROR', 'Не удалось проверить trusted-run sidecar');
  }
  if (markers.length === 0 && !markerExists) return false;
  let fileMarker;
  try { fileMarker = JSON.parse(fs.readFileSync(markerFile, 'utf8')); }
  catch { throw fail('INTEGRITY_ERROR', 'Trusted-run sidecar повреждён или отсутствует'); }
  if (fileMarker.schemaVersion !== '0.2.0' || fileMarker.domain !== 'trusted-run' ||
      fileMarker.runId !== frozen.manifest.runId || fileMarker.manifestSha256 !== frozen.manifestSha256) {
    throw fail('INTEGRITY_ERROR', 'Trusted-run sidecar не совпадает с замороженным прогоном');
  }
  if (markers.length === 0) return false;
  const marker = markers[0];
  if (marker.schemaVersion !== '0.2.0' || marker.domain !== 'trusted-run' ||
      marker.runId !== frozen.manifest.runId || marker.manifestSha256 !== frozen.manifestSha256) {
    throw fail('INTEGRITY_ERROR', 'Trusted-run маркер не совпадает с замороженным прогоном');
  }
  return true;
}

function trustedRunIntentFile(root, runId) {
  return path.join(path.resolve(root), 'runs', '.trusted-intents', `${runId}.json`);
}

function trustedRunIntent(root, runId, frozen) {
  const file = trustedRunIntentFile(root, runId);
  let intent;
  try { intent = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return false;
    throw fail('INTEGRITY_ERROR', 'Trusted-run intent повреждён или не читается');
  }
  if (intent.schemaVersion !== '0.2.0' || intent.domain !== 'trusted-run-intent' ||
      intent.runId !== frozen.manifest.runId || intent.manifestSha256 !== frozen.manifestSha256) {
    throw fail('INTEGRITY_ERROR', 'Trusted-run intent не совпадает с замороженным прогоном');
  }
  return true;
}

async function assertRunMode(store, runDir, frozen, trusted) {
  let markedTrusted = trustedRunMarker(store, runDir, frozen);
  const intent = trustedRunIntent(store.root, frozen.manifest.runId, frozen);
  if (!trusted && intent) throw fail('TRUSTED_RUN_REQUIRES_TRUSTED_ENTRY', 'Прогон зарезервирован доверенным входом');
  if (trusted && !markedTrusted) markedTrusted = await ensureTrustedRunMarker(store, runDir, frozen, { createIfMissing: intent });
  if (!trusted && !markedTrusted) {
    const sidecar = path.join(runDir, 'trust', 'trusted-run.json');
    try { fs.lstatSync(sidecar); throw fail('TRUSTED_RUN_REQUIRES_TRUSTED_ENTRY', 'Неполный trusted-run marker требует доверенного входа для восстановления'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  if (trusted && !markedTrusted) throw fail('INTEGRITY_ERROR', 'Доверенный вход не может принять прогон без durable trusted-run маркера');
  if (!trusted && markedTrusted) throw fail('TRUSTED_RUN_REQUIRES_TRUSTED_ENTRY', 'Прогон требует доверенного start/observe/reconcile');
  return markedTrusted;
}

function hasPotentialTrustedRunMarker(runDir) {
  const sidecar = path.join(runDir, 'trust', 'trusted-run.json');
  try { fs.lstatSync(sidecar); return true; }
  catch (error) {
    if (error.code !== 'ENOENT') throw fail('INTEGRITY_ERROR', 'Не удалось проверить trusted-run sidecar');
  }
  const intentFile = path.join(path.dirname(runDir), '.trusted-intents', `${path.basename(runDir)}.json`);
  try { fs.lstatSync(intentFile); return true; }
  catch (error) { if (error.code !== 'ENOENT') throw fail('INTEGRITY_ERROR', 'Не удалось проверить trusted-run intent'); }
  try {
    const events = fs.readFileSync(path.join(runDir, 'events.jsonl'), 'utf8');
    return events.includes('TRUSTED_RUN');
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw fail('INTEGRITY_ERROR', 'Не удалось проверить режим неполного прогона');
  }
}

function writeTrustedRunIntent(root, frozen) {
  const directory = path.join(path.resolve(root), 'runs', '.trusted-intents');
  fs.mkdirSync(directory, { recursive: true });
  const file = trustedRunIntentFile(root, frozen.manifest.runId);
  const body = `${JSON.stringify({ schemaVersion: '0.2.0', domain: 'trusted-run-intent',
    runId: frozen.manifest.runId, manifestSha256: frozen.manifestSha256 })}\n`;
  let fd;
  try {
    fd = fs.openSync(file, 'wx', 0o600);
    fs.writeFileSync(fd, body); fs.fsyncSync(fd);
  } catch (error) {
    if (error.code !== 'EEXIST') throw fail('INTEGRITY_ERROR', 'Trusted-run intent не записан');
    const existing = trustedRunIntent(root, frozen.manifest.runId, frozen);
    if (!existing) throw fail('INTEGRITY_ERROR', 'Trusted-run intent отсутствует после конфликта записи');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  let dirFd;
  try { dirFd = fs.openSync(directory, 'r'); fs.fsyncSync(dirFd); }
  catch (error) { if (!['EPERM', 'EINVAL', 'EISDIR'].includes(error.code)) throw error; }
  finally { if (dirFd !== undefined) fs.closeSync(dirFd); }
}

function writeTrustedRunMarker(runDir, frozen) {
  const dir = path.join(runDir, 'trust');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'trusted-run.json');
  const body = `${JSON.stringify({ schemaVersion: '0.2.0', domain: 'trusted-run', runId: frozen.manifest.runId, manifestSha256: frozen.manifestSha256 })}\n`;
  const fd = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  let dirFd;
  try { dirFd = fs.openSync(dir, 'r'); fs.fsyncSync(dirFd); }
  catch (error) { if (!['EPERM', 'EINVAL', 'EISDIR'].includes(error.code)) throw error; }
  finally { if (dirFd !== undefined) fs.closeSync(dirFd); }
}

async function ensureTrustedRunMarker(store, runDir, frozen, { createIfMissing = false } = {}) {
  const repairLock = path.join(runDir, 'trust', 'trusted-run-repair.lock');
  fs.mkdirSync(path.dirname(repairLock), { recursive: true });
  return withFileMutex(repairLock, () => {
    if (trustedRunMarker(store, runDir, frozen)) return true;
    const markerFile = path.join(runDir, 'trust', 'trusted-run.json');
    let markerExists = false;
    try { fs.lstatSync(markerFile); markerExists = true; }
    catch (error) { if (error.code !== 'ENOENT') throw fail('INTEGRITY_ERROR', 'Не удалось проверить trusted-run sidecar'); }
    if (!markerExists) {
      if (!createIfMissing) throw fail('INTEGRITY_ERROR', 'Существующий прогон без trusted-run sidecar нельзя повысить до trusted');
      writeTrustedRunMarker(runDir, frozen);
    }
    // The sidecar binds the only repairable fact to the immutable snapshot. Re-read
    // it under the same mutex before appending the event, making initial and repair paths idempotent.
    const sidecar = trustedRunMarker(store, runDir, frozen);
    if (sidecar) return true;
    const body = JSON.parse(fs.readFileSync(markerFile, 'utf8'));
    if (body.schemaVersion !== '0.2.0' || body.domain !== 'trusted-run' ||
        body.runId !== frozen.manifest.runId || body.manifestSha256 !== frozen.manifestSha256) {
      throw fail('INTEGRITY_ERROR', 'Trusted-run sidecar не совпадает с замороженным прогоном');
    }
    store.appendEvent(runDir, { type: 'TRUSTED_RUN', schemaVersion: '0.2.0', domain: 'trusted-run',
      runId: frozen.manifest.runId, manifestSha256: frozen.manifestSha256 });
    return true;
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

function runSnapshotMutexFile(store, runId) {
  return path.join(store.root, 'runs', `.${runId}.snapshot.lock`);
}

async function withRunSnapshotMutex(store, runId, action) {
  const lockFile = runSnapshotMutexFile(store, runId);
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  return withFileMutex(lockFile, action);
}

async function withPublicationLock(runDir, action) {
  const lockFile = path.join(runDir, 'trust', 'publication.lock');
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  return withFileMutex(lockFile, action);
}

function cancelRequested(runDir, runId) {
  return cancellations.has(runId) || fs.existsSync(cancelFile(runDir));
}

function foreignOwnerAlive(runDir) {
  const owner = readJsonFile(path.join(runDir, 'owner.json'));
  return Boolean(owner && owner.pid !== process.pid && pidAlive(owner.pid));
}

async function withLeaseAcquisitionLock(file, action) {
  const helperPath = path.join(process.env.SystemRoot || process.env.windir || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const escapedPath = path.resolve(file).replace(/'/g, "''");
  const script = `$f = [System.IO.File]::Open('${escapedPath}', [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None); [Console]::Out.WriteLine('LOCKED'); [Console]::In.ReadLine() | Out-Null; $f.Dispose()`;
  const helper = spawn(helperPath, ['-NoProfile', '-NonInteractive', '-Command', script], {
    stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true
  });
  const exited = new Promise(resolve => helper.once('exit', (code, signal) => resolve({ code, signal })));
  let buffer = '';
  const stopHelper = async () => {
    if (helper.exitCode === null && helper.signalCode === null) helper.kill();
    await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 5000))]);
  };
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(fail('CONTRACT_INVALID', 'Таймаут захвата lease mutex')), 10000);
      const finish = callback => value => { clearTimeout(timer); callback(value); };
      helper.stdout.setEncoding('utf8');
      helper.stdout.on('data', chunk => {
        buffer += chunk;
        if (buffer.includes('LOCKED')) finish(resolve)();
      });
      helper.once('error', error => finish(reject)(fail('CONTRACT_INVALID', 'Не запущен Windows lease mutex: ' + error.message)));
      helper.once('exit', code => {
        if (!buffer.includes('LOCKED')) finish(reject)(fail('CONTRACT_INVALID', `Windows lease mutex завершился: exit=${code}`));
      });
    });
  } catch (error) {
    await stopHelper();
    throw error;
  }
  try { return action(); }
  finally {
    helper.stdin.end();
    await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 5000))]);
    if (helper.exitCode === null && helper.signalCode === null) await stopHelper();
  }
}

async function acquireLease(root, environmentId, fixtureId, runId) {
  const file = leasePath(root, environmentId, fixtureId);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  return withLeaseAcquisitionLock(file + '.acquire.lock', () => {
    const token = randomUUID();
    const body = `${JSON.stringify({ runId, pid: process.pid, token, at: now() })}\n`;
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const fd = fs.openSync(file, 'wx', 0o600);
        try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); }
        finally { fs.closeSync(fd); }
        return { file, token };
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const current = readJsonFile(file);
        if (current && pidAlive(current.pid)) throw fail('CONTRACT_INVALID', 'Fixture занят живым прогоном');
        const latest = readJsonFile(file);
        if (latest && equal(latest, current)) {
          try { fs.unlinkSync(file); } catch {}
        }
      }
    }
    throw fail('CONTRACT_INVALID', 'Не удалось получить владение fixture');
  });
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
  return new Promise((resolve, reject) => {
    let exit = child.exitCode !== null || child.signalCode !== null
      ? { code: child.exitCode, signal: child.signalCode }
      : null;
    let disconnected = !child.connected;
    let settled = false;
    let stopping = false;
    let stopReason = null;
    let stopTimer = null;
    const cleanup = () => {
      clearTimeout(timer);
      if (stopTimer) clearTimeout(stopTimer);
      child.removeListener('error', onError);
      child.removeListener('exit', onExit);
      child.removeListener('disconnect', onDisconnect);
    };
    const finish = () => {
      if (!exit || !disconnected) return;
      if (settled) return;
      settled = true;
      cleanup();
      if (stopping) {
        const error = fail('WORKER_LOST', stopReason || 'Дочерний процесс остановлен после ошибки');
        reject(error);
      } else resolve(exit);
    };
    const rejectOnce = error => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onError = error => {
      // Spawn errors before a PID exists prove that no worker ran. Once there is
      // a process, an error event alone does not prove it has stopped.
      if (child.pid == null && child.exitCode === null && child.signalCode === null) {
        rejectOnce(error);
        return;
      }
      stopAndConfirm('Ошибка дочернего процесса: ' + String(error.message || error));
    };
    const onExit = (code, signal) => { exit = { code, signal }; finish(); };
    const onDisconnect = () => { disconnected = true; finish(); };
    const stopAndConfirm = reason => {
      if (stopping || settled) return;
      stopping = true;
      stopReason = reason;
      try { child.kill('SIGKILL'); } catch {}
      // A timeout is not terminal until the child is known to have stopped and
      // its IPC channel is closed. Otherwise it could still POST or append evidence.
      stopTimer = setTimeout(() => {
        const error = fail('WORKER_STOP_UNCONFIRMED', 'Истёк срок ожидания; остановка дочернего процесса не подтверждена');
        error.workerTerminationUnknown = true;
        rejectOnce(error);
      }, 5000);
      finish();
    };
    const timer = setTimeout(() => stopAndConfirm('Истёк срок ожидания дочернего процесса'), timeoutMs);
    child.once('error', onError);
    if (!exit) child.once('exit', onExit);
    if (!disconnected) child.once('disconnect', onDisconnect);
    finish();
  });
}

async function runInternal(bundle, options = {}, internalTrust = null) {
  const { root, headed = false, fault = null, fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '' } = options;
  const trust = internalTrust;
  assertOldEntryOptions(options);
  if (!root) throw new TypeError('Нужен корень локального хранилища');
  let runId;
  let lease = null;
  let retainLease = false;
  let trustDenial = null;
  const store = new RunStore(root);
  let runDir;
  try {
    runId = safeRunId(bundle?.manifest?.runId);
    validate('ScenarioSchema', bundle.scenario); validate('OperationContract', bundle.operation);
    validate('FixtureContract', bundle.fixture); validate('RunProtocol', bundle.manifest);
    const snapshot = await withRunSnapshotMutex(store, runId, async () => {
      if (fs.existsSync(store.runPath(runId))) {
        return { adopted: await adoptExisting(store, runId, bundle, Boolean(trust)) };
      }
      const frozenHint = { manifest: bundle.manifest, manifestSha256: digest(bundle.manifest) };
      const priorIntent = trustedRunIntent(store.root, runId, frozenHint);
      if (!trust && priorIntent) throw fail('TRUSTED_RUN_REQUIRES_TRUSTED_ENTRY', 'Прогон зарезервирован доверенным входом');
      if (trust) writeTrustedRunIntent(store.root, frozenHint);
      try {
        runDir = store.snapshot(bundle, { runId, pid: process.pid, at: now() });
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        return { adopted: await adoptExisting(store, runId, bundle, Boolean(trust)) };
      }
      const frozen = verifyFrozenBundle(store, runDir);
      if (trust) await ensureTrustedRunMarker(store, runDir, frozen, { createIfMissing: true });
      return { runDir, frozen };
    });
    if (snapshot.adopted) return snapshot.adopted;
    runDir = snapshot.runDir;
    const frozen = snapshot.frozen;
    const { manifest, operation, scenario, fixture } = frozen;
    assertApprovedOperation(operation, scenario);
    claimFixture(store, manifest.environment.id, fixture.fixtureId, runId);

    store.appendEvent(runDir, { type: 'STATE', state: 'PREFLIGHT' });
    if (trust) {
      const preflight = await trust.preflight({ store, runDir, frozen, bundle });
      if (!preflight || preflight.allow !== true) {
        trustDenial = preflight?.denial || { verdictCode: 'CONTRACT_INVALID', message: 'Доверенный preflight отказал без решения' };
        throw fail(trustDenial.verdictCode, trustDenial.message);
      }
    }
    const before = await readJson(new URL('/environment', manifest.environment.baseUrl));
    if (before.environmentId !== manifest.environment.id || before.fingerprint !== manifest.environment.fingerprint) {
      throw fail('FIXTURE_UNAVAILABLE', 'Идентификатор или fingerprint стенда не совпадает с утверждённым окружением');
    }
    const lockFile = path.join(store.root, 'locks', `${digest({ environmentId: manifest.environment.id, fixtureId: fixture.fixtureId })}.lock`);
    lease = await acquireLease(store.root, manifest.environment.id, fixture.fixtureId, runId);
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
      // Доверенный путь использует отдельный Browser Worker, который получает закреплённый сокет
      // и Bearer по IPC, а не открывает новое TCP-соединение к стенду.
      const browserFile = trust
        ? new URL('../browser/trusted-worker.mjs', import.meta.url)
        : new URL('../browser/worker.mjs', import.meta.url);
      const browserNonce = randomUUID();
      // E-04: доверенный путь доставляет только секрет, выданный по credentialRef среды.
      const deliveredToken = trust && typeof trust.credentialSecret === 'function'
        ? (trust.credentialSecret() ?? fixtureToken)
        : fixtureToken;
      const browser = spawnWorker(browserFile, [runDir, frozen.manifestSha256, browserNonce], {
        QA_ADAPTANT_HEADED: headed ? '1' : '0',
        ...(trust ? {} : { QA_ADAPTANT_FIXTURE_TOKEN: deliveredToken }),
        ...(fault ? { QA_ADAPTANT_FAULT: fault } : {})
      });
      activeBrowsers.set(runId, browser);
      fs.writeFileSync(path.join(runDir, 'browser.pid'), `${JSON.stringify({ pid: browser.pid, nonce: browserNonce })}\n`);
      if (trust) {
        const pinned = await trust.preparePinnedDispatch({ frozen, token: deliveredToken, child: browser, store, runDir });
        if (!pinned || pinned.allow !== true) {
          trustDenial = pinned?.denial || { verdictCode: 'ENVIRONMENT_CHANGED', message: 'Закреплённое соединение со стендом не установлено' };
          throw fail(trustDenial.verdictCode, trustDenial.message);
        }
      }
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
            if (trust && !intentRecord) {
              const dispatch = await trust.dispatch({ store, runDir, frozen, intent: payload });
              if (!dispatch || dispatch.allow !== true) {
                trustDenial = dispatch?.denial || { verdictCode: 'CONTRACT_INVALID', message: 'Доверенный dispatch отказал без решения' };
                throw fail(trustDenial.verdictCode, trustDenial.message);
              }
            }
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
            if (trust) {
              const liveness = await trust.beforeRequestAck({ store, runDir, frozen, request: p });
              if (!liveness || liveness.allow !== true) {
                trustDenial = liveness?.denial || { verdictCode: 'ENVIRONMENT_CHANGED', message: 'Живой процесс стенда не подтверждён перед отправкой' };
                throw fail('ENVIRONMENT_CHANGED', trustDenial.message);
              }
            }
            if (fault === 'pauseBeforeRequestAck') {
              store.appendEvent(runDir, { type: 'STATE', state: 'REQUEST_ACK_PAUSED' });
              await new Promise(resolve => setTimeout(resolve, 1000));
            }
            await withPublicationLock(runDir, async () => {
              if (cancelRequested(runDir, runId)) throw fail('CANCELED', 'Отмена зафиксирована до ACK разрешения POST');
              const artifact = { requestId: p.requestId, intentId: p.intentId, operationId: p.operationId, method: p.method, path: p.path, fixtureId: p.fixtureId, fields: p.fields };
              const envelope = store.appendEvidence(runDir, { runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: intentRecord.envelope.stepId, producer: 'browser', kind: 'request', artifact, requestId: p.requestId, parentEvidenceIds: [intentRecord.envelope.evidenceId] });
              requestRecord = { envelope, artifact };
              store.appendEvent(runDir, { type: 'REQUEST_DURABLE', requestId: p.requestId, evidenceId: envelope.evidenceId });
              await ack({ type: 'EVIDENCE_ACK', runId, requestId: p.requestId, durable: true });
            });
            return;
          }
          if (message.type === 'HTTP_RESPONSE') {
            const p = message.payload || {};
            if (trust && requestRecord && p.requestId === requestRecord.artifact.requestId) {
              // Подмена стенда после POST (P0-02): ответ без валидной подписи стенда не становится evidence.
              const responseCheck = await trust.verifyDispatchResponse({ payload: p });
              if (!responseCheck || responseCheck.allow !== true) {
                trustDenial = responseCheck?.denial || { verdictCode: 'ENVIRONMENT_CHANGED', message: 'Ответ стенда не подтверждён подписью' };
                throw fail('ENVIRONMENT_CHANGED', trustDenial.message);
              }
            }
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
          if (message.type === 'ERROR') { workerError = message.payload; store.appendEvent(runDir, { type: 'BROWSER_ERROR', code: workerError?.code || 'BROWSER_ERROR', message: String(workerError?.message || '').slice(0, 300) }); return; }
          if (['READY', 'STEP', 'HTTP_FAILED'].includes(message.type)) {
            store.appendEvent(runDir, { type: message.type, payload: message.payload || {} });
            return;
          }
          throw fail('CONTRACT_INVALID', `Неизвестное событие Browser: ${message.type}`);
        }).catch(error => { workerError ||= { code: error.code || 'CONTROL_IPC_ERROR', message: error.message }; killTree(browser.pid); });
      });
      let exit;
      let stopUnconfirmed = false;
      try { exit = await waitForChild(browser, manifest.budget.deadlineMs); }
      catch (error) {
        if (error?.workerTerminationUnknown) {
          retainLease = true;
          stopUnconfirmed = true;
        }
        throw error;
      }
      finally {
        clearInterval(cancelPoll);
        if (!stopUnconfirmed) {
          activeBrowsers.delete(runId);
          try { fs.unlinkSync(path.join(runDir, 'browser.pid')); } catch {}
        }
      }
      await eventQueue;
      if (exit.code !== 0 && !workerError) workerError = { code: 'WORKER_LOST', message: `Browser завершился с кодом ${exit.code}` };
      const canceled = cancelRequested(runDir, runId);

      if (trustDenial && !intentRecord) {
        cancellations.delete(runId);
        store.appendEvent(runDir, { type: 'STATE', state: 'TRUST_DENIED', phase: trustDenial.phase || 'preflight', code: trustDenial.reasonCode });
        return persistVerdict(store, runDir, frozen, resultVerdict(frozen, 'BLOCKED', trustDenial.verdictCode, trustDenial.message));
      }
      if (trustDenial && intentRecord) {
        cancellations.delete(runId);
        store.appendEvent(runDir, { type: 'STATE', state: 'TRUST_DENIED', phase: 'dispatch-after-intent', code: trustDenial.reasonCode });
        return persistVerdict(store, runDir, frozen, resultVerdict(frozen, 'INCONCLUSIVE', 'ENVIRONMENT_CHANGED', trustDenial.message));
      }
      store.appendEvent(runDir, { type: 'STATE', state: 'VERIFYING', intentPersisted: Boolean(intentRecord), browserDone: gotDone });
      if (!intentRecord) {
        const code = canceled ? 'CANCELED' : (workerError?.code || 'CONTRACT_INVALID');
        const blocked = ['ELEMENT_AMBIGUOUS', 'CONTRACT_INVALID', 'CANCELED'].includes(code);
        const verdict = resultVerdict(frozen, blocked ? 'BLOCKED' : 'INCONCLUSIVE', blocked ? code : 'WORKER_LOST', canceled ? 'Прогон отменён до отправки мутации' : (workerError?.message || 'Действие не было подтверждено'));
        cancellations.delete(runId);
        return persistVerdict(store, runDir, frozen, verdict);
      }
      const browserUncertain = Boolean(workerError) || !gotDone || exit.code !== 0;
      const lossDetail = `exit=${exit.code ?? 'null'}, signal=${exit.signal || 'none'}, done=${gotDone}, phase=${workerError?.code || (gotDone ? 'DONE' : 'NO_DONE')}${workerError?.message ? `, ipc=${String(workerError.message).slice(0, 160)}` : ''}`;
      cancellations.delete(runId);
      return await verifyAndPersist(store, runDir, { fault, browserUncertain, canceled, fixtureToken: deliveredToken, lossDetail, trust, lease });
    } finally {
      try { fs.unlinkSync(lockFile); } catch {}
    }
  } catch (error) {
    if (!error?.workerTerminationUnknown) {
      activeBrowsers.delete(runId);
      cancellations.delete(runId);
    }
    if (!runDir) throw error;
    if (process.env.QA_ADAPTANT_DEBUG === '1') console.error(error);
    if (trust && error && error.trustedPublication) {
      // P2-04: состояние остаётся PUBLICATION_PENDING, терминальный verdict без terminal-choice не пишется.
      // Повторный reconcile дочитывает durable candidate/choice и завершает публикацию.
      const code = typeof error.code === 'string' ? error.code : 'CONTRACT_INVALID';
      try {
        store.appendEvent(runDir, { type: 'STATE', state: 'PUBLICATION_PENDING', reasonCode: code, message: String(error.message || '').slice(0, 200) });
      } catch { /* журнал может быть недоступен: ошибка публикации важнее */ }
      throw error;
    }
    if (error?.workerTerminationUnknown) {
      try {
        store.appendEvent(runDir, { type: 'STATE', state: 'PUBLICATION_PENDING', reasonCode: 'WORKER_STOP_UNCONFIRMED', message: String(error.message || '').slice(0, 200) });
      } catch { /* Preserve pending state by retaining the fixture lease even if the journal is unavailable. */ }
      throw error;
    }
    const frozen = verifyFrozenBundle(store, runDir);
    const evidence = store.readEvidence(runDir);
    const possiblyMutated = evidence.some(r => r.envelope.kind === 'mutation-intent');
    const integrity = error.code === 'INTEGRITY_ERROR' || error.message?.includes('INTEGRITY_ERROR');
    const candidate = integrity ? 'INTEGRITY_ERROR' : error.code;
    const reasonCode = reasonCodes.includes(candidate) ? candidate : (possiblyMutated ? 'WORKER_LOST' : 'CONTRACT_INVALID');
    const verdict = resultVerdict(frozen, possiblyMutated ? 'INCONCLUSIVE' : 'BLOCKED', reasonCode, error.message || 'Прогон остановлен', { integrityVerified: !integrity });
    return persistVerdict(store, runDir, frozen, verdict);
  } finally {
    if (runId && !retainLease) releaseLease(lease, runId);
  }
}

export async function run(bundle, options = {}) {
  if (arguments.length > 2) throw fail('CONTRACT_INVALID', 'Старый run() не принимает внутренний доверенный контекст');
  return runInternal(bundle, options, null);
}

async function adoptExisting(store, runId, bundle, trusted = false) {
  const runDir = store.runPath(runId);
  for (let attempt = 0; attempt < 40; attempt++) {
    if (!fs.existsSync(path.join(runDir, 'manifest.json')) || !fs.existsSync(path.join(runDir, 'owner.json'))) {
      await new Promise(resolve => setTimeout(resolve, 25));
      continue;
    }
    const frozen = verifyFrozenBundle(store, runDir);
    await assertRunMode(store, runDir, frozen, trusted);
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
  let evidence = store.readEvidence(runDir);
  let verdict = assertTerminalEvidence(evidence, frozen);
  if (!verdict) {
    const claimed = [...store.readEvents(runDir)].reverse().find(event => event.type === 'VERDICT_DURABLE' || (event.type === 'STATE' && event.state === 'FINISHED'));
    if (claimed) {
      evidence = store.readEvidence(runDir);
      verdict = assertTerminalEvidence(evidence, frozen);
      if (!verdict) throw fail('INTEGRITY_ERROR', 'INTEGRITY_ERROR: терминальный результат в событиях не подтверждён журналом evidence');
    } else return null;
  }
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

async function verifyAndPersist(store, runDir, { fault = null, browserUncertain = true, canceled = false, fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '', lossDetail = '', trust = null, lease = null } = {}) {
  const frozen = verifyFrozenBundle(store, runDir);
  const finished = terminalResult(store, runDir, frozen);
  if (finished) return finished;
  if (trust) {
    // Доверенный путь: Verification и публикация выполняются доверенным Worker'ом внутри trust.publish.
    // Замороженный Verification 0.1 здесь не запускается и его вердикт не используется.
    store.appendEvent(runDir, { type: 'STATE', state: 'TRUSTED_VERIFYING' });
    try {
      return await trust.publish({
        store, runDir, frozen,
        canceled: canceled || cancelRequested(runDir, frozen.manifest.runId),
        browserUncertain, lease, fault
      });
    } catch (error) {
      if (error && typeof error === 'object') error.trustedPublication = true;
      throw error;
    }
  }
  const verificationFile = new URL('../verification/worker.mjs', import.meta.url);
  const args = [runDir, frozen.manifestSha256];
  if (browserUncertain) args.push('--browser-unconfirmed');
  if (browserUncertain && lossDetail) args.push(`--browser-loss=${encodeURIComponent(lossDetail)}`);
  if (canceled) args.push('--cancellation');
  const verification = spawnWorker(verificationFile, args, { QA_ADAPTANT_FAULT: fault || '', QA_ADAPTANT_FIXTURE_TOKEN: fixtureToken });
  const result = await waitForResult(verification, frozen.manifest.runId, frozen.manifest.budget.deadlineMs);
  const verifierExit = await waitForChild(verification, 5000);
  if (verifierExit.code !== 0) throw fail('WORKER_LOST', `Verification Worker завершился с ошибкой: exit=${verifierExit.code}, signal=${verifierExit.signal || 'none'}`);
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
  if (trust) {
    try {
      return await trust.publish({ store, runDir, frozen, verdict, lease });
    } catch (error) {
      // P2-04: ошибка публикации доверенного прогона не должна превращаться в verdict без terminal-choice.
      if (error && typeof error === 'object') error.trustedPublication = true;
      throw error;
    }
  }
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

async function startInternal(bundle, options = {}, internalTrust = null) {
  assertOldEntryOptions(options);
  if (!options.root) throw new TypeError('Нужен корень локального хранилища');
  const runId = safeRunId(bundle?.manifest?.runId);
  const store = new RunStore(options.root);
  const runDir = store.runPath(runId);
  if (!fs.existsSync(runDir)) return runInternal(bundle, options, internalTrust);
  const state = await withRunSnapshotMutex(store, runId, async () => {
    if (!fs.existsSync(runDir)) return { restart: true };
    let frozen;
    try { frozen = openFrozen(store, runDir); }
    catch (error) {
      if (error.code === 'INCOMPLETE_RUN' && !mutationEvidenceKnown(store, runId)) {
        if (hasPotentialTrustedRunMarker(runDir)) {
          if (!internalTrust) throw fail('TRUSTED_RUN_REQUIRES_TRUSTED_ENTRY', 'Неполный trusted-run нельзя перезапускать через generic start');
          throw fail('INTEGRITY_ERROR', 'Повреждённый trusted-run snapshot нельзя переносить в quarantine или запускать повторно');
        }
        preserveIncomplete(store, runId);
        return { restart: true };
      }
      throw error;
    }
    await assertRunMode(store, runDir, frozen, Boolean(internalTrust));
    if (!equal(frozen.scenario, bundle.scenario) || !equal(frozen.operation, bundle.operation) ||
        !equal(frozen.fixture, bundle.fixture) || !equal(frozen.manifest, bundle.manifest)) {
      throw fail('CONTRACT_INVALID', 'Повторный START содержит другой snapshot для того же runId');
    }
    const finished = terminalResult(store, runDir, frozen);
    if (finished) return { result: finished };
    if (foreignOwnerAlive(runDir)) return { result: runningView(runId, runDir, store) };
    return { reconcile: true };
  });
  if (state.restart) return runInternal(bundle, options, internalTrust);
  if (state.result) return state.result;
  return reconcileInternal({ root: options.root, runId, fault: options.fault || null, fixtureToken: options.fixtureToken || process.env.QA_ADAPTANT_FIXTURE_TOKEN || '' }, internalTrust);
}

export async function start(bundle, options = {}) {
  if (arguments.length > 2) throw fail('CONTRACT_INVALID', 'Старый start() не принимает внутренний доверенный контекст');
  return startInternal(bundle, options, null);
}

export async function startTrustedInternal(bundle, options, internalTrust) {
  if (!isTrustedRunnerContext(internalTrust)) throw fail('CONTRACT_INVALID', 'Внутренний trusted runner требует capability доверенного входа');
  return startInternal(bundle, options, internalTrust);
}

export async function observe(options = {}) {
  assertOldEntryOptions(options);
  const { root, runId } = options;
  const store = new RunStore(root);
  const safeId = safeRunId(runId);
  const runDir = store.runPath(safeId);
  const frozen = openFrozen(store, runDir);
  await assertRunMode(store, runDir, frozen, false);
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

async function recoverPendingPublication({ store, runDir, frozen, trust, lease = null }) {
  if (trust && typeof trust.recoverPendingPublication === 'function') {
    return trust.recoverPendingPublication({ store, runDir, frozen, lease });
  }
  return null;
}

async function reconcileInternal(options = {}, internalTrust = null) {
  assertOldEntryOptions(options);
  const { root, runId, fault = null, canceled = false, fixtureToken = process.env.QA_ADAPTANT_FIXTURE_TOKEN || '' } = options;
  const trust = internalTrust;
  const store = new RunStore(root);
  const safeId = safeRunId(runId);
  const runDir = store.runPath(safeId);
  const frozen = openFrozen(store, runDir);
  await assertRunMode(store, runDir, frozen, Boolean(trust));
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
  const lease = await acquireLease(root, frozen.manifest.environment.id, frozen.fixture.fixtureId, safeId);
  try {
    const recovered = await recoverPendingPublication({ store, runDir, frozen, trust, lease });
    if (recovered) return recovered;
    // E-04: чтение при восстановлении тоже получает только секрет, разрешённый credentialRef среды.
    let deliveredToken = fixtureToken;
    if (trust && typeof trust.ensureCredential === 'function') deliveredToken = await trust.ensureCredential({ frozen });
    return verifyAndPersist(store, runDir, { fault, browserUncertain: true, canceled, fixtureToken: deliveredToken, trust, lease });
  } finally {
    releaseLease(lease, safeId);
  }
}

export async function reconcile(options = {}) {
  if (arguments.length > 1) throw fail('CONTRACT_INVALID', 'Старый reconcile() не принимает внутренний доверенный контекст');
  return reconcileInternal(options, null);
}

export async function reconcileTrustedInternal(options, internalTrust) {
  if (!isTrustedRunnerContext(internalTrust)) throw fail('CONTRACT_INVALID', 'Внутренний trusted runner требует capability доверенного входа');
  return reconcileInternal(options, internalTrust);
}

async function cancelInternal(options = {}, trusted = false) {
  const { root, runId } = options;
  const store = new RunStore(root);
  const safeId = safeRunId(runId);
  const runDir = store.runPath(safeId);
  const frozen = await withRunSnapshotMutex(store, safeId, async () => {
    const snapshot = openFrozen(store, runDir);
    await assertRunMode(store, runDir, snapshot, trusted);
    return snapshot;
  });
  const cancellation = await withPublicationLock(runDir, () => {
    const finished = terminalResult(store, runDir, frozen);
    if (finished) return { finished };
    try {
      fs.lstatSync(path.join(runDir, 'trust', 'terminal-choice.json'));
      throw fail('PUBLICATION_PENDING', 'Terminal outcome уже зафиксирован; отмена не меняет его задним числом');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const requestFile = cancelFile(runDir);
    try {
      const fd = fs.openSync(requestFile, 'wx', 0o600);
      try { fs.writeFileSync(fd, `${JSON.stringify({ at: now(), pid: process.pid })}\n`); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
    } catch (error) { if (error.code !== 'EEXIST') throw error; }
    return { requested: true };
  });
  if (cancellation.finished) return cancellation.finished;
  cancellations.set(safeId, true);
  const browser = activeBrowsers.get(safeId);
  if (browser) killTree(browser.pid);
  else {
    const pid = recordedBrowserPid(runDir);
    if (pid) killTree(pid);
  }
  return { runId: safeId, runDir, state: 'CANCEL_REQUESTED', verdict: null, evidenceIds: store.readEvidence(runDir).map(item => item.envelope.evidenceId) };
}

export async function cancel(options = {}) {
  assertOldEntryOptions(options);
  return cancelInternal(options, false);
}

export async function cancelTrustedInternal(options, internalTrust) {
  if (!isTrustedRunnerContext(internalTrust)) throw fail('CONTRACT_INVALID', 'Внутренний trusted cancel требует capability доверенного входа');
  return cancelInternal(options, true);
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
    child.once('exit', code => { if (code !== 0) { clearTimeout(timer); reject(fail('WORKER_LOST', `Verification Worker завершился без результата: exit=${code}, phase=WAIT_RESULT`)); } });
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
