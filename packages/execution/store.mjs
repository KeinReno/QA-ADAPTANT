import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonical, digest } from '../core/canonical.mjs';
import { withFileMutex } from '../core/file-mutex.mjs';
import { assertTaskPassSupported, ExecutionPlanSchema, LegacyExecutionPlanSchema, PlannerResponseReceiptSchema, PLAN_SCHEMA_VERSION, TaskDispatchIntentSchema, TaskEventSchema, TaskSchema, TaskStateSchema, transitionTask } from './contracts.mjs';

const bytes = value => Buffer.from(`${canonical(value)}\n`, 'utf8');
const isoNow = () => new Date().toISOString();
const error = (code, message) => Object.assign(new Error(message), { code });
const entryNameIsResponse = value => /^planner-response-[A-Za-z0-9-]{36}$/.test(value);
const modelOutputFromPlan = plan => ({ normalizedGoal: plan.normalizedGoal, requirements: plan.requirements, missingContext: plan.missingContext, steps: plan.steps, estimatedRisk: plan.estimatedRisk, approvalRequirements: plan.approvalRequirements, validationRules: plan.validationRules });
const syncDirectoryDurably = directory => {
  let fd;
  try { fd = fs.openSync(directory, 'r'); fs.fsyncSync(fd); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
};
const stateOf = task => {
  const { journalSequence: _sequence, journalHeadSha256: _head, ...state } = task;
  return TaskStateSchema.parse(state);
};

function atomicWrite(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  const fd = fs.openSync(temporary, 'wx', 0o600);
  try { fs.writeFileSync(fd, content); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
}

export class TaskStore {
  constructor(root, { verifyTaskPass = null, plannerAclGuard = () => false, maxPlannerResponseBytes = 100000, maxPlannerRequestBytes = 64000, syncDirectory = syncDirectoryDurably } = {}) {
    this.root = path.resolve(root);
    this.verifyTaskPass = verifyTaskPass;
    this.plannerAclGuard = plannerAclGuard;
    this.maxPlannerResponseBytes = maxPlannerResponseBytes;
    this.maxPlannerRequestBytes = maxPlannerRequestBytes;
    this.syncDirectory = syncDirectory;
    fs.mkdirSync(this.root, { recursive: true });
    if (fs.lstatSync(this.root).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Task root не может быть symlink');
    this.lockPath = path.join(this.root, '.task-store.lock');
  }

  #assertPlannerStoreAccess() {
    if (typeof this.plannerAclGuard !== 'function' || this.plannerAclGuard() !== true) throw error('ARTIFACT_ACCESS_UNVERIFIED', 'ACL PlannerResponse store не подтверждён');
  }

  #taskPath(taskId) {
    if (!/^task-[A-Za-z0-9_-]{1,140}$/.test(taskId)) throw error('INVALID_TASK_ID', 'Некорректный taskId');
    const dir = path.resolve(this.root, 'tasks', taskId);
    const parent = path.resolve(this.root, 'tasks');
    if (!dir.startsWith(`${parent}${path.sep}`)) throw error('INVALID_TASK_ID', 'Task path вне хранилища');
    if (fs.existsSync(parent) && fs.lstatSync(parent).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог tasks не может быть symlink');
    if (fs.existsSync(dir) && fs.lstatSync(dir).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Task directory не может быть symlink');
    return dir;
  }

  #assertRegularFile(file, parent) {
    const parentStat = fs.lstatSync(parent), fileStat = fs.lstatSync(file);
    const parentReal = fs.realpathSync(parent), fileReal = fs.realpathSync(file);
    if (parentStat.isSymbolicLink() || !parentStat.isDirectory() || fileStat.isSymbolicLink() || !fileStat.isFile() || !fileReal.startsWith(`${parentReal}${path.sep}`)) {
      throw error('INTEGRITY_ERROR', 'Task storage содержит файл вне выделенного каталога');
    }
  }

  #events(taskId, { allowEmpty = false } = {}) {
    const dir = this.#taskPath(taskId), file = path.join(dir, 'events.jsonl');
    if (!fs.existsSync(file)) throw error('INTEGRITY_ERROR', 'Task journal отсутствует');
    this.#assertRegularFile(file, dir);
    const raw = fs.readFileSync(file, 'utf8');
    if (raw && !raw.endsWith('\n')) throw error('INTEGRITY_ERROR', 'Неполная запись task journal');
    let events;
    try { events = raw.split('\n').filter(Boolean).map(line => JSON.parse(line)); }
    catch { throw error('INTEGRITY_ERROR', 'Повреждён task journal'); }
    if (!events.length && !allowEmpty) throw error('INTEGRITY_ERROR', 'Task journal не содержит исходного события');
    let previous = null;
    events.forEach((event, index) => {
      const { sha256, ...unsigned } = event;
      try { TaskEventSchema.parse(event); }
      catch { throw error('INTEGRITY_ERROR', 'Некорректная запись task journal'); }
      if (event.taskId !== taskId || event.sequence !== index + 1 || event.previousSha256 !== previous || event.state.taskId !== taskId || digest(unsigned) !== sha256) {
        throw error('INTEGRITY_ERROR', 'Нарушена hash-chain task journal');
      }
      previous = sha256;
    });
    return events;
  }

  #readPlan(taskId, planId = null) {
    const taskDir = this.#taskPath(taskId), dir = path.join(taskDir, 'plans');
    if (!fs.existsSync(dir) || fs.lstatSync(dir).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог plans отсутствует или является symlink');
    const files = fs.readdirSync(dir).filter(name => /^\d{6}\.json$/.test(name)).sort().reverse();
    for (const file of files) {
      const planPath = path.join(dir, file);
      this.#assertRegularFile(planPath, dir);
      let plan;
      try {
        const value = JSON.parse(fs.readFileSync(planPath, 'utf8'));
        plan = value?.schemaVersion === PLAN_SCHEMA_VERSION ? ExecutionPlanSchema.parse(value) : LegacyExecutionPlanSchema.parse(value);
      }
      catch { throw error('INTEGRITY_ERROR', 'Повреждён файл плана'); }
      const { sha256, ...unsigned } = plan;
      if (plan.taskId !== taskId || plan.version !== Number(file.slice(0, 6)) || digest(unsigned) !== sha256) throw error('INTEGRITY_ERROR', 'План изменён или не соответствует Task');
      const events = this.#events(taskId);
      const committed = events.some(event => event.type === 'PLAN_VERSION_CREATED' && event.payload.planId === plan.planId && event.payload.sha256 === sha256);
      if (committed && (!planId || plan.planId === planId)) {
        if (plan.schemaVersion === PLAN_SCHEMA_VERSION && plan.provider.mode === 'MODEL') {
          const ref = plan.plannerResponse;
          const validated = events.find(event => event.type === 'PLANNER_RESPONSE_VALIDATED' && event.payload.responseId === ref.responseId && event.payload.requestId === ref.requestId && event.payload.requestSha256 === ref.requestSha256 && event.payload.responseSha256 === ref.responseSha256 && event.payload.modelId === plan.provider.modelId);
          const artifact = this.#readPlannerResponseSync(taskId, ref.responseId);
          if (!validated || validated.payload.planResultSha256 !== ref.planResultSha256 || digest(modelOutputFromPlan(plan)) !== ref.planResultSha256 || artifact.receipt.requestId !== ref.requestId || artifact.receipt.requestSha256 !== ref.requestSha256 || artifact.receipt.responseSha256 !== ref.responseSha256 || artifact.receipt.byteLength !== ref.byteLength || artifact.receipt.providerId !== plan.provider.providerId || artifact.receipt.configuredModelId !== plan.provider.modelId) throw error('INTEGRITY_ERROR', 'PlannerResponse не совпадает с provenance плана');
        }
        return plan;
      }
    }
    throw error('PLAN_NOT_FOUND', `План недоступен для Task ${taskId}`);
  }

  #snapshot(taskId) {
    const dir = this.#taskPath(taskId), file = path.join(dir, 'task.json');
    const events = this.#events(taskId), last = events.at(-1);
    const expected = TaskSchema.parse({ ...last.state, journalSequence: last.sequence, journalHeadSha256: last.sha256 });
    let saved = null;
    if (fs.existsSync(file)) {
      this.#assertRegularFile(file, dir);
      try { saved = TaskSchema.parse(JSON.parse(fs.readFileSync(file, 'utf8'))); }
      catch { /* journal is authoritative; recover the cached snapshot below */ }
    }
    if (saved && saved.journalSequence > expected.journalSequence) throw error('INTEGRITY_ERROR', 'Task journal усечён относительно snapshot');
    if (saved && saved.journalSequence === expected.journalSequence && saved.journalHeadSha256 !== expected.journalHeadSha256) throw error('INTEGRITY_ERROR', 'Task snapshot указывает на другой journal head');
    if (!saved || saved.journalSequence < expected.journalSequence || canonical(saved) !== canonical(expected)) atomicWrite(file, bytes(expected));
    if (expected.originalRequestSha256 !== digest(expected.originalRequest)) throw error('INTEGRITY_ERROR', 'Исходный текст Task изменён в journal');
    return expected;
  }

  #commit(taskId, state, type, payload = {}) {
    const events = this.#events(taskId, { allowEmpty: type === 'TASK_CREATED' }), previous = events.at(-1);
    const checkedState = TaskStateSchema.parse(state);
    const unsigned = {
      eventId: `event-${randomUUID()}`, sequence: events.length + 1, taskId, type,
      at: isoNow(), payload, state: checkedState, previousSha256: previous?.sha256 || null
    };
    const event = TaskEventSchema.parse({ ...unsigned, sha256: digest(unsigned) });
    const eventsFile = path.join(this.#taskPath(taskId), 'events.jsonl');
    const fd = fs.openSync(eventsFile, 'a', 0o600);
    try { fs.writeFileSync(fd, bytes(event)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const snapshot = TaskSchema.parse({ ...checkedState, journalSequence: event.sequence, journalHeadSha256: event.sha256 });
    atomicWrite(path.join(this.#taskPath(taskId), 'task.json'), bytes(snapshot));
    return snapshot;
  }

  async createTask({ originalRequest, ownerRef, contextRefs = [], environmentRef = null, policyRef = null } = {}) {
    return withFileMutex(this.lockPath, () => {
      const taskId = `task-${randomUUID()}`, now = isoNow();
      const state = TaskStateSchema.parse({
        schemaVersion: '0.3.0', taskId, originalRequest, originalRequestSha256: digest(originalRequest),
        normalizedGoal: '', status: 'DRAFT', createdAt: now, updatedAt: now, ownerRef, contextRefs,
        executionPlanId: null, environmentRef, policyRef, approvalRef: null, runIds: [], result: null, revision: 1
      });
      const dir = this.#taskPath(taskId);
      fs.mkdirSync(path.join(this.root, 'tasks'), { recursive: true });
      fs.mkdirSync(dir, { recursive: false });
      fs.mkdirSync(path.join(dir, 'plans'), { recursive: false });
      fs.writeFileSync(path.join(dir, 'events.jsonl'), '', { flag: 'wx', mode: 0o600 });
      return this.#commit(taskId, state, 'TASK_CREATED', { revision: state.revision });
    });
  }

  async getTask(taskId) { return withFileMutex(this.lockPath, () => this.#snapshot(taskId)); }

  async getEvents(taskId) { return withFileMutex(this.lockPath, () => this.#events(taskId)); }

  async listTasks() {
    return withFileMutex(this.lockPath, () => {
      const dir = path.join(this.root, 'tasks');
      if (!fs.existsSync(dir)) return [];
      if (fs.lstatSync(dir).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог tasks не может быть symlink');
      return fs.readdirSync(dir, { withFileTypes: true }).filter(entry => entry.isDirectory() && entry.name.startsWith('task-'))
        .map(entry => this.#snapshot(entry.name)).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    });
  }

  async listTaskEntries() {
    return withFileMutex(this.lockPath, () => {
      const dir = path.join(this.root, 'tasks');
      if (!fs.existsSync(dir)) return { tasks: [], corrupt: [] };
      if (fs.lstatSync(dir).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог tasks не может быть symlink');
      const tasks = [], corrupt = [];
      for (const entry of fs.readdirSync(dir, { withFileTypes: true }).filter(item => (item.isDirectory() || item.isSymbolicLink()) && item.name.startsWith('task-'))) {
        try { tasks.push(this.#snapshot(entry.name)); }
        catch (cause) { corrupt.push({ taskId: entry.name, reasonCode: cause?.code || 'INTEGRITY_ERROR' }); }
      }
      tasks.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      return { tasks, corrupt };
    });
  }

  async transition(taskId, nextStatus, { payload = {}, patch = {}, expected = null } = {}) {
    return withFileMutex(this.lockPath, async () => {
      const current = this.#snapshot(taskId);
      if (expected && (expected.revision !== current.revision || (expected.planId !== undefined && expected.planId !== current.executionPlanId))) {
        throw error('TASK_CONFLICT', 'Task изменился до завершения команды');
      }
      if (expected?.planSha256) {
        const currentPlan = this.#readPlan(taskId, current.executionPlanId);
        if (currentPlan.sha256 !== expected.planSha256) throw error('TASK_CONFLICT', 'Версия плана изменилась до завершения команды');
      }
      const transitioned = transitionTask(current, nextStatus);
      const allowedPatch = ['normalizedGoal', 'executionPlanId', 'environmentRef', 'policyRef', 'approvalRef', 'runIds', 'result'];
      if (Object.keys(patch).some(key => !allowedPatch.includes(key))) throw error('INVALID_TASK_PATCH', 'Поле Task нельзя изменить этим методом');
      const next = TaskStateSchema.parse({ ...stateOf(transitioned), ...patch, status: nextStatus, revision: current.revision + 1, updatedAt: isoNow() });
      if (next.result?.taskOutcome === 'PASS') {
        if (nextStatus !== 'COMPLETED') throw error('UNVERIFIED_TASK_PASS', 'Task PASS допустим только при завершении жизненного цикла');
        const plan = this.#readPlan(taskId, next.executionPlanId);
        assertTaskPassSupported(next.result, { plan, runIds: next.runIds });
        if (typeof this.verifyTaskPass !== 'function') throw error('UNVERIFIED_TASK_PASS', 'Независимая проверка trusted observer не настроена');
        let independentlyVerified = false;
        try { independentlyVerified = await this.verifyTaskPass({ task: next, plan, result: next.result }); }
        catch { throw error('UNVERIFIED_TASK_PASS', 'Не удалось независимо проверить trusted run/evidence'); }
        if (independentlyVerified !== true) throw error('UNVERIFIED_TASK_PASS', 'Trusted observer не подтвердил все run/evidence refs');
      }
      if (next.result && next.result.taskOutcome !== 'PASS' && nextStatus === 'COMPLETED' && !['FAIL', 'PARTIAL'].includes(next.result.taskOutcome)) {
        throw error('INVALID_TASK_RESULT', 'Task outcome не соответствует завершению lifecycle');
      }
      if (nextStatus === 'COMPLETED' && !next.result) throw error('INCOMPLETE_TASK_RESULT', 'COMPLETED требует агрегированный результат');
      return this.#commit(taskId, next, 'TASK_STATE_CHANGED', { from: current.status, to: nextStatus, ...payload });
    });
  }

  async appendEvent(taskId, type, payload = {}) {
    return withFileMutex(this.lockPath, () => {
      const current = this.#snapshot(taskId);
      return this.#commit(taskId, stateOf(current), type, payload);
    });
  }

  #activePlannerRequest(taskId) {
    const events = this.#events(taskId);
    let active = null;
    for (const event of events) {
      if (event.type === 'PLANNER_REQUEST_STARTED') active = event.payload;
      if (['PLANNER_REQUEST_FINISHED', 'PLANNER_RESPONSE_REJECTED', 'PLAN_VERSION_CREATED'].includes(event.type)) {
        const requestId = event.payload.requestId || event.payload.plannerResponse?.requestId;
        if (active && requestId === active.requestId) active = null;
      }
    }
    return active;
  }

  async beginPlannerRequest(taskId, request) {
    return withFileMutex(this.lockPath, () => {
      this.#assertPlannerStoreAccess();
      const task = this.#snapshot(taskId);
      if (task.status !== 'PLANNING') throw error('INVALID_TASK_TRANSITION', 'Planner request допустим только в состоянии PLANNING');
      if (this.#activePlannerRequest(taskId)) throw error('PLANNER_REQUEST_ACTIVE', 'У Task уже есть незавершённый Planner request');
      if (request.taskId !== taskId || request.originalRequestSha256 !== task.originalRequestSha256 || !/^[a-f0-9]{64}$/.test(request.requestSha256 || '')) throw error('INVALID_PLANNER_REQUEST', 'Planner request не связан с точной Task версией');
      const unsigned = { requestId: request.requestId, requestSha256: request.requestSha256, taskId, originalRequestSha256: task.originalRequestSha256, providerId: request.providerId, configuredModelId: request.configuredModelId, mode: request.mode, taskRevision: task.revision, startedAt: request.startedAt };
      return this.#commit(taskId, stateOf(task), 'PLANNER_REQUEST_STARTED', unsigned);
    });
  }

  async savePlannerResponse(taskId, { requestSha256, requestBodyBytes, response } = {}) {
    return withFileMutex(this.lockPath, () => {
      this.#assertPlannerStoreAccess();
      const task = this.#snapshot(taskId);
      const active = this.#activePlannerRequest(taskId);
      if (task.status !== 'PLANNING' || !active || active.requestSha256 !== requestSha256) throw error('PLANNER_REQUEST_MISMATCH', 'PlannerResponse не соответствует активному запросу');
      if (!(requestBodyBytes instanceof Uint8Array) || !(response?.bodyBytes instanceof Uint8Array)) throw error('INVALID_PLANNER_RESPONSE', 'PlannerResponse bytes недоступны');
      if (requestBodyBytes.byteLength > this.maxPlannerRequestBytes || response.bodyBytes.byteLength > this.maxPlannerResponseBytes) throw error('OUTPUT_LIMIT', 'PlannerResponse превышает лимит TaskStore');
      if (response.requestId !== active.requestId || response.providerId !== active.providerId || response.configuredModelId !== active.configuredModelId || response.mode !== active.mode) throw error('PLANNER_PROVENANCE_MISMATCH', 'PlannerResponse не совпадает с durable request intent');
      const responseId = `planner-response-${randomUUID()}`;
      const bodyBytes = Buffer.from(response.bodyBytes);
      const outboundBytes = Buffer.from(requestBodyBytes);
      const receipt = PlannerResponseReceiptSchema.parse({
        schemaVersion: '0.3.2', responseId, taskId, requestId: active.requestId, requestSha256: active.requestSha256,
        requestBodySha256: digest(outboundBytes), providerId: response.providerId, configuredModelId: response.configuredModelId, mode: response.mode,
        receivedAt: response.receivedAt, contentType: response.contentType || 'application/octet-stream', statusCode: response.statusCode,
        byteLength: bodyBytes.byteLength, responseSha256: digest(bodyBytes), backendReference: response.backendReference || null, status: 'RECEIVED'
      });
      const parent = path.join(this.#taskPath(taskId), 'planner-responses');
      fs.mkdirSync(parent, { recursive: true });
      if (fs.lstatSync(parent).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог PlannerResponse не может быть symlink');
      const staging = path.join(parent, `.${responseId}.${randomUUID()}.staging`);
      const finalDir = path.join(parent, responseId);
      fs.mkdirSync(staging, { recursive: false, mode: 0o700 });
      const writeSynced = (file, data) => {
        const fd = fs.openSync(file, 'wx', 0o600);
        try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      };
      writeSynced(path.join(staging, 'request.bin'), outboundBytes);
      writeSynced(path.join(staging, 'response.bin'), bodyBytes);
      writeSynced(path.join(staging, 'receipt.json'), bytes(receipt));
      try { this.syncDirectory(staging); }
      catch { throw error('PLANNER_RESPONSE_DURABILITY_FAILED', 'PlannerResponse staging directory не удалось durable sync'); }
      fs.renameSync(staging, finalDir);
      this.#commit(taskId, stateOf(task), 'PLANNER_RESPONSE_STORED', { responseId, requestId: receipt.requestId, requestSha256: receipt.requestSha256, responseSha256: receipt.responseSha256, byteLength: receipt.byteLength });
      return receipt;
    });
  }

  async getPlannerResponse(taskId, responseId) {
    return withFileMutex(this.lockPath, () => {
      this.#assertPlannerStoreAccess();
      const taskDir = this.#taskPath(taskId), parent = path.join(taskDir, 'planner-responses');
      if (!/^planner-response-[A-Za-z0-9-]{36}$/.test(responseId || '') || !fs.existsSync(parent) || fs.lstatSync(parent).isSymbolicLink()) throw error('PLANNER_RESPONSE_NOT_FOUND', 'PlannerResponse недоступен');
      const dir = path.join(parent, responseId);
      if (!fs.existsSync(dir) || fs.lstatSync(dir).isSymbolicLink()) throw error('PLANNER_RESPONSE_NOT_FOUND', 'PlannerResponse недоступен');
      const receiptPath = path.join(dir, 'receipt.json'), responsePath = path.join(dir, 'response.bin'), requestPath = path.join(dir, 'request.bin');
      for (const file of [receiptPath, responsePath, requestPath]) this.#assertRegularFile(file, dir);
      let receipt;
      try { receipt = PlannerResponseReceiptSchema.parse(JSON.parse(fs.readFileSync(receiptPath, 'utf8'))); }
      catch { throw error('PLANNER_RESPONSE_CORRUPT', 'Повреждены метаданные PlannerResponse'); }
      const bodyBytes = fs.readFileSync(responsePath), requestBodyBytes = fs.readFileSync(requestPath);
      if (receipt.responseId !== responseId || receipt.taskId !== taskId || bodyBytes.byteLength !== receipt.byteLength || digest(bodyBytes) !== receipt.responseSha256 || digest(requestBodyBytes) !== receipt.requestBodySha256) throw error('PLANNER_RESPONSE_CORRUPT', 'Нарушена целостность PlannerResponse');
      const stored = this.#events(taskId).some(event => event.type === 'PLANNER_RESPONSE_STORED' && event.payload.responseId === responseId && event.payload.responseSha256 === receipt.responseSha256);
      if (!stored) throw error('PLANNER_RESPONSE_NOT_COMMITTED', 'PlannerResponse не опубликован в journal');
      return { receipt, bodyBytes, requestBodyBytes };
    });
  }

  async getActivePlannerRequest(taskId) {
    return withFileMutex(this.lockPath, () => this.#activePlannerRequest(taskId));
  }

  async getStoredPlannerResponseForRequest(taskId, requestId) {
    return withFileMutex(this.lockPath, () => {
      const event = this.#events(taskId).find(item => item.type === 'PLANNER_RESPONSE_STORED' && item.payload.requestId === requestId);
      if (!event) return null;
      return this.#readPlannerResponseSync(taskId, event.payload.responseId);
    });
  }

  async recoverPlannerResponseFiles(taskId) {
    return withFileMutex(this.lockPath, () => {
      this.#assertPlannerStoreAccess();
      const task = this.#snapshot(taskId), parent = path.join(this.#taskPath(taskId), 'planner-responses');
      if (!fs.existsSync(parent)) return { recovered: [], stagingIncomplete: false };
      if (fs.lstatSync(parent).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог PlannerResponse является symlink');
      const entries = fs.readdirSync(parent, { withFileTypes: true });
      const staging = entries.filter(item => item.name.endsWith('.staging') || item.name.includes('.staging'));
      if (staging.length) return { recovered: [], stagingIncomplete: true };
      const active = this.#activePlannerRequest(taskId), recovered = [];
      for (const entry of entries.filter(item => item.isDirectory() && entryNameIsResponse(item.name))) {
        const dir = path.join(parent, entry.name);
        const receiptPath = path.join(dir, 'receipt.json'), responsePath = path.join(dir, 'response.bin'), requestPath = path.join(dir, 'request.bin');
        for (const file of [receiptPath, responsePath, requestPath]) this.#assertRegularFile(file, dir);
        let receipt;
        try { receipt = PlannerResponseReceiptSchema.parse(JSON.parse(fs.readFileSync(receiptPath, 'utf8'))); }
        catch { throw error('PLANNER_RESPONSE_CORRUPT', 'Повреждены метаданные PlannerResponse'); }
        const bodyBytes = fs.readFileSync(responsePath), requestBytes = fs.readFileSync(requestPath);
        if (receipt.responseId !== entry.name || receipt.taskId !== taskId || bodyBytes.byteLength !== receipt.byteLength || digest(bodyBytes) !== receipt.responseSha256 || digest(requestBytes) !== receipt.requestBodySha256) throw error('PLANNER_RESPONSE_CORRUPT', 'Нарушена целостность PlannerResponse');
        const stored = this.#events(taskId).some(event => event.type === 'PLANNER_RESPONSE_STORED' && event.payload.responseId === receipt.responseId);
        if (!stored) {
          if (!active || task.status !== 'PLANNING' || active.requestId !== receipt.requestId || active.requestSha256 !== receipt.requestSha256) throw error('PLANNER_RESPONSE_ORPHANED', 'PlannerResponse не связан с активным запросом');
          this.#commit(taskId, stateOf(task), 'PLANNER_RESPONSE_STORED', { responseId: receipt.responseId, requestId: receipt.requestId, requestSha256: receipt.requestSha256, responseSha256: receipt.responseSha256, byteLength: receipt.byteLength });
          recovered.push(receipt.responseId);
        }
      }
      return { recovered, stagingIncomplete: false };
    });
  }

  async recordPlannerResponseValidated(taskId, responseId, { modelId, planResultSha256 }) {
    return withFileMutex(this.lockPath, () => {
      const task = this.#snapshot(taskId), active = this.#activePlannerRequest(taskId);
      if (!active || task.status !== 'PLANNING') throw error('PLANNER_REQUEST_MISMATCH', 'Нет активного Planner request');
      const dir = path.join(this.#taskPath(taskId), 'planner-responses', responseId);
      const receipt = PlannerResponseReceiptSchema.parse(JSON.parse(fs.readFileSync(path.join(dir, 'receipt.json'), 'utf8')));
      if (receipt.requestId !== active.requestId || receipt.providerId !== active.providerId || receipt.configuredModelId !== modelId || receipt.mode !== 'MODEL' || digest(fs.readFileSync(path.join(dir, 'response.bin'))) !== receipt.responseSha256) throw error('PLANNER_PROVENANCE_MISMATCH', 'Подтверждённый modelId не совпадает с host config');
      return this.#commit(taskId, stateOf(task), 'PLANNER_RESPONSE_VALIDATED', { responseId, requestId: receipt.requestId, requestSha256: receipt.requestSha256, responseSha256: receipt.responseSha256, modelId, planResultSha256 });
    });
  }

  async rejectPlannerResponse(taskId, responseId, { reasonCode = 'INVALID_RESPONSE' } = {}) {
    return withFileMutex(this.lockPath, () => {
      const task = this.#snapshot(taskId), active = this.#activePlannerRequest(taskId);
      const receipt = responseId ? this.#readPlannerResponseSync(taskId, responseId).receipt : null;
      if (!active || (receipt && receipt.requestId !== active.requestId)) throw error('PLANNER_REQUEST_MISMATCH', 'PlannerResponse не связан с активным запросом');
      return this.#commit(taskId, stateOf(task), 'PLANNER_RESPONSE_REJECTED', { requestId: active.requestId, responseId: receipt?.responseId || null, responseSha256: receipt?.responseSha256 || null, reasonCode });
    });
  }

  async finishPlannerRequest(taskId, requestId, { reasonCode = 'PLANNER_FAILED', outcome = 'UNKNOWN' } = {}) {
    return withFileMutex(this.lockPath, () => {
      const task = this.#snapshot(taskId), active = this.#activePlannerRequest(taskId);
      if (!active || active.requestId !== requestId) return task;
      return this.#commit(taskId, stateOf(task), 'PLANNER_REQUEST_FINISHED', { requestId, reasonCode, outcome });
    });
  }

  async recordDispatchIntent(taskId, intent, expected) {
    return withFileMutex(this.lockPath, () => {
      const current = this.#snapshot(taskId);
      if (current.status !== 'READY' || current.revision !== expected?.revision || current.executionPlanId !== expected?.planId) {
        throw error('TASK_CONFLICT', 'Task или одобренный план изменился до dispatch intent');
      }
      const plan = this.#readPlan(taskId, current.executionPlanId);
      if (plan.sha256 !== expected?.planSha256) throw error('TASK_CONFLICT', 'Digest плана изменился до dispatch intent');
      const checked = TaskDispatchIntentSchema.parse(intent);
      const step = plan.steps.find(item => item.stepId === checked.stepId);
      if (!step || step.adapterId !== checked.adapterId || step.executionRef === null || digest(step.executionRef) !== checked.executionRefSha256) {
        throw error('INVALID_DISPATCH_INTENT', 'Dispatch intent не соответствует утверждённому шагу');
      }
      const transitioned = transitionTask(current, 'RUNNING');
      return this.#commit(taskId, stateOf(transitioned), 'DISPATCH_INTENT', { ...checked, planId: plan.planId, planSha256: plan.sha256 });
    });
  }

  async recordDispatchReturned(taskId, { runId, executionOutcome, reasonCode = null }) {
    return withFileMutex(this.lockPath, () => {
      const current = this.#snapshot(taskId);
      if (current.status !== 'RUNNING') throw error('INVALID_TASK_TRANSITION', 'DISPATCH_RETURNED допустим только для RUNNING Task');
      if (!current.runIds.includes(runId)) {
        const next = TaskStateSchema.parse({ ...stateOf(current), runIds: [...current.runIds, runId], revision: current.revision + 1, updatedAt: isoNow() });
        return this.#commit(taskId, next, 'DISPATCH_RETURNED', { runId, executionOutcome, reasonCode });
      }
      throw error('DUPLICATE_DISPATCH_RESULT', 'Результат dispatch уже сохранён');
    });
  }

  async recordRecoveryRunId(taskId, { runId, reasonCode = null }) {
    return withFileMutex(this.lockPath, () => {
      const current = this.#snapshot(taskId);
      if (!['RUNNING', 'VERIFYING'].includes(current.status)) throw error('INVALID_TASK_TRANSITION', 'Recovery run ref допустим только для активной Task');
      if (current.runIds.includes(runId)) return current;
      const next = TaskStateSchema.parse({ ...stateOf(current), runIds: [...current.runIds, runId], revision: current.revision + 1, updatedAt: isoNow() });
      return this.#commit(taskId, next, 'RECOVERY_RUN_OBSERVED', { runId, reasonCode });
    });
  }

  async recordDispatchUncertain(taskId, { runId = null, reasonCode }) {
    return withFileMutex(this.lockPath, () => {
      const current = this.#snapshot(taskId);
      if (current.status !== 'RUNNING') throw error('INVALID_TASK_TRANSITION', 'Неопределённый dispatch допустим только для RUNNING Task');
      const transitioned = transitionTask(current, 'INCONCLUSIVE');
      const runIds = runId && !current.runIds.includes(runId) ? [...current.runIds, runId] : current.runIds;
      const next = TaskStateSchema.parse({ ...stateOf(transitioned), runIds, revision: current.revision + 1, updatedAt: isoNow() });
      return this.#commit(taskId, next, 'DISPATCH_OUTCOME_UNKNOWN', { runId, reasonCode });
    });
  }

  async savePlan(taskId, draft) {
    return withFileMutex(this.lockPath, () => {
      const task = this.#snapshot(taskId);
      if (task.status !== 'PLANNING') throw error('INVALID_TASK_TRANSITION', 'План можно сохранить только в состоянии PLANNING');
      const mode = draft.provider?.mode;
      if (mode === 'MODEL') {
        const ref = draft.plannerResponse;
        if (!ref) throw error('PLANNER_RESPONSE_REQUIRED', 'MODEL plan требует сохранённый PlannerResponse');
        const events = this.#events(taskId);
        const validated = events.find(event => event.type === 'PLANNER_RESPONSE_VALIDATED' && event.payload.responseId === ref.responseId && event.payload.requestId === ref.requestId && event.payload.requestSha256 === ref.requestSha256 && event.payload.responseSha256 === ref.responseSha256 && event.payload.modelId === draft.provider.modelId);
        const artifact = this.#readPlannerResponseSync(taskId, ref.responseId);
        if (!validated || validated.payload.planResultSha256 !== ref.planResultSha256 || digest(modelOutputFromPlan(draft)) !== ref.planResultSha256 || artifact.receipt.responseSha256 !== ref.responseSha256 || artifact.receipt.requestSha256 !== ref.requestSha256 || artifact.receipt.requestId !== ref.requestId || artifact.receipt.byteLength !== ref.byteLength || artifact.receipt.providerId !== draft.provider.providerId || artifact.receipt.configuredModelId !== draft.provider.modelId) throw error('PLANNER_RESPONSE_MISMATCH', 'MODEL plan provenance не связана с точным результатом durable PlannerResponse');
        const active = this.#activePlannerRequest(taskId);
        if (!active || active.requestId !== ref.requestId || active.requestSha256 !== ref.requestSha256) throw error('PLANNER_REQUEST_MISMATCH', 'MODEL plan не связан с активным Planner request');
      } else if (mode === 'MOCK') {
        draft = { ...draft, plannerResponse: null };
      }
      const plansDir = path.join(this.#taskPath(taskId), 'plans');
      if (fs.lstatSync(plansDir).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог plans не может быть symlink');
      const events = this.#events(taskId);
      const committedPlanIds = new Set(events.filter(event => event.type === 'PLAN_VERSION_CREATED').map(event => event.payload.planId));
      const orphanFiles = fs.readdirSync(plansDir).filter(name => /^\d{6}\.json$/.test(name)).filter(name => {
        try { return !committedPlanIds.has(JSON.parse(fs.readFileSync(path.join(plansDir, name), 'utf8')).planId); }
        catch { return true; }
      });
      if (orphanFiles.length) {
        if (mode !== 'MODEL' || orphanFiles.length !== 1) throw error('ORPHAN_PLAN_UNRECOVERABLE', 'Нельзя безопасно восстановить осиротевшую версию плана');
        const orphanFile = orphanFiles[0];
        let orphan;
        try { orphan = ExecutionPlanSchema.parse(JSON.parse(fs.readFileSync(path.join(plansDir, orphanFile), 'utf8'))); }
        catch { throw error('ORPHAN_PLAN_UNRECOVERABLE', 'Осиротевший план повреждён или не соответствует текущей схеме'); }
        const { sha256: orphanSha, ...orphanUnsigned } = orphan;
        if (orphan.taskId !== taskId || orphan.version !== Number(orphanFile.slice(0, 6)) || digest(orphanUnsigned) !== orphanSha || orphan.provider.providerId !== draft.provider.providerId || orphan.provider.modelId !== draft.provider.modelId || canonical(orphan.plannerResponse) !== canonical(draft.plannerResponse) || canonical(orphan.validation) !== canonical(draft.validation) || digest(modelOutputFromPlan(orphan)) !== draft.plannerResponse?.planResultSha256 || digest(modelOutputFromPlan(draft)) !== draft.plannerResponse?.planResultSha256) throw error('ORPHAN_PLAN_UNRECOVERABLE', 'Осиротевший план не совпадает с точным результатом текущего PlannerResponse');
        const recoveredState = TaskStateSchema.parse({ ...stateOf(task), normalizedGoal: orphan.normalizedGoal, executionPlanId: orphan.planId, status: 'PLAN_READY', revision: task.revision + 1, updatedAt: isoNow() });
        const committed = this.#commit(taskId, recoveredState, 'PLAN_VERSION_CREATED', { payloadSchemaVersion: '0.3.2', planId: orphan.planId, version: orphan.version, sha256: orphan.sha256, providerMode: orphan.provider.mode, plannerResponse: orphan.plannerResponse, executable: orphan.validation.executable });
        return { task: committed, plan: orphan };
      }
      const version = fs.readdirSync(plansDir).filter(name => /^\d{6}\.json$/.test(name)).length + 1;
      const planId = `plan-${taskId.slice(5)}-${version}`;
      const unsigned = { ...draft, schemaVersion: PLAN_SCHEMA_VERSION, planId, taskId, version, createdAt: isoNow() };
      delete unsigned.sha256;
      const plan = ExecutionPlanSchema.parse({ ...unsigned, sha256: digest(unsigned) });
      const file = path.join(plansDir, `${String(version).padStart(6, '0')}.json`);
      if (fs.existsSync(file)) throw error('PLAN_VERSION_CONFLICT', 'Версия плана уже существует');
      atomicWrite(file, bytes(plan));
      const next = TaskStateSchema.parse({ ...stateOf(task), normalizedGoal: plan.normalizedGoal, executionPlanId: planId, status: 'PLAN_READY', revision: task.revision + 1, updatedAt: isoNow() });
      const committed = this.#commit(taskId, next, 'PLAN_VERSION_CREATED', { payloadSchemaVersion: '0.3.2', planId, version, sha256: plan.sha256, providerMode: plan.provider.mode, plannerResponse: plan.plannerResponse, executable: plan.validation.executable });
      return { task: committed, plan };
    });
  }

  #readPlannerResponseSync(taskId, responseId) {
    this.#assertPlannerStoreAccess();
    const taskDir = this.#taskPath(taskId), parent = path.join(taskDir, 'planner-responses');
    if (!/^planner-response-[A-Za-z0-9-]{36}$/.test(responseId || '') || !fs.existsSync(parent) || fs.lstatSync(parent).isSymbolicLink()) throw error('PLANNER_RESPONSE_NOT_FOUND', 'PlannerResponse недоступен');
    const dir = path.join(parent, responseId);
    if (!fs.existsSync(dir) || fs.lstatSync(dir).isSymbolicLink()) throw error('PLANNER_RESPONSE_NOT_FOUND', 'PlannerResponse недоступен');
    const receiptPath = path.join(dir, 'receipt.json'), responsePath = path.join(dir, 'response.bin'), requestPath = path.join(dir, 'request.bin');
    for (const file of [receiptPath, responsePath, requestPath]) this.#assertRegularFile(file, dir);
    let receipt;
    try { receipt = PlannerResponseReceiptSchema.parse(JSON.parse(fs.readFileSync(receiptPath, 'utf8'))); }
    catch { throw error('PLANNER_RESPONSE_CORRUPT', 'Повреждены метаданные PlannerResponse'); }
    const bodyBytes = fs.readFileSync(responsePath), requestBodyBytes = fs.readFileSync(requestPath);
    if (receipt.responseId !== responseId || receipt.taskId !== taskId || bodyBytes.byteLength !== receipt.byteLength || digest(bodyBytes) !== receipt.responseSha256 || digest(requestBodyBytes) !== receipt.requestBodySha256) throw error('PLANNER_RESPONSE_CORRUPT', 'Нарушена целостность PlannerResponse');
    const stored = this.#events(taskId).some(event => event.type === 'PLANNER_RESPONSE_STORED' && event.payload.responseId === responseId && event.payload.responseSha256 === receipt.responseSha256);
    if (!stored) throw error('PLANNER_RESPONSE_NOT_COMMITTED', 'PlannerResponse не опубликован в journal');
    return { receipt, bodyBytes, requestBodyBytes };
  }

  async getPlan(taskId, planId = null) { return withFileMutex(this.lockPath, () => this.#readPlan(taskId, planId)); }
}
