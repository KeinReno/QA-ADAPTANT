import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonical, digest } from '../core/canonical.mjs';
import { withFileMutex } from '../core/file-mutex.mjs';
import { assertTaskPassSupported, ExecutionPlanSchema, TaskEventSchema, TaskSchema, TaskStateSchema, transitionTask } from './contracts.mjs';

const bytes = value => Buffer.from(`${canonical(value)}\n`, 'utf8');
const isoNow = () => new Date().toISOString();
const error = (code, message) => Object.assign(new Error(message), { code });
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
  constructor(root, { verifyTaskPass = null } = {}) {
    this.root = path.resolve(root);
    this.verifyTaskPass = verifyTaskPass;
    fs.mkdirSync(this.root, { recursive: true });
    if (fs.lstatSync(this.root).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Task root не может быть symlink');
    this.lockPath = path.join(this.root, '.task-store.lock');
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
      try { plan = ExecutionPlanSchema.parse(JSON.parse(fs.readFileSync(planPath, 'utf8'))); }
      catch { throw error('INTEGRITY_ERROR', 'Повреждён файл плана'); }
      const { sha256, ...unsigned } = plan;
      if (plan.taskId !== taskId || plan.version !== Number(file.slice(0, 6)) || digest(unsigned) !== sha256) throw error('INTEGRITY_ERROR', 'План изменён или не соответствует Task');
      if (!planId || plan.planId === planId) return plan;
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

  async savePlan(taskId, draft) {
    return withFileMutex(this.lockPath, () => {
      const task = this.#snapshot(taskId);
      if (task.status !== 'PLANNING') throw error('INVALID_TASK_TRANSITION', 'План можно сохранить только в состоянии PLANNING');
      const plansDir = path.join(this.#taskPath(taskId), 'plans');
      if (fs.lstatSync(plansDir).isSymbolicLink()) throw error('INTEGRITY_ERROR', 'Каталог plans не может быть symlink');
      const version = fs.readdirSync(plansDir).filter(name => /^\d{6}\.json$/.test(name)).length + 1;
      const planId = `plan-${taskId.slice(5)}-${version}`;
      const unsigned = { ...draft, schemaVersion: '0.3.0', planId, taskId, version, createdAt: isoNow() };
      delete unsigned.sha256;
      const plan = ExecutionPlanSchema.parse({ ...unsigned, sha256: digest(unsigned) });
      const file = path.join(plansDir, `${String(version).padStart(6, '0')}.json`);
      if (fs.existsSync(file)) throw error('PLAN_VERSION_CONFLICT', 'Версия плана уже существует');
      atomicWrite(file, bytes(plan));
      const next = TaskStateSchema.parse({ ...stateOf(task), normalizedGoal: plan.normalizedGoal, executionPlanId: planId, status: 'PLAN_READY', revision: task.revision + 1, updatedAt: isoNow() });
      const committed = this.#commit(taskId, next, 'PLAN_VERSION_CREATED', { planId, version, sha256: plan.sha256, providerMode: plan.provider.mode, executable: plan.validation.executable });
      return { task: committed, plan };
    });
  }

  async getPlan(taskId, planId = null) { return withFileMutex(this.lockPath, () => this.#readPlan(taskId, planId)); }
}
