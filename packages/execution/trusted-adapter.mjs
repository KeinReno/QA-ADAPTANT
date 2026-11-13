import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonical, digest } from '../core/canonical.mjs';
import { ExecutionAdapterError } from './adapter.mjs';

const bytes = value => Buffer.from(`${canonical(value)}\n`, 'utf8');
const runIdPattern = /^run-[A-Za-z0-9_-]{1,140}$/;
const planDigest = plan => { const { sha256, ...unsigned } = plan; return digest(unsigned) === sha256; };

function atomicWrite(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  const fd = fs.openSync(temporary, 'wx', 0o600);
  try { fs.writeFileSync(fd, content); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
}

export class TrustedFacadeExecutionAdapter {
  constructor({ id = 'trusted-facade', root, executionRefs, resolveTrustOptions, facade = null, capabilityList = [] } = {}) {
    if (typeof root !== 'string' || !root) throw new TypeError('Trusted adapter требует отдельный run store root');
    if (typeof resolveTrustOptions !== 'function') throw new TypeError('Нужен host-side Trust approval/options resolver');
    this.id = id;
    this.root = path.resolve(root);
    this.preparedDir = path.join(this.root, 'adaptant-prepared');
    this.launchDir = path.join(this.root, 'adaptant-launches');
    this.executionRefs = executionRefs instanceof Map ? new Map(executionRefs) : new Map(Object.entries(executionRefs || {}));
    this.resolveTrustOptions = resolveTrustOptions;
    this.facade = facade;
    this.capabilityList = Object.freeze([...capabilityList]);
    fs.mkdirSync(this.root, { recursive: true });
    if (fs.lstatSync(this.root).isSymbolicLink()) throw new ExecutionAdapterError('INTEGRITY_ERROR', 'Run store root не может быть symlink');
    const rootReal = fs.realpathSync(this.root);
    fs.mkdirSync(this.preparedDir, { recursive: true });
    fs.mkdirSync(this.launchDir, { recursive: true });
    for (const directory of [this.preparedDir, this.launchDir]) {
      const stat = fs.lstatSync(directory);
      const real = fs.realpathSync(directory);
      if (stat.isSymbolicLink() || !stat.isDirectory() || !real.startsWith(`${rootReal}${path.sep}`)) {
        throw new ExecutionAdapterError('INTEGRITY_ERROR', 'Каталоги prepared/launch должны оставаться внутри run store root');
      }
    }
  }

  capabilities() { return this.capabilityList; }

  #preparedFile(runId) {
    if (!runIdPattern.test(runId)) throw new ExecutionAdapterError('INVALID_RUN_ID', 'Некорректный runId');
    const file = path.join(this.preparedDir, `${runId}.json`);
    if (fs.existsSync(file)) {
      const stat = fs.lstatSync(file);
      if (stat.isSymbolicLink() || !stat.isFile() || !fs.realpathSync(file).startsWith(`${fs.realpathSync(this.preparedDir)}${path.sep}`)) {
        throw new ExecutionAdapterError('INTEGRITY_ERROR', 'Prepared bundle path вышел за каталог адаптера');
      }
    }
    return file;
  }

  async #facade() { return this.facade || await import('../../apps/control/trusted.mjs'); }

  #assertTrustContext(options) {
    if (!options || typeof options.root !== 'string' || !options.root || typeof options.trustRoot !== 'string' || !options.trustRoot) {
      throw new ExecutionAdapterError('TRUST_CONTEXT_UNAVAILABLE', 'Trusted observer configuration unavailable');
    }
    if (path.resolve(options.root) !== this.root) throw new ExecutionAdapterError('TRUST_ROOT_MISMATCH', 'Trusted facade должен использовать закреплённый run store root');
    return options;
  }

  #assertTrustOptions(options, task = null) {
    if (!options || typeof options.root !== 'string' || !options.root || typeof options.trustRoot !== 'string' || !options.trustRoot ||
        typeof options.approvalId !== 'string' || !options.approvalId || !options.approval ||
        !options.issuer || !options.subject || (!options.anchorKeyPath && !options.signerPipe)) {
      throw new ExecutionAdapterError('TRUST_APPROVAL_UNAVAILABLE', 'Для trusted run отсутствует Trust approval или безопасная конфигурация');
    }
    this.#assertTrustContext(options);
    if (task?.approvalRef && task.approvalRef === options.approvalId) {
      throw new ExecutionAdapterError('APPROVAL_DOMAIN_MISMATCH', 'Owner plan approval нельзя повторно использовать как Trust approval');
    }
    return options;
  }

  async prepare({ task, plan, step, executionRef }) {
    const approvedStep = plan?.steps?.find(candidate => candidate.stepId === step?.stepId);
    if (task?.status !== 'READY' || task.taskId !== plan?.taskId || task.executionPlanId !== plan?.planId || !task.approvalRef || !planDigest(plan) ||
        !approvedStep || digest(approvedStep) !== digest(step) || step.required !== true || step.actionType !== 'trusted-scenario' ||
        step.adapterId !== this.id || step.executionRef !== executionRef) {
      throw new ExecutionAdapterError('ADAPTER_INPUT_MISMATCH', 'Task, утверждённый план, ExecutionStep и executionRef должны точно совпадать');
    }
    const entry = this.executionRefs.get(executionRef);
    if (!entry || typeof entry.buildBundle !== 'function') throw new ExecutionAdapterError('EXECUTION_REF_UNAVAILABLE', 'Execution ref отсутствует в host registry');
    const runId = `run-${randomUUID()}`;
    let bundle;
    try { bundle = await entry.buildBundle({ task, plan, step, runId }); }
    catch { throw new ExecutionAdapterError('BUNDLE_PREPARATION_FAILED', 'Host registry не подготовил trusted bundle', { dispatched: false }); }
    if (!bundle?.manifest || bundle.manifest.runId !== runId || !bundle.operation || !bundle.scenario || !bundle.fixture) {
      throw new ExecutionAdapterError('BUNDLE_INVALID', 'Prepared bundle не имеет ожидаемой формы', { dispatched: false });
    }
    const bundleDigest = digest(bundle);
    const file = this.#preparedFile(runId);
    if (fs.existsSync(file)) throw new ExecutionAdapterError('RUN_ID_CONFLICT', 'Run ID уже подготовлен');
    const binding = { runId, taskId: task.taskId, planId: plan.planId, planSha256: plan.sha256, approvalRef: task.approvalRef, stepId: step.stepId, stepSha256: digest(step), executionRef, bundleDigest };
    const preparedDigest = digest(binding);
    atomicWrite(file, bytes({ schemaVersion: '0.3.0', ...binding, preparedDigest, bundle }));
    try {
      const trustOptions = this.#assertTrustOptions(await this.resolveTrustOptions({ task, plan, step, bundle, runId, executionRef }), task);
    } catch (cause) {
      throw cause instanceof ExecutionAdapterError ? cause : new ExecutionAdapterError('TRUST_APPROVAL_UNAVAILABLE', 'Host не разрешил Trust approval', { dispatched: false });
    }
    return { runId, bundleDigest, preparedDigest, preparedRef: runId };
  }

  #readPrepared(runId, expectedDigest = null) {
    const file = this.#preparedFile(runId);
    if (!fs.existsSync(file)) throw new ExecutionAdapterError('PREPARED_BUNDLE_MISSING', 'Prepared bundle отсутствует');
    let record;
    try { record = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { throw new ExecutionAdapterError('INTEGRITY_ERROR', 'Prepared bundle повреждён'); }
    const { schemaVersion: _schemaVersion, preparedDigest, bundle, ...binding } = record;
    if (record.schemaVersion !== '0.3.0' || record.runId !== runId || bundle?.manifest?.runId !== runId || digest(bundle) !== record.bundleDigest ||
        digest(binding) !== preparedDigest || (expectedDigest && expectedDigest !== preparedDigest)) {
      throw new ExecutionAdapterError('INTEGRITY_ERROR', 'Prepared binding/digest не совпал с durable intent');
    }
    return record;
  }

  async start({ task, plan, step, prepared, idempotencyKey }) {
    const record = this.#readPrepared(prepared?.runId, prepared?.preparedDigest);
    const approvedStep = plan?.steps?.find(candidate => candidate.stepId === step?.stepId);
    if (prepared.preparedRef !== record.runId || task?.status !== 'RUNNING' || task.taskId !== record.taskId || plan?.taskId !== record.taskId ||
        task.executionPlanId !== record.planId || plan.planId !== record.planId || plan.sha256 !== record.planSha256 || !planDigest(plan) ||
        task.approvalRef !== record.approvalRef || step?.stepId !== record.stepId ||
        !approvedStep || digest(approvedStep) !== record.stepSha256 || digest(step) !== record.stepSha256 || step.adapterId !== this.id ||
        step.executionRef !== record.executionRef || !task.approvalRef || !/^[a-f0-9]{64}$/.test(idempotencyKey || '')) {
      throw new ExecutionAdapterError('ADAPTER_INPUT_MISMATCH', 'Dispatch не совпадает с подготовленным binding утверждённого плана', { dispatched: false });
    }
    const launch = path.join(this.launchDir, `${record.runId}.json`);
    let fd;
    try {
      fd = fs.openSync(launch, 'wx', 0o600);
      fs.writeFileSync(fd, bytes({ runId: record.runId, bundleDigest: record.bundleDigest, idempotencyKey, at: new Date().toISOString() }));
      fs.fsyncSync(fd);
    } catch (cause) {
      if (cause?.code === 'EEXIST') throw new ExecutionAdapterError('DISPATCH_ALREADY_ATTEMPTED', 'Повторный вызов start для этого run запрещён', { dispatched: true, runId: record.runId });
      throw new ExecutionAdapterError('DISPATCH_MARKER_FAILED', 'Не удалось durable-отметить попытку запуска', { dispatched: false });
    } finally { if (fd !== undefined) fs.closeSync(fd); }
    let options;
    try { options = this.#assertTrustOptions(await this.resolveTrustOptions({ task, plan, step, bundle: record.bundle, runId: record.runId, executionRef: record.executionRef }), task); }
    catch (cause) {
      throw cause instanceof ExecutionAdapterError ? new ExecutionAdapterError(cause.code, cause.message, { dispatched: false, runId: record.runId }) : new ExecutionAdapterError('TRUST_APPROVAL_UNAVAILABLE', 'Trust approval недоступен до вызова trusted facade', { dispatched: false, runId: record.runId });
    }
    this.#assertTrustOptions(options, task);
    try {
      const result = await (await this.#facade()).startTrusted(record.bundle, options);
      // Runner result/verdict не используется как подтверждение Task.
      return { runId: record.runId, executionOutcome: result?.executionOutcome === 'FAILED' ? 'FAILED' : result?.executionOutcome === 'UNKNOWN' ? 'UNKNOWN' : 'SUCCEEDED', reasonCode: null };
    } catch (cause) {
      throw new ExecutionAdapterError(cause?.code || 'TRUSTED_START_FAILED', 'Trusted facade не подтвердил завершение start; исход будет наблюдаться по закреплённому runId', { dispatched: true, runId: record.runId });
    }
  }

  async observe({ runId, expectedPreparedDigest = null }) {
    const record = this.#readPrepared(runId, expectedPreparedDigest);
    const options = this.#assertTrustContext(await this.resolveTrustOptions({ runId, executionRef: record.executionRef, bundle: record.bundle, phase: 'observe' }));
    const observed = await (await this.#facade()).observeTrusted({ root: options.root, trustRoot: options.trustRoot, runId, approvalId: options.approvalId });
    if (observed.runId !== runId) throw new ExecutionAdapterError('INTEGRITY_ERROR', 'Trusted observer вернул другой runId');
    return {
      runId,
      trusted: observed.trusted === true,
      passed: observed.passed === true,
      verdict: observed.trusted === true && observed.verdict ? { verdict: observed.verdict.verdict, reasonCode: observed.verdict.reasonCode || null } : null,
      reasonCode: observed.reasonCode || null,
      state: observed.state || null,
      evidenceIds: Array.isArray(observed.evidenceIds) ? observed.evidenceIds.filter(value => typeof value === 'string') : [],
      manifestSha256: observed.manifestSha256 || null,
      publication: observed.publication || null
    };
  }

  async cancel({ runId, actorRef }) {
    const record = this.#readPrepared(runId);
    const options = this.#assertTrustContext(await this.resolveTrustOptions({ runId, executionRef: record.executionRef, phase: 'cancel', actorRef }));
    return (await this.#facade()).cancelTrusted({ root: options.root, trustRoot: options.trustRoot, runId, subject: options.subject, approvalId: options.approvalId });
  }

  async reconcile({ runId, expectedPreparedDigest = null }) {
    const record = this.#readPrepared(runId, expectedPreparedDigest);
    const options = this.#assertTrustOptions(await this.resolveTrustOptions({ runId, executionRef: record.executionRef, bundle: record.bundle, phase: 'reconcile' }));
    await (await this.#facade()).reconcileTrusted({ ...options, runId });
    return this.observe({ runId, expectedPreparedDigest: record.preparedDigest });
  }

  async verifyTaskPass({ plan, result }) {
    try {
      for (const step of plan.steps.filter(item => item.required)) {
        if (step.adapterId !== this.id) return false;
        const outcome = result.stepOutcomes.find(item => item.stepId === step.stepId);
        if (!outcome || outcome.trustedVerification !== true || outcome.verificationOutcome !== 'PASS' || outcome.runIds.length !== 1) return false;
        const runId = outcome.runIds[0];
        const observed = await this.observe({ runId });
        if (!observed.trusted || !observed.passed || observed.verdict?.verdict !== 'PASS') return false;
        if (outcome.evidenceRefs.some(ref => ref.runId !== runId || !observed.evidenceIds.includes(ref.evidenceId))) return false;
        if (new Set(outcome.evidenceRefs.map(ref => ref.evidenceId)).size !== observed.evidenceIds.length || observed.evidenceIds.some(id => !outcome.evidenceRefs.some(ref => ref.evidenceId === id))) return false;
      }
      return true;
    } catch { return false; }
  }
}
