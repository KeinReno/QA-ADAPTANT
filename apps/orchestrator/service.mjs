import { TaskSchema } from '../../packages/execution/contracts.mjs';
import { assertExecutionAdapter } from '../../packages/execution/adapter.mjs';
import { PlannerResultSchema, PlannerProviderError } from '../../packages/planner/provider.mjs';
import { validatePlanDraft } from '../../packages/planner/validate.mjs';

const failure = (code, message) => Object.assign(new Error(message), { code });

export class TaskService {
  constructor({ store, plannerProvider, approvalVerifier = null, adapters = new Map(), registeredExecutionRefs = [], approvedScenarioRefs = [], allowedCapabilities = [], availabilityTimeoutMs = 5000, plannerTimeoutMs = 30000, maxPlannerResponseBytes = 100000 } = {}) {
    if (!store) throw new TypeError('TaskStore обязателен');
    if (!plannerProvider) throw new TypeError('PlannerProvider обязателен; fallback не выбирается автоматически');
    this.store = store;
    this.plannerProvider = plannerProvider;
    this.approvalVerifier = approvalVerifier;
    this.adapters = adapters instanceof Map ? adapters : new Map(Object.entries(adapters));
    this.registeredExecutionRefs = Object.freeze([...registeredExecutionRefs]);
    this.approvedScenarioRefs = Object.freeze([...approvedScenarioRefs]);
    this.allowedCapabilities = Object.freeze([...allowedCapabilities]);
    this.availabilityTimeoutMs = availabilityTimeoutMs;
    this.plannerTimeoutMs = plannerTimeoutMs;
    this.maxPlannerResponseBytes = maxPlannerResponseBytes;
  }

  async create(input) { return this.store.createTask(input); }

  async plan(taskId) {
    let task = await this.store.getTask(taskId);
    if (!['DRAFT', 'PLAN_READY', 'AWAITING_APPROVAL', 'BLOCKED'].includes(task.status)) {
      throw failure('INVALID_TASK_TRANSITION', `Нельзя планировать Task в состоянии ${task.status}`);
    }
    task = await this.store.transition(taskId, 'PLANNING', {
      patch: { approvalRef: null, executionPlanId: null, result: null },
      payload: { providerId: this.plannerProvider.id || 'unknown' }
    });
    try {
      const availability = await this.#boundedProviderCall(() => this.plannerProvider.availability(), this.availabilityTimeoutMs);
      if (!availability || availability.status !== 'AVAILABLE') {
        await this.store.appendEvent(taskId, 'PLANNER_UNAVAILABLE', { providerId: availability?.providerId || 'unknown', reasonCode: availability?.reasonCode || 'NOT_CONFIGURED' });
        return { task: await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'PLANNER_UNAVAILABLE' } }), plan: null };
      }
      const rawBytes = await this.#boundedProviderCall(signal => this.plannerProvider.plan({
        requestId: `plan-request-${task.revision}`,
        taskId,
        originalRequest: task.originalRequest,
        context: { allowedActionTypes: ['trusted-scenario', 'clarification', 'observation'], environmentRefs: task.environmentRef ? [task.environmentRef] : [], approvedScenarioRefs: this.approvedScenarioRefs, constraints: ['Модель не выдаёт полномочия', 'Только зарегистрированные trusted execution refs'] },
        outputSchemaVersion: '0.3.0', deadlineMs: this.plannerTimeoutMs, maxOutputBytes: this.maxPlannerResponseBytes, signal
      }), this.plannerTimeoutMs);
      if (!(rawBytes instanceof Uint8Array)) throw failure('INVALID_RESPONSE', 'Planner обязан вернуть ограниченный JSON response bytes');
      if (rawBytes.byteLength > this.maxPlannerResponseBytes) throw failure('OUTPUT_LIMIT', 'Planner ответ превышает локальный лимит размера');
      let raw;
      try { raw = JSON.parse(Buffer.from(rawBytes).toString('utf8')); }
      catch { throw failure('INVALID_RESPONSE', 'Planner вернул некорректный JSON'); }
      const result = PlannerResultSchema.parse(raw);
      const configuredProviderId = availability.providerId || this.plannerProvider.id;
      const configuredMode = this.plannerProvider.mode || 'MODEL';
      if (result.providerId !== configuredProviderId || result.mode !== configuredMode) throw failure('INVALID_PLAN', 'Planner output provenance не совпадает с локальной конфигурацией');
      const checked = validatePlanDraft(result.output, {
        taskId,
        provider: { providerId: configuredProviderId, modelId: availability.modelId ?? null, mode: configuredMode },
        registeredExecutionRefs: this.registeredExecutionRefs.filter(ref => this.approvedScenarioRefs.includes(ref)),
        registeredAdapters: [...this.adapters.keys()],
        allowedCapabilities: this.allowedCapabilities
      });
      const requiresTrustedRun = checked.steps.some(step => step.mutating || step.adapterId !== null || step.executionRef !== null || step.actionType === 'trusted-scenario');
      const policyChecked = {
        ...checked,
        approvalRequirements: ['OWNER_PLAN_APPROVAL', ...(requiresTrustedRun ? ['TRUST_APPROVAL'] : [])]
      };
      const { plan } = await this.store.savePlan(taskId, policyChecked);
      if (!plan.validation.executable) {
        await this.store.appendEvent(taskId, 'PLAN_NOT_EXECUTABLE', { planId: plan.planId, findings: plan.validation.findings });
        return { task: await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'PLAN_NOT_EXECUTABLE', planId: plan.planId } }), plan };
      }
      if (plan.approvalRequirements.includes('OWNER_PLAN_APPROVAL')) {
        return { task: await this.store.transition(taskId, 'AWAITING_APPROVAL', { payload: { planId: plan.planId, planSha256: plan.sha256 } }), plan };
      }
      return { task: await this.store.transition(taskId, 'READY', { payload: { planId: plan.planId } }), plan };
    } catch (error) {
      const current = await this.store.getTask(taskId);
      if (current.status === 'PLANNING') {
        const reasonCode = error instanceof PlannerProviderError ? error.code : (error.code || 'INVALID_PLAN');
        await this.store.appendEvent(taskId, 'PLANNER_FAILED', { reasonCode });
        return { task: await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode } }), plan: null };
      }
      throw error;
    }
  }

  async #boundedProviderCall(invoke, timeoutMs) {
    const controller = new AbortController();
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new PlannerProviderError('TIMEOUT', 'Истёк локальный лимит времени Planner'));
      }, timeoutMs);
    });
    try { return await Promise.race([Promise.resolve().then(() => invoke(controller.signal)), timeout]); }
    finally { clearTimeout(timer); }
  }

  async approvePlan(taskId, { planId, actorRef, approvalRef } = {}) {
    const task = await this.store.getTask(taskId);
    const plan = await this.store.getPlan(taskId, planId);
    if (task.status !== 'AWAITING_APPROVAL' || task.executionPlanId !== plan.planId) throw failure('PLAN_NOT_CURRENT', 'Подтверждается только текущая версия плана в состоянии ожидания');
    if (actorRef !== task.ownerRef) throw failure('OWNER_MISMATCH', 'Подтверждение может дать только владелец Task');
    if (!this.approvalVerifier) throw failure('OWNER_APPROVAL_UNAVAILABLE', 'Проверяющий подтверждение владельца не настроен');
    const accepted = await this.approvalVerifier({ task, plan, actorRef, approvalRef });
    if (!accepted) throw failure('OWNER_APPROVAL_INVALID', 'Подтверждение владельца не прошло проверку');
    return this.store.transition(taskId, 'READY', {
      patch: { approvalRef }, expected: { revision: task.revision, planId: plan.planId, planSha256: plan.sha256 },
      payload: { planId, planSha256: plan.sha256, actorRef, approvalRef }
    });
  }

  async start(taskId) {
    const task = await this.store.getTask(taskId);
    if (task.status !== 'READY') throw failure('TASK_NOT_READY', `Task нельзя запустить в состоянии ${task.status}`);
    const plan = await this.store.getPlan(taskId, task.executionPlanId);
    const executableSteps = plan.steps.filter(item => item.actionType === 'trusted-scenario');
    if (executableSteps.length !== 1) {
      const reasonCode = executableSteps.length ? 'UNSUPPORTED_EXECUTION_SHAPE' : 'NO_EXECUTABLE_TRUSTED_STEP';
      const blocked = await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode } });
      return { task: blocked, started: false };
    }
    const step = executableSteps[0];
    const adapter = this.adapters.get(step.adapterId);
    if (!adapter) {
      const blocked = await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'EXECUTOR_UNAVAILABLE', adapterId: step.adapterId } });
      return { task: blocked, started: false };
    }
    assertExecutionAdapter(adapter);
    let adapterCapabilities;
    try { adapterCapabilities = adapter.capabilities(); }
    catch {
      const blocked = await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'ADAPTER_CAPABILITIES_UNAVAILABLE', adapterId: step.adapterId } });
      return { task: blocked, started: false };
    }
    if (!Array.isArray(adapterCapabilities) || step.requiredCapabilities.some(capability => !adapterCapabilities.includes(capability))) {
      const blocked = await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'ADAPTER_CAPABILITY_UNSUPPORTED', adapterId: step.adapterId } });
      return { task: blocked, started: false };
    }
    throw failure('EXECUTION_ADAPTER_NOT_IMPLEMENTED', 'Trusted adapter dispatch подключается на этапе C');
  }

  async cancel(taskId, actorRef) {
    const task = await this.store.getTask(taskId);
    if (task.ownerRef !== actorRef) throw failure('OWNER_MISMATCH', 'Отменить Task может только владелец');
    if (['DRAFT', 'PLANNING', 'PLAN_READY', 'AWAITING_APPROVAL', 'READY', 'BLOCKED'].includes(task.status)) {
      return this.store.transition(taskId, 'CANCELED', { payload: { actorRef, beforeDispatch: true } });
    }
    throw failure('CANCELLATION_REQUIRES_ADAPTER', 'После dispatch отмена требует поддерживаемого trusted adapter');
  }

  async observe(taskId) {
    const task = TaskSchema.parse(await this.store.getTask(taskId));
    let plan = null;
    if (task.executionPlanId) plan = await this.store.getPlan(taskId, task.executionPlanId);
    return { task, plan, events: await this.store.getEvents(taskId) };
  }

  async recover() {
    const { tasks, corrupt } = await this.store.listTaskEntries();
    const recovered = [], blocked = corrupt.map(item => item.taskId), inconclusive = [], integrityBlocked = [...blocked];
    for (const task of tasks) {
      if (task.executionPlanId) {
        try { await this.store.getPlan(task.taskId, task.executionPlanId); }
        catch (cause) {
          integrityBlocked.push(task.taskId);
          if (['PLAN_READY', 'AWAITING_APPROVAL', 'READY'].includes(task.status)) {
            await this.store.transition(task.taskId, 'BLOCKED', { payload: { reasonCode: 'PLAN_INTEGRITY_ERROR', detailCode: cause?.code || 'INTEGRITY_ERROR' } });
          } else if (['RUNNING', 'VERIFYING'].includes(task.status)) {
            await this.store.transition(task.taskId, 'INCONCLUSIVE', { payload: { reasonCode: 'PLAN_INTEGRITY_ERROR', detailCode: cause?.code || 'INTEGRITY_ERROR', runIds: task.runIds } });
            inconclusive.push(task.taskId);
          }
          continue;
        }
      }
      if (task.status === 'PLANNING') {
        await this.store.transition(task.taskId, 'BLOCKED', { payload: { reasonCode: 'PLANNER_INTERRUPTED' } });
        blocked.push(task.taskId);
      } else if (task.status === 'RUNNING' || task.status === 'VERIFYING') {
        await this.store.transition(task.taskId, 'INCONCLUSIVE', { payload: { reasonCode: 'EXECUTION_STATE_UNKNOWN', runIds: task.runIds } });
        inconclusive.push(task.taskId);
      } else recovered.push(task.taskId);
    }
    return { recovered, blocked, inconclusive, integrityBlocked };
  }
}
