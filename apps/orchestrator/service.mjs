import { randomUUID } from 'node:crypto';
import { TaskSchema } from '../../packages/execution/contracts.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { assertExecutionAdapter } from '../../packages/execution/adapter.mjs';
import { PlannerAvailabilitySchema, PlannerResultSchema, PlannerProviderError } from '../../packages/planner/provider.mjs';
import { validatePlanDraft } from '../../packages/planner/validate.mjs';

const failure = (code, message) => Object.assign(new Error(message), { code });

export class TaskService {
  constructor({ store, plannerProvider, approvalVerifier = null, adapters = new Map(), registeredExecutionRefs = [], approvedScenarioRefs = [], plannerActionCatalog = [], allowedCapabilities = [], availabilityTimeoutMs = 5000, plannerTimeoutMs = 30000, maxPlannerResponseBytes = 100000, maxPlannerRequestBytes = 64000 } = {}) {
    if (!store) throw new TypeError('TaskStore обязателен');
    if (!plannerProvider) throw new TypeError('PlannerProvider обязателен; fallback не выбирается автоматически');
    if (typeof plannerProvider.id !== 'string' || !plannerProvider.id || !['MODEL', 'MOCK'].includes(plannerProvider.mode)) throw new TypeError('PlannerProvider обязан иметь локально заданные id и mode=MODEL|MOCK');
    if (typeof plannerProvider.availability !== 'function' || typeof plannerProvider.plan !== 'function') throw new TypeError('PlannerProvider обязан реализовать availability() и plan()');
    this.store = store;
    this.plannerProvider = plannerProvider;
    this.approvalVerifier = approvalVerifier;
    this.adapters = adapters instanceof Map ? adapters : new Map(Object.entries(adapters));
    this.registeredExecutionRefs = Object.freeze([...registeredExecutionRefs]);
    this.approvedScenarioRefs = Object.freeze([...approvedScenarioRefs]);
    this.plannerActionCatalog = Object.freeze(structuredClone(plannerActionCatalog));
    this.allowedCapabilities = Object.freeze([...allowedCapabilities]);
    this.availabilityTimeoutMs = availabilityTimeoutMs;
    this.plannerTimeoutMs = plannerTimeoutMs;
    this.maxPlannerResponseBytes = maxPlannerResponseBytes;
    this.maxPlannerRequestBytes = maxPlannerRequestBytes;
  }

  async create(input) { return this.store.createTask(input); }

  async #finishObserved({ taskId, plan, step, runId, executionOutcome, observation, observerError = null }) {
    let current = await this.store.getTask(taskId);
    const terminal = new Set(['COMPLETED', 'FAILED', 'CANCELED', 'BLOCKED', 'INCONCLUSIVE']);
    if (terminal.has(current.status)) return { task: current, plan, started: true, observation, result: current.result };
    if (current.status === 'RUNNING') {
      try {
        current = await this.store.transition(taskId, 'VERIFYING', {
          payload: { runId, adapterId: step.adapterId },
          expected: { revision: current.revision, planId: plan.planId, planSha256: plan.sha256 }
        });
      } catch (cause) {
        current = await this.store.getTask(taskId);
        if (terminal.has(current.status)) return { task: current, plan, started: true, observation, result: current.result };
        if (current.status !== 'VERIFYING') throw cause;
      }
    }
    if (current.status !== 'VERIFYING') return { task: current, plan, started: true, observation, result: current.result };
    const evidenceIds = Array.isArray(observation?.evidenceIds) ? observation.evidenceIds : [];
    const trusted = observation?.trusted === true;
    const verdict = trusted ? observation.verdict?.verdict : null;
    const taskOutcome = trusted && observation.passed === true && verdict === 'PASS'
      ? 'PASS'
      : trusted && verdict === 'FAIL' ? 'FAIL'
        : trusted && verdict === 'CANCELED' ? 'CANCELED' : 'INCONCLUSIVE';
    const verificationOutcome = taskOutcome === 'PASS' ? 'PASS' : taskOutcome === 'FAIL' ? 'FAIL' : 'INCONCLUSIVE';
    const verifiedExecutionOutcome = trusted && ['PASS', 'FAIL'].includes(verdict) ? 'SUCCEEDED' : executionOutcome;
    const result = {
      taskOutcome, plannerMode: plan.provider.mode,
      stepOutcomes: [{ stepId: step.stepId, executionOutcome: verifiedExecutionOutcome, verificationOutcome, trustedVerification: trusted,
        runIds: [runId], evidenceRefs: evidenceIds.map(evidenceId => ({ runId, evidenceId })) }],
      reasonCode: taskOutcome === 'PASS' ? null : observerError || observation?.reasonCode || 'TRUSTED_RESULT_NOT_PASS',
      message: taskOutcome === 'PASS' ? 'Trusted observer подтвердил выполнение' : 'Trusted observer не подтвердил PASS'
    };
    const finalStatus = taskOutcome === 'PASS' || taskOutcome === 'FAIL' ? 'COMPLETED' : taskOutcome === 'CANCELED' ? 'CANCELED' : 'INCONCLUSIVE';
    let finalTask;
    try {
      finalTask = await this.store.transition(taskId, finalStatus, {
        patch: { result }, payload: { runId, taskOutcome, reasonCode: result.reasonCode },
        expected: { revision: current.revision, planId: plan.planId, planSha256: plan.sha256 }
      });
    } catch (cause) {
      finalTask = await this.store.getTask(taskId);
      if (!terminal.has(finalTask.status)) throw cause;
    }
    return { task: finalTask, plan, started: true, observation, result: finalTask.result };
  }

  async #saveValidatedPlan(taskId, rawBytes, { providerId, modelId, mode, availability, plannerResponseRef = null, validatedModelId = null }) {
    if (!(rawBytes instanceof Uint8Array)) throw failure('INVALID_RESPONSE', 'Planner обязан вернуть ограниченный JSON response bytes');
    if (rawBytes.byteLength > this.maxPlannerResponseBytes) throw failure('OUTPUT_LIMIT', 'Planner ответ превышает локальный лимит размера');
    let raw;
    try { raw = JSON.parse(Buffer.from(rawBytes).toString('utf8')); }
    catch { throw failure('INVALID_RESPONSE', 'Planner вернул некорректный JSON'); }
    const result = PlannerResultSchema.parse(raw);
    if (result.providerId !== providerId || result.modelId !== modelId || result.mode !== mode || availability.providerId !== providerId || availability.modelId !== modelId || availability.mode !== mode || availability.status !== 'AVAILABLE') throw failure('INVALID_PLAN', 'Planner output provenance не совпадает с локальной конфигурацией и availability');
    if (mode === 'MODEL') {
      if (!plannerResponseRef || validatedModelId !== modelId) throw failure('INVALID_PLAN', 'Проверенный MODEL result не связан с durable response receipt');
      plannerResponseRef = { ...plannerResponseRef, planResultSha256: '0'.repeat(64) };
    }
    const checked = validatePlanDraft(result.output, {
      taskId,
      provider: { providerId, modelId, mode },
      plannerResponse: plannerResponseRef,
      registeredExecutionRefs: this.registeredExecutionRefs.filter(ref => this.approvedScenarioRefs.includes(ref)),
      registeredAdapters: [...this.adapters.keys()],
      allowedCapabilities: this.allowedCapabilities
    });
    const requiresTrustedRun = checked.steps.some(step => step.mutating || step.adapterId !== null || step.executionRef !== null || step.actionType === 'trusted-scenario');
    const policyChecked = { ...checked, approvalRequirements: ['OWNER_PLAN_APPROVAL', ...(requiresTrustedRun ? ['TRUST_APPROVAL'] : [])] };
    if (mode === 'MODEL') {
      const planResultSha256 = digest({ normalizedGoal: policyChecked.normalizedGoal, requirements: policyChecked.requirements, missingContext: policyChecked.missingContext, steps: policyChecked.steps, estimatedRisk: policyChecked.estimatedRisk, approvalRequirements: policyChecked.approvalRequirements, validationRules: policyChecked.validationRules });
      await this.store.recordPlannerResponseValidated(taskId, plannerResponseRef.responseId, { modelId: validatedModelId, planResultSha256 });
      plannerResponseRef = { ...plannerResponseRef, planResultSha256 };
      policyChecked.plannerResponse = plannerResponseRef;
    }
    const { plan } = await this.store.savePlan(taskId, policyChecked);
    if (!plan.validation.executable) {
      await this.store.appendEvent(taskId, 'PLAN_NOT_EXECUTABLE', { planId: plan.planId, findings: plan.validation.findings });
      return { task: await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'PLAN_NOT_EXECUTABLE', planId: plan.planId } }), plan };
    }
    if (plan.approvalRequirements.includes('OWNER_PLAN_APPROVAL')) return { task: await this.store.transition(taskId, 'AWAITING_APPROVAL', { payload: { planId: plan.planId, planSha256: plan.sha256 } }), plan };
    return { task: await this.store.transition(taskId, 'READY', { payload: { planId: plan.planId } }), plan };
  }

  async plan(taskId) {
    let task = await this.store.getTask(taskId);
    if (!['DRAFT', 'PLAN_READY', 'AWAITING_APPROVAL', 'BLOCKED'].includes(task.status)) {
      throw failure('INVALID_TASK_TRANSITION', `Нельзя планировать Task в состоянии ${task.status}`);
    }
    task = await this.store.transition(taskId, 'PLANNING', {
      patch: { approvalRef: null, executionPlanId: null, result: null },
      payload: { providerId: this.plannerProvider.id || 'unknown' }
    });
    let activeRequestId = null;
    let storedResponseId = null;
    try {
      const availability = PlannerAvailabilitySchema.parse(await this.#boundedProviderCall(() => this.plannerProvider.availability(), this.availabilityTimeoutMs));
      const configuredProviderId = this.plannerProvider.id;
      const configuredMode = this.plannerProvider.mode;
      if (availability.providerId !== configuredProviderId || availability.mode !== configuredMode) throw failure('INVALID_PLAN', 'Planner availability не совпадает с локальной конфигурацией provenance');
      if (!availability || availability.status !== 'AVAILABLE') {
        await this.store.appendEvent(taskId, 'PLANNER_UNAVAILABLE', { providerId: availability.providerId, reasonCode: availability.reasonCode || 'NOT_CONFIGURED', mode: configuredMode });
        return { task: await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'PLANNER_UNAVAILABLE' } }), plan: null };
      }
      const plannerRequest = {
        requestId: `plan-request-${randomUUID()}`,
        taskId,
        originalRequest: task.originalRequest,
        originalRequestSha256: task.originalRequestSha256,
        context: {
          allowedActionTypes: ['trusted-scenario', 'clarification', 'observation'],
          environmentRefs: task.environmentRef ? [task.environmentRef] : [],
          approvedScenarioRefs: this.approvedScenarioRefs,
          actionCatalog: this.plannerActionCatalog,
          constraints: ['Модель не выдаёт полномочия', 'Только зарегистрированные trusted execution refs', 'Не выполнять неизвестные операции']
        },
        outputSchemaVersion: '0.3.0', deadlineMs: this.plannerTimeoutMs,
        maxInputBytes: this.maxPlannerRequestBytes, maxOutputBytes: this.maxPlannerResponseBytes
      };
      let rawBytes;
      let plannerResponseRef = null;
      if (configuredMode === 'MODEL') {
        const modelProvider = this.plannerProvider;
        if (typeof modelProvider.buildRequest !== 'function' || typeof modelProvider.invoke !== 'function' || typeof modelProvider.parseResponse !== 'function') throw failure('INVALID_PROVIDER', 'MODEL Planner обязан реализовать buildRequest/invoke/parseResponse');
        if (await modelProvider.accessGuard?.() !== true) throw new PlannerProviderError('ARTIFACT_ACCESS_UNVERIFIED', 'Проверка доступа к PlannerResponse не пройдена');
        plannerRequest.requestSha256 = digest(plannerRequest);
        const invocation = modelProvider.buildRequest(plannerRequest);
        if (invocation.requestId !== plannerRequest.requestId || invocation.requestSha256 !== plannerRequest.requestSha256 || invocation.providerId !== configuredProviderId || invocation.configuredModelId !== availability.modelId || invocation.requestBodyBytes.byteLength > this.maxPlannerRequestBytes) throw failure('INVALID_REQUEST', 'Inference request не соответствует локальному контракту');
        activeRequestId = invocation.requestId;
        await this.store.beginPlannerRequest(taskId, {
          ...plannerRequest, providerId: configuredProviderId, configuredModelId: availability.modelId, mode: configuredMode, startedAt: new Date().toISOString()
        });
        try {
          const response = await this.#boundedProviderCall(signal => modelProvider.invoke(invocation, { signal }), this.plannerTimeoutMs);
          const receipt = await this.store.savePlannerResponse(taskId, { requestSha256: plannerRequest.requestSha256, requestBodyBytes: invocation.requestBodyBytes, response });
          storedResponseId = receipt.responseId;
          const persisted = await this.store.getPlannerResponse(taskId, receipt.responseId);
          const parsed = modelProvider.parseResponse({ ...response, bodyBytes: persisted.bodyBytes });
          const result = PlannerResultSchema.parse(JSON.parse(Buffer.from(parsed.resultBytes).toString('utf8')));
          if (result.providerId !== configuredProviderId || result.modelId !== availability.modelId || result.mode !== configuredMode || parsed.modelId !== availability.modelId) throw failure('INVALID_PLAN', 'Backend-reported modelId не совпадает с локальной конфигурацией');
          rawBytes = parsed.resultBytes;
          plannerResponseRef = { responseId: receipt.responseId, requestId: receipt.requestId, requestSha256: receipt.requestSha256, responseSha256: receipt.responseSha256, byteLength: receipt.byteLength };
        } catch (error) {
          if (activeRequestId) {
            if (storedResponseId) await this.store.rejectPlannerResponse(taskId, storedResponseId, { reasonCode: error.code || 'INVALID_RESPONSE' }).catch(() => {});
            else await this.store.finishPlannerRequest(taskId, activeRequestId, { reasonCode: error.code || 'PLANNER_FAILED', outcome: 'UNKNOWN' }).catch(() => {});
          }
          throw error;
        }
      } else {
        rawBytes = await this.#boundedProviderCall(signal => this.plannerProvider.plan({ ...plannerRequest, signal }), this.plannerTimeoutMs);
      }
      return await this.#saveValidatedPlan(taskId, rawBytes, { providerId: configuredProviderId, modelId: availability.modelId, mode: configuredMode, availability, plannerResponseRef, validatedModelId: storedResponseId ? availability.modelId : null });
    } catch (error) {
      const current = await this.store.getTask(taskId);
      if (current.status === 'PLANNING') {
        const reasonCode = error instanceof PlannerProviderError ? error.code : (error.code || 'INVALID_PLAN');
        if (activeRequestId) {
          if (storedResponseId) await this.store.rejectPlannerResponse(taskId, storedResponseId, { reasonCode }).catch(() => {});
          else await this.store.finishPlannerRequest(taskId, activeRequestId, { reasonCode, outcome: 'UNKNOWN' }).catch(() => {});
        }
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
    let task = await this.store.getTask(taskId);
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
    let task = await this.store.getTask(taskId);
    if (task.status !== 'READY') throw failure('TASK_NOT_READY', `Task нельзя запустить в состоянии ${task.status}`);
    const plan = await this.store.getPlan(taskId, task.executionPlanId);
    const requiredSteps = plan.steps.filter(item => item.required);
    const executableSteps = requiredSteps.filter(item => item.actionType === 'trusted-scenario');
    if (requiredSteps.length !== 1 || executableSteps.length !== 1) {
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
    let prepared;
    try { prepared = await adapter.prepare({ task, plan, step, executionRef: step.executionRef }); }
    catch (error) {
      const blocked = await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: error.code || 'ADAPTER_PREPARE_FAILED', adapterId: step.adapterId } });
      return { task: blocked, started: false };
    }
    if (!prepared || typeof prepared.runId !== 'string' || typeof prepared.preparedRef !== 'string' || !/^[a-f0-9]{64}$/.test(prepared.preparedDigest || '')) {
      const blocked = await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: 'ADAPTER_PREPARE_INVALID', adapterId: step.adapterId } });
      return { task: blocked, started: false };
    }
    const idempotencyKey = digest({ taskId, planId: plan.planId, stepId: step.stepId, runId: prepared.runId });
    try {
      const dispatchTask = await this.store.recordDispatchIntent(taskId, {
        runId: prepared.runId, stepId: step.stepId, adapterId: adapter.id,
        executionRefSha256: digest(step.executionRef), preparedDigest: prepared.preparedDigest, idempotencyKey
      }, { revision: task.revision, planId: plan.planId, planSha256: plan.sha256 });
      task = dispatchTask;
    } catch (error) {
      if (error.code === 'TASK_CONFLICT') throw error;
      const current = await this.store.getTask(taskId);
      if (current.status === 'READY') return { task: await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: error.code || 'DISPATCH_INTENT_FAILED' } }), started: false };
      throw error;
    }
    let started;
    try {
      started = await adapter.start({ task, plan, step, prepared, idempotencyKey });
      if (!started || started.runId !== prepared.runId || !['SUCCEEDED', 'FAILED', 'UNKNOWN'].includes(started.executionOutcome)) {
        throw Object.assign(new Error('Adapter вернул некорректный dispatch result'), { code: 'ADAPTER_RESULT_INVALID', dispatched: true });
      }
      await this.store.recordDispatchReturned(taskId, { runId: prepared.runId, executionOutcome: started.executionOutcome, reasonCode: started.reasonCode || null });
    } catch (error) {
      const afterError = await this.store.getTask(taskId);
      if (!['RUNNING'].includes(afterError.status)) return { task: afterError, plan, started: true, reasonCode: error.code || 'DISPATCH_OUTCOME_ALREADY_RECORDED' };
      if (error.dispatched === false) {
        return { task: await this.store.transition(taskId, 'BLOCKED', { payload: { reasonCode: error.code || 'ADAPTER_START_FAILED', runId: prepared.runId } }), started: false };
      }
      const taskAfterUnknown = await this.store.recordDispatchUncertain(taskId, { runId: prepared.runId, reasonCode: error.code || 'DISPATCH_OUTCOME_UNKNOWN' });
      return { task: taskAfterUnknown, started: false, reasonCode: error.code || 'DISPATCH_OUTCOME_UNKNOWN' };
    }
    let observation = null, observerError = null;
    try { observation = await adapter.observe({ runId: prepared.runId, task, plan, step, expectedPreparedDigest: prepared.preparedDigest }); }
    catch (error) { observerError = error?.code || 'TRUSTED_OBSERVER_FAILED'; }
    return this.#finishObserved({ taskId, plan, step, runId: prepared.runId, executionOutcome: started.executionOutcome, observation, observerError });
  }

  async cancel(taskId, actorRef) {
    const task = await this.store.getTask(taskId);
    if (task.ownerRef !== actorRef) throw failure('OWNER_MISMATCH', 'Отменить Task может только владелец');
    if (['DRAFT', 'PLANNING', 'PLAN_READY', 'AWAITING_APPROVAL', 'READY', 'BLOCKED'].includes(task.status)) {
      return this.store.transition(taskId, 'CANCELED', { payload: { actorRef, beforeDispatch: true } });
    }
    if (!['RUNNING', 'VERIFYING'].includes(task.status)) throw failure('TASK_NOT_CANCELLABLE', `Task нельзя отменить в состоянии ${task.status}`);
    const events = await this.store.getEvents(taskId);
    const intent = [...events].reverse().find(event => event.type === 'DISPATCH_INTENT');
    const runId = task.runIds.at(-1) || intent?.payload?.runId;
    const plan = await this.store.getPlan(taskId, task.executionPlanId);
    const step = plan.steps.find(item => item.stepId === intent?.payload?.stepId);
    const adapter = step && this.adapters.get(step.adapterId);
    if (!runId || !adapter) {
      return this.store.transition(taskId, 'INCONCLUSIVE', { payload: { reasonCode: 'CANCEL_RUN_REF_UNAVAILABLE', actorRef } });
    }
    assertExecutionAdapter(adapter);
    await this.store.appendEvent(taskId, 'CANCEL_REQUESTED', { actorRef, runId, adapterId: adapter.id });
    try {
      await adapter.cancel({ runId, actorRef, task, plan, step });
      const observation = await adapter.observe({ runId, task, plan, step, expectedPreparedDigest: intent.payload.preparedDigest });
      const returned = [...events].reverse().find(event => event.type === 'DISPATCH_RETURNED' && event.payload.runId === runId);
      return this.#finishObserved({ taskId, plan, step, runId, executionOutcome: returned?.payload?.executionOutcome || 'UNKNOWN', observation });
    } catch (error) {
      const latest = await this.store.getTask(taskId);
      if (['COMPLETED', 'FAILED', 'CANCELED', 'BLOCKED', 'INCONCLUSIVE'].includes(latest.status)) {
        return { task: latest, cancelRequested: false, result: latest.result, reasonCode: 'TASK_ALREADY_FINISHED' };
      }
      await this.store.appendEvent(taskId, 'CANCEL_OUTCOME_UNKNOWN', { actorRef, runId, reasonCode: error?.code || 'CANCEL_UNCONFIRMED' });
      return { task: await this.store.getTask(taskId), cancelRequested: true, reasonCode: error?.code || 'CANCEL_UNCONFIRMED' };
    }
  }

  async observe(taskId) {
    const task = TaskSchema.parse(await this.store.getTask(taskId));
    let plan = null;
    if (task.executionPlanId) plan = await this.store.getPlan(taskId, task.executionPlanId);
    return { task, plan, events: await this.store.getEvents(taskId) };
  }

  async plannerStatus() {
    try {
      const availability = PlannerAvailabilitySchema.parse(await this.#boundedProviderCall(() => this.plannerProvider.availability(), this.availabilityTimeoutMs));
      if (availability.providerId !== this.plannerProvider.id || availability.mode !== this.plannerProvider.mode) return { providerId: this.plannerProvider.id, modelId: null, mode: this.plannerProvider.mode, status: 'UNAVAILABLE', reasonCode: 'PROVENANCE_MISMATCH' };
      return { providerId: availability.providerId, modelId: availability.status === 'AVAILABLE' ? availability.modelId : null, mode: availability.mode, status: availability.status, reasonCode: availability.reasonCode || null };
    } catch (error) {
      return { providerId: this.plannerProvider.id, modelId: null, mode: this.plannerProvider.mode, status: 'UNAVAILABLE', reasonCode: error.code || 'PROVIDER_UNAVAILABLE' };
    }
  }

  async #recoverPlanningTask(task) {
    const active = await this.store.getActivePlannerRequest(task.taskId);
    if (!active || active.mode !== 'MODEL' || active.providerId !== this.plannerProvider.id || this.plannerProvider.mode !== 'MODEL' || typeof this.plannerProvider.parseResponse !== 'function') {
      if (active) await this.store.finishPlannerRequest(task.taskId, active.requestId, { reasonCode: 'PLANNER_INTERRUPTED', outcome: 'UNKNOWN' });
      return this.store.transition(task.taskId, 'BLOCKED', { payload: { reasonCode: 'PLANNER_INTERRUPTED' } });
    }
    try {
      const files = await this.store.recoverPlannerResponseFiles(task.taskId);
      if (files.stagingIncomplete) throw failure('PLANNER_RESPONSE_INCOMPLETE', 'PlannerResponse staging запись прервана');
      const stored = await this.store.getStoredPlannerResponseForRequest(task.taskId, active.requestId);
      if (!stored) throw failure('PLANNER_OUTCOME_UNKNOWN', 'Ответ модели не был надёжно сохранён; inference повторять запрещено');
      const receipt = stored.receipt;
      const parsed = this.plannerProvider.parseResponse({ requestId: receipt.requestId, providerId: receipt.providerId, configuredModelId: receipt.configuredModelId, mode: receipt.mode, receivedAt: receipt.receivedAt, contentType: receipt.contentType, statusCode: receipt.statusCode, bodyBytes: stored.bodyBytes, backendReference: receipt.backendReference });
      const result = PlannerResultSchema.parse(JSON.parse(Buffer.from(parsed.resultBytes).toString('utf8')));
      if (parsed.modelId !== active.configuredModelId || result.modelId !== active.configuredModelId || result.providerId !== active.providerId || result.mode !== active.mode) throw failure('INVALID_PLAN', 'Backend-reported modelId не совпадает с сохранённым request intent');
      const ref = { responseId: receipt.responseId, requestId: receipt.requestId, requestSha256: receipt.requestSha256, responseSha256: receipt.responseSha256, byteLength: receipt.byteLength };
      const availability = { status: 'AVAILABLE', providerId: active.providerId, modelId: parsed.modelId, mode: 'MODEL' };
      return await this.#saveValidatedPlan(task.taskId, parsed.resultBytes, { providerId: active.providerId, modelId: parsed.modelId, mode: 'MODEL', availability, plannerResponseRef: ref, validatedModelId: parsed.modelId });
    } catch (error) {
      const currentActive = await this.store.getActivePlannerRequest(task.taskId);
      if (currentActive) {
        const saved = await this.store.getStoredPlannerResponseForRequest(task.taskId, currentActive.requestId).catch(() => null);
        if (saved) await this.store.rejectPlannerResponse(task.taskId, saved.receipt.responseId, { reasonCode: error.code || 'PLANNER_INTERRUPTED' }).catch(() => {});
        else await this.store.finishPlannerRequest(task.taskId, currentActive.requestId, { reasonCode: error.code || 'PLANNER_INTERRUPTED', outcome: 'UNKNOWN' }).catch(() => {});
      }
      const current = await this.store.getTask(task.taskId);
      if (current.status === 'PLANNING') return this.store.transition(task.taskId, 'BLOCKED', { payload: { reasonCode: error.code || 'PLANNER_INTERRUPTED' } });
      throw error;
    }
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
        try {
          const recoveredPlan = await this.#recoverPlanningTask(task);
          if (recoveredPlan.task.status === 'BLOCKED') blocked.push(task.taskId);
          else recovered.push(task.taskId);
        } catch {
          blocked.push(task.taskId);
        }
      } else if (task.status === 'RUNNING' || task.status === 'VERIFYING') {
        try {
          const events = await this.store.getEvents(task.taskId);
          const intent = [...events].reverse().find(event => event.type === 'DISPATCH_INTENT');
          const runId = task.runIds.at(-1) || intent?.payload?.runId;
          const plan = await this.store.getPlan(task.taskId, task.executionPlanId);
          const step = plan.steps.find(item => item.stepId === intent?.payload?.stepId);
          const adapter = step && this.adapters.get(step.adapterId);
          if (!runId || !intent || !adapter) throw failure('RECOVERY_REF_UNAVAILABLE', 'Нет закреплённого runId/adapter для recovery');
          assertExecutionAdapter(adapter);
          const cancelRequested = events.some(event => event.type === 'CANCEL_REQUESTED' && event.payload.runId === runId);
          if (cancelRequested) {
            try { await adapter.cancel({ runId, actorRef: task.ownerRef, task, plan, step }); }
            catch { /* cancel уже мог быть подтверждён или run ещё не зарегистрирован; reconcile ниже устанавливает исход */ }
          }
          const observation = await adapter.reconcile({ runId, task, plan, step, expectedPreparedDigest: intent.payload.preparedDigest });
          if (!task.runIds.includes(runId)) await this.store.recordRecoveryRunId(task.taskId, { runId, reasonCode: 'TRUSTED_RECONCILE_OBSERVED' });
          const returned = [...events].reverse().find(event => event.type === 'DISPATCH_RETURNED' && event.payload.runId === runId);
          const outcome = returned?.payload?.executionOutcome || 'UNKNOWN';
          await this.#finishObserved({ taskId: task.taskId, plan, step, runId, executionOutcome: outcome, observation });
          const finalTask = await this.store.getTask(task.taskId);
          if (finalTask.status === 'INCONCLUSIVE') inconclusive.push(task.taskId);
          else recovered.push(task.taskId);
        } catch (cause) {
          const current = await this.store.getTask(task.taskId);
          if (['COMPLETED', 'FAILED', 'CANCELED', 'BLOCKED'].includes(current.status)) {
            recovered.push(task.taskId);
            continue;
          }
          if (['RUNNING', 'VERIFYING'].includes(current.status)) {
            await this.store.transition(task.taskId, 'INCONCLUSIVE', { payload: { reasonCode: cause?.code || 'EXECUTION_STATE_UNKNOWN', runIds: current.runIds } });
          }
          inconclusive.push(task.taskId);
        }
      } else recovered.push(task.taskId);
    }
    return { recovered, blocked, inconclusive, integrityBlocked };
  }
}
