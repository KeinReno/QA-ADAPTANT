import { z } from 'zod';

export const EXECUTION_VERSION = '0.3.0';
export const TASK_SCHEMA_VERSION = '0.3.0';
export const PLAN_SCHEMA_VERSION = '0.3.1';
const id = z.string().min(1).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const iso = z.iso.datetime();

export const TASK_STATES = [
  'DRAFT', 'PLANNING', 'PLAN_READY', 'AWAITING_APPROVAL', 'READY', 'RUNNING',
  'VERIFYING', 'COMPLETED', 'FAILED', 'CANCELED', 'BLOCKED', 'INCONCLUSIVE'
];
export const STEP_STATES = [
  'PENDING', 'READY', 'DISPATCHING', 'RUNNING', 'VERIFYING', 'COMPLETED',
  'FAILED', 'BLOCKED', 'CANCELED', 'INCONCLUSIVE', 'SKIPPED'
];

export const TaskResultSchema = z.strictObject({
  taskOutcome: z.enum(['PASS', 'FAIL', 'BLOCKED', 'INCONCLUSIVE', 'CANCELED', 'PARTIAL']),
  plannerMode: z.enum(['MODEL', 'MOCK']),
  stepOutcomes: z.array(z.strictObject({
    stepId: id,
    executionOutcome: z.enum(['SUCCEEDED', 'FAILED', 'UNKNOWN', 'NOT_STARTED']),
    verificationOutcome: z.enum(['PASS', 'FAIL', 'BLOCKED', 'INCONCLUSIVE', 'NOT_AVAILABLE']),
    trustedVerification: z.boolean(),
    runIds: z.array(id),
    evidenceRefs: z.array(z.strictObject({ runId: id, evidenceId: id }))
  })),
  reasonCode: id.nullable(),
  message: z.string().max(4000)
});

export const TaskStateSchema = z.strictObject({
  schemaVersion: z.literal(TASK_SCHEMA_VERSION),
  taskId: id,
  originalRequest: z.string().min(1).max(20000),
  originalRequestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  normalizedGoal: z.string().max(4000),
  status: z.enum(TASK_STATES),
  createdAt: iso,
  updatedAt: iso,
  ownerRef: id,
  contextRefs: z.array(id).max(100),
  executionPlanId: id.nullable(),
  environmentRef: id.nullable(),
  policyRef: id.nullable(),
  approvalRef: id.nullable(),
  runIds: z.array(id).max(100),
  result: TaskResultSchema.nullable(),
  revision: z.number().int().positive()
});

export const TaskSchema = TaskStateSchema.extend({
  journalSequence: z.number().int().nonnegative(),
  journalHeadSha256: z.string().regex(/^[a-f0-9]{64}$/).nullable()
});

export const PlanRequirementSchema = z.strictObject({
  requirementId: id,
  statement: z.string().min(1).max(2000),
  mandatory: z.boolean()
});

export const ExecutionStepSchema = z.strictObject({
  stepId: id,
  description: z.string().min(1).max(2000),
  actionType: z.enum(['trusted-scenario', 'clarification', 'observation']),
  prerequisites: z.array(id).max(100),
  adapterId: id.nullable(),
  executionRef: id.nullable(),
  requiredCapabilities: z.array(id).max(100),
  mutating: z.boolean(),
  required: z.boolean(),
  validationRules: z.array(z.strictObject({ ruleId: id, requirementId: id })).max(100)
});

const planFields = {
  planId: id,
  taskId: id,
  version: z.number().int().positive(),
  createdAt: iso,
  provider: z.strictObject({ providerId: id, modelId: id.nullable(), mode: z.enum(['MODEL', 'MOCK']) }).superRefine((provider, context) => {
    if (provider.mode === 'MODEL' && provider.modelId === null) context.addIssue({ code: 'custom', path: ['modelId'], message: 'MODEL provenance требует конкретный modelId' });
    if (provider.mode === 'MOCK' && provider.modelId !== null) context.addIssue({ code: 'custom', path: ['modelId'], message: 'MOCK provenance не принимает modelId' });
  }),
  plannerResponse: z.strictObject({
    responseId: id,
    requestId: id,
    requestSha256: z.string().regex(/^[a-f0-9]{64}$/),
    responseSha256: z.string().regex(/^[a-f0-9]{64}$/),
    byteLength: z.number().int().positive(),
    planResultSha256: z.string().regex(/^[a-f0-9]{64}$/)
  }).nullable(),
  normalizedGoal: z.string().min(1).max(4000),
  requirements: z.array(PlanRequirementSchema).min(1).max(100),
  missingContext: z.array(z.string().min(1).max(2000)).max(100),
  steps: z.array(ExecutionStepSchema).min(1).max(100),
  estimatedRisk: z.enum(['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN']),
  approvalRequirements: z.array(z.enum(['OWNER_PLAN_APPROVAL', 'TRUST_APPROVAL'])),
  validationRules: z.array(z.strictObject({ ruleId: id, requirementId: id })).max(200),
  validation: z.strictObject({ valid: z.literal(true), executable: z.boolean(), findings: z.array(z.string().max(2000)).max(100) }),
  sha256: z.string().regex(/^[a-f0-9]{64}$/)
};

export const LegacyExecutionPlanSchema = z.strictObject({ schemaVersion: z.literal('0.3.0'), ...Object.fromEntries(Object.entries(planFields).filter(([key]) => key !== 'plannerResponse')) });
export const ExecutionPlanSchema = z.strictObject({ schemaVersion: z.literal(PLAN_SCHEMA_VERSION), ...planFields }).superRefine((plan, context) => {
  if (plan.provider.mode === 'MODEL' && plan.plannerResponse === null) context.addIssue({ code: 'custom', path: ['plannerResponse'], message: 'MODEL plan обязан ссылаться на PlannerResponse' });
  if (plan.provider.mode === 'MOCK' && plan.plannerResponse !== null) context.addIssue({ code: 'custom', path: ['plannerResponse'], message: 'MOCK plan не ссылается на MODEL response' });
});

export const PlannerResponseReceiptSchema = z.strictObject({
  schemaVersion: z.literal('0.3.2'), responseId: id, taskId: id, requestId: id,
  requestSha256: z.string().regex(/^[a-f0-9]{64}$/), requestBodySha256: z.string().regex(/^[a-f0-9]{64}$/),
  providerId: id, configuredModelId: id.nullable(), mode: z.enum(['MODEL', 'MOCK']), receivedAt: iso,
  contentType: z.string().min(1).max(160), statusCode: z.number().int().min(100).max(599),
  byteLength: z.number().int().nonnegative(), responseSha256: z.string().regex(/^[a-f0-9]{64}$/),
  backendReference: z.string().max(512).nullable(), status: z.literal('RECEIVED')
}).superRefine((receipt, context) => {
  if (receipt.mode === 'MODEL' && !receipt.configuredModelId) context.addIssue({ code: 'custom', path: ['configuredModelId'], message: 'MODEL receipt требует configuredModelId' });
  if (receipt.mode === 'MOCK' && receipt.configuredModelId !== null) context.addIssue({ code: 'custom', path: ['configuredModelId'], message: 'MOCK receipt не принимает modelId' });
});

const plannerEventPayloadSchemas = {
  PLANNER_REQUEST_STARTED: z.strictObject({ requestId: id, requestSha256: z.string().regex(/^[a-f0-9]{64}$/), taskId: id, originalRequestSha256: z.string().regex(/^[a-f0-9]{64}$/), providerId: id, configuredModelId: id.nullable(), mode: z.enum(['MODEL', 'MOCK']), taskRevision: z.number().int().positive(), startedAt: iso }),
  PLANNER_RESPONSE_STORED: z.strictObject({ responseId: id, requestId: id, requestSha256: z.string().regex(/^[a-f0-9]{64}$/), responseSha256: z.string().regex(/^[a-f0-9]{64}$/), byteLength: z.number().int().nonnegative() }),
  PLANNER_RESPONSE_VALIDATED: z.strictObject({ responseId: id, requestId: id, requestSha256: z.string().regex(/^[a-f0-9]{64}$/), responseSha256: z.string().regex(/^[a-f0-9]{64}$/), modelId: id, planResultSha256: z.string().regex(/^[a-f0-9]{64}$/) }),
  PLANNER_RESPONSE_REJECTED: z.strictObject({ requestId: id, responseId: id.nullable(), responseSha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(), reasonCode: id }),
  PLANNER_REQUEST_FINISHED: z.strictObject({ requestId: id, reasonCode: id, outcome: z.enum(['UNKNOWN', 'FAILED', 'CANCELED']) }),
  PLANNER_UNAVAILABLE: z.strictObject({ providerId: id, reasonCode: id, mode: z.enum(['MODEL', 'MOCK']) }),
  PLANNER_FAILED: z.strictObject({ reasonCode: id })
};

export const TaskEventSchema = z.strictObject({
  eventId: id,
  sequence: z.number().int().positive(),
  taskId: id,
  type: id,
  at: iso,
  payload: z.record(z.string(), z.unknown()),
  state: TaskStateSchema,
  previousSha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/)
}).superRefine((event, context) => {
  const payloadSchema = plannerEventPayloadSchemas[event.type];
  if (payloadSchema) {
    const parsed = payloadSchema.safeParse(event.payload);
    if (!parsed.success) context.addIssue({ code: 'custom', path: ['payload'], message: `Некорректный payload события ${event.type}` });
  }
  if (event.type === 'PLAN_VERSION_CREATED') {
    const base = { planId: id, version: z.number().int().positive(), sha256: z.string().regex(/^[a-f0-9]{64}$/), providerMode: z.enum(['MODEL', 'MOCK']), executable: z.boolean() };
    const legacy = z.strictObject(base).safeParse(event.payload);
    const modern = z.strictObject({ ...base, payloadSchemaVersion: z.literal('0.3.2'), plannerResponse: ExecutionPlanSchema.shape.plannerResponse }).safeParse(event.payload);
    if (!legacy.success && !modern.success) context.addIssue({ code: 'custom', path: ['payload'], message: 'Некорректный payload события PLAN_VERSION_CREATED' });
    else if (modern.success && modern.data.providerMode === 'MODEL' && modern.data.plannerResponse === null) context.addIssue({ code: 'custom', path: ['payload', 'plannerResponse'], message: 'MODEL PLAN_VERSION_CREATED обязан ссылаться на PlannerResponse' });
  }
});

export const TaskDispatchIntentSchema = z.strictObject({
  runId: id,
  stepId: id,
  adapterId: id,
  executionRefSha256: z.string().regex(/^[a-f0-9]{64}$/),
  preparedDigest: z.string().regex(/^[a-f0-9]{64}$/),
  idempotencyKey: z.string().regex(/^[a-f0-9]{64}$/)
});

export const ALLOWED_TASK_TRANSITIONS = Object.freeze({
  DRAFT: ['PLANNING', 'CANCELED'],
  PLANNING: ['PLAN_READY', 'BLOCKED', 'FAILED', 'CANCELED'],
  PLAN_READY: ['PLANNING', 'AWAITING_APPROVAL', 'READY', 'BLOCKED', 'CANCELED'],
  AWAITING_APPROVAL: ['PLANNING', 'READY', 'BLOCKED', 'CANCELED'],
  READY: ['RUNNING', 'BLOCKED', 'CANCELED'],
  RUNNING: ['VERIFYING', 'FAILED', 'BLOCKED', 'INCONCLUSIVE', 'CANCELED'],
  VERIFYING: ['COMPLETED', 'FAILED', 'BLOCKED', 'INCONCLUSIVE', 'CANCELED'],
  COMPLETED: [], FAILED: [], CANCELED: [], BLOCKED: ['PLANNING'], INCONCLUSIVE: []
});

export function transitionTask(task, nextStatus) {
  const parsed = TaskSchema.parse(task);
  if (!ALLOWED_TASK_TRANSITIONS[parsed.status]?.includes(nextStatus)) {
    throw Object.assign(new Error(`Недопустимый переход задания: ${parsed.status} -> ${nextStatus}`), { code: 'INVALID_TASK_TRANSITION' });
  }
  return TaskSchema.parse({ ...parsed, status: nextStatus, updatedAt: new Date().toISOString(), revision: parsed.revision + 1 });
}

export function assertTaskPassSupported(result, { plan, runIds = [] } = {}) {
  const parsed = TaskResultSchema.parse(result);
  const stepIds = parsed.stepOutcomes.map(item => item.stepId);
  if (new Set(stepIds).size !== stepIds.length) throw Object.assign(new Error('Task result содержит повторный stepId'), { code: 'INVALID_TASK_RESULT' });
  if (parsed.taskOutcome !== 'PASS') return parsed;
  if (!plan) throw Object.assign(new Error('Для Task PASS отсутствует сохранённый план'), { code: 'UNVERIFIED_TASK_PASS' });
  if (stepIds.some(stepId => !plan.steps.some(step => step.stepId === stepId))) throw Object.assign(new Error('Task result ссылается на неизвестный stepId'), { code: 'UNVERIFIED_TASK_PASS' });
  const requiredSteps = plan.steps.filter(step => step.required);
  for (const step of requiredSteps) {
    const outcome = parsed.stepOutcomes.find(item => item.stepId === step.stepId);
    if (!outcome || outcome.executionOutcome !== 'SUCCEEDED' || outcome.verificationOutcome !== 'PASS' || !outcome.trustedVerification || !outcome.runIds.length || !outcome.evidenceRefs.length) {
      throw Object.assign(new Error('Task PASS требует trusted PASS и evidence для каждого обязательного шага'), { code: 'UNVERIFIED_TASK_PASS' });
    }
    if (outcome.runIds.some(runId => !runIds.includes(runId)) || outcome.evidenceRefs.some(ref => !outcome.runIds.includes(ref.runId))) {
      throw Object.assign(new Error('Task PASS содержит несвязанные run/evidence refs'), { code: 'UNVERIFIED_TASK_PASS' });
    }
  }
  if (parsed.plannerMode !== plan.provider.mode) throw Object.assign(new Error('Task result provenance не совпадает с версией плана'), { code: 'UNVERIFIED_TASK_PASS' });
  return parsed;
}

export function validateExecutionPlan(plan, { allowedActionTypes = ['trusted-scenario', 'clarification', 'observation'], registeredExecutionRefs = [], registeredAdapters = [], allowedCapabilities = [] } = {}) {
  const parsed = ExecutionPlanSchema.parse(plan);
  const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_PLAN' }); };
  const reqIds = parsed.requirements.map(item => item.requirementId);
  const stepIds = parsed.steps.map(item => item.stepId);
  const ruleIds = parsed.validationRules.map(item => item.ruleId);
  if (new Set(reqIds).size !== reqIds.length || new Set(stepIds).size !== stepIds.length || new Set(ruleIds).size !== ruleIds.length) fail('Повтор идентификатора в плане');
  if (!parsed.steps.some(step => step.required)) fail('В плане нет обязательного шага');
  if (parsed.steps.some(step => !allowedActionTypes.includes(step.actionType))) fail('План содержит неподдерживаемое действие');
  const reqSet = new Set(reqIds);
  if (parsed.validationRules.some(rule => !reqSet.has(rule.requirementId))) fail('Правило ссылается на отсутствующее требование');
  const requirementByRule = new Map(parsed.validationRules.map(rule => [rule.ruleId, rule.requirementId]));
  for (const requirement of parsed.requirements.filter(item => item.mandatory)) {
    if (!parsed.validationRules.some(rule => rule.requirementId === requirement.requirementId)) fail('Обязательное требование не имеет правила проверки');
    if (!parsed.steps.some(step => step.validationRules.some(rule => rule.requirementId === requirement.requirementId))) fail('Обязательное требование не привязано к проверке шага');
  }
  const byId = new Map(parsed.steps.map(step => [step.stepId, step]));
  const indegree = new Map(stepIds.map(stepId => [stepId, 0]));
  const children = new Map(stepIds.map(stepId => [stepId, []]));
  for (const step of parsed.steps) {
    if (new Set(step.prerequisites).size !== step.prerequisites.length) fail('Повтор зависимости шага');
    for (const prerequisite of step.prerequisites) {
      if (!byId.has(prerequisite) || prerequisite === step.stepId) fail('Шаг ссылается на отсутствующую или собственную зависимость');
      indegree.set(step.stepId, indegree.get(step.stepId) + 1);
      children.get(prerequisite).push(step.stepId);
    }
    if (step.validationRules.some(rule => requirementByRule.get(rule.ruleId) !== rule.requirementId)) fail('Шаг ссылается на отсутствующее или несогласованное правило/требование');
    if (step.adapterId !== null && !registeredAdapters.includes(step.adapterId)) fail('Модель выбрала незарегистрированный adapter');
    if (step.requiredCapabilities.some(capability => !allowedCapabilities.includes(capability))) fail('Модель запросила неизвестную capability');
    if (step.executionRef !== null && !registeredExecutionRefs.includes(step.executionRef)) fail('Модель выбрала неизвестную execution ref');
    if (step.actionType !== 'trusted-scenario' && (step.adapterId !== null || step.executionRef !== null)) fail('Adapter/execution ref допустимы только для trusted-scenario');
    if (step.actionType === 'trusted-scenario' && step.adapterId && step.executionRef !== null && !registeredExecutionRefs.includes(step.executionRef)) fail('Модель выбрала неизвестную execution ref');
  }
  const ready = stepIds.filter(stepId => indegree.get(stepId) === 0);
  let visited = 0;
  while (ready.length) {
    const stepId = ready.shift(); visited++;
    for (const child of children.get(stepId)) {
      indegree.set(child, indegree.get(child) - 1);
      if (indegree.get(child) === 0) ready.push(child);
    }
  }
  if (visited !== stepIds.length) fail('Зависимости плана содержат цикл');
  const executable = parsed.steps.every(step => step.actionType !== 'trusted-scenario' || (step.adapterId && step.executionRef && registeredExecutionRefs.includes(step.executionRef))) && parsed.missingContext.length === 0;
  const findings = [];
  if (parsed.missingContext.length) findings.push('Не хватает контекста для утверждения исполнимого плана');
  if (parsed.steps.some(step => step.actionType === 'trusted-scenario' && (!step.adapterId || !step.executionRef))) findings.push('Шаг trusted-сценария не связан с зарегистрированным адаптером и execution ref');
  return { ...parsed, steps: parsed.steps.map(step => ({ ...step, mutating: step.mutating || step.adapterId !== null || step.executionRef !== null || step.actionType === 'trusted-scenario' })), validation: { valid: true, executable, findings } };
}

export function topologicalExecutionSteps(steps) {
  const position = new Map(steps.map((step, index) => [step.stepId, index]));
  const remaining = new Map(steps.map(step => [step.stepId, new Set(step.prerequisites)]));
  const ordered = [];
  while (remaining.size) {
    const ready = [...remaining.entries()]
      .filter(([, prerequisites]) => [...prerequisites].every(id => !remaining.has(id)))
      .map(([stepId]) => stepId)
      .sort((a, b) => position.get(a) - position.get(b));
    if (!ready.length) throw Object.assign(new Error('Зависимости плана не допускают топологической сортировки'), { code: 'INVALID_PLAN' });
    for (const stepId of ready) {
      ordered.push(steps[position.get(stepId)]);
      remaining.delete(stepId);
    }
  }
  return ordered;
}
