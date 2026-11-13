import { z } from 'zod';
import { EXECUTION_VERSION } from '../execution/contracts.mjs';

const id = z.string().min(1).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const PlannerModeSchema = z.enum(['MODEL', 'MOCK']);
const RuleSchema = z.strictObject({ ruleId: id, requirementId: id });
export const PlanDraftSchema = z.strictObject({
  normalizedGoal: z.string().min(1).max(4000),
  requirements: z.array(z.strictObject({ requirementId: id, statement: z.string().min(1).max(2000), mandatory: z.boolean() })).min(1).max(100),
  missingContext: z.array(z.string().min(1).max(2000)).max(100),
  steps: z.array(z.strictObject({
    stepId: id,
    description: z.string().min(1).max(2000),
    actionType: z.enum(['trusted-scenario', 'clarification', 'observation']),
    prerequisites: z.array(id).max(100),
    adapterId: id.nullable(),
    executionRef: id.nullable(),
    requiredCapabilities: z.array(id).max(100),
    mutating: z.boolean(),
    required: z.boolean(),
    validationRules: z.array(RuleSchema).max(100)
  })).min(1).max(100),
  estimatedRisk: z.enum(['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN']),
  approvalRequirements: z.array(z.enum(['OWNER_PLAN_APPROVAL', 'TRUST_APPROVAL'])),
  validationRules: z.array(RuleSchema).max(200)
});

export const PlannerResultSchema = z.strictObject({
  providerId: id,
  modelId: id.nullable(),
  mode: PlannerModeSchema,
  output: PlanDraftSchema,
  usage: z.strictObject({ inputTokens: z.number().int().nonnegative().optional(), outputTokens: z.number().int().nonnegative().optional() }).optional()
});

export const PlannerAvailabilitySchema = z.strictObject({
  status: z.enum(['AVAILABLE', 'UNAVAILABLE']),
  providerId: id,
  modelId: id.nullable().optional(),
  mode: PlannerModeSchema,
  reasonCode: id.optional()
}).superRefine((availability, context) => {
  if (availability.status === 'AVAILABLE') {
    if (availability.modelId === undefined) context.addIssue({ code: 'custom', path: ['modelId'], message: 'Доступный Planner обязан объявить modelId или null' });
    if (availability.reasonCode !== undefined) context.addIssue({ code: 'custom', path: ['reasonCode'], message: 'Доступный Planner не должен объявлять reasonCode' });
    if (availability.mode === 'MODEL' && availability.modelId == null) context.addIssue({ code: 'custom', path: ['modelId'], message: 'MODEL Planner обязан иметь конкретный modelId' });
    if (availability.mode === 'MOCK' && availability.modelId !== null) context.addIssue({ code: 'custom', path: ['modelId'], message: 'MOCK Planner не может объявлять modelId' });
  } else if (!availability.reasonCode) {
    context.addIssue({ code: 'custom', path: ['reasonCode'], message: 'Недоступный Planner обязан указать reasonCode' });
  }
});

export class PlannerProviderError extends Error {
  constructor(code, message) { super(message); this.name = 'PlannerProviderError'; this.code = code; }
}

export async function readBoundedPlannerBytes(response, { maxBytes = 100000, signal } = {}) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || !response?.body?.getReader) throw new PlannerProviderError('INVALID_RESPONSE', 'Planner response stream недоступен');
  const declaredLength = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    try { await response.body.cancel(); } catch { /* поток мог закрыться */ }
    throw new PlannerProviderError('OUTPUT_LIMIT', 'Planner response превышает допустимый размер');
  }
  if (response.ok === false) {
    try { await response.body.cancel(); } catch { /* поток мог закрыться */ }
    throw new PlannerProviderError(response.status === 429 ? 'RATE_LIMITED' : 'PROVIDER_UNAVAILABLE', `Planner HTTP status ${response.status}`);
  }
  const reader = response.body.getReader(), chunks = [];
  const cancelOnAbort = () => { reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancelOnAbort, { once: true });
  let total = 0;
  try {
    while (true) {
      if (signal?.aborted) throw new PlannerProviderError('CANCELED', 'Planner request отменён');
      const { done, value } = await reader.read();
      if (signal?.aborted) throw new PlannerProviderError('CANCELED', 'Planner request отменён');
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new PlannerProviderError('OUTPUT_LIMIT', 'Planner response превышает допустимый размер');
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    try { await reader.cancel(); } catch { /* поток уже завершён */ }
    if (error instanceof PlannerProviderError) throw error;
    if (signal?.aborted) throw new PlannerProviderError('CANCELED', 'Planner request отменён');
    throw new PlannerProviderError('NETWORK_ERROR', 'Не удалось получить Planner response');
  } finally {
    signal?.removeEventListener('abort', cancelOnAbort);
    reader.releaseLock();
  }
}

export class DeterministicMockPlanner {
  constructor() { this.id = 'mock-deterministic'; this.mode = 'MOCK'; }

  async availability() { return { status: 'AVAILABLE', providerId: this.id, modelId: null, mode: this.mode }; }

  async plan(request) {
    if (request.outputSchemaVersion !== EXECUTION_VERSION) throw new PlannerProviderError('UNSUPPORTED', 'Версия Planner contract не поддерживается');
    const original = request.originalRequest;
    const missingContext = ['Нужно явно выбрать заранее утверждённый исполнимый сценарий, покрывающий поручение'];
    const requirements = [{ requirementId: 'req-user-goal', statement: 'Проверить требования исходного поручения пользователя', mandatory: true }];
    const rule = { ruleId: 'rule-trusted-verdict', requirementId: 'req-user-goal' };
    const output = {
      normalizedGoal: original.trim().replace(/\s+/g, ' ').slice(0, 4000),
      requirements,
      missingContext,
      steps: [{
        stepId: 'step-trusted-scenario',
        description: 'Найти и подтвердить утверждённый сценарий, покрывающий поручение',
        actionType: 'clarification',
        prerequisites: [],
        adapterId: null,
        executionRef: null,
        requiredCapabilities: [],
        mutating: false,
        required: true,
        validationRules: [rule]
      }],
      estimatedRisk: 'UNKNOWN',
      approvalRequirements: ['OWNER_PLAN_APPROVAL'],
      validationRules: [rule]
    };
    return Buffer.from(JSON.stringify(PlannerResultSchema.parse({ providerId: this.id, modelId: null, mode: 'MOCK', output })), 'utf8');
  }
}

export class UnavailablePlannerProvider {
  constructor(id = 'unconfigured', mode = 'MODEL') { this.id = id; this.mode = mode; }
  async availability() { return { status: 'UNAVAILABLE', providerId: this.id, modelId: null, mode: this.mode, reasonCode: 'NOT_CONFIGURED' }; }
  async plan() { throw new PlannerProviderError('PROVIDER_UNAVAILABLE', 'Planner provider не настроен'); }
}
