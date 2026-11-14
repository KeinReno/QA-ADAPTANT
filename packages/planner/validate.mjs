import { digest } from '../core/canonical.mjs';
import { PLAN_SCHEMA_VERSION, validateExecutionPlan } from '../execution/contracts.mjs';
import { PlanDraftSchema } from './provider.mjs';

export function validatePlanDraft(input, { taskId, provider, plannerResponse = null, registeredExecutionRefs = [], registeredAdapters = [], allowedCapabilities = [], allowedActionTypes } = {}) {
  const draft = PlanDraftSchema.parse(input);
  const now = new Date().toISOString();
  const provisional = {
    ...draft,
    schemaVersion: PLAN_SCHEMA_VERSION,
    planId: 'plan-validation-placeholder',
    taskId,
    version: 1,
    createdAt: now,
    provider,
    plannerResponse,
    validation: { valid: true, executable: false, findings: [] },
    sha256: '0'.repeat(64)
  };
  const checked = validateExecutionPlan(provisional, { allowedActionTypes, registeredExecutionRefs, registeredAdapters, allowedCapabilities });
  const { sha256: _ignored, ...unsigned } = checked;
  return { ...checked, sha256: digest(unsigned) };
}
