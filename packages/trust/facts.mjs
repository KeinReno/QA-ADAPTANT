import { verifyAndAssertPrincipal } from './identity.mjs';
import { readApprovalState } from './approval.mjs';
import { loadEnvironmentRecord } from './environment.mjs';

// Сборщик фактов для PDP. WP-03 не делает ввод-вывод: всё, что ниже, читает Control.
// Ошибки чтения не бросаются наружу, а становятся фактом с кодом: PDP обязан вернуть
// INDETERMINATE или DENY, а не превратить отказ хранилища в разрешение.

function codeOf(error, fallback) {
  return error && typeof error.code === 'string' ? error.code : fallback;
}

export function expectedFromFrozen(frozen) {
  const { manifest, operation, scenario, fixture } = frozen;
  return {
    operation,
    inputs: operation.inputs,
    // Approval подписывает проекцию {id, field, equals} в порядке массива, а не operation.effects целиком.
    effects: operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
    scenarioContentSha256: scenario?.approval?.contentSha256 ?? null,
    fixtureId: fixture.fixtureId,
    environmentId: manifest.environment.id,
    environmentGeneration: null,
    resource: { method: 'POST', path: '/records' }
  };
}

export function principalFact(trust, card, constraints = {}) {
  if (!card) return { body: null, error: 'PRINCIPAL_UNKNOWN' };
  try {
    return { body: verifyAndAssertPrincipal(trust, card, constraints), error: null };
  } catch (error) {
    return { body: null, error: codeOf(error, 'PRINCIPAL_UNKNOWN') };
  }
}

export function approvalFact({ trust, trustRoot, approvalId, approval, issuer, subject, windowsSid, expected, runId }) {
  try {
    const viewed = readApprovalState(trust, approval, { issuer, subject, windowsSid, trustRoot, expected, approvalId });
    return {
      body: viewed.body,
      state: viewed.state,
      error: null,
      consumption: viewed.consumption,
      revocation: viewed.revocation
    };
  } catch (error) {
    // state обязан остаться одним из состояний контракта: null дал бы отказ формы, а не причину.
    return { body: null, state: 'missing', error: codeOf(error, 'APPROVAL_SIGNATURE_INVALID'), consumption: null, revocation: null };
  }
}

export function environmentFact({ trust, trustRoot, environmentId, origin, generation }) {
  try {
    const record = loadEnvironmentRecord(trust, trustRoot, environmentId);
    if (origin && record.origin !== origin) return { record: null, error: 'ENVIRONMENT_ATTESTATION_FAILED' };
    if (Number.isInteger(generation) && record.generation !== generation) return { record: null, error: 'ENVIRONMENT_ATTESTATION_FAILED' };
    return { record, error: null };
  } catch (error) {
    return { record: null, error: codeOf(error, 'ENVIRONMENT_UNKNOWN') };
  }
}

// Единая форма facts. Отсутствующие части получают безопасные значения, а не undefined:
// PDP разбирает форму строго и на неполных данных должен отказывать.
export function buildFacts(parts = {}) {
  const now = parts.now || new Date().toISOString();
  return {
    phase: parts.phase,
    now,
    authenticatedSid: parts.authenticatedSid ?? null,
    trustStore: parts.trustStore || { available: true, code: null },
    principal: parts.principal || { body: null, error: 'PRINCIPAL_UNKNOWN' },
    issuer: parts.issuer || { body: null, error: 'PRINCIPAL_UNKNOWN' },
    approval: parts.approval || { body: null, state: 'missing', error: 'APPROVAL_MISSING', consumption: null, revocation: null },
    expected: parts.expected,
    environment: parts.environment || { record: null, error: 'ENVIRONMENT_UNKNOWN', attestation: { ok: false, body: null, error: 'ENVIRONMENT_UNAVAILABLE' } },
    run: parts.run || { runId: null, canceled: false, mutationRecorded: false },
    registry: parts.registry || { operationAllowed: false, effectsMatch: false }
  };
}
