import { digest } from './canonical.mjs';
import { IndependentRead, validate, validateVerdictCoverage } from '../contracts/index.mjs';

const bad = code => { throw new Error(`INTEGRITY_ERROR: ${code}`); };
const oneParent = (items, item, kind) => {
  if (item.envelope.parentEvidenceIds.length !== 1) bad(`${kind.toUpperCase()}_PARENT`);
  const parent = items.find(candidate => candidate.envelope.evidenceId === item.envelope.parentEvidenceIds[0]);
  if (!parent || parent.envelope.kind !== kind) bad(`${kind.toUpperCase()}_PARENT`);
  return parent;
};

export function assertEvidenceRefs(items, bundle, { requireMutation = true } = {}) {
  const { manifest, fixture, scenario, operation, manifestSha256 } = bundle;
  const nodes = new Map(scenario.nodes.map(node => [node.id, node]));
  const mutationNode = scenario.nodes.find(node => node.action.type === 'click');
  const verifyNode = scenario.nodes.at(-1);
  for (const item of items) {
    const { envelope, artifact } = item;
    if (envelope.runId !== manifest.runId || envelope.manifestSha256 !== manifestSha256 || envelope.fixtureId !== fixture.fixtureId) bad('EVIDENCE_SCOPE');
    if (!nodes.has(envelope.stepId)) bad('EVIDENCE_STEP');
    if (envelope.kind === 'mutation-intent') {
      if (envelope.producer !== 'control' || envelope.stepId !== mutationNode.id || envelope.parentEvidenceIds.length !== 0 ||
          artifact.operationId !== operation.id || artifact.mutationName !== operation.mutation.name ||
          artifact.intentId !== `${manifest.runId}:${envelope.stepId}` || artifact.stepId !== envelope.stepId ||
          artifact.inputsSha256 !== digest(operation.inputs) || artifact.fixtureId !== fixture.fixtureId) bad('INTENT_INVALID');
    } else if (envelope.kind === 'request') {
      const intent = oneParent(items, item, 'mutation-intent');
      if (envelope.producer !== 'browser' || envelope.stepId !== mutationNode.id || envelope.requestId !== artifact.requestId ||
          artifact.operationId !== operation.id || artifact.intentId !== intent.artifact.intentId ||
          artifact.method !== 'POST' || artifact.path !== '/records' || artifact.fixtureId !== fixture.fixtureId ||
          digest(artifact.fields) !== digest({ ...operation.inputs, fixtureId: fixture.fixtureId })) bad('REQUEST_INVALID');
    } else if (envelope.kind === 'response') {
      const request = oneParent(items, item, 'request');
      if (envelope.producer !== 'browser' || envelope.stepId !== mutationNode.id || envelope.requestId !== request.envelope.requestId ||
          artifact.requestId !== request.envelope.requestId || artifact.intentId !== request.artifact.intentId ||
          artifact.operationId !== operation.id || !artifact.entity || !envelope.entity ||
          artifact.entity.kind !== operation.entityKind || envelope.entity.kind !== operation.entityKind ||
          artifact.entity.id !== envelope.entity.id || artifact.fixtureId !== fixture.fixtureId ||
          request.artifact.fixtureId !== artifact.fixtureId || artifact.status < 200 || artifact.status >= 300) bad('RESPONSE_INVALID');
    } else if (envelope.kind === 'independent-read') {
      const parent = item.envelope.parentEvidenceIds.length === 1
        ? items.find(candidate => candidate.envelope.evidenceId === item.envelope.parentEvidenceIds[0])
        : null;
      if (!parent || !['request', 'response'].includes(parent.envelope.kind)) bad('READ_PARENT');
      try { IndependentRead.parse(artifact); } catch { bad('READ_INVALID'); }
      const expectedFields = new Set([...Object.keys(operation.inputs), ...operation.verification.identityFields]);
      if (envelope.producer !== 'verification' || envelope.stepId !== verifyNode.id || envelope.requestId !== artifact.requestId ||
          artifact.fixtureId !== fixture.fixtureId || artifact.environmentFingerprint !== manifest.environment.fingerprint ||
          !envelope.entity || envelope.entity.kind !== operation.entityKind || envelope.entity.id !== artifact.entity.id ||
          artifact.entity.kind !== operation.entityKind || Object.keys(artifact.fields).some(field => !expectedFields.has(field))) bad('READ_INVALID');
      if (parent.envelope.kind === 'response' && (parent.envelope.entity.id !== artifact.entity.id || parent.artifact.entity.id !== artifact.entity.id)) bad('READ_IDENTITY');
      for (const field of operation.verification.identityFields) {
        const expected = field === fixture.ownership.field ? fixture.ownership.value : operation.inputs[field];
        if (!Object.hasOwn(artifact.fields, field) || artifact.fields[field] !== expected) bad('READ_IDENTITY');
      }
      for (const checkId of envelope.checkIds) {
        const effect = operation.effects.find(candidate => candidate.id === checkId);
        if (!effect || !Object.hasOwn(artifact.fields, effect.field)) bad('READ_CHECK');
      }
    } else if (envelope.kind !== 'verdict') bad('EVIDENCE_KIND');
  }
  const intents = items.filter(item => item.envelope.kind === 'mutation-intent');
  const requests = items.filter(item => item.envelope.kind === 'request');
  const responses = items.filter(item => item.envelope.kind === 'response');
  if (intents.length > 1 || requests.length > 1 || responses.length > 1) bad('EVIDENCE_CHAIN');
  if (requireMutation && (intents.length !== 1 || requests.length !== 1)) bad('EVIDENCE_CHAIN');
  return { intent: intents[0] || null, request: requests[0] || null, response: responses[0] || null };
}

export function assertTerminalEvidence(items, bundle) {
  const verdicts = items.filter(item => item.envelope.kind === 'verdict');
  if (!verdicts.length) return null;
  if (verdicts.length !== 1 || items.at(-1) !== verdicts[0]) bad('VERDICT_ORDER');
  const final = verdicts[0];
  const { envelope, artifact: verdict } = final;
  const { manifest, operation, scenario } = bundle;
  if (envelope.producer !== 'verification' || envelope.stepId !== scenario.nodes.at(-1).id) bad('VERDICT_PRODUCER');
  try { validate('VerdictPolicy', verdict); } catch { bad('VERDICT_INVALID'); }
  if (verdict.runId !== manifest.runId || verdict.manifestSha256 !== bundle.manifestSha256) bad('VERDICT_SCOPE');
  const body = items.slice(0, -1);
  const chain = assertEvidenceRefs(body, bundle, { requireMutation: ['PASS', 'FAIL'].includes(verdict.verdict) });
  const reads = body.filter(item => item.envelope.kind === 'independent-read');
  try { validateVerdictCoverage(verdict, operation, reads); } catch { bad('VERDICT_COVERAGE'); }
  for (const check of verdict.checks) {
    if (check.evidenceIds.some(id => !envelope.parentEvidenceIds.includes(id))) bad('VERDICT_PARENT');
    if (['BLOCKED'].includes(verdict.verdict) && (['SATISFIED', 'VIOLATED'].includes(check.status) || check.evidenceIds.length)) bad('BLOCKED_PROOF');
  }
  if (['PASS', 'FAIL'].includes(verdict.verdict) && (!chain.response || !reads.length)) bad('VERDICT_CHAIN');
  return verdict;
}
