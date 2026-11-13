import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest } from '../packages/core/canonical.mjs';
import { TaskStore } from '../packages/execution/store.mjs';
import { TrustedFacadeExecutionAdapter } from '../packages/execution/trusted-adapter.mjs';
import { TaskService } from '../apps/orchestrator/service.mjs';
import { localBundle, localFixtureContract } from '../adapters/local/bundle.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { createTrustRoot, loadTrustRoot, signTrustedDocument, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { signApproval } from '../packages/trust/approval.mjs';
import { commitEnvironmentRecord, signEnvironmentRecord } from '../packages/trust/environment.mjs';
import { currentUserSid } from '../packages/trust/windows-sid.mjs';

const sid = currentUserSid();

export async function trustedLocalWorld(t, { standOptions = {} } = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'adaptant03-e2e-'));
  const runRoot = path.join(base, 'runs'), taskRoot = path.join(base, 'tasks');
  const secretsDir = path.join(base, 'secrets'), trustRoot = path.join(base, 'trust');
  const created = await createTrustRoot({ secretsDir, trustRoot, runDir: runRoot });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = await serveLocalFixture({ generation: 1, ...standOptions });
  const environmentRecord = signEnvironmentRecord(ownerKey, {
    environmentId: stand.environmentId, generation: stand.generation, kind: 'local-stand', status: 'active',
    origin: stand.baseUrl, standKeyId: stand.standKeyId, credentialRef: 'local:fixture-token'
  });
  commitEnvironmentRecord(trust, trustRoot, environmentRecord);
  const issuer = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner'],
    keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const subject = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'],
    keyId: created.ownerKeyId, windowsSid: sid, status: 'active'
  });
  const trustApprovals = new Map();
  const trustResolutionDiagnostics = [];
  const resolveTrustOptions = async ({ task, bundle, runId }) => {
    if (bundle && !trustApprovals.has(runId)) {
      const fixture = bundle.fixture;
      const issuedAt = new Date().toISOString();
      const approvalId = `trust-${runId}`;
      const approval = signApproval(ownerKey, {
        approvalId, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
        operationId: bundle.operation.id, operationVersion: bundle.operation.version,
        scenarioContentSha256: bundle.scenario.approval.contentSha256, operationSha256: digest(bundle.operation),
        approvedInputsHash: digest(bundle.operation.inputs), fixtureId: fixture.fixtureId,
        targetEnvironmentId: stand.environmentId, environmentGeneration: stand.generation,
        targetResource: { method: 'POST', path: '/records' },
        allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
        issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
        approvalNonce: randomUUID().replaceAll('-', '').padEnd(64, '0').slice(0, 64), keyId: created.ownerKeyId
      }, trust, trustRoot);
      trustApprovals.set(runId, approval);
    }
    const approval = trustApprovals.get(runId);
    const options = {
      root: runRoot, trustRoot, approvalId: approval?.approvalId, approval, issuer, subject,
      anchorKeyPath: path.join(secretsDir, 'anchor.key'), standPublicKey: stand.standPublicKey,
      credentials: { 'local:fixture-token': stand.authToken }, planOwnerRef: task?.approvalRef || null
    };
    trustResolutionDiagnostics.push({ runId, hasApproval: Boolean(options.approval), hasApprovalId: Boolean(options.approvalId), hasIssuer: Boolean(options.issuer), hasSubject: Boolean(options.subject), hasSigner: Boolean(options.anchorKeyPath) });
    return options;
  };
  t.after(async () => {
    await stand.close();
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return { base, runRoot, taskRoot, secretsDir, trustRoot, trust, ownerKey, created, stand, issuer, subject, resolveTrustOptions, trustResolutionDiagnostics };
}

export async function approvedLocalTask(t, options = {}) {
  const world = await trustedLocalWorld(t, options);
  const adapterId = 'trusted-local';
  const executionRef = 'local-create-record-v1';
  const adapter = new TrustedFacadeExecutionAdapter({
    id: adapterId,
    root: world.runRoot,
    executionRefs: new Map([[executionRef, { buildBundle: ({ runId }) => {
      const fixture = localFixtureContract(world.stand, runId);
      world.stand.fixtureId = fixture.fixtureId;
      const bundle = localBundle(world.stand, { runId });
      bundle.fixture = fixture;
      bundle.manifest.fixtureSha256 = digest(fixture);
      bundle.manifest.budget.deadlineMs = 60000;
      return bundle;
    } }]]),
    resolveTrustOptions: world.resolveTrustOptions
  });
  const store = new TaskStore(world.taskRoot, { verifyTaskPass: adapter.verifyTaskPass.bind(adapter) });
  const plannerProvider = {
    id: 'local-test-planner', mode: 'MOCK',
    async availability() { return { status: 'AVAILABLE', providerId: this.id, modelId: null }; },
    async plan() {
      const rule = { ruleId: 'rule-created-record', requirementId: 'req-created-record' };
      return Buffer.from(JSON.stringify({ providerId: this.id, modelId: null, mode: 'MOCK', output: {
        normalizedGoal: 'Создать запись на изолированном локальном стенде и независимо прочитать её',
        requirements: [{ requirementId: 'req-created-record', statement: 'Запись существует с точными значениями', mandatory: true }],
        missingContext: [],
        steps: [{ stepId: 'step-local-create', description: 'Исполнить заранее зарегистрированный локальный сценарий',
          actionType: 'trusted-scenario', prerequisites: [], adapterId, executionRef, requiredCapabilities: [],
          mutating: true, required: true, validationRules: [rule] }],
        estimatedRisk: 'MEDIUM', approvalRequirements: [], validationRules: [rule]
      } }));
    }
  };
  const service = new TaskService({
    store, plannerProvider, adapters: new Map([[adapterId, adapter]]), registeredExecutionRefs: [executionRef],
    approvedScenarioRefs: [executionRef], approvalVerifier: async ({ actorRef, approvalRef, plan }) => actorRef === 'local-owner' && approvalRef === `owner-plan:${plan.sha256}`
  });
  const originalRequest = 'Проверь локальный сценарий создания записи и подтверди точные значения независимым чтением.';
  const task = await service.create({ originalRequest, ownerRef: 'local-owner', environmentRef: world.stand.environmentId });
  const planned = await service.plan(task.taskId);
  const approved = await service.approvePlan(task.taskId, { planId: planned.plan.planId, actorRef: 'local-owner', approvalRef: `owner-plan:${planned.plan.sha256}` });
  return { world, adapter, adapterId, executionRef, store, service, task, plan: planned.plan, step: planned.plan.steps[0], approved, originalRequest };
}
