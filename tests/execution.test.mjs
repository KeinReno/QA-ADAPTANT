import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TaskStore } from '../packages/execution/store.mjs';
import { topologicalExecutionSteps, validateExecutionPlan } from '../packages/execution/contracts.mjs';
import { TaskService } from '../apps/orchestrator/service.mjs';
import { DeterministicMockPlanner, UnavailablePlannerProvider } from '../packages/planner/provider.mjs';
import { readBoundedPlannerBytes } from '../packages/planner/provider.mjs';
import { validatePlanDraft } from '../packages/planner/validate.mjs';
import { canonical, digest } from '../packages/core/canonical.mjs';

const tempRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), 'adaptant03-task-'));
const clean = root => fs.rmSync(root, { recursive: true, force: true });

function draft({ goal = 'Проверить задачу', missingContext = ['Нужен утверждённый сценарий'] } = {}) {
  const rule = { ruleId: 'rule-result', requirementId: 'req-result' };
  return {
    normalizedGoal: goal,
    requirements: [{ requirementId: 'req-result', statement: 'Получить подтверждённый результат', mandatory: true }],
    missingContext,
    steps: [{ stepId: 'step-clarify', description: 'Уточнить утверждённый сценарий', actionType: 'clarification', prerequisites: [], adapterId: null, executionRef: null, requiredCapabilities: [], mutating: false, required: true, validationRules: [rule] }],
    estimatedRisk: 'UNKNOWN', approvalRequirements: ['OWNER_PLAN_APPROVAL'], validationRules: [rule]
  };
}

test('execution contracts reject invalid transitions, dependency cycles and model-invented privileges', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const task = await store.createTask({ originalRequest: 'Запрос', ownerRef: 'owner-1' });
    await assert.rejects(store.transition(task.taskId, 'COMPLETED'), { code: 'INVALID_TASK_TRANSITION' });
    const base = validatePlanDraft(draft(), { taskId: task.taskId, provider: { providerId: 'mock-deterministic', modelId: null, mode: 'MOCK' } });
    const cyclic = { ...base, steps: [
      { ...base.steps[0], stepId: 'step-a', prerequisites: ['step-b'] },
      { ...base.steps[0], stepId: 'step-b', prerequisites: ['step-a'] }
    ] };
    assert.throws(() => validateExecutionPlan(cyclic), { code: 'INVALID_PLAN' });
    const ordered = topologicalExecutionSteps([
      { ...base.steps[0], stepId: 'step-b', prerequisites: ['step-a'] },
      { ...base.steps[0], stepId: 'step-a', prerequisites: [] }
    ]);
    assert.deepEqual(ordered.map(step => step.stepId), ['step-a', 'step-b']);
    const withUnknownCapability = { ...base, steps: [{ ...base.steps[0], requiredCapabilities: ['delete-everything'] }] };
    assert.throws(() => validateExecutionPlan(withUnknownCapability), { code: 'INVALID_PLAN' });
    const mismatchedRulePair = { ...base,
      requirements: [...base.requirements, { requirementId: 'req-extra', statement: 'Дополнительное требование', mandatory: false }],
      validationRules: [...base.validationRules, { ruleId: 'rule-extra', requirementId: 'req-extra' }],
      steps: [{ ...base.steps[0], validationRules: [{ ruleId: 'rule-result', requirementId: 'req-extra' }] }]
    };
    assert.throws(() => validateExecutionPlan(mismatchedRulePair), { code: 'INVALID_PLAN' });
  } finally { clean(root); }
});

test('TaskStore preserves exact request, versions plans immutably and verifies the journal chain', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const originalRequest = '  Проверь\r\nавторизацию тестового приложения.  ';
    const task = await store.createTask({ originalRequest, ownerRef: 'owner-1', contextRefs: ['context-local'] });
    assert.equal((await store.getTask(task.taskId)).originalRequest, originalRequest);
    await store.transition(task.taskId, 'PLANNING');
    const p1 = validatePlanDraft(draft(), { taskId: task.taskId, provider: { providerId: 'mock-deterministic', modelId: null, mode: 'MOCK' } });
    const first = await store.savePlan(task.taskId, p1);
    assert.equal(first.plan.version, 1);
    await store.transition(task.taskId, 'BLOCKED');
    await store.transition(task.taskId, 'PLANNING');
    const p2 = validatePlanDraft(draft({ goal: 'Повторно сформированная цель' }), { taskId: task.taskId, provider: { providerId: 'mock-deterministic', modelId: null, mode: 'MOCK' } });
    const second = await store.savePlan(task.taskId, p2);
    assert.equal(second.plan.version, 2);
    assert.equal((await store.getPlan(task.taskId, first.plan.planId)).normalizedGoal, 'Проверить задачу');
    assert.equal((await store.getTask(task.taskId)).originalRequest, originalRequest);
    const events = await store.getEvents(task.taskId);
    assert.equal(events.length, 6);
    const taskFile = path.join(root, 'tasks', task.taskId, 'task.json');
    fs.writeFileSync(taskFile, `${JSON.stringify(first.task)}\n`);
    const repaired = await store.getTask(task.taskId);
    assert.equal(repaired.executionPlanId, second.plan.planId);
    assert.equal(repaired.journalSequence, 6);
    const eventFile = path.join(root, 'tasks', task.taskId, 'events.jsonl');
    fs.writeFileSync(eventFile, `${events.slice(0, 5).map(event => JSON.stringify(event)).join('\n')}\n`);
    await assert.rejects(store.getTask(task.taskId), { code: 'INTEGRITY_ERROR' });
    fs.writeFileSync(eventFile, `${events.map(event => JSON.stringify(event)).join('\n')}\n`);
    fs.appendFileSync(eventFile, `${JSON.stringify({ tampered: true })}\n`);
    await assert.rejects(store.getEvents(task.taskId), { code: 'INTEGRITY_ERROR' });
  } finally { clean(root); }
});

test('concurrent duplicate planning transitions serialize; recovery never redispatches', async () => {
  const root = tempRoot();
  try {
    const storeA = new TaskStore(root), storeB = new TaskStore(root);
    const task = await storeA.createTask({ originalRequest: 'Проверить', ownerRef: 'owner-1' });
    const race = await Promise.allSettled([storeA.transition(task.taskId, 'PLANNING'), storeB.transition(task.taskId, 'PLANNING')]);
    assert.equal(race.filter(item => item.status === 'fulfilled').length, 1);
    assert.equal(race.filter(item => item.status === 'rejected').length, 1);
    const service = new TaskService({ store: new TaskStore(root), plannerProvider: new DeterministicMockPlanner() });
    const recovered = await service.recover();
    assert.deepEqual(recovered.blocked, [task.taskId]);
    assert.deepEqual(recovered.inconclusive, []);
    assert.equal((await storeA.getTask(task.taskId)).status, 'BLOCKED');
  } finally { clean(root); }
});

test('recovery isolates corrupt journals and blocks an active task whose immutable plan is missing', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const corrupt = await store.createTask({ originalRequest: 'Повреждённая задача', ownerRef: 'owner-1' });
    const corruptJournal = path.join(root, 'tasks', corrupt.taskId, 'events.jsonl');
    fs.appendFileSync(corruptJournal, '{bad json}\n');

    const missingPlan = await store.createTask({ originalRequest: 'План задачи', ownerRef: 'owner-1' });
    await store.transition(missingPlan.taskId, 'PLANNING');
    const validDraft = validatePlanDraft(draft(), { taskId: missingPlan.taskId, provider: { providerId: 'mock-deterministic', modelId: null, mode: 'MOCK' } });
    const saved = await store.savePlan(missingPlan.taskId, validDraft);
    await store.transition(missingPlan.taskId, 'AWAITING_APPROVAL');
    fs.rmSync(path.join(root, 'tasks', missingPlan.taskId, 'plans', '000001.json'));

    const healthy = await store.createTask({ originalRequest: 'Здоровая задача', ownerRef: 'owner-1' });
    const recovery = await new TaskService({ store: new TaskStore(root), plannerProvider: new DeterministicMockPlanner() }).recover();
    assert.ok(recovery.integrityBlocked.includes(corrupt.taskId));
    assert.ok(recovery.integrityBlocked.includes(missingPlan.taskId));
    assert.ok(recovery.recovered.includes(healthy.taskId));
    assert.equal((await store.getTask(missingPlan.taskId)).status, 'BLOCKED');
    assert.equal(saved.plan.version, 1);
  } finally { clean(root); }
});

test('mock planner provenance is explicit and unsupported plan remains blocked without a run', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const mock = new DeterministicMockPlanner();
    let approvedScenarioRefsSeen;
    const plannerProvider = { id: mock.id, mode: 'MOCK', availability: () => mock.availability(), async plan(request) { approvedScenarioRefsSeen = request.context.approvedScenarioRefs; return mock.plan(request); } };
    const service = new TaskService({ store, plannerProvider });
    const request = 'Проверь авторизацию: корректный вход, отказ неверному паролю и закрытый ресурс для пользователя без полномочий.';
    const task = await service.create({ originalRequest: request, ownerRef: 'owner-1', contextRefs: ['ordinary-context-ref'] });
    const result = await service.plan(task.taskId);
    assert.equal(result.task.originalRequest, request);
    assert.equal(result.task.status, 'BLOCKED');
    assert.equal(result.plan.provider.mode, 'MOCK');
    assert.equal(result.plan.validation.executable, false);
    assert.match(result.plan.missingContext[0], /утверждённый исполнимый сценарий/);
    assert.deepEqual(result.task.runIds, []);
    assert.deepEqual(approvedScenarioRefsSeen, []);
    assert.ok((await service.observe(task.taskId)).events.some(event => event.type === 'PLAN_NOT_EXECUTABLE'));
  } finally { clean(root); }
});

test('missing provider and malformed planner response fail closed', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const unavailable = new TaskService({ store, plannerProvider: new UnavailablePlannerProvider() });
    const first = await unavailable.create({ originalRequest: 'План', ownerRef: 'owner-1' });
    assert.equal((await unavailable.plan(first.taskId)).task.status, 'BLOCKED');

    const broken = new TaskService({ store, plannerProvider: {
      id: 'bad-provider', mode: 'MOCK',
      async availability() { return { status: 'AVAILABLE', providerId: 'bad-provider', modelId: null, mode: 'MOCK' }; },
      async plan() { return Buffer.from(JSON.stringify({ providerId: 'bad-provider', modelId: null, mode: 'MOCK', output: { steps: [{ command: 'Remove-Item -Recurse C:\\' }] } })); }
    } });
    const second = await broken.create({ originalRequest: 'План', ownerRef: 'owner-1' });
    assert.equal((await broken.plan(second.taskId)).task.status, 'BLOCKED');
    assert.equal((await broken.observe(second.taskId)).events.at(-1).payload.reasonCode, 'INVALID_PLAN');
  } finally { clean(root); }
});

test('planner provenance rejects mismatched provider, mode and modelId without fallback', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    let planCalls = 0;
    const validOutput = draft({ goal: 'Проверить происхождение плана', missingContext: [] });
    const scenarios = [
      { configured: { id: 'local-model', mode: 'MODEL' }, availability: { status: 'AVAILABLE', providerId: 'other-model', modelId: 'model-v1', mode: 'MODEL' }, result: { providerId: 'local-model', modelId: 'model-v1', mode: 'MODEL', output: validOutput }, calls: false },
      { configured: { id: 'test-double', mode: 'MOCK' }, availability: { status: 'AVAILABLE', providerId: 'test-double', modelId: null, mode: 'MOCK' }, result: { providerId: 'test-double', modelId: null, mode: 'MODEL', output: validOutput }, calls: true },
      { configured: { id: 'test-double', mode: 'MOCK' }, availability: { status: 'AVAILABLE', providerId: 'test-double', modelId: null, mode: 'MOCK' }, result: { providerId: 'test-double', modelId: 'invented-model', mode: 'MOCK', output: validOutput }, calls: true },
      { configured: { id: 'local-model', mode: 'MODEL' }, availability: { status: 'AVAILABLE', providerId: 'local-model', modelId: null, mode: 'MODEL' }, result: { providerId: 'local-model', modelId: null, mode: 'MODEL', output: validOutput }, calls: false },
        { configured: { id: 'local-model', mode: 'MODEL' }, availability: { status: 'AVAILABLE', providerId: 'local-model', modelId: null, mode: 'MOCK' }, result: { providerId: 'local-model', modelId: null, mode: 'MOCK', output: validOutput }, calls: false },
        { configured: { id: 'test-double', mode: 'MOCK' }, availability: { status: 'AVAILABLE', providerId: 'test-double', modelId: null, mode: 'MOCK' }, result: { providerId: 'other-model', modelId: null, mode: 'MOCK', output: validOutput }, calls: true },
      { configured: { id: 'test-double', mode: 'MOCK' }, availability: { status: 'AVAILABLE', providerId: 'test-double', modelId: null, mode: 'MOCK' }, result: { providerId: 'test-double', modelId: 'invented-model', mode: 'MOCK', output: validOutput }, calls: true }
    ];
    for (const scenario of scenarios) {
      const callsBefore = planCalls;
      const plannerProvider = {
        ...scenario.configured,
        async availability() { return scenario.availability; },
        async plan() { planCalls++; return Buffer.from(JSON.stringify(scenario.result)); }
      };
      const service = new TaskService({ store, plannerProvider });
      const task = await service.create({ originalRequest: 'Проверить provenance', ownerRef: 'owner-provenance' });
      const outcome = await service.plan(task.taskId);
      assert.equal(outcome.task.status, 'BLOCKED');
      assert.equal(outcome.plan, null);
      assert.equal((await service.observe(task.taskId)).events.at(-1).payload.reasonCode, 'INVALID_PLAN');
      assert.equal(planCalls > callsBefore, scenario.calls);
    }
    const unavailableService = new TaskService({ store, plannerProvider: new UnavailablePlannerProvider('unconfigured-model') });
    const unavailableTask = await unavailableService.create({ originalRequest: 'Не включать скрытый fallback', ownerRef: 'owner-provenance' });
    const unavailableOutcome = await unavailableService.plan(unavailableTask.taskId);
    assert.equal(unavailableOutcome.task.status, 'BLOCKED');
    assert.equal(unavailableOutcome.plan, null);
    assert.ok((await unavailableService.observe(unavailableTask.taskId)).events.some(event => event.type === 'PLANNER_UNAVAILABLE'));
    assert.throws(() => new TaskService({ store, plannerProvider: { id: 'implicit-mode', availability() {}, plan() {} } }), /локально заданные id и mode/);
  } finally { clean(root); }
});

test('recovery blocks legacy MODEL plans without modelId and preserves historical bytes', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const task = await store.createTask({ originalRequest: 'Проверить старую provenance запись', ownerRef: 'owner-legacy' });
    await store.transition(task.taskId, 'PLANNING');
    const validDraft = validatePlanDraft(draft(), { taskId: task.taskId, provider: { providerId: 'legacy-test-provider', modelId: null, mode: 'MOCK' } });
    const saved = await store.savePlan(task.taskId, validDraft);
    await store.transition(task.taskId, 'AWAITING_APPROVAL');

    const planPath = path.join(root, 'tasks', task.taskId, 'plans', '000001.json');
    const { sha256: _previousDigest, ...unsignedLegacyPlan } = saved.plan;
    const legacyUnsigned = { ...unsignedLegacyPlan, provider: { providerId: 'legacy-model-provider', modelId: null, mode: 'MODEL' } };
    const legacyPlan = { ...legacyUnsigned, sha256: digest(legacyUnsigned) };
    fs.writeFileSync(planPath, `${canonical(legacyPlan)}\n`);
    const planBytesBeforeRecovery = fs.readFileSync(planPath);
    const journalPath = path.join(root, 'tasks', task.taskId, 'events.jsonl');
    const journalBeforeRecovery = fs.readFileSync(journalPath, 'utf8');

    const recovery = await new TaskService({ store: new TaskStore(root), plannerProvider: new DeterministicMockPlanner() }).recover();
    assert.ok(recovery.integrityBlocked.includes(task.taskId));
    assert.equal((await store.getTask(task.taskId)).status, 'BLOCKED');
    assert.deepEqual(fs.readFileSync(planPath), planBytesBeforeRecovery);
    assert.ok(fs.readFileSync(journalPath, 'utf8').startsWith(journalBeforeRecovery));
    assert.equal((await store.getEvents(task.taskId)).at(-1).payload.reasonCode, 'PLAN_INTEGRITY_ERROR');
  } finally { clean(root); }
});

test('owner approval is tied to the current plan version; plan approval is not an execution verdict', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const rule = { ruleId: 'rule-trusted', requirementId: 'req-auth' };
    const provider = {
      id: 'test-model', mode: 'MOCK',
      async availability() { return { status: 'AVAILABLE', providerId: this.id, modelId: null, mode: 'MOCK' }; },
      async plan() { return Buffer.from(JSON.stringify({
        providerId: this.id, modelId: null, mode: 'MOCK', output: {
          normalizedGoal: 'Проверить авторизацию по утверждённому сценарию',
          requirements: [{ requirementId: 'req-auth', statement: 'Результат должен быть подтверждён', mandatory: true }],
          missingContext: [],
          steps: [{ stepId: 'step-auth', description: 'Исполнить trusted scenario', actionType: 'trusted-scenario', prerequisites: [], adapterId: 'trust-run', executionRef: 'auth-approved-v1', requiredCapabilities: ['read-record'], mutating: false, required: true, validationRules: [rule] }],
          estimatedRisk: 'HIGH', approvalRequirements: [], validationRules: [rule]
        }
      })); }
    };
    const adapter = { id: 'trust-run', capabilities: () => [], prepare: async () => ({}), start: async () => ({}), observe: async () => ({}), cancel: async () => ({}), reconcile: async () => ({}) };
    const service = new TaskService({ store, plannerProvider: provider, adapters: new Map([['trust-run', adapter]]), registeredExecutionRefs: ['auth-approved-v1'], approvedScenarioRefs: ['auth-approved-v1'], allowedCapabilities: ['read-record'], approvalVerifier: async ({ actorRef, approvalRef, plan }) => actorRef === 'owner-1' && approvalRef === `approval:${plan.sha256}` });
    const task = await service.create({ originalRequest: 'Проверить авторизацию', ownerRef: 'owner-1' });
    const planned = await service.plan(task.taskId);
    assert.equal(planned.task.status, 'AWAITING_APPROVAL');
    assert.equal(planned.plan.steps[0].mutating, true);
    assert.deepEqual(planned.plan.approvalRequirements, ['OWNER_PLAN_APPROVAL', 'TRUST_APPROVAL']);
    await assert.rejects(service.approvePlan(task.taskId, { planId: planned.plan.planId, actorRef: 'other-owner', approvalRef: `approval:${planned.plan.sha256}` }), { code: 'OWNER_MISMATCH' });
    const approved = await service.approvePlan(task.taskId, { planId: planned.plan.planId, actorRef: 'owner-1', approvalRef: `approval:${planned.plan.sha256}` });
    assert.equal(approved.status, 'READY');
    assert.equal(approved.runIds.length, 0);
    assert.equal((await service.observe(task.taskId)).plan.provider.mode, 'MOCK');
    const capabilityCheck = await service.start(task.taskId);
    assert.equal(capabilityCheck.started, false);
    assert.equal(capabilityCheck.task.status, 'BLOCKED');
    assert.equal((await service.observe(task.taskId)).events.at(-1).payload.reasonCode, 'ADAPTER_CAPABILITY_UNSUPPORTED');
    const unapprovedService = new TaskService({ store, plannerProvider: provider, adapters: new Map([['trust-run', adapter]]), registeredExecutionRefs: ['auth-approved-v1'], approvedScenarioRefs: [], approvalVerifier: async () => true });
    const unapprovedTask = await unapprovedService.create({ originalRequest: 'Исполнить сценарий без owner catalogue', ownerRef: 'owner-1' });
    const unapprovedPlan = await unapprovedService.plan(unapprovedTask.taskId);
    assert.equal(unapprovedPlan.task.status, 'BLOCKED');
    assert.equal(unapprovedPlan.plan, null);
    assert.equal((await unapprovedService.observe(unapprovedTask.taskId)).events.at(-1).payload.reasonCode, 'INVALID_PLAN');
  } finally { clean(root); }
});

test('bounded Planner response enforces stream limits; timeout and oversized provider output block the task', async () => {
  const response = new Response(new Uint8Array(32));
  await assert.rejects(readBoundedPlannerBytes(response, { maxBytes: 16 }), { code: 'OUTPUT_LIMIT' });
  let canceled = false;
  const stalledResponse = new Response(new ReadableStream({ pull() { return new Promise(() => {}); }, cancel() { canceled = true; } }));
  const controller = new AbortController();
  const pendingRead = readBoundedPlannerBytes(stalledResponse, { maxBytes: 16, signal: controller.signal });
  controller.abort();
  await assert.rejects(pendingRead, { code: 'CANCELED' });
  assert.equal(canceled, true);
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const oversized = new TaskService({ store, maxPlannerResponseBytes: 64, plannerProvider: {
      id: 'oversized', mode: 'MOCK', async availability() { return { status: 'AVAILABLE', providerId: this.id, modelId: null, mode: 'MOCK' }; },
      async plan() { return Buffer.alloc(65, 32); }
    } });
    const task1 = await oversized.create({ originalRequest: 'План', ownerRef: 'owner-1' });
    assert.equal((await oversized.plan(task1.taskId)).task.status, 'BLOCKED');
    assert.equal((await oversized.observe(task1.taskId)).events.at(-1).payload.reasonCode, 'OUTPUT_LIMIT');

    const timeout = new TaskService({ store, plannerTimeoutMs: 10, plannerProvider: {
      id: 'hung', mode: 'MOCK', async availability() { return { status: 'AVAILABLE', providerId: this.id, modelId: null, mode: 'MOCK' }; },
      async plan() { return new Promise(() => {}); }
    } });
    const task2 = await timeout.create({ originalRequest: 'План', ownerRef: 'owner-1' });
    assert.equal((await timeout.plan(task2.taskId)).task.status, 'BLOCKED');
    assert.equal((await timeout.observe(task2.taskId)).events.at(-1).payload.reasonCode, 'TIMEOUT');
  } finally { clean(root); }
});

test('owner approval compare-and-transition rejects a stale decision after concurrent replanning', async () => {
  const root = tempRoot();
  let enteredApproval;
  let releaseApproval;
  const entered = new Promise(resolve => { enteredApproval = resolve; });
  const wait = new Promise(resolve => { releaseApproval = resolve; });
  try {
    const store = new TaskStore(root);
    const rule = { ruleId: 'rule-trusted', requirementId: 'req-auth' };
    const provider = {
      id: 'test-model', mode: 'MOCK',
      async availability() { return { status: 'AVAILABLE', providerId: this.id, modelId: null, mode: 'MOCK' }; },
      async plan() { return Buffer.from(JSON.stringify({ providerId: this.id, modelId: null, mode: 'MOCK', output: {
        normalizedGoal: 'Исполнить сценарий', requirements: [{ requirementId: 'req-auth', statement: 'Проверить', mandatory: true }], missingContext: [],
        steps: [{ stepId: 'step-auth', description: 'Trusted', actionType: 'trusted-scenario', prerequisites: [], adapterId: 'trust-run', executionRef: 'auth-v1', requiredCapabilities: [], mutating: true, required: true, validationRules: [rule] }],
        estimatedRisk: 'HIGH', approvalRequirements: [], validationRules: [rule]
      } })); }
    };
    const adapter = { id: 'trust-run', capabilities: () => [], prepare: async () => ({}), start: async () => ({}), observe: async () => ({}), cancel: async () => ({}), reconcile: async () => ({}) };
    const service = new TaskService({ store, plannerProvider: provider, adapters: new Map([['trust-run', adapter]]), registeredExecutionRefs: ['auth-v1'], approvedScenarioRefs: ['auth-v1'], approvalVerifier: async () => { enteredApproval(); await wait; return true; } });
    const task = await service.create({ originalRequest: 'Проверить', ownerRef: 'owner-1' });
    const planned = await service.plan(task.taskId);
    const approving = service.approvePlan(task.taskId, { planId: planned.plan.planId, actorRef: 'owner-1', approvalRef: `approval:${planned.plan.sha256}` });
    await entered;
    await store.transition(task.taskId, 'PLANNING', { patch: { approvalRef: null, executionPlanId: null } });
    releaseApproval();
    await assert.rejects(approving, { code: 'TASK_CONFLICT' });
    assert.equal((await store.getTask(task.taskId)).status, 'PLANNING');
  } finally { releaseApproval?.(); clean(root); }
});

test('TaskStore rejects PASS without trusted evidence bound to every required step', async () => {
  const root = tempRoot();
  try {
    const store = new TaskStore(root);
    const rule = { ruleId: 'rule-trusted', requirementId: 'req-auth' };
    const provider = { id: 'model', mode: 'MOCK', async availability() { return { status: 'AVAILABLE', providerId: this.id, modelId: null, mode: 'MOCK' }; }, async plan() {
      return Buffer.from(JSON.stringify({ providerId: this.id, modelId: null, mode: 'MOCK', output: {
        normalizedGoal: 'Исполнить', requirements: [{ requirementId: 'req-auth', statement: 'Проверить', mandatory: true }], missingContext: [],
        steps: [{ stepId: 'step-auth', description: 'Trusted', actionType: 'trusted-scenario', prerequisites: [], adapterId: 'trust-run', executionRef: 'auth-v1', requiredCapabilities: [], mutating: true, required: true, validationRules: [rule] }],
        estimatedRisk: 'HIGH', approvalRequirements: [], validationRules: [rule]
      } }));
    } };
    const adapter = { id: 'trust-run', capabilities: () => [], prepare: async () => ({}), start: async () => ({}), observe: async () => ({}), cancel: async () => ({}), reconcile: async () => ({}) };
    const service = new TaskService({ store, plannerProvider: provider, adapters: new Map([['trust-run', adapter]]), registeredExecutionRefs: ['auth-v1'], approvedScenarioRefs: ['auth-v1'], approvalVerifier: async () => true });
    const task = await service.create({ originalRequest: 'Проверить', ownerRef: 'owner-1' });
    const planned = await service.plan(task.taskId);
    const ready = await service.approvePlan(task.taskId, { planId: planned.plan.planId, actorRef: 'owner-1', approvalRef: 'owner-ok' });
    await store.transition(task.taskId, 'RUNNING', { patch: { runIds: ['run-local-1'] } });
    await store.transition(task.taskId, 'VERIFYING');
    const falsePass = { taskOutcome: 'PASS', plannerMode: 'MOCK', stepOutcomes: [{ stepId: 'step-auth', executionOutcome: 'SUCCEEDED', verificationOutcome: 'PASS', trustedVerification: false, runIds: ['run-local-1'], evidenceRefs: [] }], reasonCode: null, message: 'PASS' };
    await assert.rejects(store.transition(task.taskId, 'COMPLETED', { patch: { result: falsePass } }), { code: 'UNVERIFIED_TASK_PASS' });
    const fabricatedPass = { ...falsePass, stepOutcomes: [{ stepId: 'step-auth', executionOutcome: 'SUCCEEDED', verificationOutcome: 'PASS', trustedVerification: true, runIds: ['run-local-1'], evidenceRefs: [{ runId: 'run-local-1', evidenceId: 'invented-evidence' }] }] };
    await assert.rejects(store.transition(task.taskId, 'COMPLETED', { patch: { result: fabricatedPass } }), { code: 'UNVERIFIED_TASK_PASS' });
    let verifierCalled = false;
    const independentlyCheckedStore = new TaskStore(root, { verifyTaskPass: async ({ task: current, plan: currentPlan, result }) => {
      verifierCalled = true;
      return current.runIds.includes('run-local-1') && currentPlan.steps.some(step => step.stepId === 'step-auth') && result.stepOutcomes[0].evidenceRefs[0].evidenceId === 'verified-evidence';
    } });
    const verifiedPass = { ...fabricatedPass, stepOutcomes: [{ ...fabricatedPass.stepOutcomes[0], evidenceRefs: [{ runId: 'run-local-1', evidenceId: 'verified-evidence' }] }] };
    await assert.rejects(independentlyCheckedStore.transition(task.taskId, 'COMPLETED', { patch: { result: fabricatedPass } }), { code: 'UNVERIFIED_TASK_PASS' });
    assert.equal(verifierCalled, true);
    await independentlyCheckedStore.transition(task.taskId, 'COMPLETED', { patch: { result: verifiedPass } });
    assert.equal((await independentlyCheckedStore.getTask(task.taskId)).result.taskOutcome, 'PASS');
    assert.equal((await store.getTask(task.taskId)).status, 'COMPLETED');
    assert.equal(ready.status, 'READY');
  } finally { clean(root); }
});
