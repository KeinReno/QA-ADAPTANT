import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { digest } from '../packages/core/canonical.mjs';
import { TrustedFacadeExecutionAdapter } from '../packages/execution/trusted-adapter.mjs';
import { approvedLocalTask } from './adaptant03-e2e-support.mjs';

test('trusted adapter rejects symlinked prepared or launch storage directories', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'adaptant03-path-'));
  try {
    const outside = path.join(base, 'outside'), root = path.join(base, 'run-root');
    fs.mkdirSync(outside); fs.mkdirSync(root);
    fs.symlinkSync(outside, path.join(root, 'adaptant-prepared'), 'junction');
    assert.throws(() => new TrustedFacadeExecutionAdapter({ root, executionRefs: {}, resolveTrustOptions: async () => ({}) }), { code: 'INTEGRITY_ERROR' });
    fs.rmSync(path.join(root, 'adaptant-prepared'), { recursive: true, force: true });
    fs.rmSync(path.join(root, 'adaptant-launches'), { recursive: true, force: true });
    fs.symlinkSync(outside, path.join(root, 'adaptant-launches'), 'junction');
    assert.throws(() => new TrustedFacadeExecutionAdapter({ root, executionRefs: {}, resolveTrustOptions: async () => ({}) }), { code: 'INTEGRITY_ERROR' });
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('Task→approved plan→public trusted facade→independent observer yields PASS with linked local evidence', { timeout: 120000 }, async t => {
  const { world, adapter, store, service, task, plan, approved, originalRequest } = await approvedLocalTask(t);
  await assert.rejects(adapter.prepare({ task: approved, plan, step: plan.steps[0], executionRef: 'scenario:substituted' }), { code: 'ADAPTER_INPUT_MISMATCH' });
  await assert.rejects(adapter.prepare({ task: approved, plan: { ...plan, planId: 'plan-substituted' }, step: plan.steps[0], executionRef: plan.steps[0].executionRef }), { code: 'ADAPTER_INPUT_MISMATCH' });
  const tamperedPlan = { ...plan, normalizedGoal: `${plan.normalizedGoal} изменено` };
  const unlaunched = await adapter.prepare({ task: approved, plan, step: plan.steps[0], executionRef: plan.steps[0].executionRef });
  const unlaunchedKey = digest({ taskId: task.taskId, planId: plan.planId, stepId: plan.steps[0].stepId, runId: unlaunched.runId });
  await assert.rejects(adapter.start({ task: { ...approved, status: 'RUNNING' }, plan: tamperedPlan, step: plan.steps[0], prepared: unlaunched, idempotencyKey: unlaunchedKey }), { code: 'ADAPTER_INPUT_MISMATCH' });
  assert.equal(approved.status, 'READY');
  assert.equal(plan.validation.executable, true);
  assert.deepEqual(plan.approvalRequirements, ['OWNER_PLAN_APPROVAL', 'TRUST_APPROVAL']);
  const executed = await service.start(task.taskId);
  assert.equal(executed.task.status, 'COMPLETED', JSON.stringify({ events: (await store.getEvents(task.taskId)).map(event => ({ type: event.type, payload: event.payload })), trustResolutionDiagnostics: world.trustResolutionDiagnostics }));
  assert.equal(executed.result.taskOutcome, 'PASS');
  assert.equal(executed.result.stepOutcomes[0].trustedVerification, true);
  assert.equal(executed.observation.trusted, true);
  assert.equal(executed.observation.verdict.verdict, 'PASS');
  assert.ok(executed.result.stepOutcomes[0].evidenceRefs.length > 0);
  assert.ok(executed.result.stepOutcomes[0].evidenceRefs.every(ref => ref.runId === executed.task.runIds[0]));
  assert.equal(world.stand.mutationCount, 1);
  assert.equal((await store.getEvents(task.taskId)).filter(event => event.type === 'DISPATCH_INTENT').length, 1);
  assert.equal((await service.observe(task.taskId)).task.originalRequest, originalRequest);

  const intent = (await store.getEvents(task.taskId)).find(event => event.type === 'DISPATCH_INTENT');
  await assert.rejects(adapter.start({ task: { ...executed.task, status: 'RUNNING' }, plan, step: plan.steps[0],
    prepared: { runId: intent.payload.runId, preparedDigest: intent.payload.preparedDigest, preparedRef: intent.payload.runId },
    idempotencyKey: intent.payload.idempotencyKey }), { code: 'DISPATCH_ALREADY_ATTEMPTED' });
  assert.equal(world.stand.mutationCount, 1);
});

test('crash recovery reconciles the durable intent by its existing runId without a second mutation', { timeout: 120000 }, async t => {
  const { world, adapter, store, service, task, plan, step } = await approvedLocalTask(t);
  const ready = await store.getTask(task.taskId);
  const prepared = await adapter.prepare({ task: ready, plan, step, executionRef: step.executionRef });
  const idempotencyKey = digest({ taskId: task.taskId, planId: plan.planId, stepId: step.stepId, runId: prepared.runId });
  await store.recordDispatchIntent(task.taskId, {
    runId: prepared.runId, stepId: step.stepId, adapterId: adapter.id,
    executionRefSha256: digest(step.executionRef), preparedDigest: prepared.preparedDigest, idempotencyKey
  }, { revision: ready.revision, planId: plan.planId, planSha256: plan.sha256 });
  const runnerResult = await adapter.start({ task: await store.getTask(task.taskId), plan, step, prepared, idempotencyKey });
  assert.equal(runnerResult.runId, prepared.runId);
  assert.equal((await store.getTask(task.taskId)).status, 'RUNNING');

  const recovered = await service.recover();
  assert.ok(recovered.recovered.includes(task.taskId), JSON.stringify({ recovered, events: (await store.getEvents(task.taskId)).map(event => ({ type: event.type, payload: event.payload })) }));
  const finished = await store.getTask(task.taskId);
  assert.equal(finished.status, 'COMPLETED');
  assert.equal(finished.result.taskOutcome, 'PASS');
  assert.deepEqual(finished.runIds, [prepared.runId]);
  assert.equal(world.stand.mutationCount, 1);
  assert.equal((await store.getEvents(task.taskId)).filter(event => event.type === 'DISPATCH_INTENT').length, 1);
});

test('post-dispatch cancellation uses trusted cancel/observe and never repeats the local mutation', { timeout: 120000 }, async t => {
  const { world, store, service, task } = await approvedLocalTask(t, { standOptions: { fault: 'delayResponse' } });
  const startPromise = service.start(task.taskId);
  let intent = null;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    intent = (await store.getEvents(task.taskId)).find(event => event.type === 'DISPATCH_INTENT');
    if (intent && world.stand.mutationCount === 1) break;
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  assert.ok(intent, 'durable dispatch intent was recorded');
  assert.equal(world.stand.mutationCount, 1);
  const cancelResult = await service.cancel(task.taskId, 'local-owner');
  const startResult = await startPromise;
  const current = await store.getTask(task.taskId);
  assert.ok(['CANCELED', 'INCONCLUSIVE', 'COMPLETED'].includes(current.status));
  assert.ok((await store.getEvents(task.taskId)).some(event => event.type === 'CANCEL_REQUESTED'));
  if (current.result?.taskOutcome === 'PASS') assert.equal(startResult.observation?.verdict?.verdict, 'PASS');
  assert.equal(world.stand.mutationCount, 1);
  assert.equal(cancelResult.task.taskId, task.taskId);
});

test('a competing canceled result wins Task CAS and start returns the persisted outcome', { timeout: 120000 }, async t => {
  const { world, store, service, task } = await approvedLocalTask(t);
  const transition = store.transition.bind(store);
  let raced = false;
  store.transition = async (taskId, nextStatus, options = {}) => {
    if (nextStatus === 'COMPLETED' && !raced) {
      raced = true;
      const candidate = options.patch.result;
      const canceledResult = { ...candidate, taskOutcome: 'CANCELED', reasonCode: 'CANCEL_WON',
        stepOutcomes: candidate.stepOutcomes.map(item => ({ ...item, verificationOutcome: 'INCONCLUSIVE' })) };
      await transition(taskId, 'CANCELED', { patch: { result: canceledResult }, payload: { reasonCode: 'CANCEL_WON' }, expected: options.expected });
    }
    return transition(taskId, nextStatus, options);
  };
  const response = await service.start(task.taskId);
  assert.equal(raced, true);
  assert.equal((await store.getTask(task.taskId)).status, 'CANCELED');
  assert.equal(response.task.status, 'CANCELED');
  assert.equal(response.result.taskOutcome, 'CANCELED');
  assert.equal(world.stand.mutationCount, 1);
});
