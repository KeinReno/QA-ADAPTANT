import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { TaskStore } from '../packages/execution/store.mjs';
import { TaskService } from '../apps/orchestrator/service.mjs';
import { OllamaPlannerProvider } from '../packages/planner/ollama.mjs';
import { createPlannerStoreAclGuard, restrictPlannerStoreToCurrentUser } from '../packages/planner/acl.mjs';
import { digest } from '../packages/core/canonical.mjs';
import { canonical } from '../packages/core/canonical.mjs';
import { validatePlanDraft } from '../packages/planner/validate.mjs';

const executionRef = 'scenario:create-record';
const adapterId = 'local-create-record';

function draft({ ref = executionRef, actionType = 'trusted-scenario' } = {}) {
  const rule = { ruleId: 'rule-record', requirementId: 'req-record' };
  return {
    normalizedGoal: 'Использовать утверждённый локальный сценарий создания записи',
    requirements: [{ requirementId: 'req-record', statement: 'Сценарий покрывает поручение', mandatory: true }],
    missingContext: [],
    steps: [{ stepId: 'step-record', description: 'Выполнить только зарегистрированный локальный сценарий', actionType, prerequisites: [], adapterId: actionType === 'trusted-scenario' ? adapterId : null, executionRef: actionType === 'trusted-scenario' ? ref : null, requiredCapabilities: [], mutating: false, required: true, validationRules: [rule] }],
    estimatedRisk: 'MEDIUM', approvalRequirements: [], validationRules: [rule]
  };
}

async function backend(t, { output = draft(), model = 'test-model:latest', status = 200, contentType = 'application/json', delayMs = 0, modelList = ['test-model:latest'] } = {}) {
  const calls = { tags: 0, chat: 0, requestBody: null };
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    if (request.url === '/api/tags') {
      calls.tags++;
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ models: modelList.map(name => ({ name, model: name })) }));
      return;
    }
    if (request.url !== '/api/chat') { response.writeHead(404); response.end(); return; }
    calls.chat++;
    calls.requestBody = Buffer.concat(chunks);
    if (delayMs) await new Promise(resolve => setTimeout(resolve, delayMs));
    response.writeHead(status, { 'content-type': contentType });
    response.end(JSON.stringify({ model, created_at: '2026-11-14T00:00:00Z', message: { role: 'assistant', content: JSON.stringify(output) }, done: true, done_reason: 'stop' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return { endpoint: `http://127.0.0.1:${server.address().port}`, calls };
}

async function configured(t, options = {}, { plannerTimeoutMs = 30000, maxResponseBytes = 100000, maxRequestBytes = 64000 } = {}) {
  const serviceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'kaiden-planner-'));
  t.after(() => fs.rmSync(serviceRoot, { recursive: true, force: true }));
  const server = await backend(t, options);
  const provider = new OllamaPlannerProvider({ endpoint: server.endpoint, modelId: 'test-model:latest', accessGuard: async () => true, maxRequestBytes, maxResponseBytes });
  // The controlled HTTP backend suite isolates protocol logic; platform directory flush is tested separately and E2E remains blocked if unavailable.
  const store = new TaskStore(serviceRoot, { plannerAclGuard: () => true, maxPlannerResponseBytes: maxResponseBytes, maxPlannerRequestBytes: maxRequestBytes, syncDirectory: () => {} });
  const service = new TaskService({ store, plannerProvider: provider, plannerTimeoutMs, adapters: new Map([[adapterId, {}]]), registeredExecutionRefs: [executionRef], approvedScenarioRefs: [executionRef], plannerActionCatalog: [{ actionType: 'trusted-scenario', adapterId, executionRef, description: 'Утверждённый локальный create-record сценарий', mutating: true }] });
  const task = await service.create({ originalRequest: 'Создай локальную запись утверждённым сценарием.', ownerRef: 'local-owner' });
  return { server, provider, store, service, task };
}

test('Ollama uses one configured local model, sends structured JSON request without tools, and rejects non-loopback endpoints', () => {
  assert.throws(() => new OllamaPlannerProvider({ endpoint: 'http://example.com:11434', modelId: 'x' }), /loopback/);
  const provider = new OllamaPlannerProvider({ modelId: 'configured-model', accessGuard: async () => true });
  const invocation = provider.buildRequest({ requestId: 'plan-request-1', requestSha256: 'a'.repeat(64), taskId: 'task-1', originalRequest: 'test', context: { actionCatalog: [], allowedActionTypes: ['clarification'], approvedScenarioRefs: [], environmentRefs: [], constraints: [] }, outputSchemaVersion: '0.3.0', maxInputBytes: 64000 });
  const request = JSON.parse(Buffer.from(invocation.requestBodyBytes).toString('utf8'));
  assert.equal(request.model, 'configured-model');
  assert.equal(request.stream, false);
  assert.equal(request.tools, undefined);
  assert.equal(typeof request.format, 'object');
  assert.match(request.messages[0].content, /недоверенные данные/);
});

test('real PlannerProvider bytes are persisted before parse and linked to the versioned approved plan', async t => {
  const { server, service, store, task } = await configured(t);
  const planned = await service.plan(task.taskId);
  assert.equal(server.calls.chat, 1);
  assert.equal(planned.task.status, 'AWAITING_APPROVAL');
  assert.equal(planned.plan.schemaVersion, '0.3.1');
  assert.equal(planned.plan.provider.mode, 'MODEL');
  assert.equal(planned.plan.provider.modelId, 'test-model:latest');
  assert.equal(planned.plan.steps[0].mutating, true, 'host validation upgrades the model-provided mutating=false');
  assert.equal(planned.plan.plannerResponse.requestId.startsWith('plan-request-'), true);
  assert.deepEqual(planned.plan.approvalRequirements, ['OWNER_PLAN_APPROVAL', 'TRUST_APPROVAL']);
  const response = await store.getPlannerResponse(task.taskId, planned.plan.plannerResponse.responseId);
  assert.equal(response.receipt.status, 'RECEIVED');
  assert.equal(response.receipt.requestId, planned.plan.plannerResponse.requestId);
  assert.equal(response.receipt.responseSha256, digest(response.bodyBytes));
  assert.equal(response.receipt.requestBodySha256, digest(response.requestBodyBytes));
  assert.deepEqual(response.bodyBytes, Buffer.from(JSON.stringify({ model: 'test-model:latest', created_at: '2026-11-14T00:00:00Z', message: { role: 'assistant', content: JSON.stringify(draft()) }, done: true, done_reason: 'stop' })));
  const events = await store.getEvents(task.taskId);
  assert.ok(events.findIndex(item => item.type === 'PLANNER_REQUEST_STARTED') < events.findIndex(item => item.type === 'PLANNER_RESPONSE_STORED'));
  assert.ok(events.findIndex(item => item.type === 'PLANNER_RESPONSE_STORED') < events.findIndex(item => item.type === 'PLANNER_RESPONSE_VALIDATED'));
  assert.equal(events.some(item => item.type === 'DISPATCH_INTENT'), false);
  await store.transition(task.taskId, 'PLANNING', { patch: { executionPlanId: null, approvalRef: null } });
  await assert.rejects(store.savePlan(task.taskId, { ...planned.plan, normalizedGoal: 'Подменённый план' }), { code: 'PLANNER_RESPONSE_MISMATCH' });
});

test('unknown executionRef from model is blocked without plan publication or dispatch', async t => {
  const { service, store, task } = await configured(t, { output: draft({ ref: 'scenario:foreign-app-login' }) });
  const planned = await service.plan(task.taskId);
  assert.equal(planned.task.status, 'BLOCKED');
  assert.equal(planned.task.executionPlanId, null);
  assert.equal((await store.getEvents(task.taskId)).some(item => item.type === 'DISPATCH_INTENT'), false);
  assert.equal((await store.getEvents(task.taskId)).some(item => item.type === 'PLANNER_RESPONSE_REJECTED'), true);
});

test('backend-reported model mismatch is saved as raw evidence then rejected, without fallback', async t => {
  const { server, service, store, task } = await configured(t, { model: 'other-model' });
  const planned = await service.plan(task.taskId);
  assert.equal(server.calls.chat, 1);
  assert.equal(planned.task.status, 'BLOCKED');
  const events = await store.getEvents(task.taskId);
  assert.equal(events.some(item => item.type === 'PLANNER_RESPONSE_STORED'), true);
  assert.equal(events.some(item => item.type === 'PLANNER_RESPONSE_REJECTED'), true);
  assert.equal(events.some(item => item.type === 'PLAN_VERSION_CREATED'), false);
  assert.equal(events.some(item => item.payload?.providerId === 'mock-deterministic'), false);
});

test('interrupted planning resumes only from saved response bytes and does not repeat inference', async t => {
  const { server, provider, store, service, task } = await configured(t);
  const planning = await store.transition(task.taskId, 'PLANNING');
  const plannerRequest = { requestId: 'plan-request-recovery', taskId: task.taskId, originalRequest: planning.originalRequest, originalRequestSha256: planning.originalRequestSha256, context: { allowedActionTypes: ['trusted-scenario', 'clarification', 'observation'], environmentRefs: [], approvedScenarioRefs: [executionRef], actionCatalog: [{ actionType: 'trusted-scenario', adapterId, executionRef, description: 'Approved local create-record', mutating: true }], constraints: ['Только разрешённые действия'] }, outputSchemaVersion: '0.3.0', maxInputBytes: 64000 };
  plannerRequest.requestSha256 = digest(plannerRequest);
  const invocation = provider.buildRequest(plannerRequest);
  await store.beginPlannerRequest(task.taskId, { ...plannerRequest, providerId: provider.id, configuredModelId: provider.modelId, mode: 'MODEL', startedAt: new Date().toISOString() });
  const response = await provider.invoke(invocation);
  const receipt = await store.savePlannerResponse(task.taskId, { requestSha256: plannerRequest.requestSha256, requestBodyBytes: invocation.requestBodyBytes, response });
  const parsed = provider.parseResponse({ ...response, bodyBytes: response.bodyBytes });
  const parsedResult = JSON.parse(Buffer.from(parsed.resultBytes).toString('utf8'));
  const placeholderRef = { responseId: receipt.responseId, requestId: receipt.requestId, requestSha256: receipt.requestSha256, responseSha256: receipt.responseSha256, byteLength: receipt.byteLength, planResultSha256: '0'.repeat(64) };
  const checked = validatePlanDraft(parsedResult.output, { taskId: task.taskId, provider: { providerId: provider.id, modelId: provider.modelId, mode: 'MODEL' }, plannerResponse: placeholderRef, registeredExecutionRefs: [executionRef], registeredAdapters: [adapterId], allowedCapabilities: [] });
  const draftWithPolicy = { ...checked, approvalRequirements: ['OWNER_PLAN_APPROVAL', 'TRUST_APPROVAL'] };
  const planResultSha256 = digest({ normalizedGoal: draftWithPolicy.normalizedGoal, requirements: draftWithPolicy.requirements, missingContext: draftWithPolicy.missingContext, steps: draftWithPolicy.steps, estimatedRisk: draftWithPolicy.estimatedRisk, approvalRequirements: draftWithPolicy.approvalRequirements, validationRules: draftWithPolicy.validationRules });
  const plannerResponse = { ...placeholderRef, planResultSha256 };
  await store.recordPlannerResponseValidated(task.taskId, receipt.responseId, { modelId: provider.modelId, planResultSha256 });
  const orphanUnsigned = { ...draftWithPolicy, schemaVersion: '0.3.1', planId: `plan-${task.taskId.slice(5)}-1`, taskId: task.taskId, version: 1, createdAt: new Date().toISOString(), provider: { providerId: provider.id, modelId: provider.modelId, mode: 'MODEL' }, plannerResponse };
  const { sha256: _discarded, ...orphanPlanUnsigned } = orphanUnsigned;
  const orphanPlan = { ...orphanPlanUnsigned, sha256: digest(orphanPlanUnsigned) };
  fs.writeFileSync(path.join(store.root, 'tasks', task.taskId, 'plans', '000001.json'), `${canonical(orphanPlan)}\n`);
  assert.equal(server.calls.chat, 1);
  const recovered = await service.recover();
  assert.deepEqual(recovered.recovered, [task.taskId]);
  assert.equal((await store.getTask(task.taskId)).status, 'AWAITING_APPROVAL');
  assert.equal(server.calls.chat, 1);
  assert.equal((await store.getPlan(task.taskId)).plannerResponse.responseId, receipt.responseId);
  assert.equal((await store.getEvents(task.taskId)).filter(item => item.type === 'PLAN_VERSION_CREATED').length, 1);
});

test('no installed configured model reports unavailable rather than falling back to MOCK', async () => {
  const provider = new OllamaPlannerProvider({ endpoint: 'http://127.0.0.1:1', modelId: 'absent-model', accessGuard: async () => true, fetchImpl: async () => { throw new Error('connection refused'); } });
  const availability = await provider.availability();
  assert.equal(availability.status, 'UNAVAILABLE');
  assert.equal(availability.mode, 'MODEL');
  assert.equal(availability.providerId, 'ollama-local');
  assert.equal(availability.modelId, null);
});

test('ACL guard permits only an explicitly restricted current-user Task store', { skip: process.platform !== 'win32' }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kaiden-planner-acl-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const guard = createPlannerStoreAclGuard(root);
  assert.equal(await guard(), false);
  assert.equal(restrictPlannerStoreToCurrentUser(root), true);
  assert.equal(await guard(), true);
});

test('oversized model response blocks and records no response artifact', async t => {
  const { service, store, task } = await configured(t, { output: { long: 'x'.repeat(5000) } }, { maxResponseBytes: 1024 });
  const planned = await service.plan(task.taskId);
  assert.equal(planned.task.status, 'BLOCKED');
  const events = await store.getEvents(task.taskId);
  assert.equal(events.some(item => item.type === 'PLANNER_RESPONSE_STORED'), false);
  assert.equal(events.some(item => item.type === 'PLANNER_REQUEST_FINISHED' && item.payload.outcome === 'UNKNOWN'), true);
});

test('wrong content type is durably recorded before strict response rejection', async t => {
  const { server, service, store, task } = await configured(t, { contentType: 'text/plain' });
  const planned = await service.plan(task.taskId);
  assert.equal(server.calls.chat, 1);
  assert.equal(planned.task.status, 'BLOCKED');
  const events = await store.getEvents(task.taskId);
  assert.equal(events.some(item => item.type === 'PLANNER_RESPONSE_STORED'), true);
  assert.equal(events.some(item => item.type === 'PLANNER_RESPONSE_REJECTED'), true);
  assert.equal(events.some(item => item.type === 'PLAN_VERSION_CREATED'), false);
});

test('tampered PlannerResponse breaks subsequent plan reads', async t => {
  const { service, store, task } = await configured(t);
  const planned = await service.plan(task.taskId);
  const bodyPath = path.join(store.root, 'tasks', task.taskId, 'planner-responses', planned.plan.plannerResponse.responseId, 'response.bin');
  fs.appendFileSync(bodyPath, 'tamper');
  await assert.rejects(store.getPlannerResponse(task.taskId, planned.plan.plannerResponse.responseId), { code: 'PLANNER_RESPONSE_CORRUPT' });
  await assert.rejects(service.observe(task.taskId), { code: 'PLANNER_RESPONSE_CORRUPT' });
});
