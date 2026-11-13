import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { chromium } from 'playwright';
import { createOrchestratorServer, listenOrchestrator, loopbackBaseUrl } from '../apps/orchestrator/http.mjs';
import { approvedLocalTask } from './adaptant03-e2e-support.mjs';

function sendHttp(server, { method = 'GET', path = '/', headers = {}, body = '' } = {}) {
  const address = server.address();
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port: address.port, method, path, headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('error', reject);
    request.end(body);
  });
}

test('local browser UI creates, approves, starts, and observes one trusted Task', { timeout: 150000 }, async t => {
  const { world, service } = await approvedLocalTask(t);
  const server = await listenOrchestrator({
    service,
    host: '127.0.0.1',
    port: 0,
    authenticate: async () => 'local-owner',
    issuePlanApproval: async ({ plan }) => `owner-plan:${plan.sha256}`,
    environmentRef: world.stand.environmentId
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const address = server.address();
  const browser = await chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${address.port}/`);
  await page.locator('#request').fill('Проверь локальный trusted сценарий создания записи с точными значениями.');
  await page.getByRole('button', { name: 'Создать Task и составить план' }).click();
  await page.getByRole('status').filter({ hasText: 'AWAITING_APPROVAL' }).waitFor({ timeout: 30000 });
  await page.getByRole('button', { name: 'Подтвердить план' }).click();
  await page.getByRole('status').filter({ hasText: 'READY' }).waitFor({ timeout: 15000 });
  await page.getByRole('button', { name: 'Запустить trusted шаг' }).click();
  await page.getByRole('status').filter({ hasText: 'COMPLETED' }).waitFor({ timeout: 30000 });
  assert.match(await page.locator('#task').textContent(), /COMPLETED/);
  assert.match(await page.locator('#events').textContent(), /PASS/);
  assert.match(await page.locator('#plan').textContent(), /MOCK/);
  assert.equal(world.stand.mutationCount, 1);
});

test('IPv6 loopback URL authority is bracketed and non-loopback hosts are rejected', () => {
  assert.equal(loopbackBaseUrl('::1'), 'http://[::1]');
  assert.equal(loopbackBaseUrl('127.0.0.1'), 'http://127.0.0.1');
  assert.throws(() => loopbackBaseUrl('0.0.0.0'), /loopback/);
});

test('loopback HTTP rejects hostile Host, Origin, missing Origin, simple content types, and OPTIONS before service access', { timeout: 30000 }, async t => {
  const calls = { authenticate: 0, create: 0, plan: 0, observe: 0, approve: 0, start: 0, cancel: 0 };
  const service = Object.fromEntries(['create', 'plan', 'observe', 'approvePlan', 'start', 'cancel'].map(name => [name, async () => { calls[name === 'approvePlan' ? 'approve' : name]++; throw new Error('service must not be called'); }]));
  let authenticated = true;
  const server = await listenOrchestrator({ service, host: '127.0.0.1', port: 0, authenticate: async () => { calls.authenticate++; return authenticated ? 'owner' : null; }, issuePlanApproval: async () => null });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const port = server.address().port;
  const host = `127.0.0.1:${port}`;
  const origin = `http://${host}`;
  const postHeaders = { host, origin, 'content-type': 'application/json' };

  const normalizedLocalhost = await sendHttp(server, { path: '/', headers: { host: `localhost:${port}` } });
  assert.equal(normalizedLocalhost.status, 200);
  assert.match(normalizedLocalhost.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(normalizedLocalhost.headers['x-frame-options'], 'DENY');
  const normalizedIpv6 = await sendHttp(server, { path: '/', headers: { host: `[::1]:${port}` } });
  assert.equal(normalizedIpv6.status, 200);

  const hostileHost = await sendHttp(server, { method: 'POST', path: '/api/tasks', headers: { ...postHeaders, host: `example.invalid:${port}` }, body: '{}' });
  assert.equal(hostileHost.status, 403);
  assert.equal(JSON.parse(hostileHost.body).code, 'HOST_REJECTED');
  const hostileOrigin = await sendHttp(server, { method: 'POST', path: '/api/tasks', headers: { ...postHeaders, origin: `http://example.invalid:${port}` }, body: '{}' });
  assert.equal(hostileOrigin.status, 403);
  assert.equal(JSON.parse(hostileOrigin.body).code, 'ORIGIN_REJECTED');
  const alternateLoopbackOrigin = await sendHttp(server, { method: 'POST', path: '/api/tasks', headers: { ...postHeaders, origin: `http://localhost:${port}` }, body: '{}' });
  assert.equal(alternateLoopbackOrigin.status, 403);
  assert.equal(JSON.parse(alternateLoopbackOrigin.body).code, 'ORIGIN_REJECTED');
  const missingOrigin = await sendHttp(server, { method: 'POST', path: '/api/tasks', headers: { host, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(missingOrigin.status, 403);
  assert.equal(JSON.parse(missingOrigin.body).code, 'ORIGIN_REJECTED');
  const wrongPort = await sendHttp(server, { method: 'GET', path: '/', headers: { host: `localhost:${port + 1}` } });
  assert.equal(wrongPort.status, 403);
  assert.equal(JSON.parse(wrongPort.body).code, 'HOST_REJECTED');
  const simplePost = await sendHttp(server, { method: 'POST', path: '/api/tasks', headers: { ...postHeaders, 'content-type': 'text/plain' }, body: '{"originalRequest":"x"}' });
  assert.equal(simplePost.status, 415);
  assert.equal(JSON.parse(simplePost.body).code, 'JSON_REQUIRED');
  const preflight = await sendHttp(server, { method: 'OPTIONS', path: '/api/tasks', headers: { host, origin } });
  assert.equal(preflight.status, 405);
  assert.equal(preflight.headers['access-control-allow-origin'], undefined);
  assert.equal(preflight.headers['access-control-allow-methods'], undefined);
  assert.equal(calls.authenticate, 2);
  assert.equal(calls.create + calls.plan + calls.observe + calls.approve + calls.start + calls.cancel, 0);

  authenticated = false;
  const unauthenticated = await sendHttp(server, { method: 'GET', path: '/', headers: { host } });
  assert.equal(unauthenticated.status, 401);
  assert.equal(unauthenticated.headers['access-control-allow-origin'], undefined);
  assert.equal(calls.authenticate, 3);
});

test('owner scoping hides foreign Tasks; HTTP cannot approve without a host grant or start before READY', { timeout: 150000 }, async t => {
  const { service, store } = await approvedLocalTask(t);
  const foreignTask = await service.create({ originalRequest: 'Задача без подтверждения', ownerRef: 'another-owner' });
  await service.plan(foreignTask.taskId);
  let actorRef = 'local-owner';
  assert.throws(() => createOrchestratorServer({ service, host: '127.0.0.1', authenticate: async () => actorRef }), /подтверждения плана владельцем/);
  let approvalCallbackCalls = 0;
  const server = await listenOrchestrator({ service, host: '127.0.0.1', port: 0, authenticate: async () => actorRef,
    issuePlanApproval: async () => { approvalCallbackCalls++; return null; } });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const port = server.address().port;
  const host = `127.0.0.1:${port}`;
  const origin = `http://${host}`;
  const jsonHeaders = { host, origin, 'content-type': 'application/json' };

  const hidden = await sendHttp(server, { path: `/api/tasks/${foreignTask.taskId}`, headers: { host } });
  assert.equal(hidden.status, 404);
  actorRef = 'another-owner';
  const beforeApprove = await store.getTask(foreignTask.taskId);
  const approval = await sendHttp(server, { method: 'POST', path: `/api/tasks/${foreignTask.taskId}/approve`, headers: jsonHeaders, body: JSON.stringify({ planId: (await store.getTask(foreignTask.taskId)).executionPlanId }) });
  assert.equal(approval.status, 400);
  assert.equal(JSON.parse(approval.body).code, 'OWNER_APPROVAL_INVALID');
  assert.equal(approvalCallbackCalls, 1);
  assert.equal((await store.getTask(foreignTask.taskId)).status, beforeApprove.status);
  const start = await sendHttp(server, { method: 'POST', path: `/api/tasks/${foreignTask.taskId}/start`, headers: jsonHeaders, body: '{}' });
  assert.equal(start.status, 400);
  assert.equal(JSON.parse(start.body).code, 'TASK_NOT_READY');
  assert.deepEqual((await store.getTask(foreignTask.taskId)).runIds, []);
  assert.equal((await store.getEvents(foreignTask.taskId)).some(event => event.type === 'DISPATCH_INTENT'), false);

  const normalizedHost = await sendHttp(server, { path: '/', headers: { host: `localhost:${port}` } });
  assert.equal(normalizedHost.status, 200);
  assert.equal(normalizedHost.headers['access-control-allow-origin'], undefined);
});
