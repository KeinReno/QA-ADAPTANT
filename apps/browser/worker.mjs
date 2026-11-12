import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { chromium } from 'playwright';
import { digest } from '../../packages/core/canonical.mjs';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';

const runDir = path.resolve(process.argv[2] || '');
const headed = process.env.QA_ADAPTANT_HEADED === '1';
const fault = process.env.QA_ADAPTANT_FAULT || '';
let runId, manifest, scenario, operation, fixture, page, intentAcked = false, intentId, mutationRequestSeen = false, controlLost = false, shuttingDown = false, injectedExit = 0;
function exitSoon(code) {
  if (injectedExit && code === 0) return;
  shuttingDown = true;
  const finalCode = injectedExit || code;
  setImmediate(() => {
    process.exitCode = finalCode;
    try { if (process.connected) process.disconnect(); } catch {}
  });
}
function sleepWhileConnected(ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(), ms);
    const poll = setInterval(() => {
      if (controlLost || !process.connected) finish(new Error('Control IPC отключён'));
    }, 40);
    function finish(error) {
      clearTimeout(timer);
      clearInterval(poll);
      if (error) reject(Object.assign(error, { code: 'WORKER_LOST' }));
      else resolve();
    }
  });
}
const ackWaiters = new Map();
const evidenceWaiters = new Map();
const requestIds = new WeakMap();
const pending = new Set();

function send(message) {
  return new Promise((resolve, reject) => {
    if (!process.connected) return reject(new Error('Control IPC отключён'));
    process.send(message, error => error ? reject(error) : resolve());
  });
}

function event(type, payload = {}) { return send({ type, runId, payload }); }

function waitAck(commandId, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { ackWaiters.delete(commandId); reject(new Error('ACK durable intent не получен')); }, timeoutMs);
    ackWaiters.set(commandId, ack => { clearTimeout(timer); resolve(ack); });
  });
}

function waitEvidenceAck(requestId, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { evidenceWaiters.delete(requestId); reject(new Error('Не получено durable подтверждение HTTP evidence')); }, timeoutMs);
    evidenceWaiters.set(requestId, message => { clearTimeout(timer); resolve(message); });
  });
}

process.on('message', message => {
  if (message?.type === 'ACK' && message.runId === runId) ackWaiters.get(message.commandId)?.(message);
  if (message?.type === 'EVIDENCE_ACK' && message.runId === runId) evidenceWaiters.get(message.requestId)?.(message);
});

function addPending(promise) {
  pending.add(promise);
  promise.catch(() => {}).finally(() => pending.delete(promise));
}

function safeFields(input) {
  const allowed = new Set([...Object.keys(operation.inputs), 'fixtureId']);
  return Object.fromEntries(Object.entries(input || {}).filter(([key, value]) => allowed.has(key) && ['string', 'number', 'boolean'].includes(typeof value)));
}

async function exactLocator(scope, role, name) {
  const locator = scope.getByRole(role, { name, exact: true });
  const count = await locator.count();
  if (count !== 1) throw Object.assign(new Error(`Цель элемента найдена ${count} раз; действие остановлено`), { code: 'ELEMENT_AMBIGUOUS' });
  return locator;
}

async function execute() {
  const store = new RunStore(path.dirname(path.dirname(runDir)));
  runId = store.readSnapshot(runDir, 'manifest').value.runId;
  const frozen = verifyFrozenBundle(store, runDir);
  if (!/^[a-f0-9]{64}$/.test(process.argv[3] || '') || frozen.manifestSha256 !== process.argv[3]) throw new Error('CONTRACT_INVALID: Browser получил другой manifest hash');
  manifest = frozen.manifest; scenario = frozen.scenario; operation = frozen.operation; fixture = frozen.fixture; runId = manifest.runId;
  const base = new URL(manifest.environment.baseUrl);
  await event('READY', { worker: 'browser' });
  const browser = await chromium.launch({ headless: !headed });
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    page = await context.newPage();
    page.setDefaultTimeout(10000);
    await context.routeWebSocket('**/*', ws => ws.close({ code: 1008, reason: 'WebSocket запрещён контрактом local 0.1' }));
    page.on('response', response => {
      const task = (async () => {
        const request = response.request();
        const url = new URL(response.url());
        if (request.method() !== 'POST' || url.pathname !== '/records') return;
        const requestId = requestIds.get(request);
        let body = {};
        try {
          body = await Promise.race([
            response.json(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('body-timeout')), 1500))
          ]);
        } catch { /* response evidence records status and absent identity */ }
        const entity = body?.id ? { kind: operation.entityKind, id: String(body.id) } : null;
        const evidenceAck = requestId ? waitEvidenceAck(requestId) : Promise.resolve();
        await event('HTTP_RESPONSE', { requestId: requestId || null, status: response.status(), responseFixtureId: typeof body?.fixtureId === 'string' ? body.fixtureId : null, entity });
        await evidenceAck;
        if (fault === 'crashControlAfterMutation') {
          injectedExit = 87;
          try { process.kill(process.ppid, 'SIGKILL'); } catch {}
          exitSoon(87);
          return;
        }
        if (fault === 'crashAfterMutation') { injectedExit = 86; exitSoon(86); return; }
      })();
      addPending(task);
    });
    page.on('requestfailed', request => {
      const url = new URL(request.url());
      if (request.method() === 'POST' && url.pathname === '/records') addPending(event('HTTP_FAILED', { reason: request.failure()?.errorText || 'request_failed' }));
    });
    await page.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin !== base.origin || url.protocol !== 'http:') return route.abort('blockedbyclient');
      if (request.method() === 'GET') return route.continue();
      if (request.method() !== 'POST' || url.pathname !== '/records') return route.abort('blockedbyclient');
      if (mutationRequestSeen) return route.abort('blockedbyclient');
      let body;
      try { body = request.postDataJSON(); } catch { return route.abort('blockedbyclient'); }
      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !Object.hasOwn(operation.inputs, key) && key !== 'fixtureId')) return route.abort('blockedbyclient');
      const fields = safeFields(body);
      if (fault === 'driftBody' && Object.hasOwn(fields, 'title')) fields.title = 'Несанкционированное значение';
      const expected = { ...operation.inputs, fixtureId: fixture.fixtureId };
      if (JSON.stringify(Object.entries(fields).sort()) !== JSON.stringify(Object.entries(expected).sort())) return route.abort('blockedbyclient');
      if (!intentAcked || !intentId || controlLost || !process.connected) return route.abort('blockedbyclient');
      mutationRequestSeen = true;
      const requestId = randomUUID();
      requestIds.set(request, requestId);
      const evidenceAck = waitEvidenceAck(requestId);
      await event('HTTP_REQUEST', { requestId, intentId, method: 'POST', path: '/records', fixtureId: fixture.fixtureId, fields, operationId: operation.id });
      await evidenceAck;
      if (controlLost || !process.connected) return route.abort('blockedbyclient');
      const headers = { ...request.headers() };
      if (process.env.QA_ADAPTANT_FIXTURE_TOKEN) headers.authorization = `Bearer ${process.env.QA_ADAPTANT_FIXTURE_TOKEN}`;
      headers['idempotency-key'] = intentId;
      return route.continue({ headers });
    });

    await event('STEP', { stepId: scenario.nodes[0].id, status: 'RUNNING' });
    for (const node of scenario.nodes) {
      const action = node.action;
      if (action.type === 'navigate') {
        await page.goto(new URL(action.path, base).href, { waitUntil: 'domcontentloaded', timeout: node.timeoutMs });
        await event('STEP', { stepId: node.id, status: 'PASS', url: new URL(page.url()).pathname });
      } else if (action.type === 'fill') {
        const form = await exactLocator(page, action.locator.containerRole, action.locator.containerName);
        const field = await exactLocator(form, action.locator.role, action.locator.name);
        await field.fill(action.value);
        await event('STEP', { stepId: node.id, status: 'PASS', action: 'fill' });
      } else if (action.type === 'click') {
        const form = await exactLocator(page, action.locator.containerRole, action.locator.containerName);
        const button = await exactLocator(form, action.locator.role, action.locator.name);
        if (fault === 'pauseBeforeIntent') await sleepWhileConnected(1500);
        if (controlLost || !process.connected) throw Object.assign(new Error('Control IPC отключён'), { code: 'WORKER_LOST' });
        const commandId = randomUUID();
        intentId = `${runId}:${node.id}`;
        await event('STEP', { stepId: node.id, status: 'INTENT_PENDING' });
        const ackPromise = waitAck(commandId, fault === 'dropIntentAck' ? 500 : 10000);
        const intentMessage = { type: 'INTENT', commandId, runId, payload: { intentId, stepId: node.id, operationId: operation.id, mutationName: operation.mutation.name, inputsSha256: digest(operation.inputs), fixtureId: fixture.fixtureId } };
        await send(intentMessage);
        if (fault === 'duplicateIntent') await send(intentMessage);
        const ack = await ackPromise;
        if (ack.durable !== true || ack.intentId !== intentId) throw new Error('ACK не подтверждает durable intent');
        intentAcked = true;
        await event('STEP', { stepId: node.id, status: 'DISPATCHED' });
        await button.click({ timeout: node.timeoutMs });
        await page.getByRole('status').waitFor({ state: 'visible', timeout: 2500 }).catch(() => {});
        await event('STEP', { stepId: node.id, status: 'ACTION_RETURNED' });
      } else if (action.type === 'verify') {
        await event('STEP', { stepId: node.id, status: 'DELEGATED_TO_VERIFIER' });
      }
    }
    await Promise.allSettled([...pending]);
    if (injectedExit) { exitSoon(injectedExit); return; }
    await event('DONE', { status: 'COMPLETED' });
  } finally {
    await browser.close().catch(() => {});
  }
}

process.on('disconnect', () => {
  if (shuttingDown) return;
  controlLost = true;
  const closing = page?.context().browser()?.close().catch(() => {});
  Promise.resolve(closing).finally(() => exitSoon(90));
});
try { await execute(); exitSoon(0); }
catch (error) {
  const code = error.code || (error.message?.startsWith('CONTRACT_INVALID') ? 'CONTRACT_INVALID' : (error.message?.startsWith('INTEGRITY_ERROR') ? 'INTEGRITY_ERROR' : 'BROWSER_ERROR'));
  try { await event('ERROR', { code, message: error.message }); } catch {}
  exitSoon(code === 'ELEMENT_AMBIGUOUS' ? 31 : 32);
}
