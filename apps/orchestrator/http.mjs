import http from 'node:http';

const UI = `<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KAIDEN QA ADAPTANT 0.3</title>
<style>
body{font:16px system-ui,sans-serif;max-width:900px;margin:32px auto;padding:0 18px;color:#202124;background:#f7f8fa}
main,section{background:white;border:1px solid #d8dde5;border-radius:10px;padding:18px;margin:14px 0}
textarea{width:100%;min-height:105px;box-sizing:border-box;font:inherit;padding:10px}button{padding:9px 14px;margin:6px 6px 0 0;cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f4f7;padding:12px;border-radius:6px}.tag{font-weight:700;color:#734c00}
</style>
<main><h1>KAIDEN QA ADAPTANT 0.3</h1>
<p>Поручение → план → подтверждение владельца → trusted run → независимый результат.</p>
<form id="create"><label for="request">Исходное поручение</label><textarea id="request" required maxlength="20000"></textarea><br><button>Создать Task и составить план</button></form>
<p id="message" role="status" aria-live="polite">Task ещё не создана.</p></main>
<section id="task-view" hidden><h2>Task</h2><pre id="task"></pre><h3>План</h3><pre id="plan"></pre>
<button id="approve" hidden>Подтвердить план</button><button id="start" hidden>Запустить trusted шаг</button><button id="cancel" hidden>Отменить</button>
<h3>Состояние, события и результат</h3><pre id="events"></pre></section>
<script>
const $=id=>document.getElementById(id), message=$('message');let currentId=null,currentPlan=null;
async function call(path,body){const r=await fetch(path,{method:body?'POST':'GET',headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const v=await r.json();if(!r.ok)throw new Error(v.message||v.code||'Запрос не выполнен');return v}
function show(v){currentId=v.task.taskId;currentPlan=v.plan||currentPlan;$('task-view').hidden=false;$('task').textContent=JSON.stringify(v.task,null,2);$('plan').textContent=currentPlan?JSON.stringify(currentPlan,null,2):'План не создан.';$('events').textContent=JSON.stringify(v.events||v.task.result||[],null,2);$('approve').hidden=v.task.status!=='AWAITING_APPROVAL';$('start').hidden=v.task.status!=='READY';$('cancel').hidden=['COMPLETED','FAILED','CANCELED','INCONCLUSIVE'].includes(v.task.status);const mode=currentPlan?.provider?.mode||'';message.textContent='Task: '+v.task.status+(mode?' · Planner: '+mode:'');}
$('create').addEventListener('submit',async e=>{e.preventDefault();try{message.textContent='Сохраняю поручение и составляю план…';const v=await call('/api/tasks',{originalRequest:$('request').value});show(v)}catch(e){message.textContent=e.message}});
$('approve').onclick=async()=>{try{message.textContent='Сохраняю подтверждение владельца…';show(await call('/api/tasks/'+currentId+'/approve',{planId:currentPlan.planId}))}catch(e){message.textContent=e.message}};
$('start').onclick=async()=>{try{message.textContent='Запускаю только утверждённый trusted шаг…';show(await call('/api/tasks/'+currentId+'/start',{}))}catch(e){message.textContent=e.message}};
$('cancel').onclick=async()=>{try{message.textContent='Отправляю отмену…';show(await call('/api/tasks/'+currentId+'/cancel',{}))}catch(e){message.textContent=e.message}};
</script></html>`;

const loopbackHosts = new Set(['127.0.0.1', '::1', 'localhost']);
function parseLoopbackAuthority(authority) {
  if (typeof authority !== 'string' || !authority || /[\s\\]/.test(authority)) return null;
  try {
    const url = new URL(`http://${authority}`);
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const port = url.port ? Number(url.port) : 80;
    return loopbackHosts.has(hostname) && Number.isInteger(port) ? { hostname, port } : null;
  } catch { return null; }
}

function requestSecurityFailure(request, server) {
  if (request.method === 'OPTIONS') return { status: 405, code: 'METHOD_NOT_ALLOWED' };
  const address = server.address();
  if (!address || typeof address === 'string') return { status: 503, code: 'SERVER_NOT_READY' };
  const target = parseLoopbackAuthority(request.headers.host);
  if (!target || target.port !== address.port) return { status: 403, code: 'HOST_REJECTED' };
  if (request.method === 'POST') {
    const origin = request.headers.origin;
    const parsedOrigin = typeof origin === 'string' && origin !== 'null' ? (() => {
      try {
        const url = new URL(origin);
        if (url.protocol !== 'http:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
        const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
        const port = url.port ? Number(url.port) : 80;
        return loopbackHosts.has(hostname) && Number.isInteger(port) ? { hostname, port } : null;
      } catch { return null; }
    })() : null;
    if (!parsedOrigin || parsedOrigin.hostname !== target.hostname || parsedOrigin.port !== target.port) return { status: 403, code: 'ORIGIN_REJECTED' };
    const contentType = request.headers['content-type'] || '';
    if (!/^application\/json(?:\s*;|$)/i.test(contentType)) return { status: 415, code: 'JSON_REQUIRED' };
  }
  return null;
}

export function loopbackBaseUrl(host) {
  if (!loopbackHosts.has(host)) throw new TypeError('Локальный UI разрешено привязывать только к loopback');
  const authorityHost = host.includes(':') ? `[${host}]` : host;
  return `http://${authorityHost}`;
}
const safeMessage = code => ({
  OWNER_MISMATCH: 'Действие доступно только владельцу Task.',
  OWNER_APPROVAL_UNAVAILABLE: 'Проверка подтверждения владельца не настроена.',
  TASK_NOT_READY: 'Task пока не готова к запуску.',
  INVALID_TASK_TRANSITION: 'Действие недоступно в текущем состоянии Task.',
  default: 'Запрос не завершён. Проверьте состояние Task и журнал.'
}[code] || 'Запрос не завершён. Проверьте состояние Task и журнал.');

function send(response, status, value, contentType = 'application/json; charset=utf-8') {
  response.writeHead(status, {
    'content-type': contentType,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    'x-frame-options': 'DENY'
  });
  response.end(contentType.startsWith('application/json') ? JSON.stringify(value) : value);
}

async function readJson(request, maxBytes) {
  const declared = Number(request.headers['content-length']);
  if (Number.isFinite(declared) && declared > maxBytes) throw Object.assign(new Error('REQUEST_TOO_LARGE'), { status: 413 });
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.byteLength;
    if (total > maxBytes) throw Object.assign(new Error('REQUEST_TOO_LARGE'), { status: 413 });
    chunks.push(chunk);
  }
  if (!total) return {};
  try { return JSON.parse(Buffer.concat(chunks, total).toString('utf8')); }
  catch { throw Object.assign(new Error('INVALID_JSON'), { status: 400 }); }
}

export function createOrchestratorServer({ service, authenticate, issuePlanApproval, environmentRef = null, host = '127.0.0.1', maxBodyBytes = 32768 } = {}) {
  if (!service) throw new TypeError('TaskService обязателен');
  if (typeof authenticate !== 'function') throw new TypeError('Нужна host-side аутентификация владельца');
  if (typeof issuePlanApproval !== 'function') throw new TypeError('Нужен host-side callback подтверждения плана владельцем');
  if (!loopbackHosts.has(host)) throw new TypeError('Локальный UI разрешено привязывать только к loopback');
  const server = http.createServer(async (request, response) => {
    let actorRef;
    try {
      const securityFailure = requestSecurityFailure(request, server);
      if (securityFailure) return send(response, securityFailure.status, { code: securityFailure.code, message: 'Запрос отклонён проверками локального origin и типа содержимого.' });
      actorRef = await authenticate(request);
      if (typeof actorRef !== 'string' || !actorRef) return send(response, 401, { code: 'UNAUTHENTICATED', message: 'Локальный пользователь не аутентифицирован.' });
      const url = new URL(request.url, loopbackBaseUrl(host));
      if (request.method === 'GET' && url.pathname === '/') return send(response, 200, UI, 'text/html; charset=utf-8');
      if (request.method === 'POST' && url.pathname === '/api/tasks') {
        const body = await readJson(request, maxBodyBytes);
        const created = await service.create({ originalRequest: body.originalRequest, ownerRef: actorRef, contextRefs: Array.isArray(body.contextRefs) ? body.contextRefs : [], environmentRef });
        return send(response, 201, await service.plan(created.taskId));
      }
      const match = /^\/api\/tasks\/(task-[A-Za-z0-9_-]{1,140})(?:\/(approve|start|cancel))?$/.exec(url.pathname);
      if (!match) return send(response, 404, { code: 'NOT_FOUND', message: 'Маршрут не найден.' });
      const [, taskId, action] = match;
      const current = await service.observe(taskId);
      if (current.task.ownerRef !== actorRef) return send(response, 404, { code: 'NOT_FOUND', message: 'Task не найдена.' });
      if (request.method === 'GET' && !action) return send(response, 200, current);
      if (request.method !== 'POST' || !action) return send(response, 405, { code: 'METHOD_NOT_ALLOWED', message: 'Метод не поддерживается.' });
      const body = await readJson(request, maxBodyBytes);
      if (action === 'approve') {
        if (typeof issuePlanApproval !== 'function') throw Object.assign(new Error('OWNER_APPROVAL_UNAVAILABLE'), { code: 'OWNER_APPROVAL_UNAVAILABLE' });
        const plan = await service.store.getPlan(taskId, body.planId);
        const approvalRef = await issuePlanApproval({ actorRef, task: current.task, plan });
        await service.approvePlan(taskId, { planId: plan.planId, actorRef, approvalRef });
      } else if (action === 'start') await service.start(taskId);
      else await service.cancel(taskId, actorRef);
      return send(response, 200, await service.observe(taskId));
    } catch (error) {
      const status = error.status || (error.code === 'OWNER_MISMATCH' ? 403 : error.code?.includes('NOT_FOUND') ? 404 : 400);
      const code = error.code || error.message || 'REQUEST_FAILED';
      return send(response, status, { code, message: safeMessage(code) });
    }
  });
  return server;
}

export async function listenOrchestrator(options = {}) {
  const server = createOrchestratorServer(options);
  const port = Number.isInteger(options.port) ? options.port : 4317;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, options.host || '127.0.0.1', resolve);
  });
  return server;
}
