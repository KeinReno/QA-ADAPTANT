// WP-08-REAUDIT — общая обвязка независимых атакующих сценариев.
//
// Назначение: переиспользуемые сценарии аудита в одном каталоге. Каждый сценарий запускается
// отдельным скриптом, принимает --target=<worktree> и заканчивается JSON-вердиктом:
//   PASS (exit 0)          — дефект на проверяемой ревизии не воспроизводится, защита сработала;
//   FAIL (exit 1)          — дефект воспроизводится (ложный PASS/обход/потеря результата);
//   INCONCLUSIVE (exit 3)  — прогон не доказателен (обвязка не совместима с ревизией, атака не выполнена).
// Правило: PASS не выставляется из exit code и не выставляется при непарсибельном/чужом JSON —
// это проверяет tests/audit-remediation/run-matrix.mjs.
//
// Продуктовый код проверяемой ветки не изменяется. Все временные каталоги — %TEMP%.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';

export const TOOL = 'WP08-REAUDIT';
export const HEREWORKTREE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

export function tempDir(prefix = 'wp08-reaudit-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function removeDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* временный каталог */ }
}

export function argValue(name, fallback = null) {
  const prefix = '--' + name + '=';
  const found = process.argv.slice(2).find(item => item.startsWith(prefix));
  return found ? found.slice(prefix.length) : fallback;
}

export function targetRoot() {
  const value = argValue('target');
  return path.resolve(value || HEREWORKTREE);
}

export function gitInfo(dir) {
  const result = { head: 'UNKNOWN', dirty: false, diffSha256: null };
  try {
    const head = spawnSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true });
    if (head.status === 0) result.head = head.stdout.trim();
    const status = spawnSync('git', ['-C', dir, 'status', '--porcelain', '--untracked-files=no'], { encoding: 'utf8', windowsHide: true });
    result.dirty = Boolean(status.stdout && status.stdout.trim());
    const diff = spawnSync('git', ['-C', dir, 'diff'], { encoding: 'utf8', windowsHide: true });
    result.diffSha256 = createHash('sha256').update(diff.stdout || '', 'utf8').digest('hex');
  } catch { /* git вне репозитория */ }
  return result;
}

// Загрузка модулей проверяемой ревизии по абсолютным URL. Необязательные модули
// (появляются в исправлениях) загружаются при наличии, отсутствие фиксируется в M.flags.
export async function loadModules(root) {
  if (!fs.existsSync(path.join(root, 'packages', 'trust', 'identity.mjs'))) {
    throw Object.assign(new Error('Каталог не похож на worktree QA ADAPTANT: ' + root), { code: 'TARGET_INVALID' });
  }
  const imp = rel => import(pathToFileURL(path.join(root, rel)).href);
  const optional = async rel => {
    if (!fs.existsSync(path.join(root, rel))) return null;
    try { return await imp(rel); } catch (error) { return { __importError: error }; }
  };
  const M = {
    root,
    canonical: await imp('packages/core/canonical.mjs'),
    store: await imp('packages/core/store.mjs'),
    bundleModule: await imp('packages/core/bundle.mjs'),
    evidencePolicy: await imp('packages/core/evidence-policy.mjs'),
    contracts: await imp('packages/contracts/index.mjs'),
    server: await imp('adapters/local/server.mjs'),
    localBundle: await imp('adapters/local/bundle.mjs'),
    identity: await imp('packages/trust/identity.mjs'),
    approval: await imp('packages/trust/approval.mjs'),
    environment: await imp('packages/trust/environment.mjs'),
    policy: await imp('packages/trust/policy.mjs'),
    anchor: await imp('packages/trust/anchor.mjs'),
    anchorSigner: await imp('packages/trust/anchor-signer.mjs'),
    facts: await imp('packages/trust/facts.mjs'),
    sidModule: await imp('packages/trust/windows-sid.mjs'),
    trusted: await imp('apps/control/trusted.mjs'),
    run: await imp('apps/control/run.mjs'),
    trustedWorker: await optional('apps/verification/trusted-worker.mjs'),
    keygen: await optional('packages/trust/keygen.mjs'),
    verificationWorker: await optional('apps/verification/worker.mjs'),
    browserWorker: await optional('apps/browser/worker.mjs'),
    flags: {}
  };
  M.flags = {
    trustedWorker: Boolean(M.trustedWorker),
    readSetAttestation: Boolean(M.trustedWorker),
    keygenCli: fs.existsSync(path.join(root, 'packages/trust/keygen.mjs'))
  };
  M.digest = value => M.canonical.digest(value);
  M.scenarioApprovalHash = value => M.canonical.scenarioApprovalHash(value);
  return M;
}

let cachedSid = null;
export function currentSid(M) {
  if (!cachedSid) cachedSid = M.sidModule.currentUserSid();
  return cachedSid;
}

// Проверка набора проверок сценария: required-проверки обязательны для PASS.
export function check(list, name, ok, detail = null) {
  list.push({ name, ok: Boolean(ok), ...(detail === null ? {} : { detail }) });
  return Boolean(ok);
}

// Единая точка выхода сценария. Возвращает объект для агрегатора и выставляет exit code.
export function emitScenario({ id, title, expected, defectObserved, actual, evidence, checks, extra = {} }) {
  const target = gitInfo(targetRoot());
  const requiredFailed = (checks || []).filter(item => item.ok !== true);
  let verdict;
  if (defectObserved) verdict = 'FAIL';
  else if (requiredFailed.length === 0) verdict = 'PASS';
  else verdict = 'INCONCLUSIVE';
  const summary = {
    tool: TOOL,
    scenario: id,
    title,
    target: { path: targetRoot(), head: target.head, dirty: target.dirty, diffSha256: target.diffSha256 },
    generatedAt: new Date().toISOString(),
    node: process.version,
    platform: process.platform,
    expected,
    actual,
    defect: defectObserved ? 'REPRODUCED' : (verdict === 'PASS' ? 'NOT_REPRODUCED' : 'UNPROVEN'),
    verdict,
    exitCode: verdict === 'PASS' ? 0 : verdict === 'FAIL' ? 1 : 3,
    checks: checks || [],
    evidence: evidence || null,
    ...extra
  };
  const text = JSON.stringify(summary, null, 2) + '\n';
  process.exitCode = summary.exitCode;
  // Явный выход после синхронной записи: детерминированный exit code и без хвостовых
  // эффектов импортированных модулей проверяемой ревизии.
  process.stdout.write(text, () => process.exit(summary.exitCode));
  return summary;
}

// Обёртка сценария: непойманная ошибка обвязки — INCONCLUSIVE, не PASS.
export async function runScenario({ id, title, expected, body }) {
  try {
    const outcome = await body();
    return emitScenario({ id, title, expected, ...outcome });
  } catch (error) {
    return emitScenario({
      id, title, expected,
      defectObserved: false,
      actual: 'сценарий не выполнен: ' + (error?.code || '') + ' ' + String(error?.message || error),
      checks: [{ name: 'обвязка сценария выполнена', ok: false, detail: String(error?.stack || error).slice(0, 1500) }],
      evidence: { error: { code: error?.code || null, message: String(error?.message || error) } }
    });
  }
}

// ---------------------------------------------------------------------------
// Управляемый стенд: контракт локального стенда + хуки аудитора (afterAttest/afterPost).
// Реализует /environment, /attest, GET/POST /records; ключ стенда создаётся модулями target.
export async function listen(server, port) {
  const started = Date.now();
  for (;;) {
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', () => resolve());
      });
      return server.address().port;
    } catch (error) {
      if (Date.now() - started > 600) throw error;
      await sleep(2);
    }
  }
}

export const fixtureHtml = String.raw`<!doctype html><html lang="ru"><meta charset="utf-8"><title>QA Adaptant local fixture</title>
<main><form aria-label="Создать запись">
<label>Название<input name="title" autocomplete="off"></label>
<label>Исполнитель<input name="executorId" autocomplete="off"></label>
<label>Комментарий<input name="comment" autocomplete="off"></label>
<label>Маркер fixture<input name="fixtureId" autocomplete="off"></label>
<button type="submit">Создать</button>
</form><p role="status" aria-live="polite"></p></main>
<script>
const form=document.querySelector('form');
form.addEventListener('submit',async event=>{
 event.preventDefault(); const fields=Object.fromEntries(new FormData(form).entries());
 const status=document.querySelector('[role=status]');
 try { const response=await fetch('/records',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(fields)});
  if(!response.ok) throw new Error('HTTP '+response.status); const data=await response.json(); status.textContent='Создана запись '+data.id;
 } catch { status.textContent='Ответ не получен; состояние требует сверки'; }
});
</script></html>`;

export async function startControlledStand(M, options = {}) {
  const {
    port = 0, environmentId = randomUUID(), generation = 1, fingerprint = 'audit-fingerprint-' + randomUUID().slice(0, 8),
    acceptAnyToken = false, afterAttest = null, afterPost = null, signAttest = true, storeRecords = 'full',
    rejectToken = false, replayAttestation = null
  } = options;
  const keys = M.environment.createStandKeys();
  const authToken = randomUUID();
  const state = {
    attestCount: 0, postCount: 0, getRecordCount: 0, environmentCount: 0,
    attestAt: [], postAt: [], posts: [], attestRequests: [], records: [], requests: [], notes: [], closed: false
  };
  let origin = null;
  const stand = {
    environmentId, generation, fingerprint, baseUrl: null, standKeyId: keys.standKeyId,
    standPublicKey: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    authToken, pid: process.pid, state, keys,
    get attestCount() { return state.attestCount; },
    get mutationCount() { return state.postCount; },
    get readCount() { return state.getRecordCount; }
  };
  const authorized = req => !rejectToken && (acceptAnyToken || req.headers.authorization === 'Bearer ' + authToken);
  const send = (res, status, body) => {
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length, 'cache-control': 'no-store' });
    res.end(bytes);
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    state.requests.push({ at: Date.now(), method: req.method, path: url.pathname, authorization: req.headers.authorization || null });
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(fixtureHtml);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/environment') {
      state.environmentCount++;
      send(res, 200, { environmentId, fingerprint, sourceRevision: 'audit-controlled-stand' });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/attest') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      let payload = null;
      try { payload = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* ниже отказ */ }
      if (!payload || typeof payload.challenge !== 'string') { send(res, 400, { error: 'challenge_required' }); return; }
      state.attestCount++;
      state.attestAt.push(Date.now());
      state.attestRequests.push({ at: Date.now(), challenge: payload.challenge });
      if (replayAttestation) { send(res, 200, { ...replayAttestation, challenge: payload.challenge }); return; }
      if (!signAttest) { send(res, 404, { error: 'no_attest' }); return; }
      const attestation = M.environment.signEnvironmentAttestation(keys.privateKey, {
        environmentId, generation, origin, pid: process.pid, challenge: payload.challenge
      });
      send(res, 200, attestation);
      if (afterAttest) setImmediate(() => { Promise.resolve(afterAttest({ n: state.attestCount, stand, server })).catch(() => { /* хук аудитора */ }); });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/records') {
      if (!authorized(req)) { send(res, 401, { error: 'unauthorized' }); return; }
      const fixtureId = url.searchParams.get('fixtureId');
      if (!fixtureId) { send(res, 400, { error: 'fixture_required' }); return; }
      state.getRecordCount++;
      send(res, 200, { records: state.records.filter(record => record.fixtureId === fixtureId).map(record => ({ ...record })) });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/records') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString('utf8');
      let payload = null;
      try { payload = JSON.parse(raw); } catch { send(res, 400, { error: 'invalid_json' }); return; }
      state.postCount++;
      state.postAt.push(Date.now());
      state.posts.push({ at: Date.now(), headers: { ...req.headers }, body: raw, authorized: authorized(req) });
      const record = { id: randomUUID(), fixtureId: String(payload?.fixtureId || ''), title: String(payload?.title || ''), executorId: String(payload?.executorId || ''), comment: String(payload?.comment || ''), status: 'created' };
      if (storeRecords === 'full') state.records.push(record);
      else if (storeRecords === 'partial') state.records.push({ ...record, comment: null });
      send(res, 201, { id: record.id, fixtureId: record.fixtureId });
      if (afterPost) setImmediate(() => { Promise.resolve(afterPost({ n: state.postCount, record, stand, server })).catch(() => { /* хук аудитора */ }); });
      return;
    }
    send(res, 404, { error: 'not_found' });
  });
  const actualPort = await listen(server, port);
  origin = 'http://127.0.0.1:' + actualPort + '/';
  stand.baseUrl = origin;
  stand.port = actualPort;
  stand.close = () => new Promise(resolve => {
    if (state.closed) { resolve(); return; }
    state.closed = true;
    try { server.closeAllConnections(); } catch { /* нет соединений */ }
    server.close(() => resolve());
  });
  return stand;
}

// Rogue-стенд на освободившемся порту.
// recordMode: 'static' — фиксированная запись; 'learn' — запись строится из фактического POST.
// attestMode: 'none' — /attest отвечает 404; 'replay' — воспроизводит захваченную подпись.
export async function startRogue({ port, environmentId, fingerprint, recordMode = 'static', record = null, attestMode = 'none', attestation = null }) {
  const state = { envGets: 0, recordGets: 0, attestGets: 0, posts: [], requests: [], closed: false, record };
  const send = (res, status, body) => {
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length, 'cache-control': 'no-store' });
    res.end(bytes);
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    state.requests.push({ at: Date.now(), method: req.method, path: url.pathname, authorization: req.headers.authorization || null });
    if (req.method === 'GET' && url.pathname === '/environment') {
      state.envGets++;
      send(res, 200, { environmentId, fingerprint, sourceRevision: 'rogue-fabricated' });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/attest') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      state.attestGets++;
      if (attestMode === 'replay' && attestation) {
        let payload = null;
        try { payload = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { payload = {}; }
        send(res, 200, { ...attestation, challenge: payload.challenge });
        return;
      }
      send(res, 404, { error: 'no_key' });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/records') {
      const fixtureId = url.searchParams.get('fixtureId');
      state.recordGets++;
      const matches = state.record ? [state.record] : [];
      send(res, 200, { records: matches.filter(item => !fixtureId || item.fixtureId === fixtureId) });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/records') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString('utf8');
      let payload = null;
      try { payload = JSON.parse(raw); } catch { payload = {}; }
      if (recordMode === 'learn') {
        state.record = {
          id: 'rogue-' + randomUUID().slice(0, 8), fixtureId: String(payload?.fixtureId || ''),
          title: String(payload?.title || ''), executorId: String(payload?.executorId || ''),
          comment: String(payload?.comment || ''), status: 'created'
        };
      }
      state.posts.push({ at: Date.now(), headers: { ...req.headers }, body: raw });
      send(res, 201, { id: state.record?.id || 'rogue-record', fixtureId: state.record?.fixtureId || String(payload?.fixtureId || '') });
      return;
    }
    send(res, 404, { error: 'not_found' });
  });
  const actualPort = await listen(server, port);
  return {
    port: actualPort, state,
    get record() { return state.record; },
    close: () => new Promise(resolve => {
      if (state.closed) { resolve(); return; }
      state.closed = true;
      try { server.closeAllConnections(); } catch { /* нет соединений */ }
      server.close(() => resolve());
    })
  };
}

// ---------------------------------------------------------------------------
// Мир доверенного прогона: trust root, запись среды, карточки принципалов, подписант.
export async function makeWorld(M, options = {}) {
  const { generation = 1, recordOverrides = {}, standOptions = {}, withRecord = true, standalone = null, withSigner = true } = options;
  const baseDir = tempDir('wp08-reaudit-world-');
  const root = path.join(baseDir, 'store');
  const secretsDir = path.join(baseDir, 'secrets');
  const trustRoot = path.join(baseDir, 'trust');
  const created = await M.identity.createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = M.identity.loadTrustRoot(trustRoot);
  const ownerKey = await M.identity.unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = standalone || await startControlledStand(M, { generation, ...standOptions });
  const sid = currentSid(M);
  let record = null;
  if (withRecord) {
    record = M.environment.signEnvironmentRecord(ownerKey, {
      environmentId: stand.environmentId,
      generation: stand.generation === undefined ? generation : stand.generation,
      kind: 'local-stand',
      status: 'active',
      origin: stand.baseUrl,
      standKeyId: stand.standKeyId,
      credentialRef: 'local:fixture-token',
      ...recordOverrides
    });
    M.environment.commitEnvironmentRecord(trust, trustRoot, record);
  }
  let signer = null;
  let signerError = null;
  if (withSigner) {
    try {
      signer = M.anchorSigner.startAnchorSigner({ trustRoot, secretsDir });
      await signer.ready;
    } catch (error) {
      signer = null;
      signerError = { code: error?.code || null, message: String(error?.message || error) };
    }
  }
  const signCard = card => M.identity.signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', ...card, keyId: created.ownerKeyId, status: 'active'
  });
  const cards = {
    owner: signCard({ principalId: 'local-owner', roles: ['owner'], windowsSid: sid }),
    operator: signCard({ principalId: 'local-operator', roles: ['operator'], windowsSid: sid })
  };
  const world = {
    baseDir, root, secretsDir, trustRoot, trust, ownerKey, stand, record, sid, cards, created, signer, signerError,
    ownerKeyId: created.ownerKeyId,
    prepare({ runId, inputs, mutate } = {}) {
      const id = runId || 'reaudit-' + randomUUID().slice(0, 8);
      const contract = M.localBundle.localFixtureContract(stand, id);
      stand.fixtureId = contract.fixtureId;
      const bundle = M.localBundle.localBundle(stand, { runId: id, inputs });
      bundle.fixture = contract;
      bundle.manifest.fixtureSha256 = M.digest(contract);
      if (mutate) mutate({ bundle, contract });
      return { bundle, contract, runId: id };
    },
    approvalFor({ bundle, contract, overrides = {}, approvalId, inputs } = {}) {
      const id = approvalId || 'approval-' + randomUUID().slice(0, 8);
      const issuedAt = new Date(Date.now() - 60000).toISOString();
      const fields = {
        approvalId: id,
        issuerPrincipalId: 'local-owner',
        subjectPrincipalId: 'local-operator',
        operationId: bundle.operation.id,
        operationVersion: bundle.operation.version,
        scenarioContentSha256: M.scenarioApprovalHash(bundle.scenario),
        operationSha256: M.digest(bundle.operation),
        approvedInputsHash: M.digest(inputs || bundle.operation.inputs),
        fixtureId: contract.fixtureId,
        targetEnvironmentId: stand.environmentId,
        environmentGeneration: stand.generation === undefined ? 1 : stand.generation,
        targetResource: { method: 'POST', path: '/records' },
        allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
        issuedAt,
        expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
        approvalNonce: 'ab'.repeat(32),
        keyId: created.ownerKeyId,
        ...overrides
      };
      return M.approval.signApproval(ownerKey, fields, trust, trustRoot);
    },
    expectedFor({ bundle, contract, inputs }) {
      return {
        operation: bundle.operation,
        inputs: inputs || bundle.operation.inputs,
        effects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
        scenarioContentSha256: M.scenarioApprovalHash(bundle.scenario),
        fixtureId: contract.fixtureId,
        environmentId: stand.environmentId,
        environmentGeneration: stand.generation === undefined ? 1 : stand.generation,
        resource: { method: 'POST', path: '/records' }
      };
    },
    trustedOptions(approval, extra = {}) {
      return {
        root, trustRoot, approvalId: approval.approvalId, approval,
        issuer: cards.owner, subject: cards.operator,
        signerPipe: signer ? signer.pipePath : null,
        standPublicKey: stand.standPublicKey, fixtureToken: stand.authToken,
        ...extra
      };
    },
    async cleanup() {
      try { if (signer) await signer.close(); } catch { /* канал уже закрыт */ }
      try { await stand.close(); } catch { /* стенд уже закрыт */ }
      removeDir(baseDir);
    }
  };
  return world;
}

// ---------------------------------------------------------------------------
// Подделка доверенного прогона: процесс того же SID, умеющий писать runDir и обращаться к
// подписанту, сам собирает цепочку evidence + PASS-candidate и просит настоящий анкер.
// mode: 'normal' — независимое чтение с совпадающими полями; 'parity-broken' — candidate PASS,
// но его checks не подтверждены независимым чтением (проверка паритета наблюдателя).
export function forgeRun(M, world, { runId, mode = 'normal', candidateVerdict = 'PASS', candidateChecks = null }) {
  const { bundle, contract } = world.prepare({ runId });
  const store = new M.store.RunStore(world.root);
  const runDir = store.snapshot(bundle, null);
  const frozen = M.bundleModule.verifyFrozenBundle(store, runDir);
  const operation = frozen.operation;
  const fixture = bundle.fixture;
  const mutationStep = 'create';
  const verifyStep = frozen.scenario.nodes.at(-1).id;
  let counter = 0;
  const nextId = prefix => prefix + '-' + String(++counter).padStart(4, '0');
  const requestId = nextId('req');
  const intent = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep,
    producer: 'control', kind: 'mutation-intent',
    artifact: {
      intentId: runId + ':' + mutationStep, stepId: mutationStep, operationId: operation.id,
      mutationName: operation.mutation.name, inputsSha256: M.digest(operation.inputs), fixtureId: fixture.fixtureId
    },
    parentEvidenceIds: []
  });
  const request = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep,
    producer: 'browser', kind: 'request', requestId,
    artifact: {
      requestId, intentId: runId + ':' + mutationStep, operationId: operation.id,
      method: 'POST', path: '/records', fixtureId: fixture.fixtureId,
      fields: { ...operation.inputs, fixtureId: fixture.fixtureId }
    },
    parentEvidenceIds: [intent.evidenceId]
  });
  const entity = { kind: 'local-record', id: nextId('record') };
  const response = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: mutationStep,
    producer: 'browser', kind: 'response', requestId, entity,
    artifact: {
      requestId, intentId: runId + ':' + mutationStep, operationId: operation.id, fixtureId: fixture.fixtureId,
      status: 201, entity
    },
    parentEvidenceIds: [request.evidenceId]
  });
  // Подложное независимое чтение: реального GET не было.
  const readFields = mode === 'parity-broken'
    ? { ...operation.inputs, comment: 'подмена поля', fixtureId: fixture.fixtureId }
    : { ...operation.inputs, fixtureId: fixture.fixtureId };
  const read = store.appendEvidence(runDir, {
    runId, manifestSha256: frozen.manifestSha256, fixtureId: fixture.fixtureId, stepId: verifyStep,
    producer: 'verification', kind: 'independent-read', requestId, entity,
    checkIds: operation.effects.map(effect => effect.id),
    artifact: {
      method: 'GET', path: '/records', fixtureId: fixture.fixtureId, entity, fields: readFields,
      environmentFingerprint: frozen.manifest.environment.fingerprint, requestId,
      httpStatus: 200, observedAt: new Date().toISOString()
    },
    parentEvidenceIds: [response.evidenceId]
  });
  const checks = candidateChecks || operation.effects.map(effect => ({
    id: effect.id, status: 'SATISFIED', evidenceIds: [read.evidenceId]
  }));
  const candidate = M.anchor.buildCandidate({
    frozen, verdict: candidateVerdict,
    reasonCode: candidateVerdict === 'PASS' ? 'NONE' : 'EVIDENCE_MISSING',
    message: 'Подложный candidate, собранный процессом того же SID',
    checks,
    ownershipVerified: candidateVerdict === 'PASS',
    integrityVerified: true
  });
  const published = M.anchor.publishCandidate(runDir, candidate);
  return { bundle, contract, store, runDir, frozen, operation, fixture, requestId, entity, evidence: { intent, request, response, read }, candidate, published };
}

// Подпись анкера настоящим публичным каналом подписанта (атакующий путь AUD-P0-01).
export async function signViaSignerClients(M, world, { runDir, approvalId, anchorId }) {
  if (!world.signer) return { ok: false, error: { code: world.signerError?.code || 'ANCHOR_UNAVAILABLE', message: world.signerError?.message || 'подписант недоступен' } };
  const client = M.anchorSigner.connectAnchorSigner(world.signer.pipePath);
  try {
    const statement = await client.sign({ runDir, approvalId, anchorId });
    return { ok: true, statement };
  } catch (error) {
    return { ok: false, error: { code: error?.code || null, message: String(error?.message || error) } };
  } finally {
    try { await client.close(); } catch { /* канал уже закрыт */ }
  }
}

// Прямая подпись анкера ключом анкера, которым владеет обвязка аудита (владелец trust root).
// Нужна для проверки наблюдателя/восстановления, когда атакующий публичный путь подписанта закрыт.
export async function signAnchorDirect(M, world, { runDir, approvalId, anchorId }) {
  const anchorKey = await M.identity.unwrapPrivateKey(path.join(world.secretsDir, 'anchor.key'));
  const binding = M.anchor.inspectEvidenceBinding({ trust: world.trust, trustRoot: world.trustRoot, runDir, approvalId, mode: 'pre-verdict' });
  const chosen = M.anchor.readCandidateBody(runDir, binding.candidate.candidateSha256);
  const body = {
    schemaVersion: '0.2.0',
    domain: 'anchor-statement',
    anchorId,
    runId: binding.frozen.manifest.runId,
    manifestSha256: binding.frozen.manifestSha256,
    chainHead: binding.chainHead,
    candidateSha256: binding.candidate.candidateSha256,
    verdict: chosen.candidate.verdict,
    reasonCode: chosen.candidate.reasonCode,
    approvalId: binding.approval.approvalId,
    inputsHash: binding.approval.approvedInputsHash,
    environmentId: binding.approval.targetEnvironmentId,
    environmentGeneration: binding.approval.environmentGeneration,
    publishedAt: new Date().toISOString(),
    keyId: world.trust['anchor-signer'].keyId
  };
  const statement = M.identity.signTrustedDocument(anchorKey, body);
  const dir = path.join(world.trustRoot, 'anchors');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, anchorId + '.json'), JSON.stringify(statement) + '\n', { flag: 'wx' });
  return { ok: true, statement, binding };
}

// Проверка паритета наблюдателя с 0.1: то, что обязан уметь старый путь.
export function canonicalParity(M, { runDir, frozen, store }) {
  const result = { evidenceRefs: null, terminal: null, coverage: null, error: null, verdict: null };
  try {
    const items = store.readEvidence(runDir);
    const body = items.filter(item => item.envelope.kind !== 'verdict');
    M.evidencePolicy.assertEvidenceRefs(body, frozen);
    result.evidenceRefs = 'ok';
    const reads = body.filter(item => item.envelope.kind === 'independent-read');
    const verdictItem = items.find(item => item.envelope.kind === 'verdict');
    if (verdictItem) {
      M.contracts.validateVerdictCoverage(verdictItem.artifact, frozen.operation, reads);
      result.coverage = 'ok';
      result.verdict = M.evidencePolicy.assertTerminalEvidence(items, frozen);
      result.terminal = 'ok';
    } else {
      result.terminal = 'no-verdict';
    }
  } catch (error) {
    result.error = String(error?.message || error);
  }
  return result;
}

// Публичные точки наблюдения, общие для сценариев.
export async function observeAll(M, world, runId) {
  const store = new M.store.RunStore(world.root);
  const runDir = store.runPath(runId);
  let frozen = null;
  try { frozen = M.bundleModule.verifyFrozenBundle(store, runDir); } catch { frozen = null; }
  let trustedObserver = null;
  try {
    trustedObserver = M.anchor.observeTrustedVerdict({ store, runDir, frozen, trust: world.trust, trustRoot: world.trustRoot });
  } catch (error) {
    trustedObserver = { error: { code: error?.code || null, message: String(error?.message || error) } };
  }
  let publicTrusted = null;
  try {
    publicTrusted = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId });
  } catch (error) {
    publicTrusted = { error: { code: error?.code || null, message: String(error?.message || error) } };
  }
  let oldObserve = null;
  try {
    const observed = await M.run.observe({ root: world.root, runId });
    oldObserve = observed.verdict ? { verdict: observed.verdict.verdict, reasonCode: observed.verdict.reasonCode } : null;
  } catch (error) {
    oldObserve = { error: String(error?.message || error) };
  }
  const parity = frozen ? canonicalParity(M, { runDir, frozen, store }) : { error: 'bundle unreadable' };
  return { store, runDir, frozen, trustedObserver, publicTrusted, oldObserve, parity };
}

export function evidenceKinds(store, runDir) {
  try { return store.readEvidence(runDir).map(item => item.envelope.kind); } catch { return ['UNREADABLE']; }
}

export function fileExists(file) {
  try { return fs.existsSync(file); } catch { return false; }
}

export function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

export function spawnNode(script, args, options = {}) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [script, ...args], { cwd: options.cwd || HEREWORKTREE, windowsHide: true, stdio: options.stdio || ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    if (child.stdout) child.stdout.on('data', chunk => out.push(chunk));
    if (child.stderr) child.stderr.on('data', chunk => err.push(chunk));
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* уже мёртв */ } }, options.timeoutMs || 180000);
    child.on('error', error => { clearTimeout(timer); resolve({ code: -1, stdout: '', stderr: String(error.message) }); });
    child.on('exit', code => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }); });
  });
}
