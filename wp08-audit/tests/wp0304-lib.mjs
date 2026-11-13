// Независимая аудиторская обвязка WP-08 / WP-03 + WP-04.
// Только чтение продуктового кода. Все временные каталоги — в %TEMP%.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

export const repoRoot = path.resolve(fileURLToPath(new URL('.', import.meta.url)), '..', '..');

export async function loadModules(dir = repoRoot) {
  const imp = rel => import(pathToFileURL(path.join(dir, rel)).href);
  const modules = {
    core: await imp('packages/core/canonical.mjs'),
    store: await imp('packages/core/store.mjs'),
    bundle: await imp('packages/core/bundle.mjs'),
    contracts: await imp('packages/contracts/index.mjs'),
    server: await imp('adapters/local/server.mjs'),
    localBundle: await imp('adapters/local/bundle.mjs'),
    identity: await imp('packages/trust/identity.mjs'),
    approval: await imp('packages/trust/approval.mjs'),
    environment: await imp('packages/trust/environment.mjs'),
    policy: await imp('packages/trust/policy.mjs'),
    anchorSigner: await imp('packages/trust/anchor-signer.mjs'),
    facts: await imp('packages/trust/facts.mjs'),
    sid: await imp('packages/trust/windows-sid.mjs'),
    trusted: await imp('apps/control/trusted.mjs'),
    run: await imp('apps/control/run.mjs')
  };
  modules.digest = modules.core.digest;
  return modules;
}

export const fixtureHtml = `<!doctype html><html lang="ru"><meta charset="utf-8"><title>QA Adaptant local fixture</title>
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

async function listen(server, port) {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return server.address().port;
}

export async function startRogue({ port, environmentId, fingerprint, attestation = null, sourceRevision = 'rogue-audit' }) {
  const state = { mutationCount: 0, attestCount: 0, requests: [], posts: [], getCount: 0 };
  const server = http.createServer((req, res) => {
    state.requests.push({ method: req.method, url: req.url });
    const send = (status, body) => {
      const bytes = Buffer.from(JSON.stringify(body));
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length, 'cache-control': 'no-store' });
      res.end(bytes);
    };
    if (req.method === 'GET' && req.url === '/environment') { send(200, { environmentId, fingerprint, sourceRevision }); return; }
    if (req.method === 'POST' && req.url === '/attest') {
      state.attestCount++;
      if (!attestation) { send(404, { error: 'no_key' }); return; }
      send(200, attestation); return;
    }
    if (req.method === 'POST' && req.url === '/records') {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        state.mutationCount++;
        state.posts.push({ headers: { ...req.headers }, body: Buffer.concat(chunks).toString('utf8') });
        send(201, { id: 'rogue-record', fixtureId: 'rogue' });
      });
      return;
    }
    send(404, { error: 'not_found' });
  });
  const actualPort = await listen(server, port);
  return {
    baseUrl: 'http://127.0.0.1:' + actualPort + '/', port: actualPort, state,
    close: () => new Promise(resolve => { try { server.closeAllConnections(); } catch { /* нет соединений */ } server.close(resolve); })
  };
}

// Управляемый стенд: тот же контракт, что adapters/local/server.mjs, плюс хуки аудитора.
export async function startControlledStand(modules, options = {}) {
  const {
    port = 0, environmentId = randomUUID(), generation = 1, fingerprint = 'audit-fingerprint',
    acceptAnyToken = false, afterAttest = null, afterPost = null, signAttest = true,
    storeRecords = 'full'
  } = options;
  const keys = modules.environment.createStandKeys();
  const authToken = randomUUID();
  const state = {
    attestCount: 0, postCount: 0, getRecordCount: 0, environmentCount: 0,
    attestAt: [], postAt: [], posts: [], attestRequests: [], records: [], notes: []
  };
  let origin = null;
  const stand = {
    environmentId, generation, fingerprint, fixtureId: 'fixture-unset', baseUrl: null,
    standKeyId: keys.standKeyId,
    standPublicKey: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    authToken, pid: process.pid, state, keys, modules,
    get attestCount() { return state.attestCount; },
    get mutationCount() { return state.postCount; }
  };
  const authorized = req => acceptAnyToken || req.headers.authorization === 'Bearer ' + authToken;
  const send = (res, status, body) => {
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length, 'cache-control': 'no-store' });
    res.end(bytes);
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
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
      if (!signAttest) { send(res, 404, { error: 'no_attest' }); return; }
      const attestation = modules.environment.signEnvironmentAttestation(keys.privateKey, {
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

export async function makeWorld(modules, options = {}) {
  const { generation = 1, recordOverrides = {}, standOptions = {}, withRecord = true, standalone, withSigner = true } = options;
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-wp08-'));
  const root = path.join(base, 'store');
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust');
  const created = await modules.identity.createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = modules.identity.loadTrustRoot(trustRoot);
  const ownerKey = await modules.identity.unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = standalone || await modules.server.serveLocalFixture({ generation, ...standOptions });
  const sid = modules.sid.currentUserSid();
  let record = null;
  if (withRecord) {
    record = modules.environment.signEnvironmentRecord(ownerKey, {
      environmentId: stand.environmentId,
      generation: stand.generation,
      kind: 'local-stand',
      status: 'active',
      origin: stand.baseUrl,
      standKeyId: stand.standKeyId,
      credentialRef: 'local:fixture-token',
      ...recordOverrides
    });
    modules.environment.commitEnvironmentRecord(trust, trustRoot, record);
  }
  let signer = null;
  if (withSigner) {
    signer = modules.anchorSigner.startAnchorSigner({ trustRoot, secretsDir });
    await signer.ready;
  }
  const signCard = card => modules.identity.signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', ...card, keyId: created.ownerKeyId, status: 'active'
  });
  const cards = {
    owner: signCard({ principalId: 'local-owner', roles: ['owner'], windowsSid: sid }),
    operator: signCard({ principalId: 'local-operator', roles: ['operator'], windowsSid: sid })
  };
  const world = {
    modules, base, root, secretsDir, trustRoot, trust, ownerKey, stand, record, sid, cards, created, signer, ownerKeyId: created.ownerKeyId,
    prepare({ runId, inputs, mutate } = {}) {
      const id = runId || 'wp08-' + randomUUID().slice(0, 8);
      const contract = modules.localBundle.localFixtureContract(stand, id);
      stand.fixtureId = contract.fixtureId;
      const bundle = modules.localBundle.localBundle(stand, { runId: id, inputs });
      bundle.fixture = contract;
      bundle.manifest.fixtureSha256 = modules.digest(contract);
      if (mutate) mutate({ bundle, contract });
      return { bundle, contract, runId: id };
    },
    approvalFor({ bundle, contract, overrides = {}, approvalId, inputs } = {}) {
      const id = approvalId || 'approval-' + randomUUID().slice(0, 8);
      const issuedAt = new Date().toISOString();
      const fields = {
        approvalId: id,
        issuerPrincipalId: 'local-owner',
        subjectPrincipalId: 'local-operator',
        operationId: bundle.operation.id,
        operationVersion: bundle.operation.version,
        scenarioContentSha256: bundle.scenario.approval.contentSha256,
        operationSha256: modules.digest(bundle.operation),
        approvedInputsHash: modules.digest(inputs || bundle.operation.inputs),
        fixtureId: contract.fixtureId,
        targetEnvironmentId: stand.environmentId,
        environmentGeneration: stand.generation,
        targetResource: { method: 'POST', path: '/records' },
        allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
        issuedAt,
        expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
        approvalNonce: 'ab'.repeat(32),
        keyId: created.ownerKeyId,
        ...overrides
      };
      return modules.approval.signApproval(ownerKey, fields, trust, trustRoot);
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
      try { fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* временный каталог */ }
    }
  };
  return world;
}

export function evidenceOf(modules, root, runId) {
  const store = new modules.store.RunStore(root);
  return store.readEvidence(store.runPath(runId));
}

export function exists(file) { return fs.existsSync(file); }
export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function listenRogue(options, attempts = 60) {
  let last = null;
  for (let i = 0; i < attempts; i++) {
    try { return await startRogue(options); } catch (error) { last = error; await sleep(100); }
  }
  throw last;
}
