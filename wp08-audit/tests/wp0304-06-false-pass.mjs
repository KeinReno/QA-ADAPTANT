// WP-08 (P0-гипотеза Lead): полный ЛОЖНЫЙ доверенный PASS через подмену среды после последней
// аттестации (T-C). Verification Worker не аттестует стенд: он читает публичные /environment и
// /records с Bearer. Сценарий A — подмена до независимых чтений Verification (детерминированно).
// Сценарий B — подмена в окне между beforeRequestAck и POST (точный сценарий Lead).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { loadModules, makeWorld, startControlledStand, sleep } from './wp0304-lib.mjs';

const modules = await loadModules();

async function listenWithRetry(server, port, deadlineMs = 400) {
  const started = Date.now();
  for (;;) {
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', () => resolve());
      });
      return server.address().port;
    } catch (error) {
      if (Date.now() - started > deadlineMs) throw error;
      await sleep(1);
    }
  }
}

// Rogue на том же origin: отдаёт /environment и /records. mode='static' — заранее известная запись,
// mode='learn' — запись строится из фактического POST, который rogue и получает.
async function startFabricatingRogue({ port, environmentId, fingerprint, mode, record = null }) {
  const state = { envGets: 0, recordGets: 0, posts: [], requests: [] };
  const built = { record };
  const send = (res, status, body) => {
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length, 'cache-control': 'no-store' });
    res.end(bytes);
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    state.requests.push({ at: Date.now(), method: req.method, path: url.pathname, authorization: req.headers.authorization || null });
    if (req.method === 'GET' && url.pathname === '/environment') { state.envGets++; send(res, 200, { environmentId, fingerprint, sourceRevision: 'rogue-fabricated' }); return; }
    if (req.method === 'GET' && url.pathname === '/records') { state.recordGets++; send(res, 200, { records: built.record ? [built.record] : [] }); return; }
    if (req.method === 'POST' && url.pathname === '/records') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString('utf8');
      let payload = null;
      try { payload = JSON.parse(raw); } catch { payload = {}; }
      if (mode === 'learn') {
        built.record = {
          id: 'rogue-' + Math.random().toString(16).slice(2), fixtureId: String(payload?.fixtureId || ''),
          title: String(payload?.title || ''), executorId: String(payload?.executorId || ''),
          comment: String(payload?.comment || ''), status: 'created'
        };
      }
      state.posts.push({ at: Date.now(), headers: { ...req.headers }, body: raw });
      send(res, 201, { id: built.record.id, fixtureId: built.record.fixtureId });
      return;
    }
    send(res, 404, { error: 'not_found' });
  });
  const actualPort = await listenWithRetry(server, port);
  return {
    port: actualPort, state, get record() { return built.record; },
    close: () => new Promise(resolve => { try { server.closeAllConnections(); } catch { /* нет */ } server.close(() => resolve()); })
  };
}

test('A: подмена стенда между POST и независимым чтением Verification даёт ложный доверенный PASS', async () => {
  let rogue = null;
  let triggered = false;
  let standRef = null;
  let fixtureIdRef = null;
  const stand = await startControlledStand(modules, {
    storeRecords: 'partial',
    afterPost: async ({ record }) => {
      // Реальный стенд сохранил НЕПОЛНУЮ запись (comment=null). Через 40 мс стенд умирает,
      // порт занимает rogue, который отдаёт Verification «полную» запись с тем же id.
      await sleep(40);
      if (triggered) return;
      triggered = true;
      await standRef.close();
      rogue = await startFabricatingRogue({
        port: standRef.port, environmentId: standRef.environmentId, fingerprint: standRef.fingerprint,
        mode: 'static', record: { ...record, fixtureId: fixtureIdRef }
      });
    }
  });
  standRef = stand;
  const world = await makeWorld(modules, { standalone: stand });
  try {
    const { bundle, contract } = world.prepare({ runId: 'wp08-lie-pass-a' });
    fixtureIdRef = contract.fixtureId;
    const approval = world.approvalFor({ bundle, contract });
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
    const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: 'wp08-lie-pass-a' });
    const actualState = stand.state.records[0] || null;
    const evidence = {
      scenario: 'A: swap after POST, before Verification independent reads',
      verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode,
      observedPassed: observed.passed, observedTrusted: observed.trusted,
      standMutationCount: stand.mutationCount,
      realStoredRecordComment: actualState ? actualState.comment : null,
      rogueTriggered: Boolean(rogue),
      rogueEnvironmentGets: rogue ? rogue.state.envGets : 0,
      rogueRecordGets: rogue ? rogue.state.recordGets : 0,
      roguePosts: rogue ? rogue.state.posts.length : 0
    };
    fs.writeFileSync(new URL('./false-pass-A.json', import.meta.url), JSON.stringify(evidence, null, 2));
    assert.equal(evidence.standMutationCount, 1);
    assert.equal(evidence.realStoredRecordComment, null, 'реальное состояние среды неполно (comment=null)');
    assert.ok(rogue && rogue.state.recordGets >= 1, 'Verification прочитал записи у rogue', JSON.stringify(evidence));
    assert.ok(rogue && rogue.state.envGets >= 1, 'Verification прочитал /environment у rogue');
    assert.equal(result.verdict.verdict, 'PASS', 'ложный PASS: ' + JSON.stringify(evidence));
    assert.equal(observed.passed, true);
    assert.equal(observed.trusted, true);
  } finally {
    if (rogue) await rogue.close();
    await world.cleanup();
  }
});

test('B: подмена в окне после beforeRequestAck (mutation уходит rogue) — попытка полного PASS', async () => {
  const attemptErrors = [];
  for (let attempt = 1; attempt <= 2; attempt++) {
    let rogue = null;
    let triggered = false;
    let standRef = null;
    let runDirRef = null;
    let swapAt = 0;
    let listenAt = 0;
    const stand = await startControlledStand(modules, {});
    standRef = stand;
    const world = await makeWorld(modules, { standalone: stand });
    try {
      const { bundle, contract } = world.prepare({ runId: 'wp08-lie-pass-b' + attempt });
      const approval = world.approvalFor({ bundle, contract });
      const store = new modules.store.RunStore(world.root);
      runDirRef = store.runPath(bundle.manifest.runId);
      const requestEvidence = path.join(runDirRef, 'evidence', '000002-request.json');
      // Наблюдатель за каталогом прогона (доступ того же SID): request-evidence появляется ПОСЛЕ T-C.
      const watcher = setInterval(async () => {
        if (triggered || !fs.existsSync(requestEvidence)) return;
        triggered = true;
        clearInterval(watcher);
        swapAt = Date.now();
        try {
          await standRef.close();
          rogue = await startFabricatingRogue({
            port: standRef.port, environmentId: standRef.environmentId, fingerprint: standRef.fingerprint, mode: 'learn'
          });
          listenAt = Date.now();
        } catch (error) {
          attemptErrors.push({ attempt, phase: 'swap', message: String(error.message || error) });
        }
      }, 1);
      let result = null;
      try { result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval)); }
      finally { clearInterval(watcher); }
      const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId }).catch(() => null);
      const evidence = {
        scenario: 'B: swap in window after beforeRequestAck before POST',
        attempt, triggered, swapAt, listenAt, swapToListenMs: listenAt ? listenAt - swapAt : null,
        verdict: result ? result.verdict.verdict : null,
        reasonCode: result ? result.verdict.reasonCode : null,
        message: result ? String(result.verdict.message).slice(0, 160) : null,
        observedPassed: observed ? observed.passed : null,
        standMutationCount: stand.mutationCount,
        roguePosts: rogue ? rogue.state.posts.length : 0,
        rogueRecordGets: rogue ? rogue.state.recordGets : 0,
        rogueEnvGets: rogue ? rogue.state.envGets : 0,
        bearerLeakedToRogue: Boolean(rogue && rogue.state.posts[0] && rogue.state.posts[0].headers.authorization),
        postTimeFromRequestEvidenceMs: rogue && rogue.state.posts[0] && swapAt ? rogue.state.posts[0].at - swapAt : null
      };
      fs.writeFileSync(new URL('./false-pass-B-attempt' + attempt + '.json', import.meta.url), JSON.stringify(evidence, null, 2));
      if (evidence.verdict === 'PASS' && evidence.standMutationCount === 0 && evidence.roguePosts === 1) {
        assert.equal(observed.passed, true);
        return;
      }
      attemptErrors.push({ attempt, phase: 'no-false-pass', evidence });
    } finally {
      if (rogue) await rogue.close();
      await world.cleanup();
    }
  }
  fs.writeFileSync(new URL('./false-pass-B-failures.json', import.meta.url), JSON.stringify(attemptErrors, null, 2));
  assert.fail('сценарий B не воспроизвёлся за 2 попытки: ' + JSON.stringify(attemptErrors).slice(0, 1200));
});
