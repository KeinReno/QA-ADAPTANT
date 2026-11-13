// WP-08 AUD-P0-02: аутентифицированный канал стенда и самопроверка среды Verification.
//
// Регрессии обязательны и должны падать, если дефект вернётся:
//   - подпись ответа stand-response проверяется ключом из доверенной регистрации;
//   - rogue-процесс на том же порту (после POST) не может подписать ответ → отказ, не PASS;
//   - подмена стенда между чтениями → ENVIRONMENT_ATTESTATION_FAILED (→ ENVIRONMENT_CHANGED/INCONCLUSIVE);
//   - replay подписи на другой challenge → отказ;
//   - старый путь 0.1 (GET /environment, POST/GET без заголовка challenge) не изменён.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import pathModule from 'node:path';
import { fork } from 'node:child_process';
import { digest } from '../packages/core/canonical.mjs';
import {
  attestPinnedConnection, attestationVerifiedReads, commitEnvironmentRecord, createStandKeys, newChallenge,
  openPinnedStandConnection, readStandResponseSignature, signEnvironmentRecord, verifyStandResponse,
  STAND_CHALLENGE_HEADER, STAND_RESPONSE_HEADER
} from '../packages/trust/environment.mjs';
import { createTrustRoot, loadTrustRoot, unwrapPrivateKey } from '../packages/trust/identity.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';
import { localBundle, localFixtureContract } from './helpers.mjs';
import { RunStore } from '../packages/core/store.mjs';
import { verifyFrozenBundle } from '../packages/core/bundle.mjs';

const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-signed-env-'));
const secretsDir = path.join(workspace, 'secrets');
const trustRoot = path.join(workspace, 'trust-root');
await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));

let environmentCounter = 0;
function nextEnvironmentId() {
  environmentCounter += 1;
  return 'signed-env-' + environmentCounter;
}

function registerStand(fixture, overrides = {}) {
  const record = signEnvironmentRecord(ownerKey, {
    environmentId: overrides.environmentId || fixture.environmentId,
    generation: overrides.generation === undefined ? fixture.generation : overrides.generation,
    kind: 'local-stand',
    status: 'active',
    origin: overrides.origin || fixture.baseUrl,
    standKeyId: overrides.standKeyId || fixture.standKeyId,
    credentialRef: 'local:test'
  });
  commitEnvironmentRecord(trust, trustRoot, record);
  return record;
}

function codeIs(code) {
  return error => {
    assert.equal(error.code, code, 'ожидался код ' + code + ', получено ' + (error.code || error) + ': ' + error.message + '\n' + (error.stack || ''));
    return true;
  };
}

async function expectThrow(fn, code) {
  await assert.rejects(async () => fn(), codeIs(code));
}

function codeIn(codes) {
  return error => {
    assert.ok(codes.includes(error.code), 'ожидался один из кодов ' + codes.join('/') + ', получено ' + (error.code || error) + ': ' + error.message);
    return true;
  };
}

function bearer(fixture) {
  return { authorization: 'Bearer ' + fixture.authToken };
}

function recordBody(fixture, overrides = {}) {
  return {
    fixtureId: overrides.fixtureId || 'fixture-signed-' + fixture.environmentId,
    title: overrides.title || 'Запись проверки',
    executorId: overrides.executorId || 'operator-local',
    comment: overrides.comment === undefined ? 'Комментарий' : overrides.comment,
    ...overrides
  };
}

async function postRecord(fixture, body, headers = {}) {
  return fetch(new URL('/records', fixture.baseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...bearer(fixture), ...headers },
    body: JSON.stringify(body),
    redirect: 'error'
  });
}

async function readJson(response) {
  const text = await response.text();
  let body = null;
  try { body = JSON.parse(text); } catch { body = null; }
  return { status: response.status, body, text, headers: response.headers, statement: signatureOrNull(response.headers) };
}

function signatureOrNull(headers) {
  try { return readStandResponseSignature(headers); } catch { return null; }
}

async function signedGet(fixture, pathname, challenge, headers = {}) {
  const response = await fetch(new URL(pathname, fixture.baseUrl), {
    headers: { ...bearer(fixture), ...headers, [STAND_CHALLENGE_HEADER]: challenge },
    redirect: 'error'
  });
  return readJson(response);
}

async function seedRecord(fixture, body = recordBody(fixture)) {
  const response = await postRecord(fixture, body);
  assert.equal(response.status, 201, 'запись должна быть создана');
  const parsed = await response.json();
  return { body, id: parsed.id, record: { ...body, id: parsed.id, status: 'created' } };
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function listenWithRetry(server, port, deadlineMs = 1500) {
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
      await new Promise(resolve => setTimeout(resolve, 5));
    }
  }
}

// Rogue-процесс на том же origin: отдаёт правдоподобные /environment и /records, но не имеет
// приватного ключа стенда, поэтому не может подписать ответ. /attest отсутствует.
async function startRogue({ port, environmentId, fingerprint, record = null }) {
  const state = { environmentGets: 0, recordGets: 0, posts: 0, requests: [] };
  const send = (res, status, body) => {
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length, 'cache-control': 'no-store' });
    res.end(bytes);
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    state.requests.push({ method: req.method, path: url.pathname, challenge: req.headers[STAND_CHALLENGE_HEADER] || null });
    if (req.method === 'GET' && url.pathname === '/environment') {
      state.environmentGets += 1;
      send(res, 200, { environmentId, fingerprint, sourceRevision: 'rogue-fabricated' });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/records') {
      state.recordGets += 1;
      send(res, 200, { records: record ? [record] : [] });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/records') { state.posts += 1; send(res, 201, { id: 'rogue-id', fixtureId: 'rogue' }); return; }
    send(res, 404, { error: 'not_found' });
  });
  const actualPort = await listenWithRetry(server, port);
  return {
    port: actualPort,
    origin: 'http://127.0.0.1:' + actualPort + '/',
    state,
    close: () => new Promise(resolve => { try { server.closeAllConnections(); } catch { /* нет */ } server.close(() => resolve()); })
  };
}

// --- 1. Подпись ответа GET /records и её проверка -------------------------------------------
test('GET /records с challenge подписан доменом stand-response и проверяется ключом регистрации', async t => {
  const fixture = await serveLocalFixture({ generation: 2 });
  t.after(() => fixture.close());
  const record = registerStand(fixture);
  const seed = await seedRecord(fixture);
  const challenge = newChallenge();
  const response = await signedGet(fixture, '/records?fixtureId=' + encodeURIComponent(seed.body.fixtureId), challenge);

  assert.equal(response.status, 200);
  assert.deepEqual(response.body.records.map(item => item.id), [seed.id], 'тело ответа не изменилось');
  const statement = response.statement;
  assert.ok(statement, 'ответ обязан нести ' + STAND_RESPONSE_HEADER);
  assert.equal(statement.schemaVersion, '0.2.1');
  assert.equal(statement.domain, 'stand-response');
  assert.equal(statement.environmentId, record.environmentId);
  assert.equal(statement.generation, 2);
  assert.equal(statement.origin, fixture.baseUrl);
  assert.equal(statement.standKeyId, fixture.standKeyId);
  assert.equal(statement.challenge, challenge);
  assert.equal(statement.method, 'GET');
  assert.equal(statement.path, '/records');
  assert.equal(statement.status, 200);
  assert.equal(statement.pid, fixture.pid);
  assert.equal(statement.keyId, fixture.standKeyId);
  assert.equal(statement.signatureAlgorithm, 'Ed25519');
  assert.equal(statement.bodySha256, digest(response.body));
  assert.equal(typeof statement.issuedAt, 'string');

  const verified = verifyStandResponse({
    trust, record, challenge, body: response.body, signature: statement,
    method: 'GET', path: '/records', status: 200, pid: fixture.pid, standPublicKey: fixture.standPublicKey
  });
  assert.equal(verified.bodySha256, statement.bodySha256);
  assert.equal(verified.domain, 'stand-response');

  // Сырые байты тела дают тот же результат, что и разобранный объект.
  const fromBytes = verifyStandResponse({
    trust, record, challenge, responseBytes: response.text, signature: statement,
    method: 'GET', path: '/records', status: 200, standPublicKey: fixture.standPublicKey
  });
  assert.equal(fromBytes.bodySha256, statement.bodySha256);
});

// --- 2. Подпись ответа POST /records --------------------------------------------------------
test('POST /records с challenge подписан; status/bodySha256 связывают фактический ответ мутации', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const record = registerStand(fixture);
  const payload = recordBody(fixture);
  const challenge = newChallenge();
  const response = await postRecord(fixture, payload, { [STAND_CHALLENGE_HEADER]: challenge });
  const parsed = await readJson(response);

  assert.equal(parsed.status, 201);
  assert.deepEqual(Object.keys(parsed.body).sort(), ['fixtureId', 'id'], 'схема тела POST 0.1 не изменилась');
  const statement = parsed.statement;
  assert.ok(statement, 'ответ POST обязан быть подписан при challenge');
  assert.equal(statement.method, 'POST');
  assert.equal(statement.path, '/records');
  assert.equal(statement.status, 201);
  assert.equal(statement.bodySha256, digest(parsed.body));
  const verified = verifyStandResponse({
    trust, record, challenge, body: parsed.body, signature: statement,
    method: 'POST', path: '/records', status: 201, pid: fixture.pid, standPublicKey: fixture.standPublicKey
  });
  assert.equal(verified.bodySha256, statement.bodySha256);
});

// --- 3. Совместимость 0.1: без challenge схема и поведение прежние --------------------------
test('старый путь 0.1: GET /environment и /records без challenge не изменены', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());

  const environment = await fetch(new URL('/environment', fixture.baseUrl), { redirect: 'error' });
  const environmentBody = await environment.json();
  assert.equal(environment.status, 200);
  assert.deepEqual(Object.keys(environmentBody).sort(), ['environmentId', 'fingerprint', 'sourceRevision']);
  assert.equal(environment.headers.get(STAND_RESPONSE_HEADER), null, 'ответ без challenge не подписывается');

  const payload = recordBody(fixture);
  const first = await postRecord(fixture, payload);
  assert.equal(first.status, 201);
  assert.equal(first.headers.get(STAND_RESPONSE_HEADER), null, 'POST без challenge не подписывается');
  // Без x-qa-run-id одноразовость не включается: старый сценарий с повторным POST сохраняется.
  const repeated = await postRecord(fixture, payload);
  assert.equal(repeated.status, 200);
  assert.equal(fixture.mutationCount, 1);
  assert.equal(fixture.recordCount, 1);

  const listed = await fetch(new URL('/records?fixtureId=' + encodeURIComponent(payload.fixtureId), fixture.baseUrl), { headers: bearer(fixture), redirect: 'error' });
  const listedBody = await listed.json();
  assert.equal(listed.status, 200);
  assert.deepEqual(Object.keys(listedBody), ['records']);
  assert.equal(listedBody.records.length, 1);
  assert.equal(listed.headers.get(STAND_RESPONSE_HEADER), null);
  assert.equal(fixture.readCount, 1, 'чтение без challenge учитывается как раньше');

  // Неверный challenge — отказ без подписи (fail-closed), тело 0.1 не затрагивается.
  const invalid = await fetch(new URL('/records?fixtureId=x', fixture.baseUrl), { headers: { ...bearer(fixture), [STAND_CHALLENGE_HEADER]: 'zz' } });
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, 'challenge_invalid');
});

// --- 4. Replay challenge --------------------------------------------------------------------
test('повторный challenge, который стенд уже подписывал, отвергается 409 без подписи', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  await seedRecord(fixture);
  const challenge = newChallenge();
  const first = await signedGet(fixture, '/records?fixtureId=' + encodeURIComponent(recordBody(fixture).fixtureId), challenge);
  assert.equal(first.status, 200);
  assert.ok(first.statement);

  const replay = await fetch(new URL('/records?fixtureId=' + encodeURIComponent(recordBody(fixture).fixtureId), fixture.baseUrl), {
    headers: { ...bearer(fixture), [STAND_CHALLENGE_HEADER]: challenge }
  });
  assert.equal(replay.status, 409);
  assert.deepEqual(await replay.json(), { error: 'replay_challenge' });
  assert.equal(replay.headers.get(STAND_RESPONSE_HEADER), null, 'повтор challenge не подписывается');

  // Тот же challenge на POST тоже отвергается.
  const replayPost = await postRecord(fixture, recordBody(fixture), { [STAND_CHALLENGE_HEADER]: challenge });
  assert.equal(replayPost.status, 409);
  assert.equal((await replayPost.json()).error, 'replay_challenge');
});

// --- 5. Replay подписи на другой challenge --------------------------------------------------
test('подпись, снятая на одном challenge, не проходит на другом (replay → отказ)', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const record = registerStand(fixture);
  const fixtureId = recordBody(fixture).fixtureId;
  const pathname = '/records?fixtureId=' + encodeURIComponent(fixtureId);
  const challengeOne = newChallenge();
  const challengeTwo = newChallenge();
  // Первое чтение — по пустому набору, затем появляется запись: тела ответов различаются.
  const first = await signedGet(fixture, pathname, challengeOne);
  const seed = await seedRecord(fixture);
  const second = await signedGet(fixture, pathname, challengeTwo);
  assert.ok(first.statement && second.statement);
  assert.equal(first.body.records.length, 0);
  assert.equal(second.body.records.length, 1);
  assert.equal(seed.body.fixtureId, fixtureId);

  await expectThrow(() => verifyStandResponse({
    trust, record, challenge: challengeTwo, body: first.body, signature: first.statement,
    method: 'GET', path: '/records', status: 200, standPublicKey: fixture.standPublicKey
  }), 'ENVIRONMENT_ATTESTATION_FAILED');
  // Подпись второго ответа с телом первого тоже не проходит.
  await expectThrow(() => verifyStandResponse({
    trust, record, challenge: challengeTwo, body: first.body, signature: second.statement,
    method: 'GET', path: '/records', status: 200, standPublicKey: fixture.standPublicKey
  }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// --- 6. Подмена тела/метаданных после подписи -----------------------------------------------
test('подмена тела, challenge, method, path, status, pid или ключа → ENVIRONMENT_ATTESTATION_FAILED', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const record = registerStand(fixture);
  const seed = await seedRecord(fixture);
  const challenge = newChallenge();
  const response = await signedGet(fixture, '/records?fixtureId=' + encodeURIComponent(seed.body.fixtureId), challenge);
  const base = {
    trust, record, challenge, body: response.body, signature: response.statement,
    method: 'GET', path: '/records', status: 200, pid: fixture.pid, standPublicKey: fixture.standPublicKey
  };
  verifyStandResponse(base); // исходная подпись валидна

  const tamperedBody = { records: [{ ...seed.record, comment: 'подмена' }] };
  const tamperedStatement = { ...response.statement, pid: response.statement.pid + 1 };
  const cases = [
    ['тело', { body: tamperedBody }],
    ['challenge', { challenge: newChallenge() }],
    ['method', { method: 'POST' }],
    ['path', { path: '/environment' }],
    ['status', { status: 201 }],
    ['pid', { pid: fixture.pid + 1 }],
    ['подпись', { signature: tamperedStatement }],
    ['чужой ключ', { standPublicKey: createStandKeys().publicKey }],
    ['без подписи', { signature: null }]
  ];
  for (const [label, overrides] of cases) {
    await expectThrow(() => verifyStandResponse({ ...base, ...overrides }), 'ENVIRONMENT_ATTESTATION_FAILED');
  }
});

// --- 7. Сверка с доверенной регистрацией среды ----------------------------------------------
test('ответ стенда сверяется с доверенной регистрацией: environmentId/generation/origin/standKeyId', async t => {
  const fixture = await serveLocalFixture({ generation: 1 });
  t.after(() => fixture.close());
  const seed = await seedRecord(fixture);
  const challenge = newChallenge();
  const response = await signedGet(fixture, '/records?fixtureId=' + encodeURIComponent(seed.body.fixtureId), challenge);
  const genuine = registerStand(fixture);
  verifyStandResponse({ trust, record: genuine, challenge, body: response.body, signature: response.statement, standPublicKey: fixture.standPublicKey });

  const otherEnvironment = registerStand(fixture, { environmentId: nextEnvironmentId() });
  const otherGeneration = registerStand(fixture, { generation: 2 });
  await expectThrow(() => verifyStandResponse({ trust, record: otherEnvironment, challenge, body: response.body, signature: response.statement, standPublicKey: fixture.standPublicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
  await expectThrow(() => verifyStandResponse({ trust, record: otherGeneration, challenge, body: response.body, signature: response.statement, standPublicKey: fixture.standPublicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');

  // Регистрация с другим origin/standKeyId — тоже отказ.
  const foreignStand = createStandKeys();
  const otherOrigin = registerStand(fixture, { environmentId: nextEnvironmentId(), origin: 'http://127.0.0.1:1/', standKeyId: foreignStand.standKeyId });
  await expectThrow(() => verifyStandResponse({ trust, record: otherOrigin, challenge, body: response.body, signature: response.statement, standPublicKey: fixture.standPublicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// --- 8. Bearer: привязка к runId и одноразовая мутация --------------------------------------
test('Bearer с x-qa-run-id привязан к runId; повторная мутация отвергается, чтение продолжает работать', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const payload = recordBody(fixture);
  const headers = { 'x-qa-run-id': 'run-alpha' };

  const first = await postRecord(fixture, payload, headers);
  assert.equal(first.status, 201);
  assert.equal(fixture.mutationCount, 1);

  const second = await postRecord(fixture, payload, headers);
  assert.equal(second.status, 403);
  assert.deepEqual(await second.json(), { error: 'token_revoked' });
  assert.equal(fixture.mutationCount, 1, 'второй мутации не было');

  // Снятый заголовок не возвращает право мутации для уже привязанного токена.
  const stripped = await postRecord(fixture, { ...payload, fixtureId: payload.fixtureId + '-other' });
  assert.equal(stripped.status, 403);
  assert.deepEqual(await stripped.json(), { error: 'token_revoked' });

  // Независимое чтение тем же токеном продолжает работать (нужно замороженному Worker 0.1).
  const read = await fetch(new URL('/records?fixtureId=' + encodeURIComponent(payload.fixtureId), fixture.baseUrl), { headers: bearer(fixture) });
  assert.equal(read.status, 200);
  assert.equal((await read.json()).records.length, 1);

  // Чужой runId и чужой Bearer отвергаются.
  const wrongRun = await fetch(new URL('/records?fixtureId=' + encodeURIComponent(payload.fixtureId), fixture.baseUrl), { headers: { ...bearer(fixture), 'x-qa-run-id': 'run-beta' } });
  assert.equal(wrongRun.status, 403);
  assert.deepEqual(await wrongRun.json(), { error: 'run_mismatch' });
  const wrongToken = await fetch(new URL('/records?fixtureId=x', fixture.baseUrl), { headers: { authorization: 'Bearer not-the-token' } });
  assert.equal(wrongToken.status, 401);
  const invalidRun = await postRecord(fixture, { fixtureId: 'x' }, { 'x-qa-run-id': 'run with space' });
  assert.equal(invalidRun.status, 400);
  assert.equal((await invalidRun.json()).error, 'run_id_invalid');
});

test('токен другой среды не принимается на этом стенде', async t => {
  const fixture = await serveLocalFixture();
  const alien = await serveLocalFixture();
  t.after(() => fixture.close());
  t.after(() => alien.close());
  const response = await fetch(new URL('/records?fixtureId=x', fixture.baseUrl), { headers: { authorization: 'Bearer ' + alien.authToken } });
  assert.equal(response.status, 401);
});

// --- 9. attestationVerifiedReads: happy path ------------------------------------------------
test('attestationVerifiedReads: до/после аттестации, владелец порта, подпись на каждом чтении', async t => {
  const fixture = await serveLocalFixture({ generation: 3 });
  t.after(() => fixture.close());
  const record = registerStand(fixture);
  const seed = await seedRecord(fixture);
  const pathname = '/records?fixtureId=' + encodeURIComponent(seed.body.fixtureId);

  const outcome = await attestationVerifiedReads({
    trust, record, standPublicKey: fixture.standPublicKey,
    headers: bearer(fixture),
    read: async context => {
      const one = await context.verifiedRead(pathname);
      const two = await context.verifiedRead(pathname);
      // Контракт чтения для Verification Worker: { status, body, bytes, attestation }.
      assert.equal(one.status, 200);
      assert.ok(Buffer.isBuffer(one.bytes));
      assert.deepEqual(JSON.parse(one.bytes.toString('utf8')), one.body);
      return { bodies: [one.body, two.body] };
    }
  });

  // Функция возвращает ровно readResult; метаданные канала — неперечислимое standReads.
  assert.deepEqual(Object.keys(outcome), ['bodies']);
  assert.equal(outcome.bodies.length, 2);
  assert.equal(outcome.bodies.every(body => body.records.length === 1), true);
  assert.equal(outcome.bodies[0].records[0].id, seed.id);
  const channel = outcome.standReads;
  assert.ok(channel, 'метаданные канала доступны через standReads');
  assert.equal(channel.reads.length, 2);
  assert.notEqual(channel.reads[0].challenge, channel.reads[1].challenge, 'challenge новый на каждое чтение');
  for (const read of channel.reads) {
    assert.equal(read.status, 200);
    assert.equal(read.path, '/records');
    assert.match(read.bodySha256, /^[a-f0-9]{64}$/);
  }
  assert.equal(channel.before.record.environmentId, record.environmentId);
  assert.equal(channel.after.attestation.pid, channel.before.attestation.pid);
  assert.equal(channel.after.portOwnerPid, channel.before.portOwnerPid);
  assert.notEqual(channel.before.attestation.challenge, channel.after.attestation.challenge, 'аттестации до и после — свежие');

  // Неподписанный ответ (/environment не подписывается) не принимается как чтение.
  await expectThrow(() => attestationVerifiedReads({
    trust, record, standPublicKey: fixture.standPublicKey, headers: bearer(fixture),
    read: async context => context.verifiedRead('/environment')
  }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// --- 10. Подмена стенда после POST: rogue не может подписать ответ --------------------------
test('rogue на том же порту после POST не может подписать ответ → Verification получает отказ, не PASS', async t => {
  const port = await freePort();
  const fixture = await serveLocalFixture({ port });
  const record = registerStand(fixture);
  const seed = await seedRecord(fixture);
  const pathname = '/records?fixtureId=' + encodeURIComponent(seed.body.fixtureId);

  // Настоящий POST уже прошёл; дальше стенд подменяется rogue-процессом того же SID.
  await fixture.close();
  const rogue = await startRogue({ port, environmentId: fixture.environmentId, fingerprint: fixture.fingerprint, record: seed.record });
  t.after(() => rogue.close());

  // Rogue отвечает правдоподобно, но без подписи стенда.
  const challenge = newChallenge();
  const rogueResponse = await fetch(new URL(pathname, rogue.origin), { headers: { ...bearer(fixture), [STAND_CHALLENGE_HEADER]: challenge } });
  assert.equal(rogueResponse.status, 200);
  const rogueBody = await rogueResponse.json();
  const rogueStatement = signatureOrNull(rogueResponse.headers);
  assert.equal(rogueStatement, null, 'rogue не имеет ключа стенда и не подписывает ответ');
  await expectThrow(() => verifyStandResponse({
    trust, record, challenge, body: rogueBody, signature: rogueStatement,
    method: 'GET', path: '/records', status: 200, standPublicKey: fixture.standPublicKey
  }), 'ENVIRONMENT_ATTESTATION_FAILED');

  // Самопроверка Verification на rogue-среде невозможна: /attest не отвечает подписью.
  await expectThrow(() => attestationVerifiedReads({
    trust, record, standPublicKey: fixture.standPublicKey, headers: bearer(fixture),
    read: async context => context.verifiedRead(pathname)
  }), 'ENVIRONMENT_ATTESTATION_FAILED');
  assert.ok(rogue.state.recordGets >= 1, 'подпись проверялась на фактическом ответе rogue');
});

// --- 11. Подмена стенда во время набора чтений ----------------------------------------------
test('подмена стенда между чтениями: закреплённый сокет рвётся, новых TCP нет, rogue не получает ничего', async t => {
  const port = await freePort();
  const fixture = await serveLocalFixture({ port });
  const record = registerStand(fixture);
  const seed = await seedRecord(fixture);
  const pathname = '/records?fixtureId=' + encodeURIComponent(seed.body.fixtureId);
  let rogue = null;
  let failure = null;

  try {
    await assert.rejects(async () => attestationVerifiedReads({
      trust, record, standPublicKey: fixture.standPublicKey, headers: bearer(fixture),
      read: async context => {
        const live = await context.verifiedRead(pathname);
        assert.equal(live.status, 200);
        // Подмена после первого чтения: rogue занимает тот же порт.
        await fixture.close();
        rogue = await startRogue({ port, environmentId: fixture.environmentId, fingerprint: fixture.fingerprint, record: seed.record });
        return live.body;
      }
    }), error => { failure = error; return codeIn(['ENVIRONMENT_UNAVAILABLE', 'ENVIRONMENT_ATTESTATION_FAILED'])(error); });
  } finally {
    if (rogue) await rogue.close();
    await fixture.close().catch(() => {});
  }
  assert.ok(rogue, 'подмена состоялась');
  assert.ok(failure, 'после подмены должен быть отказ, а не доверенный результат');
  // Главное: закреплённое соединение не переоткрывается, rogue не получил ни одного запроса и Bearer.
  assert.equal(rogue.state.requests.length, 0, 'по закреплённому пути rogue не получил ни одного HTTP-запроса');
  assert.equal(rogue.state.posts, 0, 'POST на rogue не ушёл');
});

// --- 12. Pinned keep-alive: аттестация и чтения на одном сокете -------------------------------
test('закреплённое соединение: /attest и чтения идут по одному TCP-сокету без новых соединений', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const record = registerStand(fixture);
  const seed = await seedRecord(fixture);
  const connection = await openPinnedStandConnection({ trust, record, standPublicKey: fixture.standPublicKey });
  try {
    const localPort = connection.socket.localPort;
    assert.ok(localPort > 0);
    assert.equal(connection.attestation.pid, fixture.pid);
    assert.equal(connection.portOwnerPid, fixture.pid);
    assert.equal(connection.attestationResponse.domain, 'stand-response');

    const challenge = newChallenge();
    const response = await connection.request({
      method: 'GET',
      path: '/records?fixtureId=' + encodeURIComponent(seed.body.fixtureId),
      headers: { ...bearer(fixture), [STAND_CHALLENGE_HEADER]: challenge }
    });
    assert.equal(response.status, 200);
    assert.equal(connection.socket.localPort, localPort, 'чтение ушло по тому же закреплённому сокету');
    verifyStandResponse({
      trust, record, challenge, body: response.body, responseBytes: response.text,
      signature: readStandResponseSignature(response.headers), method: 'GET', path: '/records', status: 200,
      pid: fixture.pid, standPublicKey: fixture.standPublicKey
    });

    // Повторная аттестация на том же сокете (стенд не закрывает keep-alive) — новый challenge.
    const again = await attestPinnedConnection(connection, { trust, record, standPublicKey: fixture.standPublicKey });
    assert.equal(again.attestation.pid, fixture.pid);
    assert.equal(connection.socket.localPort, localPort, 'повторная аттестация ушла по тому же сокету');
    assert.notEqual(again.challenge, connection.attestationResponse?.challenge);
    assert.equal(fixture.mutationCount, 1);
    assert.equal(fixture.readCount, 1);
  } finally {
    connection.close();
  }
  assert.equal(connection.socket.destroyed, true, 'close() закрывает закреплённый сокет');
});

// --- 13. Доверенный Browser Worker: единственный POST по закреплённому сокету -----------------
const trustedWorkerPath = pathModule.resolve('apps/browser/trusted-worker.mjs');

async function prepareWorkerWorld(t, runId, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-signed-worker-'));
  const fixture = await serveLocalFixture(options);
  t.after(async () => {
    await fixture.close().catch(() => {});
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  const contract = localFixtureContract(fixture, runId);
  fixture.fixtureId = contract.fixtureId;
  const bundle = localBundle(fixture, { runId });
  bundle.fixture = contract;
  bundle.manifest.fixtureSha256 = digest(contract);
  const store = new RunStore(root);
  const runDir = store.snapshot(bundle, { runId, pid: process.pid, at: new Date().toISOString() });
  const frozen = verifyFrozenBundle(store, runDir);
  const record = registerStand(fixture);
  const click = frozen.scenario.nodes.find(node => node.action.type === 'click');
  const job = {
    type: 'PINNED_JOB', runId,
    manifestSha256: frozen.manifestSha256,
    stepId: click.id,
    intentId: runId + ':' + click.id,
    operationId: frozen.operation.id,
    mutationName: frozen.operation.mutation.name,
    inputsSha256: digest(frozen.operation.inputs),
    fixtureId: contract.fixtureId,
    entityKind: frozen.operation.entityKind,
    origin: fixture.baseUrl,
    token: fixture.authToken,
    fields: { ...frozen.operation.inputs, fixtureId: contract.fixtureId },
    timeoutMs: 5000
  };
  return { root, fixture, store, runDir, frozen, record, contract, job };
}

function sendWithSocket(child, message, socket) {
  return new Promise((resolve, reject) => {
    child.send(message, socket, error => error ? reject(error) : resolve());
  });
}

test('доверенный Browser Worker: POST только по закреплённому сокету, evidence по схеме 0.1, подпись ответа проверена', { timeout: 60000 }, async t => {
  const { fixture, store, runDir, frozen, record, contract, job } = await prepareWorkerWorld(t, 'worker-pinned-ok');
  // T-C: Control открывает ОДНО соединение и аттестует его на этом же сокете.
  const connection = await openPinnedStandConnection({ trust, record, standPublicKey: fixture.standPublicKey });

  const child = fork(trustedWorkerPath, [], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'], windowsHide: true, env: process.env });
  t.after(() => { try { child.kill('SIGKILL'); } catch { /* уже завершён */ } });
  const messages = [];
  let intentEvidence = null;
  let requestEvidence = null;
  let responseEvidence = null;
  let done = null;
  let workerError = null;
  let finishedResolve;
  const finished = new Promise(resolve => { finishedResolve = resolve; });
  let exitCode = null;
  const exited = new Promise(resolve => child.once('exit', code => { exitCode = code; resolve(code); }));

  child.on('message', message => {
    messages.push(message);
    (async () => {
      if (message.type === 'INTENT') {
        const intent = message.payload;
        intentEvidence = store.appendEvidence(runDir, {
          runId: job.runId, manifestSha256: job.manifestSha256, fixtureId: job.fixtureId,
          stepId: intent.stepId, producer: 'control', kind: 'mutation-intent', artifact: intent, parentEvidenceIds: []
        });
        child.send({ type: 'ACK', commandId: message.commandId, runId: job.runId, intentId: intent.intentId, evidenceId: intentEvidence.evidenceId, durable: true });
      } else if (message.type === 'HTTP_REQUEST') {
        const p = message.payload;
        const artifact = { requestId: p.requestId, intentId: p.intentId, operationId: p.operationId, method: p.method, path: p.path, fixtureId: p.fixtureId, fields: p.fields };
        requestEvidence = store.appendEvidence(runDir, {
          runId: job.runId, manifestSha256: job.manifestSha256, fixtureId: job.fixtureId, stepId: job.stepId,
          producer: 'browser', kind: 'request', artifact, requestId: p.requestId, parentEvidenceIds: [intentEvidence.evidenceId]
        });
        child.send({ type: 'EVIDENCE_ACK', runId: job.runId, requestId: p.requestId, durable: true });
      } else if (message.type === 'HTTP_RESPONSE') {
        const p = message.payload;
        assert.ok(p.responseSignature, 'Control обязан получить подпись ответа POST');
        verifyStandResponse({
          trust, record, challenge: p.responseChallenge, body: p.responseBody, signature: p.responseSignature,
          method: 'POST', path: '/records', status: p.status, pid: fixture.pid, standPublicKey: fixture.standPublicKey
        });
        const artifact = { requestId: p.requestId, intentId: job.intentId, operationId: frozen.operation.id, fixtureId: p.responseFixtureId, status: p.status, entity: p.entity };
        responseEvidence = store.appendEvidence(runDir, {
          runId: job.runId, manifestSha256: job.manifestSha256, fixtureId: job.fixtureId, stepId: job.stepId,
          producer: 'browser', kind: 'response', artifact, requestId: p.requestId, entity: p.entity,
          parentEvidenceIds: [requestEvidence.evidenceId]
        });
        child.send({ type: 'EVIDENCE_ACK', runId: job.runId, requestId: p.requestId, durable: true });
      } else if (message.type === 'DONE') { done = message; finishedResolve(); }
      else if (message.type === 'ERROR') { workerError = message.payload; finishedResolve(); }
    })().catch(error => { workerError = { code: error.code || 'CONTROL_ERROR', message: error.message }; finishedResolve(); });
  });

  await sendWithSocket(child, job, connection.socket);
  await finished;
  await exited;
  assert.equal(workerError, null, 'Worker не должен сообщать об ошибке: ' + JSON.stringify(workerError));
  assert.ok(done, 'Worker обязан прислать DONE');
  assert.equal(exitCode, 0);
  const types = messages.map(message => message.type);
  for (const type of ['INTENT', 'HTTP_REQUEST', 'HTTP_RESPONSE', 'DONE']) {
    assert.ok(types.includes(type), 'в протоколе нет ' + type);
  }
  assert.ok(types.indexOf('HTTP_RESPONSE') < types.indexOf('DONE'), 'DONE только после подтверждённого ответа');
  assert.equal(fixture.mutationCount, 1, 'ровно одна мутация');
  assert.equal(fixture.recordCount, 1);

  const evidence = store.readEvidence(runDir);
  assert.deepEqual(evidence.map(item => item.envelope.kind), ['mutation-intent', 'request', 'response']);
  const responseItem = evidence.find(item => item.envelope.kind === 'response');
  assert.equal(responseItem.artifact.status, 201);
  assert.equal(responseItem.artifact.entity.id, responseItem.envelope.entity.id);
  assert.equal(responseItem.artifact.fixtureId, contract.fixtureId);
  assert.equal(responseItem.artifact.status < 300 && responseItem.artifact.status >= 200, true);
  assert.equal(fixture.readCount, 0, 'доверенный POST не использует публичных чтений');
});

test('сценарий B аудита: подмена стенда между T-C и POST — rogue не получает ни POST, ни Bearer, DONE нет', { timeout: 60000 }, async t => {
  const port = await freePort();
  const { fixture, job } = await prepareWorkerWorld(t, 'worker-pinned-b', { port });
  const record = registerStand(fixture);
  const connection = await openPinnedStandConnection({ trust, record, standPublicKey: fixture.standPublicKey });

  const child = fork(trustedWorkerPath, [], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'], windowsHide: true, env: process.env });
  t.after(() => { try { child.kill('SIGKILL'); } catch { /* уже завершён */ } });
  const messages = [];
  let rogue = null;
  let httpFailed = null;
  let workerError = null;
  let sawDone = false;
  let finishedResolve;
  const finished = new Promise(resolve => { finishedResolve = resolve; });
  let exitCode = null;
  const exited = new Promise(resolve => child.once('exit', code => { exitCode = code; resolve(code); }));
  t.after(async () => { if (rogue) await rogue.close().catch(() => {}); });

  child.on('message', message => {
    messages.push(message);
    (async () => {
      if (message.type === 'INTENT') {
        child.send({ type: 'ACK', commandId: message.commandId, runId: job.runId, intentId: message.payload.intentId, durable: true });
      } else if (message.type === 'HTTP_REQUEST') {
        // Подмена на последнем IPC-рубежe перед POST: T-C уже завершена, запрос ещё не отправлен.
        await fixture.close();
        rogue = await startRogue({ port, environmentId: fixture.environmentId, fingerprint: fixture.fingerprint, record: null });
        await new Promise(resolve => setTimeout(resolve, 120));
        child.send({ type: 'EVIDENCE_ACK', runId: job.runId, requestId: message.payload.requestId, durable: true });
      } else if (message.type === 'HTTP_FAILED') { httpFailed = message.payload; }
      else if (message.type === 'DONE') { sawDone = true; finishedResolve(); }
      else if (message.type === 'ERROR') { workerError = message.payload; finishedResolve(); }
    })().catch(error => { workerError = { code: error.code || 'CONTROL_ERROR', message: error.message }; finishedResolve(); });
  });

  await sendWithSocket(child, job, connection.socket);
  await finished;
  await exited;

  // Никакого PASS: DONE не пришёл, POST не подтверждён, Worker сообщил отказ.
  assert.equal(sawDone, false, 'DONE после подмены запрещён — PASS невозможен');
  assert.ok(workerError, 'Worker обязан сообщить отказ после разрыва закреплённого соединения');
  assert.ok(httpFailed || workerError, 'подмена закреплённого стенда должна остановить Worker до DONE');
  assert.notEqual(exitCode, 0);

  // Критерий владельца: rogue не получил ни POST, ни Bearer.
  assert.ok(rogue, 'подмена состоялась');
  assert.equal(rogue.state.posts, 0, 'roguePosts=0');
  assert.equal(rogue.state.requests.length, 0, 'по закреплённому пути rogue не получил ни одного HTTP-запроса');
  const leaked = JSON.stringify(rogue.state.requests).includes(fixture.authToken) || messages.some(message => JSON.stringify(message).includes(fixture.authToken));
  // Токен ходит только внутри fork IPC доверенных процессов; наружу к rogue — нет.
  assert.equal(JSON.stringify(rogue.state.requests).includes(fixture.authToken), false, 'bearerLeaked=false');
  assert.equal(leaked, false, 'Bearer не должен покидать доверенные процессы');
  assert.equal(fixture.mutationCount, 0, 'реальной мутации не было');
});
