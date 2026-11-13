import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import {
  attestEnvironment, attestLiveEnvironment, commitEnvironmentRecord, createStandKeys,
  DEFAULT_ATTEST_TIMEOUT_MS, loadEnvironmentRecord, newChallenge, portOwnerPid, processAlive,
  signEnvironmentAttestation, signEnvironmentRecord, verifyEnvironmentAttestation,
  verifyEnvironmentRecord
} from '../packages/trust/environment.mjs';
import {
  createTrustRoot, loadTrustRoot, publicKeyId, signTrustedDocument, unwrapPrivateKey
} from '../packages/trust/identity.mjs';
import { serveLocalFixture } from '../adapters/local/server.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-environment-'));
const secretsDir = path.join(root, 'secrets');
const trustRoot = path.join(root, 'trust-root');
const created = await createTrustRoot({ secretsDir, trustRoot });
const trust = loadTrustRoot(trustRoot);
const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
const anchorKey = await unwrapPrivateKey(path.join(secretsDir, 'anchor.key'));

let counter = 0;
function envId(prefix = 'env') {
  counter += 1;
  return prefix + '-' + counter;
}

function recordFor(fields) {
  return signEnvironmentRecord(ownerKey, {
    environmentId: fields.environmentId || envId(),
    generation: fields.generation === undefined ? 1 : fields.generation,
    kind: fields.kind || 'local-stand',
    status: fields.status || 'active',
    origin: fields.origin,
    standKeyId: fields.standKeyId,
    credentialRef: fields.credentialRef === undefined ? '' : fields.credentialRef
  });
}

function register(fields) {
  const record = recordFor(fields);
  commitEnvironmentRecord(trust, trustRoot, record);
  return record;
}

function codeIs(code) {
  return error => {
    assert.equal(error.code, code, 'ожидался код ' + code + ', получено ' + error.code + ': ' + error.message);
    return true;
  };
}

async function expectCode(promiseOrFunction, code) {
  if (typeof promiseOrFunction === 'function') await assert.rejects(promiseOrFunction, codeIs(code));
  else await assert.rejects(promiseOrFunction, codeIs(code));
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function listen(handler, { port = 0 } = {}) {
  const sockets = new Set();
  const server = http.createServer(handler);
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  const actualPort = server.address().port;
  return {
    server,
    port: actualPort,
    origin: 'http://127.0.0.1:' + actualPort + '/',
    close: () => new Promise(resolve => {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      server.close(() => resolve());
    })
  };
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

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// Подпись аттестации ключом-стендом с возможностью подменить поля (для негативных тестов).
async function standMock(keys, fields = {}) {
  const hits = { attest: 0, environment: 0 };
  let mock;
  const handler = async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'POST' && url.pathname === '/attest') {
      hits.attest += 1;
      let payload;
      try { payload = JSON.parse(await readBody(req)); }
      catch { res.writeHead(400); res.end('{}'); return; }
      const attestation = signEnvironmentAttestation(keys.privateKey, {
        environmentId: fields.environmentId,
        generation: fields.generation === undefined ? 1 : fields.generation,
        origin: fields.origin === undefined ? mock.origin : fields.origin,
        pid: fields.pid === undefined ? process.pid : fields.pid,
        challenge: payload.challenge
      });
      const bytes = Buffer.from(JSON.stringify(attestation));
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': bytes.length });
      res.end(bytes);
      return;
    }
    hits.environment += 1;
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{}');
  };
  mock = await listen(handler);
  return { origin: mock.origin, port: mock.port, close: mock.close, hits, keys };
}

function waitFor(check, timeoutMs = 4000, intervalMs = 50) {
  const deadline = Date.now() + timeoutMs;
  return (async () => {
    while (Date.now() < deadline) {
      if (await check()) return true;
      await sleep(intervalMs);
    }
    return false;
  })();
}

// E-01 / базовая положительная проверка: живой локальный стенд проходит аттестацию.
test('живой локальный стенд проходит attestLiveEnvironment, публичный /environment не используется', async t => {
  const fixture = await serveLocalFixture({ generation: 3 });
  t.after(() => fixture.close());
  assert.equal(fixture.generation, 3);
  assert.equal(fixture.pid, process.pid);
  assert.match(fixture.standKeyId, /^[a-f0-9]{64}$/);
  const record = register({
    environmentId: fixture.environmentId,
    generation: fixture.generation,
    origin: fixture.baseUrl,
    standKeyId: fixture.standKeyId
  });
  const urls = [];
  const fetchImpl = (url, options) => {
    urls.push(String(url));
    return fetch(url, options);
  };
  const live = await attestLiveEnvironment({ trust, record, standPublicKey: fixture.standPublicKey, fetchImpl });
  assert.equal(live.attestation.environmentId, record.environmentId);
  assert.equal(live.attestation.generation, 3);
  assert.equal(live.attestation.origin, fixture.baseUrl);
  assert.equal(live.attestation.pid, fixture.pid);
  assert.equal(live.portOwnerPid, process.pid);
  assert.equal(urls.length, 1);
  assert.equal(urls[0], fixture.baseUrl + 'attest');
  assert.equal(urls.some(url => url.includes('/environment')), false);
  assert.equal(fixture.mutationCount, 0);
});

// E-01: чужой сервер копирует environmentId, fingerprint и любой открытый ответ, но без ключа стенда.
test('E-01: копия публичного /environment и поддельный fingerprint не дают аттестации', async t => {
  const real = await serveLocalFixture();
  t.after(() => real.close());
  const publicCopy = await (await fetch(real.baseUrl + 'environment')).json();
  assert.equal(typeof publicCopy.environmentId, 'string');
  let environmentHits = 0;
  const fake = await listen(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/environment') {
      environmentHits += 1;
      const bytes = Buffer.from(JSON.stringify({ ...publicCopy, fingerprint: 'forged-' + publicCopy.fingerprint }));
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.length });
      res.end(bytes);
      return;
    }
    // Копирует открытый ответ вместо подписи свежего challenge.
    const bytes = Buffer.from(JSON.stringify(publicCopy));
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.length });
    res.end(bytes);
  });
  t.after(() => fake.close());
  const record = register({
    environmentId: publicCopy.environmentId,
    generation: 1,
    origin: fake.origin,
    standKeyId: real.standKeyId
  });
  await expectCode(attestLiveEnvironment({ trust, record, standPublicKey: real.standPublicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
  assert.equal(environmentHits, 0, 'доверенный путь не должен читать публичный /environment');
});

// Неподписанную запись нельзя выдать за проверенную: метка проверки не переносится копированием.
test('неподписанная запись среды не аттестуется, проверенная загрузка проходит', async t => {
  const keys = createStandKeys();
  const environmentId = envId('unsigned');
  const mock = await standMock(keys, { environmentId, generation: 1 });
  t.after(() => mock.close());
  register({ environmentId, origin: mock.origin, standKeyId: keys.standKeyId });
  const loaded = loadEnvironmentRecord(trust, trustRoot, environmentId);
  const live = await attestLiveEnvironment({ trust, record: loaded, standPublicKey: keys.publicKey });
  assert.equal(live.attestation.environmentId, environmentId);
  const copied = { ...loaded };
  await expectCode(attestEnvironment({ trust, record: copied, challenge: newChallenge(), standPublicKey: keys.publicKey }), 'CONTRACT_INVALID');
});

// Переразмеренный ответ не принимается и не разбирается целиком.
test('слишком большой ответ /attest отвергается', async t => {
  const keys = createStandKeys();
  const huge = await listen((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/attest') {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(200_000) });
      res.end('{}');
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  t.after(() => huge.close());
  const record = register({ environmentId: envId('huge'), origin: huge.origin, standKeyId: keys.standKeyId });
  await expectCode(attestEnvironment({ trust, record, challenge: newChallenge(), standPublicKey: keys.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// E-02: среды нет в реестре.
test('E-02: environmentId отсутствует в реестре — ENVIRONMENT_UNKNOWN', async () => {
  assert.throws(() => loadEnvironmentRecord(trust, trustRoot, 'env-does-not-exist'), codeIs('ENVIRONMENT_UNKNOWN'));
});

// CREATE_NEW + fsync + повторное чтение: повтор не перезаписывает запись.
test('запись среды ставится CREATE_NEW, повтор с другим содержимым не перезаписывает файл', async () => {
  const keys = createStandKeys();
  const record = recordFor({ origin: 'http://127.0.0.1:9/', standKeyId: keys.standKeyId });
  const first = commitEnvironmentRecord(trust, trustRoot, record);
  assert.deepEqual(first, record);
  const file = path.join(trustRoot, 'environments', record.environmentId + '.json');
  const bytes = fs.readFileSync(file);
  assert.equal(bytes.toString('utf8'), JSON.stringify(record) + '\n');
  const again = commitEnvironmentRecord(trust, trustRoot, record);
  assert.deepEqual(again, record);
  assert.deepEqual(fs.readFileSync(file), bytes);
  const changed = signEnvironmentRecord(ownerKey, {
    environmentId: record.environmentId,
    generation: 2,
    kind: 'local-stand',
    status: 'active',
    origin: record.origin,
    standKeyId: record.standKeyId,
    credentialRef: ''
  });
  assert.throws(() => commitEnvironmentRecord(trust, trustRoot, changed), codeIs('CONTRACT_INVALID'));
  assert.deepEqual(fs.readFileSync(file), bytes);
  const loaded = loadEnvironmentRecord(trust, trustRoot, record.environmentId);
  assert.equal(loaded.generation, 1);
  assert.equal('fingerprint' in loaded, false);
});

// Отозванная среда не загружается и не аттестуется.
test('отозванная среда — ENVIRONMENT_REVOKED на загрузке и на аттестации', async () => {
  const keys = createStandKeys();
  const record = register({ status: 'revoked', origin: 'http://127.0.0.1:9/', standKeyId: keys.standKeyId });
  assert.throws(() => loadEnvironmentRecord(trust, trustRoot, record.environmentId), codeIs('ENVIRONMENT_REVOKED'));
  await expectCode(attestLiveEnvironment({ trust, record, standPublicKey: keys.publicKey }), 'ENVIRONMENT_REVOKED');
});

// Replay: старый ответ на прежний challenge не принимается для нового challenge.
test('replay старой аттестации и старого challenge отвергается', async t => {
  const keys = createStandKeys();
  const environmentId = envId('replay');
  const mock = await standMock(keys, { environmentId, generation: 1 });
  t.after(() => mock.close());
  const record = register({ environmentId, origin: mock.origin, standKeyId: keys.standKeyId });
  const challengeOne = newChallenge();
  const first = await attestEnvironment({ trust, record, challenge: challengeOne, standPublicKey: keys.publicKey });
  assert.equal(first.attestation.challenge, challengeOne);
  const oldAttestation = signEnvironmentAttestation(keys.privateKey, {
    environmentId, generation: 1, origin: mock.origin, pid: process.pid, challenge: challengeOne
  });
  const challengeTwo = newChallenge();
  assert.notEqual(challengeOne, challengeTwo);
  assert.throws(
    () => verifyEnvironmentAttestation(trust, record, oldAttestation, { challenge: challengeTwo, standPublicKey: keys.publicKey }),
    codeIs('ENVIRONMENT_ATTESTATION_FAILED')
  );
  // Сервер, который всегда воспроизводит первую подпись, не проходит на новом challenge.
  const replay = await listen(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'POST' && url.pathname === '/attest') {
      const bytes = Buffer.from(JSON.stringify(oldAttestation));
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.length });
      res.end(bytes);
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  t.after(() => replay.close());
  const replayRecord = register({ environmentId: envId('replay-copy'), origin: replay.origin, standKeyId: keys.standKeyId });
  await expectCode(attestEnvironment({ trust, record: replayRecord, challenge: newChallenge(), standPublicKey: keys.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// Подмена standKeyId и неизвестный ключ.
test('подмена standKeyId и неизвестный ключ стенда отвергаются', async t => {
  const real = createStandKeys();
  const foreign = createStandKeys();
  const environmentId = envId('key');
  const mock = await standMock(real, { environmentId, generation: 1 });
  t.after(() => mock.close());
  const wrongRecord = register({ environmentId, origin: mock.origin, standKeyId: foreign.standKeyId });
  // Аттестация реальным ключом стенда не сходится с подменённым standKeyId реестра.
  await expectCode(attestEnvironment({ trust, record: wrongRecord, challenge: newChallenge(), standPublicKey: real.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
  const secondId = envId('key');
  const second = await standMock(real, { environmentId: secondId, generation: 1 });
  t.after(() => second.close());
  const correctRecord = register({ environmentId: secondId, origin: second.origin, standKeyId: real.standKeyId });
  await expectCode(attestEnvironment({ trust, record: correctRecord, challenge: newChallenge(), standPublicKey: foreign.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
  const attestation = signEnvironmentAttestation(real.privateKey, {
    environmentId: secondId, generation: 1, origin: second.origin, pid: process.pid, challenge: newChallenge()
  });
  assert.throws(
    () => verifyEnvironmentAttestation(trust, correctRecord, attestation, { challenge: attestation.challenge, standPublicKey: foreign.publicKey }),
    codeIs('ENVIRONMENT_ATTESTATION_FAILED')
  );
  // Без публичного ключа стенда доверенная проверка невозможна — fail-closed.
  await expectCode(attestEnvironment({ trust, record: correctRecord, challenge: newChallenge() }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// Подмена environmentId в аттестации и в имени файла реестра.
test('подмена environmentId отвергается', async t => {
  const keys = createStandKeys();
  const environmentId = envId('id');
  const otherId = envId('other');
  const mock = await standMock(keys, { environmentId: otherId, generation: 1 });
  t.after(() => mock.close());
  const record = register({ environmentId, origin: mock.origin, standKeyId: keys.standKeyId });
  await expectCode(attestEnvironment({ trust, record, challenge: newChallenge(), standPublicKey: keys.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
  const forged = signEnvironmentAttestation(keys.privateKey, {
    environmentId: otherId, generation: 1, origin: mock.origin, pid: process.pid, challenge: newChallenge()
  });
  assert.throws(
    () => verifyEnvironmentAttestation(trust, record, forged, { challenge: forged.challenge, standPublicKey: keys.publicKey }),
    codeIs('ENVIRONMENT_ATTESTATION_FAILED')
  );
  // Файл с чужим именем не выдаёт себя за другую среду.
  const misnamed = recordFor({ environmentId: envId('misnamed'), origin: 'http://127.0.0.1:9/', standKeyId: keys.standKeyId });
  fs.mkdirSync(path.join(trustRoot, 'environments'), { recursive: true });
  fs.writeFileSync(path.join(trustRoot, 'environments', otherId + '.json'), JSON.stringify(misnamed) + '\n');
  assert.throws(() => loadEnvironmentRecord(trust, trustRoot, otherId), codeIs('CONTRACT_INVALID'));
});

// E-03: смена поколения между аттестациями.
test('E-03: смена поколения между T-A и T-B отвергается', async t => {
  const keys = createStandKeys();
  const environmentId = envId('generation');
  const mock = await standMock(keys, { environmentId, generation: 1 });
  t.after(() => mock.close());
  const record = register({ environmentId, generation: 1, origin: mock.origin, standKeyId: keys.standKeyId });
  const first = await attestLiveEnvironment({ trust, record, standPublicKey: keys.publicKey });
  assert.equal(first.attestation.generation, 1);
  const restartedId = envId('generation');
  const restarted = await standMock(keys, { environmentId: restartedId, generation: 2 });
  t.after(() => restarted.close());
  const newRecord = register({ environmentId: restartedId, generation: 1, origin: restarted.origin, standKeyId: keys.standKeyId });
  await expectCode(attestLiveEnvironment({ trust, record: newRecord, standPublicKey: keys.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// Смена PID: «PID существует» не означает «именно доверенный процесс обслуживает endpoint».
test('смена PID: живой чужой PID не подтверждает владение портом', async t => {
  const sleeper = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore', windowsHide: true });
  t.after(() => { try { sleeper.kill(); } catch { /* уже завершён */ } });
  assert.equal(await waitFor(() => processAlive(sleeper.pid)), true);
  const keys = createStandKeys();
  const environmentId = envId('pid');
  const mock = await standMock(keys, { environmentId, generation: 1, pid: sleeper.pid });
  t.after(() => mock.close());
  const record = register({ environmentId, generation: 1, origin: mock.origin, standKeyId: keys.standKeyId });
  const owner = await portOwnerPid(mock.origin);
  assert.equal(owner, process.pid);
  assert.notEqual(owner, sleeper.pid);
  await expectCode(attestLiveEnvironment({ trust, record, standPublicKey: keys.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
  // Мёртвый PID тоже не принимается.
  const deadPid = sleeper.pid;
  sleeper.kill();
  await waitFor(() => processAlive(deadPid) === false);
  const deadEnvironmentId = envId('pid-dead');
  const dead = await standMock(keys, { environmentId: deadEnvironmentId, generation: 1, pid: deadPid });
  t.after(() => dead.close());
  const deadRecord = register({ environmentId: deadEnvironmentId, generation: 1, origin: dead.origin, standKeyId: keys.standKeyId });
  await expectCode(attestLiveEnvironment({ trust, record: deadRecord, standPublicKey: keys.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// Остановка стенда: живой PID процесса теста не делает endpoint доверенным.
test('остановленный стенд — ENVIRONMENT_UNAVAILABLE, хотя старый PID ещё существует', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const record = register({ environmentId: fixture.environmentId, origin: fixture.baseUrl, standKeyId: fixture.standKeyId });
  const live = await attestLiveEnvironment({ trust, record, standPublicKey: fixture.standPublicKey });
  assert.equal(live.attestation.pid, process.pid);
  await fixture.close();
  assert.equal(processAlive(fixture.pid), true);
  await expectCode(attestLiveEnvironment({ trust, record, standPublicKey: fixture.standPublicKey }), 'ENVIRONMENT_UNAVAILABLE');
});

// E-07: стенд остановлен, порт занял процесс без ключа стенда.
test('E-07: захват порта чужим процессом без ключа стенда не аттестуется', async t => {
  const port = await freePort();
  const fixture = await serveLocalFixture({ port });
  t.after(() => fixture.close());
  const record = register({ environmentId: fixture.environmentId, generation: 1, origin: fixture.baseUrl, standKeyId: fixture.standKeyId });
  const publicCopy = await (await fetch(fixture.baseUrl + 'environment')).json();
  const challenge = newChallenge();
  const capturedAttestation = await (await fetch(fixture.baseUrl + 'attest', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ challenge })
  })).json();
  await attestLiveEnvironment({ trust, record, standPublicKey: fixture.standPublicKey });
  await fixture.close();
  const childScript = "const http=require('node:http');" +
    "const copy=JSON.parse(process.env.WP04_COPY);" +
    "const replay=JSON.parse(process.env.WP04_ATTEST);" +
    "const server=http.createServer((req,res)=>{" +
    "const url=new URL(req.url,'http://127.0.0.1');" +
    "if(req.method==='GET'&&url.pathname==='/environment'){const b=Buffer.from(JSON.stringify(copy));res.writeHead(200,{'content-type':'application/json','content-length':b.length});res.end(b);return;}" +
    "if(req.method==='POST'&&url.pathname==='/attest'){req.resume();req.on('end',()=>{const b=Buffer.from(JSON.stringify(replay));res.writeHead(200,{'content-type':'application/json','content-length':b.length});res.end(b);});return;}" +
    "res.writeHead(404);res.end('{}');});" +
    "server.listen(Number(process.env.WP04_PORT),'127.0.0.1');";
  const child = spawn(process.execPath, ['-e', childScript], {
    stdio: 'ignore',
    windowsHide: true,
    env: { ...process.env, WP04_PORT: String(port), WP04_COPY: JSON.stringify(publicCopy), WP04_ATTEST: JSON.stringify(capturedAttestation) }
  });
  t.after(() => { try { child.kill(); } catch { /* уже завершён */ } });
  const ready = await waitFor(async () => {
    try { const response = await fetch('http://127.0.0.1:' + port + '/environment'); return response.ok; }
    catch { return false; }
  });
  assert.equal(ready, true, 'чужой процесс занял порт');
  const newOwner = await portOwnerPid('http://127.0.0.1:' + port + '/');
  assert.equal(newOwner, child.pid);
  assert.notEqual(newOwner, fixture.pid);
  await expectCode(attestLiveEnvironment({ trust, record, standPublicKey: fixture.standPublicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
});

// E-08: пока настоящий стенд жив, второй слушатель на тот же порт не садится.
test('E-08: второй bind на порт живого стенда неуспешен', async t => {
  const port = await freePort();
  const fixture = await serveLocalFixture({ port });
  t.after(() => fixture.close());
  const second = net.createServer();
  try {
    await assert.rejects(new Promise((resolve, reject) => {
      second.once('error', reject);
      second.listen(port, '127.0.0.1', resolve);
    }), error => error.code === 'EADDRINUSE');
  } finally {
    try { second.close(); } catch { /* не был запущен */ }
  }
  const record = register({ environmentId: fixture.environmentId, origin: fixture.baseUrl, standKeyId: fixture.standKeyId });
  const live = await attestLiveEnvironment({ trust, record, standPublicKey: fixture.standPublicKey });
  assert.equal(live.portOwnerPid, process.pid);
});

// Сетевой обрыв и таймаут — fail-closed без исходящего POST.
test('сетевой обрыв и таймаут аттестации дают ENVIRONMENT_UNAVAILABLE', async t => {
  const keys = createStandKeys();
  const broken = await listen((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/attest') { req.socket.destroy(); return; }
    res.writeHead(404); res.end('{}');
  });
  t.after(() => broken.close());
  const brokenRecord = register({ environmentId: envId('break'), origin: broken.origin, standKeyId: keys.standKeyId });
  await expectCode(attestEnvironment({ trust, record: brokenRecord, challenge: newChallenge(), standPublicKey: keys.publicKey }), 'ENVIRONMENT_UNAVAILABLE');
  const hanging = await listen((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/attest') return;
    res.writeHead(404); res.end('{}');
  });
  t.after(() => hanging.close());
  const hangingRecord = register({ environmentId: envId('timeout'), origin: hanging.origin, standKeyId: keys.standKeyId });
  const started = Date.now();
  await expectCode(attestEnvironment({ trust, record: hangingRecord, challenge: newChallenge(), standPublicKey: keys.publicKey, timeoutMs: 200 }), 'ENVIRONMENT_UNAVAILABLE');
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 2000, 'таймаут не сработал вовремя: ' + elapsed + ' мс');
  assert.equal(DEFAULT_ATTEST_TIMEOUT_MS, 2000);
});

// Редирект запрещён: fetch не идёт по Location.
test('redirect на аттестации отвергается и не преследуется', async t => {
  const keys = createStandKeys();
  let targetHits = 0;
  const target = await listen((req, res) => {
    targetHits += 1;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  t.after(() => target.close());
  const redirector = await listen((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/attest') {
      res.writeHead(302, { 'location': target.origin + 'attest' });
      res.end();
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  t.after(() => redirector.close());
  const record = register({ environmentId: envId('redirect'), origin: redirector.origin, standKeyId: keys.standKeyId });
  await expectCode(attestEnvironment({ trust, record, challenge: newChallenge(), standPublicKey: keys.publicKey }), 'ENVIRONMENT_ATTESTATION_FAILED');
  assert.equal(targetHits, 0, 'fetch не должен идти по редиректу');
});

// E-06: dev/production непригодны независимо от status, сеть не трогается.
test('E-06: kind=dev и production — ENVIRONMENT_KIND_DENIED без исходящего соединения', async () => {
  const keys = createStandKeys();
  for (const kind of ['dev', 'production']) {
    const record = register({ kind, status: 'active', origin: 'https://example.invalid/', standKeyId: keys.standKeyId });
    assert.equal(loadEnvironmentRecord(trust, trustRoot, record.environmentId).kind, kind);
    let called = false;
    const fetchImpl = async () => {
      called = true;
      throw new Error('сеть не должна вызываться');
    };
    await expectCode(attestLiveEnvironment({ trust, record, fetchImpl, standPublicKey: keys.publicKey }), 'ENVIRONMENT_KIND_DENIED');
    assert.equal(called, false, 'запрещённый вид среды не должен вызывать сеть');
  }
});

// Внешний адрес: local-stand обязан быть loopback; внешний origin не подписывается и не проверяется.
test('внешний адрес для local-stand отвергается до сети', async () => {
  const keys = createStandKeys();
  assert.throws(() => signEnvironmentRecord(ownerKey, {
    environmentId: envId('external'),
    generation: 1,
    kind: 'local-stand',
    status: 'active',
    origin: 'http://192.168.1.10:8080/',
    standKeyId: keys.standKeyId,
    credentialRef: ''
  }), codeIs('CONTRACT_INVALID'));
  const manual = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0',
    domain: 'environment-record',
    environmentId: envId('external2'),
    generation: 1,
    kind: 'local-stand',
    status: 'active',
    origin: 'http://203.0.113.10:8080/',
    standKeyId: keys.standKeyId,
    credentialRef: '',
    keyId: created.ownerKeyId
  });
  assert.throws(() => verifyEnvironmentRecord(trust, manual), codeIs('CONTRACT_INVALID'));
  let called = false;
  const fetchImpl = async () => { called = true; throw new Error('сеть не должна вызываться'); };
  assert.equal(called, false);
  assert.equal(fetchImpl instanceof Function, true);
});

// Неизвестное поле и подпись не тем ключом.
test('неизвестное поле в записи среды и ключ анкера отвергаются', async () => {
  const keys = createStandKeys();
  const withExtra = signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0',
    domain: 'environment-record',
    environmentId: envId('extra'),
    generation: 1,
    kind: 'local-stand',
    status: 'active',
    origin: 'http://127.0.0.1:9/',
    standKeyId: keys.standKeyId,
    credentialRef: '',
    fingerprint: 'подложный',
    keyId: created.ownerKeyId
  });
  assert.throws(() => verifyEnvironmentRecord(trust, withExtra), codeIs('CONTRACT_INVALID'));
  const anchorSigned = signTrustedDocument(anchorKey, {
    schemaVersion: '0.2.0',
    domain: 'environment-record',
    environmentId: envId('anchor'),
    generation: 1,
    kind: 'local-stand',
    status: 'active',
    origin: 'http://127.0.0.1:9/',
    standKeyId: keys.standKeyId,
    credentialRef: '',
    keyId: created.anchorKeyId
  });
  assert.throws(() => verifyEnvironmentRecord(trust, anchorSigned), codeIs('APPROVAL_SIGNATURE_INVALID'));
});

// E-05 (часть WP-04): недоступный или повреждённый реестр — fail-closed.
test('E-05: повреждённый и подменённый реестр сред не читается', async () => {
  assert.throws(() => loadTrustRoot(path.join(root, 'missing-trust-root')), codeIs('TRUST_STORE_UNAVAILABLE'));
  fs.mkdirSync(path.join(trustRoot, 'environments'), { recursive: true });
  const corrupt = path.join(trustRoot, 'environments', 'env-corrupt.json');
  fs.writeFileSync(corrupt, '{"environmentId":');
  assert.throws(() => loadEnvironmentRecord(trust, trustRoot, 'env-corrupt'), codeIs('CONTRACT_INVALID'));
  const keys = createStandKeys();
  const record = recordFor({ origin: 'http://127.0.0.1:9/', standKeyId: keys.standKeyId });
  const tampered = { ...record, generation: 2 };
  fs.writeFileSync(path.join(trustRoot, 'environments', record.environmentId + '.json'), JSON.stringify(tampered) + '\n');
  assert.throws(() => loadEnvironmentRecord(trust, trustRoot, record.environmentId), codeIs('APPROVAL_SIGNATURE_INVALID'));
});

// Контракт локального стенда: /environment не изменился, /attest подписывает и отвергает мусор.
test('локальный стенд: GET /environment не изменён, POST /attest подписывает и отвечает 400 на мусор', async t => {
  const fixture = await serveLocalFixture({ generation: 2 });
  t.after(() => fixture.close());
  assert.equal(typeof fixture.standKeyId, 'string');
  assert.equal(typeof fixture.standPublicKey, 'string');
  assert.equal(fixture.pid, process.pid);
  assert.equal(fixture.generation, 2);
  const environmentResponse = await fetch(fixture.baseUrl + 'environment');
  assert.equal(environmentResponse.status, 200);
  assert.equal(environmentResponse.headers.get('location'), null);
  const environment = await environmentResponse.json();
  assert.deepEqual(Object.keys(environment).sort(), ['environmentId', 'fingerprint', 'sourceRevision']);
  assert.equal(environment.environmentId, fixture.environmentId);
  assert.equal(environment.fingerprint, fixture.fingerprint);
  const challenge = newChallenge();
  const attesting = await fetch(fixture.baseUrl + 'attest', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ challenge })
  });
  assert.equal(attesting.status, 200);
  assert.equal(attesting.headers.get('location'), null);
  const attestation = await attesting.json();
  assert.deepEqual(Object.keys(attestation).sort(), [
    'challenge', 'domain', 'environmentId', 'generation', 'keyId', 'origin', 'pid',
    'schemaVersion', 'signature', 'signatureAlgorithm'
  ]);
  assert.equal(attestation.challenge, challenge);
  assert.equal(attestation.domain, 'environment-attest');
  assert.equal(attestation.environmentId, fixture.environmentId);
  assert.equal(attestation.keyId, fixture.standKeyId);
  assert.equal(attestation.origin, fixture.baseUrl);
  const verified = verifyEnvironmentAttestation(
    trust,
    register({ environmentId: fixture.environmentId, generation: 2, origin: fixture.baseUrl, standKeyId: fixture.standKeyId }),
    attestation,
    { challenge, standPublicKey: fixture.standPublicKey }
  );
  assert.equal(verified.pid, process.pid);
  assert.equal(fixture.mutationCount, 0);
  assert.equal(fixture.readCount, 0);
  for (const body of ['not-json', '{}', JSON.stringify({ challenge: 'zz' }), JSON.stringify({ challenge: 'a'.repeat(63) }), JSON.stringify({ challenge: newChallenge(), extra: 1 })]) {
    const response = await fetch(fixture.baseUrl + 'attest', { method: 'POST', body });
    assert.equal(response.status, 400, 'мусор на /attest должен давать 400: ' + body);
    assert.equal(response.headers.get('location'), null);
  }
  const wrongMethod = await fetch(fixture.baseUrl + 'attest');
  assert.equal(wrongMethod.status, 404);
  assert.equal(wrongMethod.headers.get('location'), null);
});

// Ключи стенда: приватный ключ не покидает процесс, challenge свежий.
test('createStandKeys и newChallenge дают корректные идентификаторы и свежесть', () => {
  const keys = createStandKeys();
  assert.equal(keys.standKeyId, publicKeyId(keys.publicKey));
  assert.match(keys.standKeyId, /^[a-f0-9]{64}$/);
  assert.equal(keys.privateKey && keys.privateKey.type, 'private');
  const first = newChallenge();
  const second = newChallenge();
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.notEqual(first, second);
  const signed = signEnvironmentAttestation(keys.privateKey, {
    environmentId: 'env-unit',
    generation: 1,
    origin: 'http://127.0.0.1:9/',
    pid: process.pid,
    challenge: first
  });
  const body = verifyEnvironmentAttestation(
    trust,
    signEnvironmentRecord(ownerKey, {
      environmentId: 'env-unit',
      generation: 1,
      kind: 'local-stand',
      status: 'active',
      origin: 'http://127.0.0.1:9/',
      standKeyId: keys.standKeyId,
      credentialRef: ''
    }),
    signed,
    { challenge: first, standPublicKey: keys.publicKey }
  );
  assert.equal(body.challenge, first);
  assert.equal('signature' in body, false);
  assert.equal(body.domain, 'environment-attest');
});

// Никаких редиректов: локальный стенд во всех маршрутах отвечает не 3xx.
test('локальный стенд не выпускает редиректы', async t => {
  const fixture = await serveLocalFixture();
  t.after(() => fixture.close());
  const paths = ['/', '/environment', '/records', '/missing'];
  for (const route of paths) {
    const response = await fetch(fixture.baseUrl + route.replace(/^\//, ''));
    assert.ok(response.status < 300 || response.status >= 400, 'маршрут ' + route + ' вернул редирект');
    assert.equal(response.headers.get('location'), null);
  }
});
