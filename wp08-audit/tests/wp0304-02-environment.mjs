// WP-08 независимый аудит WP-04: реестр сред, подпись/поколение/standKeyId, свежий
// challenge-response, PID/владелец порта, монопольный bind, kind=dev/production, целостность.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, startRogue, sleep, listenRogue } from './wp0304-lib.mjs';

const modules = await loadModules();
const env = modules.environment;

function codeOf(fn) {
  try { fn(); return 'NO_THROW'; } catch (error) { return error.code || ('NO_CODE:' + error.message); }
}
async function acodeOf(fn) {
  try { await fn(); return 'NO_THROW'; } catch (error) { return error.code || ('NO_CODE:' + error.message); }
}

function withStand(fn) {
  return async () => {
    const world = await makeWorld(modules);
    try { return await fn(world); } finally { await world.cleanup(); }
  };
}

test('E-01: повтор ранее снятой аттестации не проходит свежий challenge', withStand(async world => {
  const stand = world.stand;
  const challenge1 = env.newChallenge();
  const first = await env.attestEnvironment({ record: world.record, trust: world.trust, challenge: challenge1, standPublicKey: stand.standPublicKey });
  assert.equal(first.attestation.challenge, challenge1);
  assert.equal(first.attestation.origin, stand.baseUrl);
  assert.equal(first.attestation.pid, process.pid);
  const challenge2 = env.newChallenge();
  assert.notEqual(challenge1, challenge2);
  // Модуль возвращает проверенное тело без подписи: предъявление его как нового документа отвергается формой.
  assert.equal(await acodeOf(() => env.verifyEnvironmentAttestation(world.trust, world.record, first.attestation, { challenge: challenge2, standPublicKey: stand.standPublicKey })), 'CONTRACT_INVALID');
  // Полное зеркало публичных полей на том же origin без ключа стенда: аттестация не выдаётся.
  const port = Number(new URL(stand.baseUrl).port);
  await stand.close();
  await sleep(150);
  const mirror = await listenRogue({ port, environmentId: stand.environmentId, fingerprint: stand.fingerprint, attestation: null });
  try {
    assert.equal(await acodeOf(() => env.attestLiveEnvironment({ trust: world.trust, record: world.record, standPublicKey: stand.standPublicKey })), 'ENVIRONMENT_ATTESTATION_FAILED');
    assert.equal(mirror.state.attestCount, 1);
    assert.equal(mirror.state.mutationCount, 0);
  } finally { await mirror.close(); }
  await sleep(150);
  // Зеркало, отдающее перехваченную аттестацию: challenge другой -> отказ.
  const replay = await listenRogue({ port, environmentId: stand.environmentId, fingerprint: stand.fingerprint, attestation: first.attestation });
  try {
    assert.equal(await acodeOf(() => env.attestEnvironment({ record: world.record, trust: world.trust, challenge: env.newChallenge(), standPublicKey: stand.standPublicKey })), 'ENVIRONMENT_ATTESTATION_FAILED');
  } finally { await replay.close(); }
}));

test('E-07: живой процесс и владелец порта проверяются до dispatch; cмена владельца порта ловится', withStand(async world => {
  const live = await env.attestLiveEnvironment({ trust: world.trust, record: world.record, standPublicKey: world.stand.standPublicKey });
  assert.equal(live.portOwnerPid, process.pid);
  assert.equal(await env.portOwnerPid('http://10.0.0.1:80/'), null);
  assert.equal(await env.portOwnerPid('http://127.0.0.1:1/'), null);
  assert.equal(env.processAlive(0), false);
  assert.equal(env.processAlive(process.pid), true);
  const port = Number(new URL(world.stand.baseUrl).port);
  await world.stand.close();
  await sleep(150);
  const rogue = await listenRogue({ port });
  try {
    assert.equal(await acodeOf(() => env.attestLiveEnvironment({ trust: world.trust, record: world.record, standPublicKey: world.stand.standPublicKey })), 'ENVIRONMENT_ATTESTATION_FAILED');
    assert.equal(rogue.state.mutationCount, 0);
  } finally { await rogue.close(); }
}));

test('E-08: монопольный bind — второй слушатель того же порта не создаётся', async () => {
  let stand = null;
  let port = 0;
  for (let attempt = 0; attempt < 20 && !stand; attempt++) {
    port = 40000 + Math.floor(Math.random() * 20000);
    try { stand = await modules.server.serveLocalFixture({ port }); } catch { stand = null; }
  }
  assert.ok(stand, 'не удалось занять свободный порт');
  try {
    await assert.rejects(() => modules.server.serveLocalFixture({ port }), error => error.code === 'EADDRINUSE');
    await assert.rejects(() => startRogue({ port }), error => error.code === 'EADDRINUSE');
    assert.equal(await env.portOwnerPid(stand.baseUrl), process.pid);
  } finally { await stand.close(); }
});

test('E-06: kind=dev/production не аттестуется и не открывает соединение', withStand(async world => {
  for (const kind of ['dev', 'production']) {
    const record = env.signEnvironmentRecord(world.ownerKey, {
      environmentId: 'env-' + kind + '-' + Date.now(), generation: 1, kind, status: 'active',
      origin: world.stand.baseUrl, standKeyId: world.stand.standKeyId, credentialRef: 'local:fixture-token'
    });
    let fetched = 0;
    const fetchImpl = () => { fetched++; throw new Error('соединение запрещено'); };
    assert.equal(await acodeOf(() => env.attestEnvironment({ record, trust: world.trust, challenge: env.newChallenge(), fetchImpl, standPublicKey: world.stand.standPublicKey })), 'ENVIRONMENT_KIND_DENIED');
    assert.equal(fetched, 0, kind + ': попытка соединения до отказа по виду среды');
  }
}));

test('Подпись записи среды: неподписанная/подменённая запись отвергается', withStand(async world => {
  const fields = {
    environmentId: world.stand.environmentId, generation: 1, kind: 'local-stand', status: 'active',
    origin: world.stand.baseUrl, standKeyId: world.stand.standKeyId, credentialRef: ''
  };
  assert.equal(codeOf(() => env.verifyEnvironmentRecord(world.trust, fields)), 'CONTRACT_INVALID');
  const signed = env.signEnvironmentRecord(world.ownerKey, fields);
  const tampered = { ...signed, origin: 'http://127.0.0.1:49999/' };
  assert.equal(codeOf(() => env.verifyEnvironmentRecord(world.trust, tampered)), 'APPROVAL_SIGNATURE_INVALID');
  // Чужой ключ owner: подпись другого owner не принимается доверенным корнем.
  const foreignRoot = await makeWorld(modules, { withRecord: false });
  try {
    const foreignSigned = env.signEnvironmentRecord(foreignRoot.ownerKey, { ...fields, environmentId: 'env-foreign-' + Date.now() });
    assert.equal(codeOf(() => env.verifyEnvironmentRecord(world.trust, foreignSigned)), 'APPROVAL_SIGNATURE_INVALID');
  } finally { await foreignRoot.cleanup(); }
  // Поколение и отзыв в реестре.
  const generationTwo = env.signEnvironmentRecord(world.ownerKey, { ...fields, generation: 2, status: 'revoked' });
  env.commitEnvironmentRecord(world.trust, world.trustRoot, generationTwo);
  assert.equal(codeOf(() => env.loadEnvironmentRecord(world.trust, world.trustRoot, fields.environmentId)), 'ENVIRONMENT_REVOKED');
  const backward = env.signEnvironmentRecord(world.ownerKey, { ...fields, generation: 1 });
  assert.equal(codeOf(() => env.commitEnvironmentRecord(world.trust, world.trustRoot, backward)), 'CONTRACT_INVALID');
  // E-05: повреждённая запись в реестре -> fail-closed CONTRACT_INVALID.
  const directory = path.join(world.trustRoot, 'environments', fields.environmentId);
  fs.writeFileSync(path.join(directory, '2.json'), '{повреждено');
  assert.equal(codeOf(() => env.loadEnvironmentRecord(world.trust, world.trustRoot, fields.environmentId)), 'CONTRACT_INVALID');
}));

test('R-08: standKeyId связывает аттестацию с owner-подписанной записью, но ключ стенда приходит извне', withStand(async world => {
  // Подмена ключа стенда: аттестация подписана другим ключом -> отказ.
  const foreign = env.createStandKeys();
  const attestation = env.signEnvironmentAttestation(foreign.privateKey, {
    environmentId: world.stand.environmentId, generation: 1, origin: world.stand.baseUrl,
    pid: process.pid, challenge: env.newChallenge()
  });
  const challenge = attestation.challenge;
  assert.equal(await acodeOf(() => env.verifyEnvironmentAttestation(world.trust, world.record, attestation, { challenge, standPublicKey: foreign.publicKey })), 'ENVIRONMENT_ATTESTATION_FAILED');
  // Тот же self-signed ключ принимается, если owner подписал запись с его standKeyId:
  // привязки к trust root (реестру ключей стендов) нет — это и есть R-08.
  const selfRecord = env.signEnvironmentRecord(world.ownerKey, {
    environmentId: 'env-r08-' + Date.now(), generation: 1, kind: 'local-stand', status: 'active',
    origin: world.stand.baseUrl, standKeyId: foreign.standKeyId, credentialRef: ''
  });
  const selfAttestation = env.signEnvironmentAttestation(foreign.privateKey, {
    environmentId: selfRecord.environmentId, generation: 1, origin: world.stand.baseUrl,
    pid: process.pid, challenge: 'ab'.repeat(32)
  });
  const verified = await env.verifyEnvironmentAttestation(world.trust, selfRecord, selfAttestation, { challenge: 'ab'.repeat(32), standPublicKey: foreign.publicKey });
  assert.equal(verified.keyId, foreign.standKeyId);
  // Без явного standPublicKey ключ стенда не находится в trust root: R-08 зафиксирован.
  assert.equal(await acodeOf(() => env.verifyEnvironmentAttestation(world.trust, selfRecord, selfAttestation, { challenge: 'ab'.repeat(32) })), 'ENVIRONMENT_ATTESTATION_FAILED');
}));

test('ИНТЕГРАЦИЯ: Symbol-метка «уже проверено» не связана с содержимым записи (мутация после проверки)', withStand(async world => {
  const loaded = env.loadEnvironmentRecord(world.trust, world.trustRoot, world.stand.environmentId);
  assert.equal(loaded.kind, 'local-stand');
  // Мутируем уже проверенное тело: повторная проверка не сверяет подпись.
  loaded.kind = 'dev';
  loaded.origin = 'http://127.0.0.1:1/';
  loaded.standKeyId = 'f'.repeat(64);
  const reverified = env.verifyEnvironmentRecord(world.trust, loaded);
  assert.equal(reverified.kind, 'dev', 'проверка приняла мутированное тело');
  assert.equal(reverified.origin, 'http://127.0.0.1:1/');
  // Следствие: неподписанное поколение можно записать в реестр (деградация до CONTRACT_INVALID при чтении).
  loaded.generation = 9;
  const committed = env.commitEnvironmentRecord(world.trust, world.trustRoot, loaded);
  assert.equal(committed.generation, 9);
  assert.equal(codeOf(() => env.loadEnvironmentRecord(world.trust, world.trustRoot, world.stand.environmentId)), 'CONTRACT_INVALID');
}));

test('Реестр: поколение строго вперёд, повтор тех же байт идемпотентен, конфликт отвергается', withStand(async world => {
  const fields = {
    environmentId: world.stand.environmentId, generation: 2, kind: 'local-stand', status: 'active',
    origin: world.stand.baseUrl, standKeyId: world.stand.standKeyId, credentialRef: ''
  };
  const record = env.signEnvironmentRecord(world.ownerKey, fields);
  assert.equal(env.commitEnvironmentRecord(world.trust, world.trustRoot, record).generation, 2);
  assert.equal(env.commitEnvironmentRecord(world.trust, world.trustRoot, record).generation, 2);
  const conflict = env.signEnvironmentRecord(world.ownerKey, { ...fields, credentialRef: 'local:other' });
  assert.equal(codeOf(() => env.commitEnvironmentRecord(world.trust, world.trustRoot, conflict)), 'CONTRACT_INVALID');
  assert.equal(env.loadEnvironmentRecord(world.trust, world.trustRoot, fields.environmentId).generation, 2);
}));
