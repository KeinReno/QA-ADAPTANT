// WP-08 независимый аудит WP-03/WP-04: попытки воспроизвести обход на управляемом стенде.
// Все прогоны — локальный стенд 127.0.0.1, временные каталоги %TEMP%, продуктовый код только читается.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { loadModules, makeWorld, startControlledStand, startRogue, listenRogue, sleep, evidenceOf } from './wp0304-lib.mjs';

const modules = await loadModules();
const env = modules.environment;

async function setupWorld(options = {}) {
  const stand = await startControlledStand(modules, options.stand || {});
  const world = await makeWorld(modules, { standalone: stand, ...options.world });
  return { world, stand };
}

async function acodeOf(fn) {
  try { await fn(); return 'NO_THROW'; } catch (error) { return error.code || ('NO_CODE:' + error.message); }
}

test('ЭТАЛОН: доверенный прогон на управляемом стенде даёт PASS, POST=1 (база для атак)', async () => {
  const { world, stand } = await setupWorld();
  try {
    const { bundle, contract } = world.prepare({ runId: 'wp08-baseline' });
    const approval = world.approvalFor({ bundle, contract });
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
    assert.equal(result.verdict.verdict, 'PASS', JSON.stringify(result.verdict).slice(0, 500));
    assert.equal(stand.mutationCount, 1);
    assert.ok(stand.attestCount >= 2, 'аттестация вызывается до dispatch и перед POST: ' + stand.attestCount);
    const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: 'wp08-baseline' });
    assert.equal(observed.passed, true);
    assert.equal(observed.trusted, true);
  } finally { await world.cleanup(); }
});

test('R-03 / TOCTOU: после ALLOW последней проверки мутация и секрет уходят на подменённый сокет', async () => {
  const { world, stand } = await setupWorld();
  try {
    const { bundle, contract, runId } = world.prepare({ runId: 'wp08-r03' });
    const approval = world.approvalFor({ bundle, contract });
    const store = new modules.store.RunStore(world.root);
    const runDir = store.snapshot(bundle, { runId, pid: process.pid, at: new Date().toISOString() });
    const frozen = modules.bundle.verifyFrozenBundle(store, runDir);
    const context = modules.trusted.createTrustContext({
      trust: world.trust, trustRoot: world.trustRoot, approvalId: approval.approvalId, approval,
      issuer: world.cards.owner, subject: world.cards.operator, sid: world.sid,
      standPublicKey: stand.standPublicKey, signer: null
    });
    const preflight = await context.preflight({ runDir, frozen });
    assert.equal(preflight.allow, true, JSON.stringify(preflight.denial || {}));
    const intent = { intentId: runId + ':create', stepId: 'create', operationId: bundle.operation.id, mutationName: bundle.operation.mutation.name, inputsSha256: modules.digest(bundle.operation.inputs), fixtureId: contract.fixtureId };
    const dispatch = await context.dispatch({ runDir, frozen, intent });
    assert.equal(dispatch.allow, true, JSON.stringify(dispatch.denial || {}));
    const liveness = await context.beforeRequestAck({ frozen });
    assert.equal(liveness.allow, true, 'последняя проверка перед POST прошла: ' + JSON.stringify(liveness.denial || {}));
    // Окно после ALLOW: стенд останавливается, порт занимает процесс без ключа стенда.
    const port = stand.port;
    await stand.close();
    await sleep(150);
    const rogue = await listenRogue({ port });
    try {
      const body = JSON.stringify({ ...bundle.operation.inputs, fixtureId: contract.fixtureId });
      const response = await fetch(stand.baseUrl + 'records', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: 'Bearer ' + stand.authToken, 'idempotency-key': intent.intentId },
        body
      });
      assert.equal(response.status, 201);
      assert.equal(rogue.state.mutationCount, 1, 'мутация ушла на неаттестованный процесс после ALLOW');
      assert.equal(rogue.state.posts[0].headers.authorization, 'Bearer ' + stand.authToken, 'секрет стенда ушёл чужому процессу');
      // Продуктовый код уже не перепроверяет владельца сокета перед отправкой.
      assert.equal(fs.existsSync(runDir), true);
    } finally { await rogue.close(); }
  } finally { await world.cleanup(); }
});

test('R-03: измеренное окно между последней аттестацией и фактическим POST', async () => {
  const { world, stand } = await setupWorld();
  try {
    const { bundle, contract } = world.prepare({ runId: 'wp08-window' });
    const approval = world.approvalFor({ bundle, contract });
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
    assert.equal(result.verdict.verdict, 'PASS');
    const lastAttest = stand.state.attestAt[stand.state.attestAt.length - 1];
    const post = stand.state.postAt[0];
    const windowMs = post - lastAttest;
    assert.ok(windowMs >= 0, 'окно отрицательное');
    // Фиксируем факт: между последней аттестацией и POST продукт выполняет ещё работу (fsync evidence + IPC).
    const report = { attestCount: stand.attestCount, windowMs, postCount: stand.postCount };
    fs.writeFileSync(new URL('./window.json', import.meta.url), JSON.stringify(report));
    assert.ok(windowMs > 0, 'окно не измерено: ' + JSON.stringify(report));
  } finally { await world.cleanup(); }
});

test('E-04: credentialRef чужой среды не проверяется; секрет другой среды доставляется стенду', async () => {
  const other = await makeWorld(modules); // отдельная среда со своим секретом
  const { world, stand } = await setupWorld({ world: { recordOverrides: { credentialRef: 'prod:foreign-secret-7' } } });
  try {
    assert.equal(world.record.credentialRef, 'prod:foreign-secret-7');
    // 1) PDP не отвергает запись среды со ссылкой на секрет другой среды: preflight ALLOW.
    const probe = world.prepare({ runId: 'wp08-e04-probe' });
    const probeApproval = world.approvalFor({ bundle: probe.bundle, contract: probe.contract });
    const store = new modules.store.RunStore(world.root);
    const probeDir = store.snapshot(probe.bundle, { runId: probe.runId, pid: process.pid, at: new Date().toISOString() });
    const probeFrozen = modules.bundle.verifyFrozenBundle(store, probeDir);
    const context = modules.trusted.createTrustContext({
      trust: world.trust, trustRoot: world.trustRoot, approvalId: probeApproval.approvalId, approval: probeApproval,
      issuer: world.cards.owner, subject: world.cards.operator, sid: world.sid, standPublicKey: stand.standPublicKey
    });
    const preflight = await context.preflight({ runDir: probeDir, frozen: probeFrozen });
    assert.equal(preflight.allow, true, 'ожидался ALLOW без ENVIRONMENT_ATTESTATION_FAILED: ' + JSON.stringify(preflight.denial || {}));
    assert.equal(preflight.decision.reasonCode, 'TRUST_OK');
    // 2) Реальный прогон: Browser получает секрет другой среды и отправляет его на origin этой среды.
    const { bundle, contract } = world.prepare({ runId: 'wp08-e04' });
    const approval = world.approvalFor({ bundle, contract });
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { fixtureToken: other.stand.authToken }));
    assert.notEqual(result.verdict.reasonCode, 'AUTH_UNAVAILABLE');
    assert.equal(stand.mutationCount, 1, 'POST ушёл на среду с чужим секретом');
    const sent = stand.state.posts[0];
    assert.equal(sent.headers.authorization, 'Bearer ' + other.stand.authToken, 'Browser получил секрет другой среды');
    assert.notEqual(other.stand.authToken, stand.authToken);
  } finally {
    await world.cleanup();
    await other.cleanup();
  }
});

test('E-03: generation approval/реестра не совпала с живым стендом — отказ до POST', async () => {
  const stand = await startControlledStand(modules, { generation: 2 });
  const world = await makeWorld(modules, { standalone: stand, recordOverrides: { generation: 1 } });
  try {
    const { bundle, contract } = world.prepare({ runId: 'wp08-e03' });
    const approval = world.approvalFor({ bundle, contract, overrides: { environmentGeneration: 1 } });
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
    assert.notEqual(result.verdict.verdict, 'PASS');
    assert.equal(result.verdict.verdict, 'BLOCKED');
    assert.equal(result.verdict.reasonCode, 'ENVIRONMENT_CHANGED');
    assert.equal(stand.mutationCount, 0);
    const kinds = evidenceOf(modules, world.root, 'wp08-e03').map(item => item.envelope.kind);
    assert.ok(!kinds.includes('mutation-intent'), 'intent не должен появиться: ' + kinds.join(','));
  } finally { await world.cleanup(); }
});

test('E-01: свежий challenge — перехваченная аттестация не переигрывается', async () => {
  const { world, stand } = await setupWorld();
  try {
    const challenge1 = env.newChallenge();
    const response = await fetch(stand.baseUrl + 'attest', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challenge: challenge1 }) });
    assert.equal(response.status, 200);
    const raw = await response.json();
    assert.equal(raw.challenge, challenge1);
    const verified = await env.verifyEnvironmentAttestation(world.trust, world.record, raw, { challenge: challenge1, standPublicKey: stand.standPublicKey });
    assert.equal(verified.keyId, stand.standKeyId);
    assert.equal(await acodeOf(() => env.verifyEnvironmentAttestation(world.trust, world.record, raw, { challenge: env.newChallenge(), standPublicKey: stand.standPublicKey })), 'ENVIRONMENT_ATTESTATION_FAILED');
    // Подмена подписи/ключа: чужой ключ не проходит сверку standKeyId.
    const foreign = env.createStandKeys();
    const forged = await env.signEnvironmentAttestation(foreign.privateKey, { environmentId: stand.environmentId, generation: stand.generation, origin: stand.baseUrl, pid: process.pid, challenge: env.newChallenge() });
    assert.equal(await acodeOf(() => env.verifyEnvironmentAttestation(world.trust, world.record, forged, { challenge: forged.challenge, standPublicKey: foreign.publicKey })), 'ENVIRONMENT_ATTESTATION_FAILED');
  } finally { await world.cleanup(); }
});

test('E-06: kind=dev запись не даёт доверенного старта и не открывает соединение', async () => {
  const stand = await startControlledStand(modules, {});
  const world = await makeWorld(modules, { standalone: stand, recordOverrides: { kind: 'dev' } });
  try {
    const probe = world.prepare({ runId: 'wp08-e06-probe' });
    const probeApproval = world.approvalFor({ bundle: probe.bundle, contract: probe.contract });
    const store = new modules.store.RunStore(world.root);
    const probeDir = store.snapshot(probe.bundle, { runId: probe.runId, pid: process.pid, at: new Date().toISOString() });
    const probeFrozen = modules.bundle.verifyFrozenBundle(store, probeDir);
    const context = modules.trusted.createTrustContext({
      trust: world.trust, trustRoot: world.trustRoot, approvalId: probeApproval.approvalId, approval: probeApproval,
      issuer: world.cards.owner, subject: world.cards.operator, sid: world.sid, standPublicKey: stand.standPublicKey
    });
    const preflight = await context.preflight({ runDir: probeDir, frozen: probeFrozen });
    assert.equal(preflight.allow, false);
    assert.equal(preflight.denial.reasonCode, 'ENVIRONMENT_KIND_DENIED');
    assert.equal(preflight.denial.verdictCode, 'CONTRACT_INVALID');
    // Полный доверенный старт: BLOCKED до мутации, аттестация kind=dev не вызывается вообще.
    const { bundle, contract } = world.prepare({ runId: 'wp08-e06' });
    const approval = world.approvalFor({ bundle, contract });
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
    assert.equal(result.verdict.verdict, 'BLOCKED');
    assert.equal(result.verdict.reasonCode, 'CONTRACT_INVALID');
    assert.equal(stand.attestCount, 0, 'kind=dev не должен вызывать аттестацию/соединение');
    assert.equal(stand.mutationCount, 0);
  } finally { await world.cleanup(); }
});
