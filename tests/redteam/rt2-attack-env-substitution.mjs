// GAP-02: подмена среды. На интеграции WP-04 должен ловить:
// (A) зеркало, копирующее публичные поля и старую аттестацию, на том же origin;
// (B) сервер без ключа стенда (нет /attest);
// (C) подмена стенда на другой реальный стенд с другим ключом на том же origin.
// Ожидание для всех: DENY ENVIRONMENT_CHANGED до POST, 0 мутаций, нет intent.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence, startRogueServer, sleep } from './_w2.mjs';

async function listenRogue(options) {
  let lastError = null;
  for (let attempt = 0; attempt < 40; attempt++) {
    try { return await startRogueServer(options); } catch (error) { lastError = error; await sleep(100); }
  }
  throw lastError;
}

async function listenStand(modules, options) {
  let lastError = null;
  for (let attempt = 0; attempt < 40; attempt++) {
    try { return await modules.server.serveLocalFixture(options); } catch (error) { lastError = error; await sleep(100); }
  }
  throw lastError;
}

await caseMain({ id: 'GAP-02', title: 'Подмена среды на том же origin', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules, { withSigner: false });
  cleanup(world.cleanup);
  const stand = world.stand;
  const origin = stand.baseUrl;
  const port = Number(new URL(origin).port);
  const environmentId = stand.environmentId;
  const fingerprint = stand.fingerprint;
  const generation = stand.generation;
  const challenge = modules.environment.newChallenge();
  const captured = await modules.environment.attestEnvironment({ record: world.record, trust: world.trust, challenge, standPublicKey: stand.standPublicKey });
  const mirrorRun = world.prepare({ runId: 'rt2-gap02-mirror' });
  const mirrorApproval = world.approvalFor({ bundle: mirrorRun.bundle, contract: mirrorRun.contract });
  const noKeyRun = world.prepare({ runId: 'rt2-gap02-nokey' });
  const noKeyApproval = world.approvalFor({ bundle: noKeyRun.bundle, contract: noKeyRun.contract });
  const keyRun = world.prepare({ runId: 'rt2-gap02-key' });
  const keyApproval = world.approvalFor({ bundle: keyRun.bundle, contract: keyRun.contract });
  await stand.close();
  await sleep(150);

  // (A) Зеркало с копией публичных полей и старой аттестацией на том же origin.
  const mirror = await listenRogue({ port, environmentId, fingerprint, attestation: captured });
  const a = await modules.trusted.startTrusted(mirrorRun.bundle, world.trustedOptions(mirrorApproval));
  checkTrustedDenial(checks, a, { verdict: 'BLOCKED', reasonCodes: ['ENVIRONMENT_CHANGED'] });
  check(checks, '(A) зеркало получило запрос аттестации, но не POST', mirror.state.attestCount >= 1 && mirror.state.mutationCount === 0, { attestCount: mirror.state.attestCount, mutationCount: mirror.state.mutationCount, requests: mirror.state.requests });
  checkNoEvidence(checks, modules, world, mirrorRun.bundle.manifest.runId, ['mutation-intent', 'request']);
  await mirror.close();
  await sleep(150);

  // (B) Процесс без ключа стенда: /attest отсутствует.
  const noKey = await listenRogue({ port, environmentId, fingerprint, attestation: null });
  const b = await modules.trusted.startTrusted(noKeyRun.bundle, world.trustedOptions(noKeyApproval));
  checkTrustedDenial(checks, b, { verdict: 'BLOCKED', reasonCodes: ['ENVIRONMENT_CHANGED'] });
  check(checks, '(B) сервер без ключа не получил POST', noKey.state.mutationCount === 0, { requests: noKey.state.requests });
  checkNoEvidence(checks, modules, world, noKeyRun.bundle.manifest.runId, ['mutation-intent', 'request']);
  await noKey.close();
  await sleep(150);

  // (C) Другой реальный стенд с другим ключом на том же origin.
  const other = await listenStand(modules, { port, environmentId, generation });
  try {
    const c = await modules.trusted.startTrusted(keyRun.bundle, world.trustedOptions(keyApproval));
    checkTrustedDenial(checks, c, { verdict: 'BLOCKED', reasonCodes: ['ENVIRONMENT_CHANGED'] });
    check(checks, '(C) подменённый стенд не получил POST', other.mutationCount === 0, { mutationCount: other.mutationCount });
    checkNoEvidence(checks, modules, world, keyRun.bundle.manifest.runId, ['mutation-intent', 'request']);
    check(checks, 'ключ подменённого стенда отличается от записи реестра', other.standKeyId !== world.record.standKeyId);
  } finally { await other.close(); }
  return { checks };
} });
