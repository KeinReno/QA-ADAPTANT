// wp0102: независимые атаки на WP-02 (approval): replay, домены, привязки, гонки, обрыв, отзыв.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { digest } from '../../packages/core/canonical.mjs';
import {
  commitApproval, consumeDispatch, readApprovalState, revokeApproval, signApproval, verifyApproval
} from '../../packages/trust/approval.mjs';
import { approvalFact } from '../../packages/trust/facts.mjs';
import { signTrustedDocument } from '../../packages/trust/identity.mjs';
import {
  commit, consumptionFile, dispatchRequest, expected, fields, makeWorld, removeWorld,
  tempDir, waitForFile, FOREIGN_SID
} from './wp0102-fixture.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const worker = path.join(repoRoot, 'wp08-audit', 'tests', 'wp0102-consumer.mjs');
const world = await makeWorld({ prefix: 'wp0102-approval-' });
test.after(() => removeWorld(world));

function consumptionRecord(file) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  const body = {
    approvalId: value.approvalId, runId: value.runId, decisionId: value.decisionId,
    inputsHash: value.inputsHash, environmentGeneration: value.environmentGeneration, consumedAt: value.consumedAt
  };
  assert.equal(value.bodySha256, digest(body), 'bodySha256 сходится с каноническим телом');
  return value;
}

function runWorker(request, { barrier = false } = {}) {
  const dir = tempDir('wp0102-child-');
  const requestFile = path.join(dir, 'request.json');
  const resultFile = path.join(dir, 'result.json');
  const payload = { ...request, resultFile };
  if (barrier) payload.readyFile = path.join(dir, 'ready');
  fs.writeFileSync(requestFile, JSON.stringify(payload));
  const child = spawn(process.execPath, [worker, requestFile], { stdio: 'ignore', windowsHide: true });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', () => {
      try { resolve(JSON.parse(fs.readFileSync(resultFile, 'utf8'))); }
      catch (error) { reject(new Error('дочерний процесс не оставил результат: ' + error.message)); }
    });
  });
  return { child, ready: barrier ? waitForFile(payload.readyFile, 20000) : Promise.resolve(), done, dir };
}

test('привязки operation/inputs/fixture/scenario/generation/effects/resource/runId отвергаются без расхода', () => {
  const cases = [
    ['операция (id)', { operation: { ...world.operation, id: 'other-operation' } }],
    ['операция (version)', { operation: { ...world.operation, version: '9.9.9' } }],
    ['входы', { inputs: { ...world.inputs, title: 'подмена' } }],
    ['fixture', { fixtureId: 'fixture-other' }],
    ['сценарий', { scenarioContentSha256: digest({ id: 'other-scenario' }) }],
    ['среда', { environmentId: 'other-stand' }],
    ['поколение', { environmentGeneration: 2 }],
    ['эффекты (порядок)', { effects: [...world.effects].reverse() }],
    ['ресурс', { resource: { method: 'POST', path: '/records-other' } }]
  ];
  for (let index = 0; index < cases.length; index += 1) {
    const [name, overrides] = cases[index];
    const id = 'wp0102-bind-' + index;
    const approval = commit(world, id);
    assert.throws(
      () => consumeDispatch(dispatchRequest(world, approval, { runId: 'run-bind', overrides: { expected: expected(world, overrides) } })),
      error => error.code === 'APPROVAL_MISMATCH',
      'несовпадение: ' + name
    );
    assert.equal(fs.existsSync(consumptionFile(world, id)), false, 'расход не создан: ' + name);
  }
  // Отсутствие фактических входов — тоже отказ, а не доверие approval.
  const approval = commit(world, 'wp0102-bind-no-expected');
  assert.throws(
    () => consumeDispatch({ ...dispatchRequest(world, approval, { runId: 'run-bind' }), expected: null }),
    error => error.code === 'APPROVAL_MISMATCH'
  );
});

test('one-shot: другой runId → APPROVAL_REPLAY, тот же runId → без второго ACK, файл неизменен', () => {
  const approval = commit(world, 'wp0102-oneshot');
  const first = consumeDispatch(dispatchRequest(world, approval, { runId: 'run-oneshot-a', decisionId: 'decision-oneshot-a' }));
  assert.equal(first.ack, true);
  assert.equal(first.code, 'TRUST_OK');
  const file = consumptionFile(world, 'wp0102-oneshot');
  const kept = fs.readFileSync(file);
  consumptionRecord(file);
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, approval, { runId: 'run-oneshot-b', decisionId: 'decision-oneshot-b' })),
    error => error.code === 'APPROVAL_REPLAY'
  );
  const again = consumeDispatch(dispatchRequest(world, approval, { runId: 'run-oneshot-a', decisionId: 'decision-oneshot-c' }));
  assert.equal(again.ack, false);
  assert.equal(again.code, 'APPROVAL_CONSUMED');
  assert.deepEqual(fs.readFileSync(file), kept, 'второй ACK не переписал расход');
  // Тот же approval на другом runId не подменяет runId в файле.
  assert.equal(JSON.parse(kept.toString('utf8')).runId, 'run-oneshot-a');
});

test('подмена закреплённого approval, подпись anchor-ключом и чужой keyId не дают ACK', () => {
  const tampered = commit(world, 'wp0102-tampered');
  const file = path.join(world.trustRoot, 'approvals', 'wp0102-tampered.json');
  const original = fs.readFileSync(file);
  const document = JSON.parse(original);
  document.signature = (document.signature[0] === '0' ? '1' : '0') + document.signature.slice(1);
  fs.writeFileSync(file, JSON.stringify(document) + '\n');
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, tampered, { runId: 'run-tampered' })),
    error => error.code === 'APPROVAL_SIGNATURE_INVALID'
  );
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-tampered')), false);
  fs.writeFileSync(file, original);

  const anchorApproval = signApproval(world.anchorKey, fields(world, 'wp0102-anchor-signed', { keyId: world.created.anchorKeyId }));
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, anchorApproval, { runId: 'run-anchor' })),
    error => error.code === 'APPROVAL_SIGNATURE_INVALID'
  );
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-anchor-signed')), false);
  // Подмена keyId в теле approval после подписи
  const swapped = { ...commit(world, 'wp0102-keyid-swap') };
  swapped.keyId = world.created.anchorKeyId;
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, swapped, { runId: 'run-swap' })),
    error => error.code === 'APPROVAL_SIGNATURE_INVALID'
  );
});

test('чужой издатель, чужой субъект и чужой SID не авторизуют расход', () => {
  const foreignIssuer = commit(world, 'wp0102-foreign-issuer', { issuerPrincipalId: 'other-owner' });
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, foreignIssuer, { runId: 'run-fi' })),
    error => error.code === 'ROLE_DENIED'
  );
  const foreignSubject = commit(world, 'wp0102-foreign-subject', { subjectPrincipalId: 'other-operator' });
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, foreignSubject, { runId: 'run-fs' })),
    error => error.code === 'ROLE_DENIED'
  );
  const foreignSid = commit(world, 'wp0102-foreign-sid');
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, foreignSid, { runId: 'run-fsid', overrides: { windowsSid: FOREIGN_SID } })),
    error => error.code === 'CALLER_UNAUTHENTICATED'
  );
  for (const id of ['wp0102-foreign-issuer', 'wp0102-foreign-subject', 'wp0102-foreign-sid']) {
    assert.equal(fs.existsSync(consumptionFile(world, id)), false);
  }
});

test('отзыв: до расхода запрещает, после расхода не отменяет уже выданный ACK и не даёт второй', () => {
  const before = commit(world, 'wp0102-revoked-before');
  revokeApproval(world.ownerKey, world.trustRoot, {
    approvalId: 'wp0102-revoked-before', reason: 'owner-revoked', revokedAt: new Date().toISOString(), keyId: world.created.ownerKeyId
  });
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, before, { runId: 'run-revoked' })),
    error => error.code === 'APPROVAL_REVOKED'
  );
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-revoked-before')), false);
  // Файл отзыва не заменяется вторым отзывом.
  assert.throws(
    () => revokeApproval(world.ownerKey, world.trustRoot, {
      approvalId: 'wp0102-revoked-before', reason: 'environment-revoked', revokedAt: new Date().toISOString(), keyId: world.created.ownerKeyId
    }),
    error => error.code === 'APPROVAL_REVOKED'
  );
  const after = commit(world, 'wp0102-revoked-after');
  const consumed = consumeDispatch(dispatchRequest(world, after, { runId: 'run-revoked-after' }));
  assert.equal(consumed.ack, true);
  revokeApproval(world.ownerKey, world.trustRoot, {
    approvalId: 'wp0102-revoked-after', reason: 'owner-revoked', revokedAt: new Date().toISOString(), keyId: world.created.ownerKeyId
  });
  const replaySame = consumeDispatch(dispatchRequest(world, after, { runId: 'run-revoked-after' }));
  assert.equal(replaySame.ack, false);
  assert.equal(replaySame.code, 'APPROVAL_CONSUMED');
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, after, { runId: 'run-revoked-after-2' })),
    error => error.code === 'APPROVAL_REPLAY'
  );
});

test('срок: просроченный и ещё не вступивший approval запрещают расход', () => {
  const now = Date.now();
  const expired = commit(world, 'wp0102-expired', {
    issuedAt: new Date(now - 12 * 60_000).toISOString(), expiresAt: new Date(now - 60_000).toISOString()
  });
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, expired, { runId: 'run-expired' })),
    error => error.code === 'APPROVAL_EXPIRED'
  );
  const early = commit(world, 'wp0102-early', {
    issuedAt: new Date(now + 5 * 60_000).toISOString(), expiresAt: new Date(now + 12 * 60_000).toISOString()
  });
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, early, { runId: 'run-early' })),
    error => error.code === 'CONTRACT_INVALID'
  );
  assert.throws(
    () => signApproval(world.ownerKey, fields(world, 'wp0102-too-long', {
      expiresAt: new Date(Date.parse(fields(world, 'x').issuedAt) + 15 * 60_000 + 1).toISOString()
    })),
    error => error.code === 'CONTRACT_INVALID'
  );
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-expired')), false);
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-early')), false);
});

test('L-07: обрыв после CREATE_NEW оставляет неполный расход, повтор и другой runId не получают ACK', () => {
  const approval = commit(world, 'wp0102-torn');
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, approval, { runId: 'run-torn-a', fault: 'after-create' })),
    error => error.code === 'CONSUMPTION_INCOMPLETE'
  );
  const file = consumptionFile(world, 'wp0102-torn');
  assert.equal(fs.existsSync(file), true, 'имя создано через CREATE_NEW');
  const torn = fs.readFileSync(file);
  assert.equal(torn.includes(Buffer.from('bodySha256')), false, 'неполное тело без bodySha256');
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, approval, { runId: 'run-torn-a' })),
    error => error.code === 'CONSUMPTION_INCOMPLETE'
  );
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, approval, { runId: 'run-torn-b' })),
    error => error.code === 'CONSUMPTION_INCOMPLETE'
  );
  assert.deepEqual(fs.readFileSync(file), torn, 'файл не дописан и не заменён');
  // Повреждённый (непустой, но неполный) файл тоже не заменяется.
  const corrupt = commit(world, 'wp0102-corrupt');
  const corruptFile = consumptionFile(world, 'wp0102-corrupt');
  fs.mkdirSync(path.dirname(corruptFile), { recursive: true });
  fs.writeFileSync(corruptFile, '{"approvalId":"wp0102-corrupt","runId":"run-corrupt"}\n');
  const corruptBefore = fs.readFileSync(corruptFile);
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, corrupt, { runId: 'run-corrupt' })),
    error => error.code === 'CONSUMPTION_INCOMPLETE'
  );
  assert.deepEqual(fs.readFileSync(corruptFile), corruptBefore);
});

test('R-01: осиротевшая блокировка guard не даёт ни ACK, ни отзыва (fail-closed ~5 с)', { timeout: 60000 }, () => {
  const approval = commit(world, 'wp0102-orphan');
  const guards = path.join(world.trustRoot, 'guards');
  fs.mkdirSync(guards, { recursive: true });
  fs.writeFileSync(path.join(guards, 'wp0102-orphan.lock'), '');
  const started = Date.now();
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, approval, { runId: 'run-orphan' })),
    error => error.code === 'CONSUMPTION_INCOMPLETE'
  );
  const consumeElapsed = Date.now() - started;
  assert.ok(consumeElapsed >= 4000, 'ожидание ограничено и fail-closed: ' + consumeElapsed + ' мс');
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-orphan')), false);
  assert.throws(
    () => revokeApproval(world.ownerKey, world.trustRoot, {
      approvalId: 'wp0102-orphan', reason: 'owner-revoked', revokedAt: new Date().toISOString(), keyId: world.created.ownerKeyId
    }),
    error => error.code === 'CONSUMPTION_INCOMPLETE'
  );
  // Ручное восстановление после доказанной остановки даёт ровно один ACK.
  fs.rmSync(path.join(guards, 'wp0102-orphan.lock'));
  const first = consumeDispatch(dispatchRequest(world, approval, { runId: 'run-orphan' }));
  assert.equal(first.ack, true);
  const second = consumeDispatch(dispatchRequest(world, approval, { runId: 'run-orphan' }));
  assert.equal(second.ack, false);
  assert.equal(second.code, 'APPROVAL_CONSUMED');
});

test('L-01/L-09: четыре процесса, один approval, разные runId — не больше одного ACK и один полный файл', { timeout: 90000 }, async () => {
  const approval = commit(world, 'wp0102-race-diff');
  const barrierDir = tempDir('wp0102-race-diff-');
  const goFile = path.join(barrierDir, 'go');
  const racers = ['run-race-a', 'run-race-b', 'run-race-c', 'run-race-d'].map(runId =>
    runWorker({ dispatch: dispatchRequest(world, approval, { runId, decisionId: 'decision-' + runId }) }, { barrier: true })
  );
  for (const racer of racers) await racer.ready;
  fs.writeFileSync(goFile, 'go');
  const results = await Promise.all(racers.map(racer => racer.done));
  const acks = results.filter(result => result.ack === true);
  assert.equal(acks.length, 1, 'ровно один ACK: ' + JSON.stringify(results));
  const losers = results.filter(result => result.ack !== true);
  assert.equal(losers.length, 3);
  for (const loser of losers) {
    assert.ok(['APPROVAL_REPLAY', 'CONSUMPTION_INCOMPLETE'].includes(loser.code), 'код проигравшего: ' + loser.code);
  }
  const file = consumptionFile(world, 'wp0102-race-diff');
  const record = consumptionRecord(file);
  const kept = fs.readFileSync(file);
  assert.equal(record.runId, acks[0].runId);
  assert.throws(
    () => consumeDispatch(dispatchRequest(world, approval, { runId: 'run-race-e' })),
    error => error.code === 'APPROVAL_REPLAY'
  );
  assert.deepEqual(fs.readFileSync(file), kept, 'файл расхода не заменён');
  for (const racer of racers) fs.rmSync(racer.dir, { recursive: true, force: true });
  fs.rmSync(barrierDir, { recursive: true, force: true });
});

test('L-09: два процесса, один approval, один runId — ровно один ACK', { timeout: 90000 }, async () => {
  const approval = commit(world, 'wp0102-race-same');
  const barrierDir = tempDir('wp0102-race-same-');
  const goFile = path.join(barrierDir, 'go');
  const racers = ['first', 'second'].map(tag =>
    runWorker({ dispatch: dispatchRequest(world, approval, { runId: 'run-race-same', decisionId: 'decision-' + tag }) }, { barrier: true })
  );
  for (const racer of racers) { racer.dir = barrierDir; await racer.ready; }
  fs.writeFileSync(goFile, 'go');
  const results = await Promise.all(racers.map(racer => racer.done));
  assert.equal(results.filter(result => result.ack === true).length, 1);
  for (const loser of results.filter(result => result.ack !== true)) {
    assert.ok(['APPROVAL_CONSUMED', 'CONSUMPTION_INCOMPLETE'].includes(loser.code), 'код: ' + loser.code);
  }
  const record = consumptionRecord(consumptionFile(world, 'wp0102-race-same'));
  assert.equal(record.runId, 'run-race-same');
  assert.match(record.decisionId, /^decision-(first|second)$/);
  assert.equal(results.filter(result => result.ack === true).length, 1, 'второго ACK нет');
  fs.rmSync(barrierDir, { recursive: true, force: true });
});

test('отзыв другого процесса до расхода не даёт ACK: гонка с барьером перед guard', { timeout: 90000 }, async () => {
  const approval = commit(world, 'wp0102-race-revoke');
  const dir = tempDir('wp0102-race-revoke-');
  const readyFile = path.join(dir, 'ready');
  const releaseFile = path.join(dir, 'release');
  const consumer = runWorker({
    dispatch: { ...dispatchRequest(world, approval, { runId: 'run-race-revoke', fault: 'before-guard' }), readyFile, releaseFile }
  });
  await waitForFile(readyFile, 20000);
  const revoker = runWorker({
    mode: 'revoke', secretsDir: world.secretsDir, trustRoot: world.trustRoot,
    revoke: { approvalId: 'wp0102-race-revoke', reason: 'owner-revoked', revokedAt: new Date().toISOString(), keyId: world.created.ownerKeyId }
  });
  const revokeResult = await revoker.done;
  assert.equal(revokeResult.code, 'REVOKED_STORED');
  fs.writeFileSync(releaseFile, 'go');
  const consumeResult = await consumer.done;
  assert.equal(consumeResult.ack, false);
  assert.equal(consumeResult.code, 'APPROVAL_REVOKED');
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-race-revoke')), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('F-WP02-01: путь «только approvalId» в readApprovalState/consumeDispatch не работает (fail-closed)', () => {
  const approval = commit(world, 'wp0102-by-id');
  const context = { issuer: world.issuer, subject: world.subject, windowsSid: world.sid, trustRoot: world.trustRoot, approvalId: 'wp0102-by-id' };
  // verifyApproval по approvalId работает, readApprovalState — нет: options.approvalId теряется.
  const viewed = verifyApproval(world.trust, null, { ...context, purpose: 'view' });
  assert.equal(viewed.state, 'issued');
  assert.equal(viewed.body.approvalId, 'wp0102-by-id');
  assert.throws(() => readApprovalState(world.trust, null, context), error => error.code === 'CONTRACT_INVALID');
  // Сборщик фактов Control наследует дефект: без переданного документа approval не читается.
  const fact = approvalFact({ trust: world.trust, trustRoot: world.trustRoot, approvalId: 'wp0102-by-id', approval: null, issuer: world.issuer, subject: world.subject, windowsSid: world.sid, expected: null, runId: null });
  assert.equal(fact.body, null);
  assert.equal(fact.error, 'CONTRACT_INVALID');
  const factWithDoc = approvalFact({ trust: world.trust, trustRoot: world.trustRoot, approvalId: 'wp0102-by-id', approval, issuer: world.issuer, subject: world.subject, windowsSid: world.sid, expected: null, runId: null });
  assert.equal(factWithDoc.error, null);
  assert.equal(factWithDoc.state, 'issued');
  // Расход по одному approvalId тоже отвергается, хотя интерфейс это предусматривает.
  assert.throws(
    () => consumeDispatch({
      trustRoot: world.trustRoot, approvalId: 'wp0102-by-id', issuer: world.issuer, subject: world.subject,
      windowsSid: world.sid, expected: expected(world), runId: 'run-by-id', decisionId: 'decision-by-id'
    }),
    error => error.code === 'CONTRACT_INVALID'
  );
  assert.equal(fs.existsSync(consumptionFile(world, 'wp0102-by-id')), false);
});

test('F-04 (подтверждение): подмена trust-объекта позволяет израсходовать rogue-approval в чужом trust root', async () => {
  const rogue = await makeWorld({ prefix: 'wp0102-rogue-' });
  const rogueApproval = signApproval(rogue.ownerKey, fields(rogue, 'wp0102-injected'), rogue.trust, rogue.trustRoot);
  // Запись в чужой trust root возможна, если у вызывающего есть право записи в каталог.
  commitApproval(rogue.trust, world.trustRoot, rogueApproval);
  const injected = consumeDispatch({
    trust: rogue.trust, trustRoot: world.trustRoot, approval: rogueApproval,
    issuer: rogue.issuer, subject: rogue.subject, windowsSid: rogue.sid,
    expected: expected(rogue), runId: 'run-injected', decisionId: 'decision-injected'
  });
  assert.equal(injected.ack, true, 'переданный trust-объект полностью определяет проверку');
  consumptionRecord(consumptionFile(world, 'wp0102-injected'));
  // Без подмены trust тот же расход отвергается.
  assert.throws(
    () => consumeDispatch({
      trustRoot: world.trustRoot, approval: rogueApproval, issuer: rogue.issuer, subject: rogue.subject,
      windowsSid: rogue.sid, expected: expected(rogue), runId: 'run-injected-2', decisionId: 'decision-injected-2'
    }),
    error => error.code === 'APPROVAL_SIGNATURE_INVALID'
  );
  removeWorld(rogue);
});

test('пути хранения: approvalId не может выйти из каталога и не может быть device/ADS-именем', () => {
  for (const approvalId of ['../escape', 'a:b', 'x\\y', 'z/../w']) {
    assert.throws(
      () => signApproval(world.ownerKey, fields(world, approvalId), world.trust, world.trustRoot),
      error => error.code === 'CONTRACT_INVALID',
      'approvalId: ' + approvalId
    );
  }
  assert.throws(
    () => signApproval(world.ownerKey, fields(world, 'a'.repeat(161)), world.trust, world.trustRoot),
    error => error.code === 'CONTRACT_INVALID'
  );
});

test('второй POST после ACK невозможен по порядку Control: dispatch до intent, без ack нет ACK и POST', () => {
  const runSource = fs.readFileSync(path.join(repoRoot, 'apps/control/run.mjs'), 'utf8');
  const trustedSource = fs.readFileSync(path.join(repoRoot, 'apps/control/trusted.mjs'), 'utf8');
  const dispatchIndex = runSource.indexOf('trust.dispatch(');
  const intentIndex = runSource.indexOf("kind: 'mutation-intent'");
  const postGateIndex = runSource.indexOf("if (!intentRecord || requestRecord) throw");
  assert.ok(dispatchIndex > 0 && intentIndex > 0 && postGateIndex > 0);
  assert.ok(dispatchIndex < intentIndex, 'durable consumption/dispatch до mutation-intent');
  assert.ok(intentIndex < runSource.indexOf('HTTP_REQUEST'), 'intent до обработки POST');
  assert.match(runSource, /if \(!dispatch \|\| dispatch\.allow !== true\)/);
  assert.match(trustedSource, /if \(consumed\.ack !== true\)/);
  assert.match(trustedSource, /allow: false/);
});
