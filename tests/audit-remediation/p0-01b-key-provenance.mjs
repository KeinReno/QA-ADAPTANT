// AUD-P0-01B: происхождение ключа Verification и подмена verification-pid.
//
// Условие владельца §10.1/§10.3.2: чужой процесс не должен получить анкер/PASS, зарегистрировав
// свой публичный ключ как verification для runId, подменив verification-pid, запустив копию
// trusted-worker из другого пути, использовав мёртвый Worker или ключ, взятый из runDir/candidate.
//
// Атака выполняется через публичный (legacy) канал подписанта. Если такого канала на ревизии нет,
// сценарий возвращает INCONCLUSIVE (атака не выполнена), а не PASS.
//
// FAIL = хотя бы одна атака дала подписанный анкер/доверенный PASS.
// PASS = все атаки отвергнуты.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  loadModules, makeWorld, prepareForgeWithConsumption, spawnFakeTrustedWorker, runScenario, check,
  targetRoot, tempDir, removeDir, sleep
} from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P0-01B',
  title: 'Происхождение ключа Verification: чужой ключ, подмена pid, копия trusted-worker, мёртвый Worker, ключ из runDir',
  expected: 'Ни одна попытка не даёт подписанного анкера/доверенного PASS; подписант требует происхождение ключа Verification',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const work = tempDir('wp08-p001b-');
    const world = await makeWorld(M);
    try {
      const canRegister = Boolean(world.signer && M.anchorSigner.connectAnchorSigner);
      check(checks, 'публичный канал подписанта доступен для проверки (иначе INCONCLUSIVE)', canRegister, {
        signer: Boolean(world.signer), error: world.signerError || null
      });
      if (!canRegister || !world.signer) {
        return { defectObserved: false, actual: 'публичный канал подписанта недоступен: атаки на происхождение ключа не выполнены (INCONCLUSIVE)', evidence: { signerError: world.signerError }, checks };
      }
      const client = M.anchorSigner.connectAnchorSigner(world.signer.pipePath);
      const records = [];
      const attacker = generateKeyPairSync('ed25519');
      const attackerPublic = attacker.publicKey;
      const attackerKeyId = createHash('sha256').update(Buffer.from(attackerPublic.export({ format: 'jwk' }).x, 'base64url')).digest('hex');

      async function attempt(name, { registration = null, fakeWorker = null, attestationFor = null, keyInRunDir = false, runId, approvalId, forged }) {
        const result = { name, registered: null, signed: false, code: null, message: null, anchorPublish: null, observer: null };
        let rid = runId;
        try {
          if (registration && typeof client.registerVerificationKey === 'function') {
            try { result.registered = await client.registerVerificationKey(rid, registration.publicKey, registration.verificationPid); }
            catch (error) { result.registrationCode = error?.code || null; result.registrationMessage = String(error?.message || error); }
          }
          let attestation = null;
          if (attestationFor) attestation = attestationFor(rid);
          const statement = await client.sign(attestation ? { runDir: forged.runDir, approvalId, anchorId: name.replace(/[^a-z0-9-]/gi, '-'), attestation } : { runDir: forged.runDir, approvalId, anchorId: name.replace(/[^a-z0-9-]/gi, '-') });
          result.signed = true;
          result.statement = { verdict: statement.verdict, candidateSha256: statement.candidateSha256, verificationKeyId: statement.verificationKeyId || null };
          // Публикуем выбор и verdict атакующего: если анкер получен, проверяем наблюдателя.
          try {
            M.anchor.publishTerminalChoice(forged.runDir, M.anchor.buildTerminalChoice({ outcome: 'anchor', candidateSha256: forged.published.candidateSha256, anchorId: statement.anchorId || name.replace(/[^a-z0-9-]/gi, '-') }));
            M.anchor.publishTerminalVerdict({ store: forged.store, runDir: forged.runDir, frozen: forged.frozen, trust: world.trust, trustRoot: world.trustRoot });
          } catch (error) { result.anchorPublish = { code: error?.code || null, message: String(error?.message || error) }; }
          const observed = M.anchor.observeTrustedVerdict({ store: forged.store, runDir: forged.runDir, frozen: forged.frozen, trust: world.trust, trustRoot: world.trustRoot });
          result.observer = { trusted: observed.trusted, passed: observed.passed, verdict: observed.verdict?.verdict || null, anchorStatus: observed.anchorStatus || null };
        } catch (error) {
          result.code = error?.code || null;
          result.message = String(error?.message || error).slice(0, 300);
        } finally {
          if (fakeWorker) fakeWorker.kill();
        }
        records.push(result);
        return result;
      }

      // Общие заготовки: чистый прогон для каждой атаки.
      async function freshRun(tag) {
        const runId = 'reaudit-p001b-' + tag + '-' + randomUUID().slice(0, 6);
        const prepared = prepareForgeWithConsumption(M, world, { runId, mode: 'normal' });
        return { runId, approvalId: prepared.approval.approvalId, forged: prepared.forged };
      }

      const buildAttestation = ({ forged, approvalId, publicKey, privateKey, pid }) => {
        if (typeof M.anchor.buildVerificationAttestation !== 'function') return null;
        const post = forged.store.readEvidence(forged.runDir);
        return M.anchor.buildVerificationAttestation(privateKey, {
          runId: forged.frozen.manifest.runId,
          manifestSha256: forged.frozen.manifestSha256,
          approvalId,
          candidateSha256: forged.published.candidateSha256,
          readSetSha256: M.anchor.computeReadSetSha256(post),
          evidenceChainHead: (() => { const last = post.at(-1)?.envelope; return last ? { sequence: last.sequence, envelopeSha256: M.digest(last) } : null; })(),
          decision: { verdict: forged.candidate.verdict, reasonCode: forged.candidate.reasonCode },
          pid,
          startedAt: new Date().toISOString(),
          nonce: randomUUID().replace(/-/g, '')
        });
      };

      // A1: чужой ключ + двойник trusted-worker по «правильному» суффиксу пути.
      {
        const fake = await spawnFakeTrustedWorker({ baseDir: path.join(work, 'a1'), withSuffix: true });
        const base = await freshRun('a1');
        const attestation = buildAttestation({ forged: base.forged, approvalId: base.approvalId, publicKey: attackerPublic, privateKey: attacker.privateKey, pid: fake.pid });
        await attempt('A1-foreign-key-fake-worker', {
          registration: { publicKey: attackerPublic, verificationPid: fake.pid },
          attestationFor: attestation ? () => attestation : null,
          fakeWorker: fake, ...base
        });
      }

      // A2: подмена verification-pid: ключ чужой, процесс-двойник убит до подписи.
      {
        const fake = await spawnFakeTrustedWorker({ baseDir: path.join(work, 'a2'), withSuffix: true });
        const base = await freshRun('a2');
        const attestation = buildAttestation({ forged: base.forged, approvalId: base.approvalId, publicKey: attackerPublic, privateKey: attacker.privateKey, pid: fake.pid });
        let registered = null;
        if (typeof client.registerVerificationKey === 'function') {
          try { registered = await client.registerVerificationKey(base.runId, attackerPublic, fake.pid); } catch { /* фиксируется ниже */ }
        }
        fake.kill();
        await sleep(300);
        const result = await attempt('A2-dead-verification-pid', {
          attestationFor: attestation ? () => attestation : null, ...base
        });
        result.registered = registered;
        result.deadWorkerAlive = fake.alive();
      }

      // A3: копия trusted-worker из другого пути без доверенного суффикса.
      {
        const fake = await spawnFakeTrustedWorker({ baseDir: path.join(work, 'a3'), withSuffix: false });
        const base = await freshRun('a3');
        const attestation = buildAttestation({ forged: base.forged, approvalId: base.approvalId, publicKey: attackerPublic, privateKey: attacker.privateKey, pid: fake.pid });
        await attempt('A3-worker-copy-another-path', {
          registration: { publicKey: attackerPublic, verificationPid: fake.pid },
          attestationFor: attestation ? () => attestation : null,
          fakeWorker: fake, ...base
        });
      }

      // A4: ключ, взятый из runDir/trust root, без регистрации у подписанта.
      {
        const base = await freshRun('a4');
        const runDir = base.forged.runDir;
        const attackerRecord = {
          algorithm: 'Ed25519', keyId: attackerKeyId || 'f'.repeat(64),
          spki: attackerPublic.export({ type: 'spki', format: 'der' }).toString('base64')
        };
        const verificationDir = path.join(world.trustRoot, 'verification');
        fs.mkdirSync(verificationDir, { recursive: true });
        const fakeRecord = {
          schemaVersion: '0.2.0', domain: 'verification-attestation-record', runId: base.runId,
          attestation: { schemaVersion: '0.2.1', domain: 'verification-attestation', note: 'подложная аттестация из runDir' },
          verificationPublicKey: attackerRecord
        };
        fs.writeFileSync(path.join(verificationDir, base.runId + '.json'), JSON.stringify(fakeRecord) + '\n');
        fs.mkdirSync(path.join(runDir, 'trust'), { recursive: true });
        fs.writeFileSync(path.join(runDir, 'trust', 'verification-key.json'), JSON.stringify(attackerRecord) + '\n');
        const attestation = buildAttestation({ forged: base.forged, approvalId: base.approvalId, publicKey: attackerPublic, privateKey: attacker.privateKey, pid: process.pid });
        await attempt('A4-key-from-runDir', { attestationFor: attestation ? () => attestation : null, keyInRunDir: true, ...base });
      }

      const anchored = records.filter(record => record.signed === true);
      const trustedPass = anchored.filter(record => record.observer && record.observer.trusted === true && record.observer.passed === true);
      const evidence = {
        scope: 'legacy-public-signer-channel; для доверенной топологии требуется отдельный процесс-родитель Control',
        registerSupported: typeof client.registerVerificationKey === 'function',
        attempts: records,
        anchoredCount: anchored.length,
        trustedPassCount: trustedPass.length
      };
      check(checks, 'ни одна попытка не дала подписанного анкера', anchored.length === 0, { anchoredCount: anchored.length });
      check(checks, 'ни одна попытка не дала trusted PASS', trustedPass.length === 0, { trustedPassCount: trustedPass.length });
      for (const record of records) {
        if (record.signed === true) {
          check(checks, 'отказ для атаки ' + record.name, false, { code: record.code, observer: record.observer });
        }
      }
      return {
        defectObserved: anchored.length > 0 || trustedPass.length > 0,
        actual: anchored.length > 0 || trustedPass.length > 0
          ? 'атака на происхождение ключа Verification удалась: анкеров ' + anchored.length + ', trusted PASS ' + trustedPass.length
          : 'все атаки на происхождение ключа Verification отвергнуты (' + records.length + ' попыток)',
        evidence,
        checks
      };
    } finally {
      try { if (world.signer) await world.signer.close(); } catch { /* закрыт */ }
      await world.cleanup();
      removeDir(work);
    }
  }
});
