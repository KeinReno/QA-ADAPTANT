// AUD-P0-01C: в доверенной топологии подписант — дочерний процесс Control с приватным fork IPC.
// Проверка поведенческая: во время/после доверенного прогона перебираем ВСЕ публичные pipe
// qa-adaptant-anchor-* (в общей среде могут быть чужие) и пытаемся через них зарегистрировать
// свой ключ Verification для своего runId и получить анкер. Приватный подписант не имеет
// публичного канала, поэтому ни один pipe не должен подписать подложный candidate.
//
// FAIL = найден публичный канал, через который получен анкер/trusted PASS.
// PASS = ни один публичный канал не подписал подложный candidate (приватный IPC).
// INCONCLUSIVE = ревизия не поддерживает приватного подписанта/подписанные ответы стенда.
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  loadModules, makeWorld, prepareForgeWithConsumption, spawnFakeTrustedWorker, runScenario, check,
  targetRoot, tempDir, removeDir, sleep
} from './audit-lib.mjs';

const execFileAsync = promisify(execFile);

async function listAnchorPipes() {
  try {
    if (process.platform !== 'win32') return [];
    const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Get-ChildItem \\\\.\\pipe\\\\ | Where-Object { $_.Name -like "qa-adaptant-anchor-*" } | Select-Object -ExpandProperty Name'], { windowsHide: true, timeout: 10000 });
    return String(stdout).split(/\r?\n/).map(item => item.trim()).filter(Boolean);
  } catch { return []; }
}

await runScenario({
  id: 'AUD-P0-01C',
  title: 'Приватный канал подписанта: подложный ключ нельзя зарегистрировать в обход Control',
  expected: 'Публичные pipe подписанта не подписывают подложный candidate доверенного прогона; канал приватный (fork IPC)',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const standResponses = typeof M.environment.verifyStandResponse === 'function';
    const canPrivateSigner = fs.existsSync(targetRoot() + '\\apps\\verification\\trusted-worker.mjs');
    check(checks, 'ревизия поддерживает новый протокол (trusted-worker и подписанные ответы)', standResponses && canPrivateSigner, { standResponses, canPrivateSigner });
    if (!standResponses || !canPrivateSigner) {
      return { defectObserved: false, actual: 'новый протокол не поддерживается: приватный канал не проверен (INCONCLUSIVE)', evidence: {}, checks };
    }
    const work = tempDir('wp08-p001c-');
    const world = await makeWorld(M, { privateSigner: true });
    try {
      // 1) Работающий новый протокол: честный прогон до PASS с приватным подписантом.
      const prepared = world.prepare({ runId: 'reaudit-p001c' });
      const approval = world.approvalFor(prepared);
      const options = world.trustedOptions(approval);
      let result = null;
      let error = null;
      try { result = await M.trusted.startTrusted(prepared.bundle, options); }
      catch (caught) { error = { code: caught?.code || null, message: String(caught?.message || caught) }; }
      const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null, trusted: null }));
      const anchorDir = world.trustRoot + '\\anchors';
      const anchorPresent = fs.existsSync(anchorDir) && fs.readdirSync(anchorDir).length > 0;
      const newProtocolPass = result?.verdict?.verdict === 'PASS' && observed.passed === true && world.stand.mutationCount === 1;
      check(checks, 'доверенный вход не передаёт публичный pipe (только anchorKeyPath)', typeof options.anchorKeyPath === 'string' && !options.signerPipe, { hasAnchorKeyPath: typeof options.anchorKeyPath === 'string', signerPipe: options.signerPipe || null });
      check(checks, 'честный прогон на новом протоколе дошёл до доверенного PASS', newProtocolPass, { verdict: result?.verdict?.verdict || null, error, observedPassed: observed?.passed, anchorPresent, mutationCount: world.stand.mutationCount });
      if (!newProtocolPass) {
        return { defectObserved: false, actual: 'новый протокол не прошёл честный прогон: атака на канал не выполнена (INCONCLUSIVE)', evidence: { error, observedPassed: observed?.passed }, checks };
      }

      // 2) Подложный прогон + попытка зарегистрировать свой ключ через каждый публичный pipe.
      const forgedCase = prepareForgeWithConsumption(M, world, { runId: 'reaudit-p001c-forge' });
      const attacker = await import('node:crypto');
      const keyPair = attacker.generateKeyPairSync('ed25519');
      const fake = await spawnFakeTrustedWorker({ baseDir: work, withSuffix: true });
      const attempts = [];
      const pipes = await listAnchorPipes();
      for (const pipe of pipes) {
        const attempt = { pipe, registered: false, signOk: false, code: null, message: null };
        let client = null;
        try {
          client = M.anchorSigner.connectAnchorSigner(pipe);
          if (typeof client.registerVerificationKey === 'function') {
            try { await client.registerVerificationKey(forgedCase.forged.frozen.manifest.runId, keyPair.publicKey, fake.pid); attempt.registered = true; }
            catch (caught) { attempt.code = caught?.code || null; attempt.message = String(caught?.message || caught).slice(0, 160); }
          }
          if (typeof M.anchor.buildVerificationAttestation === 'function') {
            const post = forgedCase.forged.store.readEvidence(forgedCase.forged.runDir);
            const attestation = M.anchor.buildVerificationAttestation(keyPair.privateKey, {
              runId: forgedCase.forged.frozen.manifest.runId,
              manifestSha256: forgedCase.forged.frozen.manifestSha256,
              approvalId: forgedCase.approval.approvalId,
              candidateSha256: forgedCase.forged.published.candidateSha256,
              readSetSha256: M.anchor.computeReadSetSha256(post),
              evidenceChainHead: (() => { const last = post.at(-1)?.envelope; return last ? { sequence: last.sequence, envelopeSha256: M.digest(last) } : null; })(),
              decision: { verdict: forgedCase.forged.candidate.verdict, reasonCode: forgedCase.forged.candidate.reasonCode },
              pid: fake.pid, startedAt: new Date().toISOString(), nonce: attacker.randomBytes(32).toString('hex')
            });
            try {
              const statement = await client.sign({ runDir: forgedCase.forged.runDir, approvalId: forgedCase.approval.approvalId, anchorId: 'anchor-p001c-' + pipe.slice(-6), attestation });
              attempt.signOk = true;
              attempt.statement = { verdict: statement.verdict, verificationKeyId: statement.verificationKeyId || null };
            } catch (caught) { attempt.code = caught?.code || null; attempt.message = String(caught?.message || caught).slice(0, 200); }
          } else {
            attempt.code = 'NO_ATTESTATION_API';
          }
        } catch (caught) {
          attempt.code = caught?.code || null;
          attempt.message = String(caught?.message || caught).slice(0, 200);
        } finally {
          try { if (client) await client.close(); } catch { /* канал закрыт */ }
        }
        attempts.push(attempt);
      }
      fake.kill();
      const signed = attempts.filter(item => item.signOk);
      const evidence = {
        newProtocolPass,
        anchorPresent,
        standMutationCount: world.stand.mutationCount,
        pipesTried: pipes.length,
        attempts,
        signedByPublicChannel: signed.length
      };
      check(checks, 'ни один публичный канал не подписал подложный candidate', signed.length === 0, { signed: signed.length, attempts });
      return {
        defectObserved: signed.length > 0,
        actual: signed.length > 0
          ? 'публичный канал подписанта подписал подложный candidate: ' + signed.map(item => item.pipe).join(', ')
          : 'приватный канал: ни один публичный pipe не подписал подложный candidate (перебрано ' + pipes.length + ')',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
      removeDir(work);
    }
  }
});
