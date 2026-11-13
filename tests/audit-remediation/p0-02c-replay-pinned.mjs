// AUD-P0-02C: закреплённое соединение и replay подписанных ответов стенда.
//   Часть 1: гибель стенда при закреплённом сокете (без rogue) — POST не должен уводить на новый
//            сокет, ложного PASS быть не должно.
//   Часть 2: rogue воспроизводит захваченные подписанные ответы стенда (attestation и stand-response)
//            на другой challenge — Verification обязан отвергнуть replay.
//
// FAIL = ложный доверенный PASS (replay принят или гибель стенда дала PASS).
// PASS = обе части закрыты. INCONCLUSIVE = нет подписанных ответов стенда на ревизии (не проверено).
import fs from 'node:fs';
import path from 'node:path';
import {
  loadModules, makeWorld, startControlledStand, startRogue, runScenario, check, targetRoot, sleep,
  STAND_CHALLENGE_HEADER, STAND_RESPONSE_HEADER, tempDir, removeDir
} from './audit-lib.mjs';

function decodeStatement(header) {
  if (!header) return null;
  try { return JSON.parse(Buffer.from(header, 'base64url').toString('utf8')); } catch { return null; }
}

async function honestControl(M, label) {
  const world = await makeWorld(M, { privateSigner: true });
  try {
    const prepared = world.prepare({ runId: 'reaudit-p002c-control-' + label });
    const approval = world.approvalFor(prepared);
    const result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval));
    const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId });
    return { ok: result?.verdict?.verdict === 'PASS' && observed.passed === true && world.stand.mutationCount === 1, result, observed, mutationCount: world.stand.mutationCount };
  } finally { await world.cleanup(); }
}

await runScenario({
  id: 'AUD-P0-02C',
  title: 'Pinned-соединение: гибель стенда и replay подписанных ответов на другой challenge',
  expected: 'Гибель стенда при закреплённом сокете и replay подписанных ответов не дают доверенного PASS',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const work = tempDir('wp08-p002c-');
    let rogue = null;
    try {
      const control = await honestControl(M, 'base');
      check(checks, 'честный контроль: доверенный PASS и ровно один POST', control.ok, { verdict: control.result?.verdict?.verdict || null, mutationCount: control.mutationCount });
      if (!control.ok) return { defectObserved: false, actual: 'честный контроль не прошёл: атаки не выполнены', evidence: {}, checks };

      // ---------- Часть 1: гибель стенда при закреплённом сокете ----------
      let part1 = null;
      {
        let standRef = null;
        let triggered = false;
        let killedAt = null;
        const stand = await startControlledStand(M, {});
        standRef = stand;
        const world = await makeWorld(M, { standalone: stand, privateSigner: true, withSigner: false });
        try {
          const prepared = world.prepare({ runId: 'reaudit-p002c-death' });
          const approval = world.approvalFor(prepared);
          const store = new M.store.RunStore(world.root);
          const runDir = store.runPath(prepared.runId);
          const evidenceDir = path.join(runDir, 'evidence');
          const watcher = setInterval(async () => {
            if (triggered) return;
            let names = [];
            try { names = fs.readdirSync(evidenceDir); } catch { return; }
            if (!names.some(name => /^\d{6}-request\.json$/.test(name))) return;
            triggered = true;
            clearInterval(watcher);
            killedAt = Date.now();
            await standRef.close();
          }, 1);
          let result = null;
          let error = null;
          try { result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval)); }
          catch (caught) { error = { code: caught?.code || null, message: String(caught?.message || caught) }; }
          finally { clearInterval(watcher); }
          const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null, trusted: null }));
          let kinds = [];
          try { kinds = store.readEvidence(runDir).map(item => item.envelope.kind); } catch { kinds = ['UNREADABLE']; }
          part1 = {
            triggered, standMutationCount: stand.mutationCount,
            verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null, error,
            observed: { trusted: observed?.trusted ?? null, passed: observed?.passed ?? null, publication: observed?.publication || null, reasonCode: observed?.reasonCode || null },
            verdictCount: kinds.filter(kind => kind === 'verdict').length,
            requestCount: kinds.filter(kind => kind === 'request').length
          };
        } finally { await world.cleanup(); }
      }
      check(checks, 'часть 1: гибель стенда при закреплённом сокете не даёт trusted PASS', part1.observed.passed !== true && part1.verdict !== 'PASS', part1);
      check(checks, 'часть 1: не более одного POST и одного verdict', part1.standMutationCount <= 1 && part1.verdictCount <= 1, { mutationCount: part1.standMutationCount, verdictCount: part1.verdictCount });

      // ---------- Часть 2: replay подписанных ответов стенда ----------
      const signedResponsesSupported = typeof M.environment.verifyStandResponse === 'function' && typeof M.environment.readStandResponseSignature === 'function';
      check(checks, 'часть 2: ревизия поддерживает подписанные ответы стенда (иначе INCONCLUSIVE)', signedResponsesSupported, {
        verifyStandResponse: typeof M.environment.verifyStandResponse, readStandResponseSignature: typeof M.environment.readStandResponseSignature
      });
      let part2 = null;
      if (signedResponsesSupported) {
        let standRef = null;
        let triggered = false;
        let capturedAttestation = null;
        let capturedAttestationStatement = null;
        let capturedRecordsResponse = null;
        let capturedRecordsStatement = null;
        const stand = await startControlledStand(M, {
          afterPost: async ({ stand, record }) => {
            await sleep(40);
            if (triggered) return;
            triggered = true;
            try {
              // Захват настоящей подписи ответа /records до подмены стенда.
              const challenge = M.environment.newChallenge();
              const response = await fetch(new URL('/records?fixtureId=' + encodeURIComponent(record.fixtureId), stand.baseUrl), {
                headers: { authorization: 'Bearer ' + stand.authToken, [STAND_CHALLENGE_HEADER]: challenge }
              });
              capturedRecordsStatement = decodeStatement(response.headers.get(STAND_RESPONSE_HEADER));
              const body = await response.json();
              capturedRecordsResponse = { challenge, body };
            } catch { /* подпись не захвачена */ }
            await standRef.close();
            rogue = await startRogue({
              port: standRef.port, environmentId: standRef.environmentId, fingerprint: standRef.fingerprint,
              recordMode: 'static', record: { ...record, fixtureId: standRef.fixtureId },
              attestMode: 'replay', attestation: capturedAttestation,
              responseReplay: capturedRecordsStatement
            });
          }
        });
        standRef = stand;
        // Захват подписи /attest на выбранный challenge до старта прогона.
        {
          const challenge = M.environment.newChallenge();
          const response = await fetch(new URL('/attest', stand.baseUrl), {
            method: 'POST', headers: { 'content-type': 'application/json', [STAND_CHALLENGE_HEADER]: challenge },
            body: JSON.stringify({ challenge })
          });
          capturedAttestation = await response.json().catch(() => null);
          capturedAttestationStatement = decodeStatement(response.headers.get(STAND_RESPONSE_HEADER));
        }
        const world = await makeWorld(M, { standalone: stand, privateSigner: true });
        try {
          const prepared = world.prepare({ runId: 'reaudit-p002c-replay' });
          const approval = world.approvalFor(prepared);
          let result = null;
          let error = null;
          try { result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval)); }
          catch (caught) { error = { code: caught?.code || null, message: String(caught?.message || caught) }; }
          const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null, trusted: null }));
          part2 = {
            capturedAttestation: Boolean(capturedAttestation),
            capturedAttestationSigned: Boolean(capturedAttestationStatement),
            capturedRecordsSigned: Boolean(capturedRecordsStatement),
            verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null, error,
            observed: { trusted: observed?.trusted ?? null, passed: observed?.passed ?? null, publication: observed?.publication || null, reasonCode: observed?.reasonCode || null },
            rogue: rogue ? {
              attestGets: rogue.state.attestGets, recordGets: rogue.state.recordGets, replayServed: rogue.state.replayServed,
              posts: rogue.state.posts.length, sawBearer: rogue.state.requests.some(item => item.authorization)
            } : null
          };
        } finally { await world.cleanup(); }
        check(checks, 'часть 2: replay подписанной аттестации/ответа не даёт trusted PASS', part2.observed.passed !== true && part2.verdict !== 'PASS', part2);
        check(checks, 'часть 2: replay был фактически предъявлен Verification', Boolean(part2.rogue && (part2.rogue.attestGets > 0 || part2.rogue.replayServed > 0)), part2.rogue);
      }

      const defect = part1.observed.passed === true || part1.verdict === 'PASS' ||
        (part2 && (part2.observed.passed === true || part2.verdict === 'PASS'));
      return {
        defectObserved: defect,
        actual: defect
          ? 'доверенный PASS при гибели/подмене закреплённого соединения или при replay подписанных ответов'
          : 'гибель закреплённого сокета и replay подписанных ответов не дают доверенного PASS',
        evidence: { control: { mutationCount: control.mutationCount }, part1, part2, signedResponsesSupported },
        checks
      };
    } finally {
      if (rogue) await rogue.close();
      removeDir(work);
    }
  }
});
