// AUD-P0-02, сценарий A: владелец сделал POST (реальный стенд сохранил неполную запись),
// после POST стенд подменяется rogue-процессом на том же порту; Verification читает rogue
// и публикует доверенный PASS. Rogue воспроизводит ранее захваченную аттестацию (replay).
//
// FAIL = дефект воспроизводится (ложный доверенный PASS при нарушенном реальном эффекте).
// PASS = среда не принята (ENVIRONMENT_CHANGED/INCONCLUSIVE), доверенного PASS нет.
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, startControlledStand, startRogue, runScenario, check, targetRoot, sleep, removeDir } from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P0-02-A',
  title: 'Подмена стенда после POST и до независимого чтения Verification',
  expected: 'Подмена среды даёт ENVIRONMENT_CHANGED/INCONCLUSIVE; доверенный PASS не публикуется; второй POST нет',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const base = fs.mkdtempSync(path.join(process.env.TEMP || '.', 'wp08-p002a-'));
    let controlWorld = null;
    let attackWorld = null;
    let rogue = null;
    try {
      // 0) Честный контроль: доверенный путь на этом стенде вообще работает.
      controlWorld = await makeWorld(M, { standOptions: { storeRecords: 'full' } });
      const controlCase = controlWorld.prepare({ runId: 'reaudit-p002a-control' });
      const controlApproval = controlWorld.approvalFor(controlCase);
      const controlResult = await M.trusted.startTrusted(controlCase.bundle, controlWorld.trustedOptions(controlApproval));
      const controlObserved = await M.trusted.observeTrusted({ root: controlWorld.root, trustRoot: controlWorld.trustRoot, runId: controlCase.runId });
      const honestOk = controlResult?.verdict?.verdict === 'PASS' && controlObserved.passed === true && controlWorld.stand.mutationCount === 1;
      check(checks, 'честный доверенный прогон даёт PASS и ровно один POST (иначе атака не доказательна)', honestOk, {
        verdict: controlResult?.verdict?.verdict || null, passed: controlObserved.passed, mutationCount: controlWorld.stand.mutationCount
      });
      await controlWorld.cleanup();
      controlWorld = null;
      if (!honestOk) return { defectObserved: false, actual: 'честный контроль не прошёл: атака не выполнена', evidence: {}, checks };

      // 1) Атака: неполная запись реального стенда, затем подмена в окне после POST.
      let standRef = null;
      let triggered = false;
      let capturedAttestation = null;
      const stand = await startControlledStand(M, {
        storeRecords: 'partial',
        afterPost: async ({ record }) => {
          await sleep(40);
          if (triggered) return;
          triggered = true;
          await standRef.close();
          rogue = await startRogue({
            port: standRef.port, environmentId: standRef.environmentId, fingerprint: standRef.fingerprint,
            recordMode: 'static', record: { ...record, fixtureId: standRef.fixtureId },
            attestMode: 'replay', attestation: capturedAttestation
          });
        }
      });
      standRef = stand;
      const challenge = M.environment.newChallenge();
      const attestationResponse = await fetch(new URL('/attest', stand.baseUrl), {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challenge })
      });
      if (attestationResponse.status === 200) capturedAttestation = await attestationResponse.json();
      check(checks, 'у аудитора есть захваченная настоящая аттестация стенда для replay', capturedAttestation !== null, { status: attestationResponse.status });

      attackWorld = await makeWorld(M, { standalone: stand, withSigner: true });
      const attackCase = attackWorld.prepare({ runId: 'reaudit-p002a-attack' });
      const approval = attackWorld.approvalFor(attackCase);
      let result = null;
      let startError = null;
      try { result = await M.trusted.startTrusted(attackCase.bundle, attackWorld.trustedOptions(approval)); }
      catch (error) { startError = { code: error?.code || null, message: String(error?.message || error) }; }
      const observed = await M.trusted.observeTrusted({ root: attackWorld.root, trustRoot: attackWorld.trustRoot, runId: attackCase.runId }).catch(error => ({ error: { code: error?.code || null, message: String(error.message || error) } }));
      const realRecord = stand.state.records[0] || null;

      const evidence = {
        runId: attackCase.runId,
        triggered, startError,
        verdict: result?.verdict?.verdict || null,
        reasonCode: result?.verdict?.reasonCode || null,
        message: result?.verdict?.message ? String(result.verdict.message).slice(0, 200) : null,
        observedPassed: observed?.passed ?? null,
        observedTrusted: observed?.trusted ?? null,
        standMutationCount: stand.mutationCount,
        realStoredRecordComment: realRecord ? realRecord.comment : null,
        rogue: rogue ? {
          environmentGets: rogue.state.envGets, recordGets: rogue.state.recordGets, attestGets: rogue.state.attestGets,
          posts: rogue.state.posts.length,
          sawBearer: rogue.state.requests.some(item => item.authorization),
          requests: rogue.state.requests.map(item => ({ method: item.method, path: item.path, auth: Boolean(item.authorization) }))
        } : null,
        evidenceKinds: (() => { try { return attackWorld ? new M.store.RunStore(attackWorld.root).readEvidence(new M.store.RunStore(attackWorld.root).runPath(attackCase.runId)).map(item => item.envelope.kind) : []; } catch { return []; } })()
      };
      const falsePass = evidence.verdict === 'PASS' && evidence.observedPassed === true && evidence.standMutationCount === 1 && Boolean(rogue && rogue.state.recordGets >= 1);
      check(checks, 'подмена стенда состоялась (rogue обслужил чтение)', Boolean(rogue && (rogue.state.recordGets + rogue.state.envGets + rogue.state.attestGets) > 0), evidence.rogue);
      if (!falsePass) {
        check(checks, 'доверенный PASS не опубликован при подменённой среде', evidence.verdict !== 'PASS' && evidence.observedPassed !== true, { verdict: evidence.verdict, observedPassed: evidence.observedPassed });
        check(checks, 'второго POST нет', evidence.standMutationCount + (evidence.rogue?.posts || 0) <= 1, { stand: evidence.standMutationCount, rogue: evidence.rogue?.posts || 0 });
        check(checks, 'терминальный verdict не более одного', evidence.evidenceKinds.filter(kind => kind === 'verdict').length <= 1, { kinds: evidence.evidenceKinds });
      }
      return {
        defectObserved: falsePass,
        actual: falsePass
          ? 'ложный доверенный PASS: реальный стенд сохранил неполную запись, Verification прочитал rogue и опубликован PASS'
          : 'подмена среды не дала доверенного PASS (вердикт: ' + (evidence.verdict || 'нет') + ', код: ' + (evidence.reasonCode || 'нет') + ')',
        evidence,
        checks
      };
    } finally {
      if (rogue) await rogue.close();
      if (controlWorld) await controlWorld.cleanup();
      if (attackWorld) await attackWorld.cleanup();
      removeDir(base);
    }
  }
});
