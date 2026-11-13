// AUD-P0-02, сценарий B: подмена стенда в окне между T-C (beforeRequestAck) и POST.
// Наблюдатель того же SID видит появление durable request-evidence, гасит стенд и поднимает
// rogue на том же порту; Browser отправляет POST rogue-процессу вместе с Bearer и получает PASS.
//
// FAIL = дефект воспроизводится (мутации на настоящем стенде нет, POST и Bearer ушли rogue, PASS).
// PASS = исправление: roguePosts=0 и bearerLeaked=false (условие владельца §10.3.3),
//        ложного доверенного PASS нет, второго POST нет.
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, startControlledStand, startRogue, runScenario, check, targetRoot, sleep, removeDir } from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P0-02-B',
  title: 'Подмена стенда в окне T-C→POST: POST и Bearer не должны уйти rogue',
  expected: 'На исправленной ревизии rogue не получает ни POST, ни Bearer (roguePosts=0, bearerLeaked=false); ложного PASS нет',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    let controlWorld = null;
    let attackWorld = null;
    let rogue = null;
    try {
      // 0) Честный контроль доверенного пути и POST на управляемом стенде.
      controlWorld = await makeWorld(M, {});
      const controlCase = controlWorld.prepare({ runId: 'reaudit-p002b-control' });
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

      // 1) Атака по окну T-C→POST.
      let standRef = null;
      let triggered = false;
      let swapAt = 0;
      let listenAt = 0;
      let postAtRogue = null;
      let watcher = null;
      const stand = await startControlledStand(M, {});
      standRef = stand;
      attackWorld = await makeWorld(M, { standalone: stand, withSigner: true });
      const attackCase = attackWorld.prepare({ runId: 'reaudit-p002b-attack' });
      const approval = attackWorld.approvalFor(attackCase);
      const store = new M.store.RunStore(attackWorld.root);
      const runDir = store.runPath(attackCase.runId);
      const evidenceDir = path.join(runDir, 'evidence');
      watcher = setInterval(async () => {
        if (triggered) return;
        let names = [];
        try { names = fs.readdirSync(evidenceDir); } catch { return; }
        if (!names.some(name => /^\d{6}-request\.json$/.test(name))) return;
        triggered = true;
        clearInterval(watcher);
        swapAt = Date.now();
        try {
          await standRef.close();
          rogue = await startRogue({
            port: standRef.port, environmentId: standRef.environmentId, fingerprint: standRef.fingerprint,
            recordMode: 'learn', attestMode: 'none'
          });
          listenAt = Date.now();
        } catch (error) {
          // rogue не успел занять порт: POST не должен пройти; фиксируем как есть
          rogue = rogue || null;
        }
      }, 1);
      let result = null;
      let startError = null;
      try { result = await M.trusted.startTrusted(attackCase.bundle, attackWorld.trustedOptions(approval)); }
      catch (error) { startError = { code: error?.code || null, message: String(error?.message || error) }; }
      finally { if (watcher) clearInterval(watcher); }
      const observed = await M.trusted.observeTrusted({ root: attackWorld.root, trustRoot: attackWorld.trustRoot, runId: attackCase.runId }).catch(error => ({ error: { code: error?.code || null, message: String(error.message || error) } }));
      const roguePosts = rogue ? rogue.state.posts.length : 0;
      if (rogue && rogue.state.posts.length) postAtRogue = rogue.state.posts[0].at;
      const bearerLeaked = Boolean(rogue && (rogue.state.posts.some(item => item.headers && item.headers.authorization) || rogue.state.requests.some(item => item.authorization)));
      const standMutationCount = stand.mutationCount;
      let evidenceKinds = [];
      try { evidenceKinds = store.readEvidence(runDir).map(item => item.envelope.kind); } catch { evidenceKinds = ['UNREADABLE']; }

      const evidence = {
        runId: attackCase.runId,
        triggered, swapToListenMs: listenAt ? listenAt - swapAt : null,
        startError,
        verdict: result?.verdict?.verdict || null,
        reasonCode: result?.verdict?.reasonCode || null,
        message: result?.verdict?.message ? String(result.verdict.message).slice(0, 200) : null,
        observedPassed: observed?.passed ?? null,
        observedTrusted: observed?.trusted ?? null,
        standMutationCount,
        roguePosts,
        rogueTotalRequests: rogue ? rogue.state.requests.length : 0,
        bearerLeaked,
        bearerInRogueRequests: rogue ? rogue.state.requests.filter(item => item.authorization).map(item => ({ method: item.method, path: item.path })) : [],
        postTimeFromRequestEvidenceMs: postAtRogue && swapAt ? postAtRogue - swapAt : null,
        evidenceKinds
      };
      const falsePass = evidence.verdict === 'PASS' && evidence.observedPassed === true && standMutationCount === 0 && roguePosts === 1 && bearerLeaked === true;
      evidence.defectShape = falsePass;
      if (!falsePass) {
        check(checks, 'доверенный PASS не опубликован', evidence.verdict !== 'PASS' && evidence.observedPassed !== true, { verdict: evidence.verdict, observedPassed: evidence.observedPassed });
        check(checks, 'условие владельца: roguePosts = 0', roguePosts === 0, { roguePosts });
        check(checks, 'условие владельца: Bearer не утёк rogue (bearerLeaked = false)', bearerLeaked === false, { bearerLeaked, requests: evidence.bearerInRogueRequests });
        check(checks, 'ровно один POST на всю атаку (нет второго POST)', standMutationCount + roguePosts <= 1, { standMutationCount, roguePosts });
        check(checks, 'терминальный verdict не более одного', evidenceKinds.filter(kind => kind === 'verdict').length <= 1, { kinds: evidenceKinds });
        check(checks, 'атака действительно выполнялась (request-evidence наблюдался)', triggered === true, { triggered });
      }
      return {
        defectObserved: falsePass,
        actual: falsePass
          ? 'ложный доверенный PASS: настоящий стенд не мутирован (mutationCount=0), POST ушёл rogue, Bearer утёк, PASS опубликован'
          : 'утечки нет: roguePosts=' + roguePosts + ', bearerLeaked=' + bearerLeaked + ', вердикт=' + (evidence.verdict || 'нет') + ', код=' + (evidence.reasonCode || 'нет'),
        evidence,
        checks
      };
    } finally {
      if (rogue) await rogue.close();
      if (controlWorld) await controlWorld.cleanup();
      if (attackWorld) await attackWorld.cleanup();
      removeDir(path.join(process.env.TEMP || '.', 'wp08-p002b-'));
    }
  }
});
