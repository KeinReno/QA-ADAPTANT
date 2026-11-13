// AUD-P0-02D: атаки на работающем новом протоколе (приватный подписант, подписанные ответы,
// закреплённое соединение), которые не покрываются подменой «после POST» и «T-C→POST»:
//   (c) подмена/гибель стенда ПОСЛЕ независимых чтений, но до итоговой аттестации;
//   (d) ответ POST без подписи стенда (неподписанный ответ).
//
// FAIL = в любом из случаев опубликован trusted PASS.
// PASS = ни один случай не даёт доверенного PASS, POST/verdict не дублируются.
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, startControlledStand, runScenario, check, targetRoot, sleep, tempDir, removeDir } from './audit-lib.mjs';

async function honestControl(M) {
  for (let attempt = 1; attempt <= 2; attempt++) {
    const world = await makeWorld(M, { privateSigner: true });
    try {
      const prepared = world.prepare({ runId: 'reaudit-p002d-control-' + attempt });
      const approval = world.approvalFor(prepared);
      const result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval));
      const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId });
      if (result?.verdict?.verdict === 'PASS' && observed.passed === true && world.stand.mutationCount === 1) {
        return { ok: true, mutationCount: world.stand.mutationCount };
      }
    } catch { /* повтор */ } finally { await world.cleanup(); }
  }
  return { ok: false, mutationCount: null };
}

await runScenario({
  id: 'AUD-P0-02D',
  title: 'Новый протокол: подмена после независимых чтений и неподписанный ответ POST',
  expected: 'Ни подмена после чтений, ни ответ POST без подписи стенда не дают доверенного PASS',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const work = tempDir('wp08-p002d-');
    try {
      const control = await honestControl(M);
      check(checks, 'честный контроль на новом протоколе: доверенный PASS и один POST', control.ok, control);
      if (!control.ok) return { defectObserved: false, actual: 'новый протокол не прошёл честный контроль: атаки не выполнены (INCONCLUSIVE)', evidence: { control }, checks };

      // ---------- (c) подмена после независимых чтений ----------
      let partC = null;
      {
        let standRef = null;
        let triggered = false;
        let swappedAt = null;
        const stand = await startControlledStand(M, {});
        standRef = stand;
        const world = await makeWorld(M, { standalone: stand, privateSigner: true });
        try {
          const prepared = world.prepare({ runId: 'reaudit-p002d-after-reads' });
          const approval = world.approvalFor(prepared);
          const store = new M.store.RunStore(world.root);
          const runDir = store.runPath(prepared.runId);
          const evidenceDir = path.join(runDir, 'evidence');
          const watcher = setInterval(async () => {
            if (triggered) return;
            let names = [];
            try { names = fs.readdirSync(evidenceDir); } catch { return; }
            if (!names.some(name => /^\d{6}-independent-read\.json$/.test(name))) return;
            triggered = true;
            clearInterval(watcher);
            swappedAt = Date.now();
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
          partC = {
            triggered, standMutationCount: stand.mutationCount,
            verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null, error,
            observed: { trusted: observed?.trusted ?? null, passed: observed?.passed ?? null, publication: observed?.publication || null, reasonCode: observed?.reasonCode || null },
            verdictCount: kinds.filter(kind => kind === 'verdict').length,
            requestCount: kinds.filter(kind => kind === 'request').length,
            readCount: kinds.filter(kind => kind === 'independent-read').length,
            anchorPresent: fs.existsSync(path.join(world.trustRoot, 'anchors')) && fs.readdirSync(path.join(world.trustRoot, 'anchors')).length > 0
          };
        } finally { await world.cleanup(); }
      }
      check(checks, '(c) подмена после независимых чтений наблюдалась', partC.triggered === true, partC);
      check(checks, '(c) после подмены после чтений нет trusted PASS', partC.observed.passed !== true && partC.verdict !== 'PASS', partC);
      check(checks, '(c) ровно один POST и не более одного verdict', partC.standMutationCount <= 1 && partC.verdictCount <= 1, { mutationCount: partC.standMutationCount, verdictCount: partC.verdictCount });

      // ---------- (d) ответ POST без подписи стенда ----------
      let partD = null;
      {
        const stand = await startControlledStand(M, { omitPostSignature: true });
        const world = await makeWorld(M, { standalone: stand, privateSigner: true });
        try {
          const prepared = world.prepare({ runId: 'reaudit-p002d-unsigned-response' });
          const approval = world.approvalFor(prepared);
          const store = new M.store.RunStore(world.root);
          const runDir = store.runPath(prepared.runId);
          let result = null;
          let error = null;
          try { result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval)); }
          catch (caught) { error = { code: caught?.code || null, message: String(caught?.message || caught) }; }
          const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null, trusted: null }));
          let kinds = [];
          try { kinds = store.readEvidence(runDir).map(item => item.envelope.kind); } catch { kinds = ['UNREADABLE']; }
          partD = {
            standMutationCount: stand.mutationCount, postCount: stand.state.posts.length,
            verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null, error,
            observed: { trusted: observed?.trusted ?? null, passed: observed?.passed ?? null, publication: observed?.publication || null, reasonCode: observed?.reasonCode || null },
            verdictCount: kinds.filter(kind => kind === 'verdict').length,
            requestCount: kinds.filter(kind => kind === 'request').length,
            responseCount: kinds.filter(kind => kind === 'response').length,
            anchorPresent: fs.existsSync(path.join(world.trustRoot, 'anchors')) && fs.readdirSync(path.join(world.trustRoot, 'anchors')).length > 0
          };
        } finally { await world.cleanup(); }
      }
      check(checks, '(d) неподписанный ответ POST не даёт trusted PASS', partD.observed.passed !== true && partD.verdict !== 'PASS', partD);
      check(checks, '(d) мутация состоялась (стенд получил POST), но PASS не опубликован', partD.standMutationCount === 1 && partD.observed.passed !== true, { mutationCount: partD.standMutationCount, verdict: partD.verdict });

      const defect = partC.observed.passed === true || partC.verdict === 'PASS' || partD.observed.passed === true || partD.verdict === 'PASS';
      return {
        defectObserved: defect,
        actual: defect
          ? 'ложный доверенный PASS: подмена после чтений или неподписанный ответ POST приняты'
          : 'подмена после независимых чтений и неподписанный ответ POST не дают доверенного PASS',
        evidence: { control, partC, partD },
        checks
      };
    } finally {
      removeDir(work);
    }
  }
});
