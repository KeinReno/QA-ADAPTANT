// AUD-P1-03: подмена выхода Verification после подписи анкера.
// После честного доверенного прогона подменяются: durable candidate, артефакт independent-read,
// запись аттестации Verification в trust root. Доверенный наблюдатель не должен показывать PASS.
//
// FAIL = после подмены файлов observeTrusted показывает trusted/PASS.
// PASS = все применимые подмены отвергнуты. INCONCLUSIVE = часть проверок не применима на ревизии.
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, runScenario, check, targetRoot } from './audit-lib.mjs';

function backup(file) {
  return { file, exists: fs.existsSync(file), bytes: fs.existsSync(file) ? fs.readFileSync(file) : null };
}
function restore(saved) {
  if (saved.exists) fs.writeFileSync(saved.file, saved.bytes);
  else { try { fs.unlinkSync(saved.file); } catch { /* файла нет */ } }
}

await runScenario({
  id: 'AUD-P1-03',
  title: 'Подмена candidate/read-set/attestation после подписи анкера',
  expected: 'Подмена файлов после подписи не даёт trusted PASS',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const world = await makeWorld(M);
    try {
      const prepared = world.prepare({ runId: 'reaudit-p103' });
      const approval = world.approvalFor(prepared);
      let result = null;
      let error = null;
      try { result = await M.trusted.startTrusted(prepared.bundle, world.trustedOptions(approval)); }
      catch (caught) { error = { code: caught?.code || null, message: String(caught?.message || caught) }; }
      const store = new M.store.RunStore(world.root);
      const runDir = store.runPath(prepared.runId);
      let frozen = null;
      try { frozen = M.bundleModule.verifyFrozenBundle(store, runDir); } catch { frozen = null; }
      const observedBefore = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null, trusted: null }));
      const honest = result?.verdict?.verdict === 'PASS' && observedBefore.passed === true;
      check(checks, 'положительный контроль: честный доверенный PASS до подмен', honest, {
        verdict: result?.verdict?.verdict || null, error, observedPassed: observedBefore.passed, mutationCount: world.stand.mutationCount
      });
      if (!honest) return { defectObserved: false, actual: 'честный доверенный PASS не получен: подмены не проверены', evidence: { error }, checks };

      const variants = [];
      async function tryTamper(name, apply, expectedApplicable = true) {
        if (!expectedApplicable) return null;
        const saved = [];
        try {
          const applied = await apply(saved);
          if (applied === false) return { name, applicable: false };
          const observed = await M.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: prepared.runId }).catch(caught => ({ error: String(caught?.message || caught), passed: null, trusted: null }));
          const record = { name, applicable: true, trusted: observed?.trusted ?? null, passed: observed?.passed ?? null, reasonCode: observed?.reasonCode || null, error: observed?.error || null };
          variants.push(record);
          return record;
        } finally {
          for (const item of saved.reverse()) restore(item);
        }
      }

      // 1) Подмена durable candidate на другой валидный candidate.
      const candidateFile = path.join(runDir, 'trust', 'candidate.json');
      await tryTamper('durable-candidate', async saved => {
        if (!fs.existsSync(candidateFile)) return false;
        saved.push(backup(candidateFile));
        const alternative = M.anchor.buildCandidate({ frozen, verdict: 'INCONCLUSIVE', reasonCode: 'EVIDENCE_MISSING', message: 'подмена после подписи', checks: prepared.bundle.operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] })), ownershipVerified: false, integrityVerified: true });
        fs.writeFileSync(candidateFile, Buffer.from(JSON.stringify(alternative) + '\n'));
        return true;
      });

      // 2) Подмена артефакта independent-read в каталоге прогона.
      await tryTamper('independent-read-artifact', async saved => {
        const evidenceDir = path.join(runDir, 'evidence');
        const names = fs.existsSync(evidenceDir) ? fs.readdirSync(evidenceDir).filter(name => name.includes('independent-read')) : [];
        if (!names.length) return false;
        const file = path.join(evidenceDir, names[0]);
        saved.push(backup(file));
        const bytes = fs.readFileSync(file);
        fs.writeFileSync(file, Buffer.concat([bytes, Buffer.from(' ')]));
        return true;
      });

      // 3) Подмена записи аттестации Verification (только если ревизия её читает).
      const verificationFeature = typeof M.anchor.readVerificationRecord === 'function';
      if (!verificationFeature) {
        check(checks, 'подмена attestation Verification применима (ревизия читает verification-record)', false, {});
      } else {
        const verificationFile = path.join(world.trustRoot, 'verification', prepared.runId + '.json');
        await tryTamper('verification-attestation-record', async saved => {
          if (!fs.existsSync(verificationFile)) return false;
          saved.push(backup(verificationFile));
          const original = JSON.parse(fs.readFileSync(verificationFile, 'utf8'));
          original.attestation.nonce = 'подмена-nonce';
          fs.writeFileSync(verificationFile, JSON.stringify(original) + '\n');
          return true;
        });
        check(checks, 'подмена attestation Verification применима (файл существует)', variants.some(item => item.name === 'verification-attestation-record' && item.applicable), { variants });
      }

      const trustedPassAfter = variants.filter(item => item.applicable && item.trusted === true && item.passed === true);
      const evidence = { runId: prepared.runId, standMutationCount: world.stand.mutationCount, variants, trustedPassAfter: trustedPassAfter.map(item => item.name) };
      check(checks, 'ни одна подмена не даёт trusted PASS', trustedPassAfter.length === 0, { trustedPassAfter: evidence.trustedPassAfter });
      return {
        defectObserved: trustedPassAfter.length > 0,
        actual: trustedPassAfter.length > 0
          ? 'подмена после подписи дала trusted PASS: ' + trustedPassAfter.map(item => item.name).join(', ')
          : 'подмены после подписи отвергнуты (' + variants.filter(item => item.applicable).length + ' применимых)',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
    }
  }
});
