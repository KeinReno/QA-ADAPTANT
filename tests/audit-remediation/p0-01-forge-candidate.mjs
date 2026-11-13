// AUD-P0-01: подложный PASS-candidate с валидной связкой approval/consumption получает
// настоящий анкер от публичного подписанта → доверенный PASS без реальной мутации.
//
// Ожидаемо (после исправления): годного анкера для подложного candidate нет, доверенный PASS
// не показывается; публичный путь подписанта отвергает несвязанное происхождение.
// FAIL = дефект воспроизводится (ложный доверенный PASS). PASS = защита сработала.
import fs from 'node:fs';
import path from 'node:path';
import { loadModules, makeWorld, forgeRun, signViaSignerClients, observeAll, runScenario, check, targetRoot, removeDir } from './audit-lib.mjs';

await runScenario({
  id: 'AUD-P0-01',
  title: 'Подложный candidate с валидной связкой approval/consumption получает годный анкер',
  expected: 'Подложный candidate не анкеруется; доверенный PASS не публикуется; второго verdict/анкера нет',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const world = await makeWorld(M);
    try {
      const runId = 'reaudit-p001';
      const forged = forgeRun(M, world, { runId, mode: 'normal' });
      const approval = world.approvalFor({ bundle: forged.bundle, contract: forged.contract });
      const expected = world.expectedFor({ bundle: forged.bundle, contract: forged.contract });
      const consumed = M.approval.consumeDispatch({
        trust: world.trust, trustRoot: world.trustRoot, approval,
        issuer: world.cards.owner, subject: world.cards.operator, windowsSid: world.sid,
        expected, runId, decisionId: 'decision-p001'
      });
      check(checks, 'атакующий израсходовал настоящий approval на этот runId', consumed.ack === true, { code: consumed.code });
      check(checks, 'скормленная цепочка evidence собрана (intent/request/response/read)', forged.evidence.read !== undefined);

      const anchorId = 'anchor-reaudit-p001';
      const signed = await signViaSignerClients(M, world, { runDir: forged.runDir, approvalId: approval.approvalId, anchorId });
      const evidence = {
        runId,
        realStandMutationCount: world.stand.mutationCount,
        signer: signed.ok
          ? { ok: true, verdict: signed.statement.verdict, candidateSha256: signed.statement.candidateSha256 }
          : { ok: false, code: signed.error?.code || null, message: signed.error?.message || null }
      };

      if (signed.ok) {
        // Сценарий атаки целиком: выбор исхода anchor и терминальный verdict пишет сам атакующий.
        M.anchor.publishTerminalChoice(forged.runDir, M.anchor.buildTerminalChoice({
          outcome: 'anchor', candidateSha256: forged.published.candidateSha256, anchorId
        }));
        M.anchor.publishTerminalVerdict({ store: forged.store, runDir: forged.runDir, frozen: forged.frozen, trust: world.trust, trustRoot: world.trustRoot });
        const second = M.anchor.publishTerminalVerdict({ store: forged.store, runDir: forged.runDir, frozen: forged.frozen, trust: world.trust, trustRoot: world.trustRoot });
        const verdicts = forged.store.readEvidence(forged.runDir).filter(item => item.envelope.kind === 'verdict');
        check(checks, 'второй терминальный verdict не создаётся', second.created === false && verdicts.length === 1, { verdicts: verdicts.length, secondCreated: second.created });

        // Обход «подмена candidate после анкера»: байты candidate не могут незаметно измениться.
        const candidateFile = path.join(forged.runDir, 'trust', 'candidate.json');
        const originalBytes = fs.readFileSync(candidateFile);
        const alternative = M.anchor.buildCandidate({
          frozen: forged.frozen, verdict: 'INCONCLUSIVE', reasonCode: 'EVIDENCE_MISSING',
          message: 'подмена candidate после анкера', checks: forged.operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] })),
          ownershipVerified: false, integrityVerified: true
        });
        fs.writeFileSync(candidateFile, Buffer.from(JSON.stringify(alternative) + '\n'));
        const afterTamper = await observeAll(M, world, runId);
        check(checks, 'подмена candidate после анкера не даёт доверенного PASS', afterTamper.trustedObserver.passed !== true, {
          trusted: afterTamper.trustedObserver.trusted, passed: afterTamper.trustedObserver.passed, reasonCode: afterTamper.trustedObserver.reasonCode
        });
        fs.writeFileSync(candidateFile, originalBytes);

        // Обход «второй анкер»: публичный подписант не выдаёт второй анкер на тот же runId.
        const secondSign = await signViaSignerClients(M, world, { runDir: forged.runDir, approvalId: approval.approvalId, anchorId: 'anchor-reaudit-p001-second' });
        check(checks, 'второй анкер для того же runId отвергнут', secondSign.ok === false, { code: secondSign.error?.code || null, ok: secondSign.ok });

        const observed = await observeAll(M, world, runId);
        evidence.trustedObserver = {
          state: observed.trustedObserver.state, trusted: observed.trustedObserver.trusted, passed: observed.trustedObserver.passed,
          verdict: observed.trustedObserver.verdict?.verdict || null, anchorStatus: observed.trustedObserver.anchorStatus || null,
          reasonCode: observed.trustedObserver.reasonCode || null
        };
        evidence.publicObserveTrusted = observed.publicTrusted ? {
          trusted: observed.publicTrusted.trusted, passed: observed.publicTrusted.passed,
          verdict: observed.publicTrusted.verdict?.verdict || null, publication: observed.publicTrusted.publication || null,
          anchorStatus: observed.publicTrusted.anchorStatus || null
        } : null;
        evidence.oldObserve = observed.oldObserve;
        evidence.verdictCount = verdicts.length;
        evidence.anchorFiles = fs.existsSync(path.join(world.trustRoot, 'anchors')) ? fs.readdirSync(path.join(world.trustRoot, 'anchors')) : [];

        const falsePass = observed.trustedObserver.trusted === true && observed.trustedObserver.passed === true && observed.trustedObserver.verdict?.verdict === 'PASS';
        check(checks, 'реальной мутации не было (стенд не вызывался)', world.stand.mutationCount === 0, { mutationCount: world.stand.mutationCount });
        const actual = falsePass
          ? 'ложный доверенный PASS: подложный candidate анкерован публичным подписантом; реальной мутации нет'
          : (signed.ok ? 'анкер выдан, но доверенный PASS не показан' : 'подписант отверг подложный candidate');
        return { defectObserved: falsePass, actual, evidence, checks };
      }

      // Подписант отказал: проверяем, что отказа нет по случайной причине обвязки.
      const observed = await observeAll(M, world, runId);
      evidence.trustedObserver = {
        state: observed.trustedObserver.state, trusted: observed.trustedObserver.trusted, passed: observed.trustedObserver.passed,
        verdict: observed.trustedObserver.verdict?.verdict || null, anchorStatus: observed.trustedObserver.anchorStatus || null,
        reasonCode: observed.trustedObserver.reasonCode || null
      };
      evidence.verdictCount = forged.store.readEvidence(forged.runDir).filter(item => item.envelope.kind === 'verdict').length;
      const refusalKnown = ['ANCHOR_BINDING_REJECTED', 'ANCHOR_CONFLICT', 'CONTRACT_INVALID', 'INTEGRITY_ERROR', 'TRUST_STORE_UNAVAILABLE', 'CANDIDATE_INCOMPLETE'].includes(signed.error?.code);
      check(checks, 'отказ подписанта относится к проверке связки/происхождения', refusalKnown, { code: signed.error?.code || null });
      check(checks, 'после отказа подписанта доверенного PASS нет', observed.trustedObserver.passed !== true, {
        trusted: observed.trustedObserver.trusted, passed: observed.trustedObserver.passed
      });
      check(checks, 'после отказа подписанта не записан терминальный verdict', evidence.verdictCount === 0, { verdictCount: evidence.verdictCount });
      return {
        defectObserved: false,
        actual: 'подложный candidate не анкерован (код отказа: ' + (signed.error?.code || 'нет') + '); доверенный PASS не опубликован',
        evidence,
        checks
      };
    } finally {
      await world.cleanup();
    }
  }
});
