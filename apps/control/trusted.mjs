// WP-06: доверенный вход Control Plane.
//
// Два входа остаются раздельными: старый start()/observe()/cancel()/reconcile() не знает
// про trust root и не выпускает доверенный PASS, а *_Trusted проходит PEP в точках T-A…T-E.
// Второго исполнителя мутаций нет: оба входа сходятся в одном run().
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { RunStore } from '../../packages/core/store.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { assertApprovedOperation } from '../../packages/core/approved-registry.mjs';
import { loadTrustRoot } from '../../packages/trust/identity.mjs';
import { consumeDispatch } from '../../packages/trust/approval.mjs';
import { attestLiveEnvironment } from '../../packages/trust/environment.mjs';
import { decide, projectToVerdict } from '../../packages/trust/policy.mjs';
import {
  anchorWithinBudget, observeTrustedVerdict, publishBudgetInconclusiveOutcome, publishCandidate,
  publishTerminalChoice, publishTerminalVerdict, readTerminalChoice, verifyAnchorStatement
} from '../../packages/trust/anchor.mjs';
import { connectAnchorSigner } from '../../packages/trust/anchor-signer.mjs';
import { currentUserSid } from '../../packages/trust/windows-sid.mjs';
import { approvalFact, buildFacts, environmentFact, expectedFromFrozen, principalFact } from '../../packages/trust/facts.mjs';
import { cancel, observe, reconcile, start } from './run.mjs';

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function nowIso() {
  return new Date().toISOString();
}

// Проекция точного кода отказа в замороженный enum 0.1. Значение проверяется validate().
function verdictCodeOf(code) {
  if (['CALLER_UNAUTHENTICATED', 'PRINCIPAL_UNKNOWN', 'PRINCIPAL_REVOKED', 'TRUST_STORE_UNAVAILABLE', 'CONSUMPTION_INCOMPLETE', 'APPROVAL_SIGNATURE_INVALID'].includes(code)) return 'AUTH_UNAVAILABLE';
  if (['ENVIRONMENT_ATTESTATION_FAILED', 'ENVIRONMENT_UNKNOWN', 'ENVIRONMENT_UNAVAILABLE', 'ENVIRONMENT_KIND_DENIED', 'ENVIRONMENT_REVOKED'].includes(code)) return 'ENVIRONMENT_CHANGED';
  if (code === 'RUN_CANCELED') return 'CANCELED';
  if (code === 'INTEGRITY_ERROR') return 'INTEGRITY_ERROR';
  return 'CONTRACT_INVALID';
}

function denialOf(decision) {
  const projection = projectToVerdict(decision);
  return {
    phase: decision.phase,
    reasonCode: decision.reasonCode,
    decisionId: decision.decisionId,
    verdictCode: projection?.reasonCode || verdictCodeOf(decision.reasonCode),
    message: 'Доверенный PEP отказал: ' + decision.reasonCode
  };
}

function errorDenial(error, phase) {
  const code = error?.code || 'CONTRACT_INVALID';
  return { phase, reasonCode: code, verdictCode: verdictCodeOf(code), message: error?.message || 'Доверенная проверка не прошла' };
}

function registryFact(frozen) {
  try {
    assertApprovedOperation(frozen.operation, frozen.scenario);
    return { operationAllowed: true, effectsMatch: true };
  } catch {
    return { operationAllowed: false, effectsMatch: false };
  }
}

function persistDecision(runDir, decision) {
  const directory = path.join(runDir, 'trust', 'decisions');
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, decision.phase + '-' + decision.decisionId + '.json');
  let fd;
  try {
    fd = fs.openSync(file, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(decision) + '\n');
    fs.fsyncSync(fd);
  } catch { /* решение не является доказательством мутации; журнал evidence не затрагивается */ }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}

export function createTrustContext(options = {}) {
  const { trust, trustRoot, approvalId, approval = null, issuer, subject, sid, standPublicKey, signer = null } = options;
  if (!trust || !trustRoot || !approvalId) throw new TypeError('Нужны trust, trustRoot и approvalId');
  let currentEnvironment = null;
  let lastDecision = null;
  let dispatchApproved = false;

  async function refreshEnvironment(runId, frozen) {
    const expected = expectedFromFrozen(frozen);
    const environment = environmentFact({ trust, trustRoot, environmentId: expected.environmentId, origin: frozen.manifest.environment.baseUrl, generation: null });
    if (!environment.record) { currentEnvironment = { record: null, error: environment.error, attestation: { ok: false, body: null, error: environment.error } }; return expected; }
    const generation = environment.record.generation;
    let attestation = { ok: false, body: null, error: 'ENVIRONMENT_ATTESTATION_FAILED' };
    // Аттестуется только активный local-stand: dev/production и неактивные записи отсекает PDP по записи.
    if (environment.record.status === 'active' && environment.record.kind === 'local-stand') {
      try {
        const live = await attestLiveEnvironment({ trust, record: environment.record, standPublicKey });
        attestation = { ok: true, body: live.attestation, error: null };
      } catch (error) {
        const code = error?.code;
        attestation = { ok: false, body: null, error: code === 'ENVIRONMENT_UNAVAILABLE' ? 'ENVIRONMENT_UNAVAILABLE' : 'ENVIRONMENT_ATTESTATION_FAILED' };
      }
    }
    currentEnvironment = { record: environment.record, error: null, attestation };
    expected.environmentGeneration = generation;
    return expected;
  }

  function factsFor(phase, { runId, frozen, expected, approvalState, canceled = false, mutationRecorded = false }) {
    return buildFacts({
      phase,
      now: nowIso(),
      authenticatedSid: sid,
      trustStore: { available: true, code: null },
      principal: principalFact(trust, subject, { windowsSid: sid }),
      issuer: principalFact(trust, issuer, { role: 'owner', domain: 'approval' }),
      approval: approvalState,
      expected,
      environment: currentEnvironment || { record: null, error: 'ENVIRONMENT_UNKNOWN', attestation: { ok: false, body: null, error: 'ENVIRONMENT_UNAVAILABLE' } },
      run: { runId, canceled, mutationRecorded },
      registry: registryFact(frozen)
    });
  }

  function approvalState(expected) {
    return approvalFact({ trust, trustRoot, approvalId, approval, issuer, subject, windowsSid: sid, expected, runId: null });
  }

  return {
    trust,
    trustRoot,
    approvalId,
    get signer() { return signer; },
    get lastDecision() { return lastDecision; },

    async preflight({ runDir, frozen }) {
      const expected = await refreshEnvironment(frozen.manifest.runId, frozen);
      // Поколение для сверки связки берётся из самого approval: без него форма facts неполна.
      const probe = approvalFact({ trust, trustRoot, approvalId, approval, issuer, subject, windowsSid: sid, expected: null, runId: null });
      if (probe.body) expected.environmentGeneration = probe.body.environmentGeneration;
      const approvalStateValue = probe.body ? approvalState(expected) : probe;
      const facts = factsFor('preflight', { runId: frozen.manifest.runId, frozen, expected, approvalState: approvalStateValue });
      const decision = decide(facts);
      lastDecision = decision;
      persistDecision(runDir, decision);
      return decision.effect === 'ALLOW' ? { allow: true, decision } : { allow: false, denial: denialOf(decision) };
    },

    async dispatch({ runDir, frozen, intent }) {
      const expected = await refreshEnvironment(frozen.manifest.runId, frozen);
      const probe = approvalFact({ trust, trustRoot, approvalId, approval, issuer, subject, windowsSid: sid, expected: null, runId: null });
      if (probe.body) expected.environmentGeneration = probe.body.environmentGeneration;
      const approvalStateValue = probe.body ? approvalState(expected) : probe;
      const facts = factsFor('dispatch', { runId: frozen.manifest.runId, frozen, expected, approvalState: approvalStateValue, mutationRecorded: false });
      const decision = decide(facts);
      lastDecision = decision;
      persistDecision(runDir, decision);
      if (decision.effect !== 'ALLOW') return { allow: false, denial: denialOf(decision) };
      try {
        const consumed = consumeDispatch({
          trust, trustRoot, approval, approvalId, issuer, subject, windowsSid: sid, expected,
          runId: frozen.manifest.runId, decisionId: decision.decisionId
        });
        if (consumed.ack !== true) {
          return { allow: false, denial: { phase: 'dispatch', reasonCode: consumed.code || 'APPROVAL_CONSUMED', verdictCode: 'CONTRACT_INVALID', message: 'Расход approval не подтверждён; ACK не выдаётся' } };
        }
      } catch (error) {
        return { allow: false, denial: errorDenial(error, 'dispatch') };
      }
      dispatchApproved = true;
      return { allow: true, decision };
    },

    async beforeRequestAck({ frozen }) {
      try {
        const record = currentEnvironment?.record;
        if (!record) fail('ENVIRONMENT_ATTESTATION_FAILED', 'Среда не подтверждена до отправки');
        await attestLiveEnvironment({ trust, record, standPublicKey });
        return { allow: true };
      } catch (error) {
        return { allow: false, denial: errorDenial(error, 'dispatch') };
      }
    },

    async publish({ store, runDir, frozen, verdict }) {
      const existing = readTerminalChoice(runDir);
      if (!existing) {
        publishCandidate(runDir, verdict);
        if (verdict.verdict === 'PASS') {
          let anchored = null;
          if (signer) {
            const anchorId = 'anchor-' + randomUUID();
            const outcome = await anchorWithinBudget({ signer, trustRoot, runDir, approvalId, anchorId });
            if (outcome.ok) {
              try {
                const body = verifyAnchorStatement(trust, outcome.statement);
                if (body.candidateSha256 !== digest(verdict)) fail('ANCHOR_BINDING_REJECTED', 'Анкер относится к другому candidate');
                anchored = { anchorId: body.anchorId };
              } catch { anchored = null; }
            }
          }
          if (anchored) {
            publishTerminalChoice(runDir, {
              schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'anchor',
              candidateSha256: digest(verdict), discardedCandidateSha256: null, anchorId: anchored.anchorId, createdAt: nowIso()
            });
          } else {
            publishBudgetInconclusiveOutcome({ runDir, frozen });
          }
        } else if (verdict.verdict === 'FAIL') {
          publishTerminalChoice(runDir, {
            schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'fail-without-anchor',
            candidateSha256: digest(verdict), discardedCandidateSha256: null, anchorId: null, createdAt: nowIso()
          });
        } else {
          publishTerminalChoice(runDir, {
            schemaVersion: '0.2.0', domain: 'terminal-choice', outcome: 'inconclusive-without-anchor',
            candidateSha256: digest(verdict), discardedCandidateSha256: null, anchorId: null, createdAt: nowIso()
          });
        }
      }
      // Проверка анкера для исхода anchor выполняется внутри publishTerminalVerdict (WP-05 D-01).
      const published = publishTerminalVerdict({ store, runDir, frozen, trust, trustRoot });
      store.appendEvent(runDir, { type: 'TRUST_VERDICT_DURABLE', evidenceId: published.evidenceId, verdict: published.verdict.verdict, anchorId: readTerminalChoice(runDir)?.anchorId || null });
      store.appendEvent(runDir, { type: 'STATE', state: 'FINISHED', verdict: published.verdict.verdict, reasonCode: published.verdict.reasonCode });
      return {
        runId: frozen.manifest.runId,
        runDir,
        verdict: published.verdict,
        evidenceIds: store.readEvidence(runDir).map(item => item.envelope.evidenceId)
      };
    }
  };
}

function assertTrustedOptions(options, required) {
  for (const key of required) {
    if (!options || options[key] === undefined || options[key] === null || options[key] === '') throw fail('CONTRACT_INVALID', 'Доверенный вход требует ' + key);
  }
}

// PASS из общего терминального результата не считается доверенным, пока не подтверждён анкером.
// Это закрывает показ подложного PASS через start/reconcile и через adopt существующего прогона.
function assertTrustedPass(result, { root, trustRoot, trust }) {
  if (!result || !result.verdict || result.verdict.verdict !== 'PASS') return result;
  const store = new RunStore(root);
  const runDir = store.runPath(result.runId);
  const frozen = verifyFrozenBundle(store, runDir);
  const anchored = observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot });
  if (!anchored.trusted || !anchored.passed) throw fail('INTEGRITY_ERROR', 'PASS доверенного прогона не подтверждён анкером');
  return result;
}

async function signerFor(options) {
  if (!options.signerPipe) return null;
  return connectAnchorSigner(options.signerPipe);
}

export async function startTrusted(bundle, options = {}) {
  assertTrustedOptions(options, ['root', 'trustRoot', 'approvalId', 'issuer', 'subject']);
  const trust = loadTrustRoot(options.trustRoot);
  const sid = currentUserSid();
  const signer = await signerFor(options);
  const context = createTrustContext({ trust, trustRoot: options.trustRoot, approvalId: options.approvalId, approval: options.approval || null, issuer: options.issuer, subject: options.subject, sid, standPublicKey: options.standPublicKey || null, signer });
  try {
    const result = await start(bundle, { root: options.root, headed: options.headed || false, fault: options.fault || null, fixtureToken: options.fixtureToken || process.env.QA_ADAPTANT_FIXTURE_TOKEN || '', trust: context });
    return assertTrustedPass(result, { root: options.root, trustRoot: options.trustRoot, trust });
  } finally {
    if (signer && typeof signer.close === 'function') signer.close();
  }
}

export async function observeTrusted({ root, trustRoot, runId } = {}) {
  assertTrustedOptions({ root, trustRoot, runId }, ['root', 'trustRoot', 'runId']);
  const trust = loadTrustRoot(trustRoot);
  const base = await observe({ root, runId });
  const store = new RunStore(root);
  const runDir = store.runPath(runId);
  const frozen = verifyFrozenBundle(store, runDir);
  const anchored = observeTrustedVerdict({ store, runDir, frozen, trust, trustRoot });
  return {
    ...base,
    verdict: anchored.trusted ? anchored.verdict : null,
    trusted: anchored.trusted,
    passed: anchored.passed,
    publication: anchored.state,
    anchorId: anchored.anchorId,
    anchorStatus: anchored.anchorStatus,
    reasonCode: anchored.reasonCode,
    unlinkedAnchorId: anchored.unlinkedAnchorId
  };
}

export async function cancelTrusted({ root, trustRoot, runId, subject } = {}) {
  assertTrustedOptions({ root, trustRoot, runId, subject }, ['root', 'trustRoot', 'runId', 'subject']);
  const trust = loadTrustRoot(trustRoot);
  const sid = currentUserSid();
  const card = principalFact(trust, subject, { windowsSid: sid });
  if (!card.body) fail(card.error || 'CALLER_UNAUTHENTICATED', 'Вызывающий не аутентифицирован для отмены');
  return cancel({ root, runId });
}

export async function reconcileTrusted({ root, trustRoot, approvalId, approval = null, issuer, subject, standPublicKey = null, signerPipe = null, runId, fault = null } = {}) {
  assertTrustedOptions({ root, trustRoot, approvalId, issuer, subject, runId }, ['root', 'trustRoot', 'approvalId', 'issuer', 'subject', 'runId']);
  const trust = loadTrustRoot(trustRoot);
  const sid = currentUserSid();
  const signer = await signerFor({ signerPipe });
  const context = createTrustContext({ trust, trustRoot, approvalId, approval, issuer, subject, sid, standPublicKey, signer });
  try {
    const result = await reconcile({ root, runId, trust: context, fault });
    return assertTrustedPass(result, { root, trustRoot, trust });
  } finally {
    if (signer && typeof signer.close === 'function') signer.close();
  }
}
