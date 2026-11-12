import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { RunStore } from '../../packages/core/store.mjs';
import { verifyFrozenBundle } from '../../packages/core/bundle.mjs';
import { digest } from '../../packages/core/canonical.mjs';
import { IndependentRead, validate, validateVerdictCoverage } from '../../packages/contracts/index.mjs';

const runDir = path.resolve(process.argv[2] || '');
const expectedManifestHash = process.argv[3] || '';
const browserUncertain = process.argv.includes('--browser-unconfirmed');
const canceled = process.argv.includes('--cancellation');
const now = () => new Date().toISOString();
const send = message => new Promise((resolve, reject) => {
  if (!process.connected) return reject(new Error('IPC_DISCONNECTED'));
  process.send(message, error => error ? reject(error) : resolve());
});
function exitSoon(code) {
  setImmediate(() => {
    process.exitCode = code;
    try { if (process.connected) process.disconnect(); } catch {}
  });
}

function verdictBase(runId, manifestSha256, checks, verdict, reasonCode, ownershipVerified, integrityVerified, message) {
  return { schemaVersion: '0.1.0', runId, manifestSha256, verdict, reasonCode, message,
    checks, ownershipVerified, integrityVerified, completedAt: now() };
}

function unknownChecks(operation) {
  return operation.effects.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] }));
}

async function jsonGet(url, timeoutMs) {
  const headers = { accept: 'application/json' };
  if (process.env.QA_ADAPTANT_FIXTURE_TOKEN) headers.authorization = `Bearer ${process.env.QA_ADAPTANT_FIXTURE_TOKEN}`;
  const response = await fetch(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers });
  if (response.status !== 200) return { status: response.status, body: null };
  const reader = response.body?.getReader();
  if (!reader) return { status: response.status, body: null };
  const chunks = []; let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > 1_048_576) { await reader.cancel(); return { status: response.status, body: null }; }
    chunks.push(Buffer.from(value));
  }
  try { return { status: response.status, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }; }
  catch { return { status: response.status, body: null }; }
}

function assertEvidenceRefs(items, bundle) {
  const { manifest, fixture, scenario, operation, manifestSha256 } = bundle;
  const nodes = new Map(scenario.nodes.map(node => [node.id, node]));
  for (const { envelope, artifact } of items) {
    if (envelope.runId !== manifest.runId || envelope.manifestSha256 !== manifestSha256 || envelope.fixtureId !== fixture.fixtureId) throw new Error('EVIDENCE_SCOPE');
    if (!nodes.has(envelope.stepId)) throw new Error('EVIDENCE_STEP');
    if (envelope.kind === 'mutation-intent') {
      if (envelope.producer !== 'control' || nodes.get(envelope.stepId).action.type !== 'click' ||
          artifact.operationId !== operation.id || artifact.intentId !== `${manifest.runId}:${envelope.stepId}` ||
          artifact.inputsSha256 !== digest(operation.inputs) || artifact.fixtureId !== fixture.fixtureId) throw new Error('INTENT_INVALID');
    }
    if (envelope.kind === 'request') {
      const intent = items.find(x => envelope.parentEvidenceIds.includes(x.envelope.evidenceId) && x.envelope.kind === 'mutation-intent');
      if (envelope.producer !== 'browser' || !intent || envelope.requestId !== artifact.requestId && artifact.requestId !== undefined ||
          artifact.operationId !== operation.id || artifact.intentId !== intent.artifact.intentId ||
          artifact.method !== 'POST' || artifact.path !== '/records' || artifact.fixtureId !== fixture.fixtureId ||
          digest(artifact.fields) !== digest({ ...operation.inputs, fixtureId: fixture.fixtureId }) ||
          intent.artifact.inputsSha256 !== digest(operation.inputs)) throw new Error('REQUEST_INVALID');
    }
    if (envelope.kind === 'response') {
      const request = items.find(x => envelope.parentEvidenceIds.includes(x.envelope.evidenceId) && x.envelope.kind === 'request');
      if (envelope.producer !== 'browser' || !request || envelope.requestId !== request.envelope.requestId ||
          (artifact.requestId !== undefined && artifact.requestId !== request.envelope.requestId) ||
          !artifact.entity || !envelope.entity || artifact.entity.kind !== operation.entityKind ||
          artifact.entity.id !== envelope.entity.id || artifact.fixtureId !== fixture.fixtureId ||
          artifact.status < 200 || artifact.status >= 300) throw new Error('RESPONSE_INVALID');
      if (request.artifact.fixtureId !== artifact.fixtureId) throw new Error('RESPONSE_FIXTURE');
    }
    if (!['mutation-intent', 'request', 'response'].includes(envelope.kind)) throw new Error('EVIDENCE_KIND');
  }
  const mutationNodes = scenario.nodes.filter(n => n.action.type === 'click');
  const intents = items.filter(x => x.envelope.kind === 'mutation-intent');
  const requests = items.filter(x => x.envelope.kind === 'request');
  const responses = items.filter(x => x.envelope.kind === 'response');
  if (mutationNodes.length !== 1 || intents.length !== 1 || requests.length !== 1 || responses.length > 1) throw new Error('EVIDENCE_CHAIN');
  if (responses.length && responses[0].envelope.parentEvidenceIds.length !== 1) throw new Error('RESPONSE_PARENT');
  return { intent: intents[0], request: requests[0], response: responses[0] || null };
}

async function execute() {
  const store = new RunStore(path.dirname(path.dirname(runDir)));
  const bundle = verifyFrozenBundle(store, runDir);
  const { manifest, operation, fixture, manifestSha256 } = bundle;
  if (manifestSha256 !== expectedManifestHash || digest(manifest) !== expectedManifestHash) throw new Error('MANIFEST_HASH');
  const base = new URL(manifest.environment.baseUrl);
  if (base.protocol !== 'http:' || base.hostname !== '127.0.0.1' || !base.port || base.pathname !== '/' || base.search || base.hash || base.username || base.password) throw new Error('ORIGIN');
  const items = store.readEvidence(runDir);
  const chain = assertEvidenceRefs(items, bundle);
  const reads = [];
  let ownershipVerified = false;
  let integrityVerified = true;
  const started = Date.now();
  const absoluteDeadline = started + manifest.budget.deadlineMs;
  const environmentUrl = new URL('/environment', base);
  const envBefore = await jsonGet(environmentUrl, Math.min(3000, manifest.budget.deadlineMs));
  if (envBefore.status !== 200 || !envBefore.body || envBefore.body.environmentId !== manifest.environment.id || envBefore.body.environmentId !== fixture.environmentId || envBefore.body.fingerprint !== manifest.environment.fingerprint) throw new Error('ENVIRONMENT_BEFORE');

  const statuses = new Map();
  for (const effect of operation.effects) {
    if (effect.appliesWhen) {
      if (!Object.hasOwn(operation.inputs, effect.appliesWhen.field)) statuses.set(effect.id, 'UNKNOWN');
      else if (operation.inputs[effect.appliesWhen.field] !== effect.appliesWhen.equals) statuses.set(effect.id, 'NOT_APPLICABLE');
    }
  }
  const active = operation.effects.filter(effect => !statuses.has(effect.id));
  const overallEnd = Math.min(absoluteDeadline, Date.now() + Math.max(...active.map(e => e.deadlineMs), 0));
  let readAttempts = 0;
  const lastProofByEffect = new Map();
  let identityFailure = false;
  while (active.some(effect => !['SATISFIED', 'UNKNOWN'].includes(statuses.get(effect.id))) || active.some(effect => !statuses.has(effect.id))) {
    const pending = active.filter(effect => !statuses.has(effect.id));
    if (!pending.length || Date.now() >= overallEnd || readAttempts >= manifest.budget.maxReadAttempts) break;
    const timeoutMs = Math.max(100, Math.min(3000, overallEnd - Date.now()));
    const url = new URL('/records', base); url.searchParams.set('fixtureId', fixture.fixtureId);
    let result = null;
    try { result = await jsonGet(url, timeoutMs); } catch { result = null; }
    readAttempts++;
    const readable = result && result.status === 200 && Array.isArray(result.body?.records);
    if (!readable) {
      const wait = Math.min(...pending.map(effect => effect.intervalMs), 1000);
      await new Promise(resolve => setTimeout(resolve, Math.min(wait, Math.max(0, overallEnd - Date.now()))));
      continue;
    }
    const matches = result.body.records.filter(record => record?.fixtureId === fixture.fixtureId);
    if (result.body.records.length > 0 && matches.length !== result.body.records.length) { identityFailure = true; break; }
    if (matches.length > 1) { identityFailure = true; break; }
    const record = matches[0];
    if (record && chain.response && (record.id !== chain.response.envelope.entity?.id || record.id !== chain.response.artifact.entity?.id)) { identityFailure = true; break; }
    if (record) {
      const responseMatches = !chain.response || (record.id === chain.response.envelope.entity.id && chain.response.envelope.entity.kind === operation.entityKind);
      const identityValid = responseMatches && record.fixtureId === fixture.fixtureId &&
        operation.verification.identityFields.every(field => Object.hasOwn(record, field) && record[field] === (field === fixture.ownership.field ? fixture.ownership.value : operation.inputs[field]));
      if (!identityValid) { identityFailure = true; break; }
      ownershipVerified = true;
      const readRequestId = randomUUID();
      const fields = Object.fromEntries([...Object.keys(operation.inputs), ...operation.verification.identityFields].filter((v, i, a) => a.indexOf(v) === i).filter(key => Object.hasOwn(record, key) && (record[key] === null || ['string', 'number', 'boolean'].includes(typeof record[key]))).map(key => [key, record[key]]));
      const observedAt = now();
      const artifact = { method: 'GET', path: '/records', fixtureId: fixture.fixtureId, entity: { kind: operation.entityKind, id: record.id }, fields, environmentFingerprint: envBefore.body.fingerprint, requestId: readRequestId, httpStatus: 200, observedAt };
      IndependentRead.parse(artifact);
      const checkIds = active.filter(effect => Object.hasOwn(fields, effect.field)).map(effect => effect.id);
      const envelope = store.appendEvidence(runDir, { runId: manifest.runId, manifestSha256, fixtureId: fixture.fixtureId,
        stepId: bundle.scenario.nodes.find(node => node.action.type === 'verify').id, producer: 'verification', kind: 'independent-read',
        artifact, requestId: readRequestId, entity: artifact.entity, parentEvidenceIds: [(chain.response || chain.request).envelope.evidenceId], checkIds });
      const entry = { envelope, artifact }; reads.push(entry);
      for (const effect of pending) {
        if (!Object.hasOwn(fields, effect.field)) continue;
        if (fields[effect.field] === effect.equals) { statuses.set(effect.id, 'SATISFIED'); lastProofByEffect.set(effect.id, envelope.evidenceId); }
        else lastProofByEffect.set(effect.id, envelope.evidenceId);
      }
    }
    if (active.some(effect => !statuses.has(effect.id))) {
      const wait = Math.min(...active.filter(effect => !statuses.has(effect.id)).map(effect => effect.intervalMs), 1000);
      await new Promise(resolve => setTimeout(resolve, Math.min(wait, Math.max(0, overallEnd - Date.now()))));
    }
  }

  const envAfter = await jsonGet(environmentUrl, Math.min(3000, Math.max(100, absoluteDeadline - Date.now()))).catch(() => null);
  if (!envAfter || envAfter.status !== 200 || envAfter.body?.environmentId !== manifest.environment.id || envAfter.body?.fingerprint !== envBefore.body.fingerprint) throw new Error('ENVIRONMENT_AFTER');
  const completedDeadline = Date.now() >= overallEnd || readAttempts >= manifest.budget.maxReadAttempts;
  const checks = operation.effects.map(effect => {
    let status = statuses.get(effect.id);
    if (!status) {
      if (effect.appliesWhen && !Object.hasOwn(operation.inputs, effect.appliesWhen.field)) status = 'UNKNOWN';
      else if (effect.appliesWhen && operation.inputs[effect.appliesWhen.field] !== effect.appliesWhen.equals) status = 'NOT_APPLICABLE';
      else if (completedDeadline && lastProofByEffect.has(effect.id)) status = 'VIOLATED';
      else status = 'UNKNOWN';
    }
    return { id: effect.id, status, evidenceIds: ['SATISFIED', 'VIOLATED'].includes(status) ? [lastProofByEffect.get(effect.id)] : [] };
  });
  let verdict, reasonCode, message;
  if (canceled) { verdict = 'INCONCLUSIVE'; reasonCode = 'CANCELED'; message = 'Прогон отменён; начавшаяся мутация не повторяется и не откатывается'; }
  else if (browserUncertain) { verdict = 'INCONCLUSIVE'; reasonCode = 'WORKER_LOST'; message = 'Browser Worker завершился без подтверждения полного выполнения; мутация не повторяется'; }
  else if (identityFailure || !chain.response) { verdict = 'INCONCLUSIVE'; reasonCode = 'RESULT_UNCONFIRMED'; message = 'Независимое чтение не удалось связать с подтверждённым ответом мутации'; }
  else if (checks.some(check => check.status === 'UNKNOWN')) { verdict = 'INCONCLUSIVE'; reasonCode = 'EVIDENCE_MISSING'; message = 'Для завершения обязательных проверок недостаточно независимых данных'; }
  else if (checks.some(check => check.status === 'VIOLATED')) { verdict = 'FAIL'; reasonCode = 'BUSINESS_INVARIANT_VIOLATED'; message = 'Независимое чтение подтвердило нарушение ожидаемого эффекта'; }
  else { verdict = 'PASS'; reasonCode = 'NONE'; message = 'Все обязательные эффекты подтверждены независимым чтением'; }
  const payloadVerdict = verdictBase(manifest.runId, manifestSha256, checks, verdict, reasonCode, ownershipVerified, integrityVerified, message);
  validateVerdictCoverage(payloadVerdict, operation, reads);
  return { runId: manifest.runId, payload: { verdict: payloadVerdict, reads } };
}

try {
  const result = await execute();
  await send({ type: 'RESULT', ...result });
} catch (error) {
  if (process.env.QA_ADAPTANT_DEBUG === '1') console.error(error);
  let runId = 'verification'; let manifestSha256 = /^[a-f0-9]{64}$/.test(expectedManifestHash) ? expectedManifestHash : '0'.repeat(64); let operation;
  try {
    const store = new RunStore(path.dirname(path.dirname(runDir)));
    const m = store.readSnapshot(runDir, 'manifest').value; runId = m.runId;
    const o = store.readSnapshot(runDir, 'operation').value; operation = o;
  } catch {}
  const checks = operation?.effects?.map(effect => ({ id: effect.id, status: 'UNKNOWN', evidenceIds: [] })) || [];
  const environmentChanged = ['ENVIRONMENT_BEFORE', 'ENVIRONMENT_AFTER'].includes(error.message);
  const integrityError = /INTEGRITY|RESPONSE_INVALID|REQUEST_INVALID|INTENT_INVALID|EVIDENCE_SCOPE|EVIDENCE_STEP|EVIDENCE_CHAIN|READ_|VERDICT_/.test(error.message);
  const reasonCode = environmentChanged ? 'ENVIRONMENT_CHANGED' : (integrityError ? 'INTEGRITY_ERROR' : 'EVIDENCE_MISSING');
  const verdict = verdictBase(runId, manifestSha256, checks, 'INCONCLUSIVE', reasonCode, false, !integrityError, 'Проверка не завершена; подробности доступны только в локальном журнале процесса');
  try { await send({ type: 'RESULT', runId, payload: { verdict, reads: [] } }); } catch {}
}
exitSoon(0);
