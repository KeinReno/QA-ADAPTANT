// Общая библиотека Red Team (Agent D, волна 1, база 0e7e6c2).
// Скрипты Red Team самостоятельны: каждый печатает JSON-вердикт и выставляет exit code.
//   exit 0 = PASS (защита/ожидаемое поведение подтверждены фактическим прогоном)
//   exit 1 = FAIL (дефект: защита не сработала / утверждение не воспроизвелось)
//   exit 3 = INCONCLUSIVE (на этой ревизии проверить нечем; причина в отчёте)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { digest } from '../../packages/core/canonical.mjs';
export { digest };
import { createTrustRoot, loadTrustRoot, unwrapPrivateKey, signTrustedDocument } from '../../packages/trust/identity.mjs';
import { signApproval } from '../../packages/trust/approval.mjs';

export const PROJECT_ROOT = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));

export function git(args, cwd = PROJECT_ROOT) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8', windowsHide: true });
  return result.status === 0 ? result.stdout.trim() : '';
}

export function revision(cwd = PROJECT_ROOT) {
  return git(['rev-parse', 'HEAD'], cwd) || 'UNKNOWN';
}

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export function remove(target) {
  try { fs.rmSync(target, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* временный каталог */ }
}

export function makeTemp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'qa-redteam-' + prefix + '-'));
}

export const INPUTS = Object.freeze({ comment: 'заметка', executorId: 'operator-1', title: 'запись' });
export const EFFECTS = Object.freeze([
  { id: 'title-saved', field: 'title', equals: INPUTS.title },
  { id: 'executor-saved', field: 'executorId', equals: INPUTS.executorId },
  { id: 'comment-saved', field: 'comment', equals: INPUTS.comment }
].map(Object.freeze));
export const OPERATION = Object.freeze({ id: 'local-create-record', version: '1.0.0', effects: EFFECTS });
export const SCENARIO_CONTENT_SHA256 = digest({ schemaVersion: '0.1.0', id: 'local-create', status: 'APPROVED' });

export async function makeTrust(prefix = 'trust') {
  const root = makeTemp(prefix);
  const secretsDir = path.join(root, 'secrets');
  const trustRoot = path.join(root, 'trust-root');
  const created = await createTrustRoot({ secretsDir, trustRoot });
  const trust = loadTrustRoot(trustRoot);
  const ownerKey = await unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const anchorKey = await unwrapPrivateKey(path.join(secretsDir, 'anchor.key'));
  return {
    root, secretsDir, trustRoot, trust, ownerKey, anchorKey,
    ownerKeyId: created.ownerKeyId, anchorKeyId: created.anchorKeyId,
    cleanup() { remove(root); }
  };
}

export function principals(env, overrides = {}) {
  const issuer = signTrustedDocument(env.ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner',
    roles: ['owner', 'operator'], keyId: env.ownerKeyId, windowsSid: 'S-1-5-21-owner', status: 'active',
    ...(overrides.issuer || {})
  });
  const subject = signTrustedDocument(env.ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator',
    roles: ['operator'], keyId: env.ownerKeyId, windowsSid: 'S-1-5-21-operator', status: 'active',
    ...(overrides.subject || {})
  });
  return { issuer, subject };
}

export function approvalFields(approvalId, overrides = {}) {
  return {
    approvalId,
    issuerPrincipalId: 'local-owner',
    subjectPrincipalId: 'local-operator',
    operationId: OPERATION.id,
    operationVersion: OPERATION.version,
    scenarioContentSha256: SCENARIO_CONTENT_SHA256,
    operationSha256: digest(OPERATION),
    approvedInputsHash: digest(INPUTS),
    fixtureId: 'fixture-local',
    targetEnvironmentId: 'local-stand',
    environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' },
    allowedEffects: EFFECTS,
    approvalNonce: digest(approvalId + '-' + randomUUID()),
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    ...overrides
  };
}

export function makeApproval(env, approvalId, overrides = {}) {
  return signApproval(env.ownerKey, { ...approvalFields(approvalId, overrides), keyId: overrides.keyId || env.ownerKeyId }, env.trust, env.trustRoot);
}

export function expectedOf(overrides = {}) {
  return {
    operation: OPERATION,
    inputs: INPUTS,
    effects: EFFECTS,
    scenarioContentSha256: SCENARIO_CONTENT_SHA256,
    fixtureId: 'fixture-local',
    environmentId: 'local-stand',
    environmentGeneration: 1,
    resource: { method: 'POST', path: '/records' },
    ...overrides
  };
}

export function dispatchRequest(env, approval, options = {}) {
  const { runId = 'run-redteam-1', decisionId = 'decision-redteam-1', overrides = {} } = options;
  const cards = env.cards || principals(env);
  return {
    trust: env.trust,
    trustRoot: env.trustRoot,
    approval,
    issuer: cards.issuer,
    subject: cards.subject,
    windowsSid: 'S-1-5-21-operator',
    expected: expectedOf(),
    runId,
    decisionId,
    ...overrides
  };
}

export function record(checks, name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  return Boolean(ok);
}

function summarize(value) {
  if (value === undefined) return 'undefined';
  try {
    const text = JSON.stringify(value);
    return text.length > 300 ? text.slice(0, 300) + '…' : text;
  } catch { return String(value); }
}

export async function expectThrow(checks, name, fn, code) {
  try {
    const value = await fn();
    record(checks, name, false, { expectedCode: code, actual: 'исключения нет', value: summarize(value) });
    return false;
  } catch (error) {
    const ok = error.code === code;
    record(checks, name, ok, ok
      ? { code }
      : { expectedCode: code, actualCode: error.code || null, message: String(error.message || error) });
    return ok;
  }
}

// Ожидать исключение по code ИЛИ по подстроке message (store.mjs бросает Error('INTEGRITY_ERROR: ...') без code).
export async function expectThrowLike(checks, name, fn, expected = {}) {
  const { code, messageIncludes } = expected;
  try {
    const value = await fn();
    record(checks, name, false, { expectedCode: code || null, expectedMessage: messageIncludes || null, actual: 'исключения нет', value: summarize(value) });
    return false;
  } catch (error) {
    const byCode = code ? error.code === code : true;
    const byMessage = messageIncludes ? String(error.message || '').includes(messageIncludes) : true;
    const ok = byCode && byMessage;
    record(checks, name, ok, ok
      ? { code: error.code || null, messageIncludes: messageIncludes || null }
      : { expectedCode: code || null, expectedMessage: messageIncludes || null, actualCode: error.code || null, message: String(error.message || error) });
    return ok;
  }
}

export async function expectTrue(checks, name, fn, predicate = value => Boolean(value)) {
  try {
    const value = await fn();
    const ok = predicate(value);
    record(checks, name, ok, { value: summarize(value) });
    return ok;
  } catch (error) {
    record(checks, name, false, { unexpectedError: error.code || null, message: String(error.message || error) });
    return false;
  }
}

export function finish({ id, title, checks, notes = [], verdict, risk = null, revisionDir = PROJECT_ROOT }) {
  const computed = checks.every(check => check.ok) ? 'PASS' : 'FAIL';
  const status = verdict || computed;
  const result = {
    tool: 'REDTEAM',
    id,
    title,
    revision: revision(revisionDir),
    risk,
    scope: 'Windows, локальный стенд 127.0.0.1; продуктовый код не менялся',
    verdict: status,
    exitCode: status === 'PASS' ? 0 : status === 'FAIL' ? 1 : 3,
    checks,
    notes,
    platform: process.platform,
    node: process.version,
    createdAt: new Date().toISOString()
  };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exitCode = result.exitCode;
  return result;
}

export function runNode(script, args = [], options = {}) {
  const { cwd = PROJECT_ROOT, env = {}, timeoutMs = 120_000 } = options;
  return new Promise(resolve => {
    const child = spawn(process.execPath, [script, ...args], { cwd, env: { ...process.env, ...env }, windowsHide: true });
    const out = [];
    const err = [];
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* уже мёртв */ } }, timeoutMs);
    child.stdout.on('data', chunk => out.push(chunk));
    child.stderr.on('data', chunk => err.push(chunk));
    child.on('error', error => { clearTimeout(timer); resolve({ code: -1, stdout: Buffer.concat(out).toString('utf8'), stderr: String(error.message) }); });
    child.on('exit', code => { clearTimeout(timer); resolve({ code: code ?? -1, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }); });
  });
}

export async function waitForFile(file, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(file)) {
    if (Date.now() > deadline) throw new Error('Не дождались файла ' + file);
    await sleep(10);
  }
}

export function findText(dir, needle) {
  const matches = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && fs.statSync(full).size <= 4 * 1024 * 1024) {
        if (fs.readFileSync(full).includes(Buffer.from(needle))) matches.push(full);
      }
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return matches;
}

export function listFiles(dir) {
  const result = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else result.push(full);
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return result;
}