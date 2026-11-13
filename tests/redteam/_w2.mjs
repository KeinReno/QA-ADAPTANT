// _w2.mjs — обвязка Red Team волны 2: работает против указанной ветки/каталога (по умолчанию integration),
// ничего в ней не меняет; все данные — временные каталоги %TEMP%. Скрипты волны 2 печатают JSON и
// выставляют exit code: 0 PASS, 1 FAIL, 3 INCONCLUSIVE.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { randomUUID, createHash } from 'node:crypto';

export const DEFAULT_TARGET = 'C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\integration';

function git(dir, args) {
  const result = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', windowsHide: true });
  return result.status === 0 ? result.stdout.trim() : '';
}

export function parseTarget(argv = process.argv.slice(2)) {
  const arg = argv.find(item => item.startsWith('--target='));
  const dir = path.resolve(arg ? arg.slice('--target='.length) : DEFAULT_TARGET);
  if (!fs.existsSync(path.join(dir, 'package.json'))) throw new Error('Целевой каталог не похож на репозиторий: ' + dir);
  return dir;
}

export function targetState(dir) {
  const status = git(dir, ['status', '--porcelain']);
  const diff = git(dir, ['diff']);
  return {
    dir,
    head: git(dir, ['rev-parse', 'HEAD']),
    dirty: status !== '',
    status,
    diffHash: createHash('sha256').update(diff).digest('hex')
  };
}

// Стабильный снимок рабочего дерева целевой ветки: живые коммиты Lead во время прогона не должны
// менять проверяемые файлы. Снимок кэшируется в %TEMP% по хэшу HEAD+diff; код не меняет исходный worktree.
export function prepareSnapshot(liveDir) {
  const live = path.resolve(liveDir);
  for (let attempt = 0; attempt < 3; attempt++) {
    const before = targetState(live);
    const key = createHash('sha256').update(before.head + '\n' + before.diffHash).digest('hex').slice(0, 16);
    const snapshotDir = path.join(os.tmpdir(), 'qa-rt2-snap-' + key);
    if (!fs.existsSync(path.join(snapshotDir, 'package.json'))) {
      try { fs.rmSync(snapshotDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* кэш */ }
      fs.cpSync(live, snapshotDir, {
        recursive: true, force: true,
        filter: source => !['node_modules', '.git'].includes(path.basename(source))
      });
      const liveModules = path.join(live, 'node_modules');
      if (fs.existsSync(liveModules)) fs.symlinkSync(liveModules, path.join(snapshotDir, 'node_modules'), 'junction');
    }
    const after = targetState(live);
    if (before.head === after.head && before.diffHash === after.diffHash) {
      return { dir: snapshotDir, live, head: before.head, dirty: before.dirty, diffHash: before.diffHash, stable: true, key };
    }
  }
  const state = targetState(live);
  return { dir: null, live, head: state.head, dirty: state.dirty, diffHash: state.diffHash, stable: false, key: null };
}

export async function loadTarget(dir) {
  const imp = rel => import(pathToFileURL(path.join(dir, rel)).href);
  const modules = {
    core: await imp('packages/core/canonical.mjs'),
    store: await imp('packages/core/store.mjs'),
    bundle: await imp('packages/core/bundle.mjs'),
    contracts: await imp('packages/contracts/index.mjs'),
    evidencePolicy: await imp('packages/core/evidence-policy.mjs'),
    server: await imp('adapters/local/server.mjs'),
    localBundle: await imp('adapters/local/bundle.mjs'),
    identity: await imp('packages/trust/identity.mjs'),
    approval: await imp('packages/trust/approval.mjs'),
    environment: await imp('packages/trust/environment.mjs'),
    anchor: await imp('packages/trust/anchor.mjs'),
    anchorSigner: await imp('packages/trust/anchor-signer.mjs'),
    policy: await imp('packages/trust/policy.mjs'),
    facts: await imp('packages/trust/facts.mjs'),
    sid: await imp('packages/trust/windows-sid.mjs'),
    trusted: await imp('apps/control/trusted.mjs'),
    run: await imp('apps/control/run.mjs')
  };
  modules.digest = modules.core.digest;
  return modules;
}

// --- Мир доверенного прогона (trust root + локальный стенд + запись среды + подписант) ------
export async function makeWorld(modules, options = {}) {
  const {
    generation = 1, recordOverrides = {}, standOptions = {}, withSigner = true, withRecord = true, commitRecord = true
  } = options;
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-rt2-'));
  const root = path.join(base, 'store');
  const secretsDir = path.join(base, 'secrets');
  const trustRoot = path.join(base, 'trust');
  const created = await modules.identity.createTrustRoot({ secretsDir, trustRoot, runDir: root });
  const trust = modules.identity.loadTrustRoot(trustRoot);
  const ownerKey = await modules.identity.unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const stand = await modules.server.serveLocalFixture({ generation, ...standOptions });
  const sid = modules.sid.currentUserSid();
  let record = null;
  if (withRecord) {
    record = modules.environment.signEnvironmentRecord(ownerKey, {
      environmentId: stand.environmentId,
      generation: stand.generation,
      kind: 'local-stand',
      status: 'active',
      origin: stand.baseUrl,
      standKeyId: stand.standKeyId,
      credentialRef: 'local:fixture-token',
      ...recordOverrides
    });
    if (commitRecord) modules.environment.commitEnvironmentRecord(trust, trustRoot, record);
  }
  let signer = null;
  if (withSigner) {
    signer = modules.anchorSigner.startAnchorSigner({ trustRoot, secretsDir });
    await signer.ready;
  }
  const signCard = card => modules.identity.signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', ...card, keyId: created.ownerKeyId, status: 'active'
  });
  const cards = {
    owner: signCard({ principalId: 'local-owner', roles: ['owner'], windowsSid: sid }),
    operator: signCard({ principalId: 'local-operator', roles: ['operator'], windowsSid: sid })
  };
  const world = {
    modules, base, root, secretsDir, trustRoot, trust, ownerKey, stand, record, signer, sid, cards, created,
    prepare({ runId, inputs, mutate } = {}) {
      const id = runId || 'rt2-' + randomUUID().slice(0, 8);
      const contract = modules.localBundle.localFixtureContract(stand, id);
      stand.fixtureId = contract.fixtureId;
      const bundle = modules.localBundle.localBundle(stand, { runId: id, inputs });
      bundle.fixture = contract;
      bundle.manifest.fixtureSha256 = modules.digest(contract);
      if (mutate) mutate({ bundle, contract });
      return { bundle, contract, runId: id };
    },
    approvalFor({ bundle, contract, overrides = {}, approvalId, inputs } = {}) {
      const id = approvalId || 'approval-' + randomUUID().slice(0, 8);
      const issuedAt = new Date().toISOString();
      const fields = {
        approvalId: id,
        issuerPrincipalId: 'local-owner',
        subjectPrincipalId: 'local-operator',
        operationId: bundle.operation.id,
        operationVersion: bundle.operation.version,
        scenarioContentSha256: bundle.scenario.approval.contentSha256,
        operationSha256: modules.digest(bundle.operation),
        approvedInputsHash: modules.digest(inputs || bundle.operation.inputs),
        fixtureId: contract.fixtureId,
        targetEnvironmentId: stand.environmentId,
        environmentGeneration: stand.generation,
        targetResource: { method: 'POST', path: '/records' },
        allowedEffects: bundle.operation.effects.map(effect => ({ id: effect.id, field: effect.field, equals: effect.equals })),
        issuedAt,
        expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
        approvalNonce: 'ab'.repeat(32),
        keyId: created.ownerKeyId,
        ...overrides
      };
      return modules.approval.signApproval(ownerKey, fields, trust, trustRoot);
    },
    trustedOptions(approval, extra = {}) {
      return {
        root,
        trustRoot,
        approvalId: approval.approvalId,
        approval,
        issuer: cards.owner,
        subject: cards.operator,
        signerPipe: signer ? signer.pipePath : null,
        standPublicKey: stand.standPublicKey,
        fixtureToken: stand.authToken,
        // E-04: секрет выдаётся только по credentialRef подписанной записи среды.
        credentials: record ? { [record.credentialRef]: stand.authToken } : {},
        ...extra
      };
    },
    async cleanup() {
      try { if (signer) await signer.close(); } catch { /* канал уже закрыт */ }
      try { await stand.close(); } catch { /* стенд уже закрыт */ }
      try { fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* временный каталог */ }
    }
  };
  return world;
}

// Пересобрать связки после изменения operation/contract: сценарий, манифест, подпись сценария.
export function rebindBundle(modules, { bundle, contract }) {
  const click = bundle.scenario.nodes.find(node => node.action.type === 'click');
  click.action.operationId = bundle.operation.id;
  click.action.mutationName = bundle.operation.mutation.name;
  const verify = bundle.scenario.nodes.at(-1);
  verify.action.operationId = bundle.operation.id;
  bundle.scenario.operation = { id: bundle.operation.id, version: bundle.operation.version, sha256: modules.digest(bundle.operation) };
  bundle.scenario.inputs = { ...bundle.operation.inputs };
  bundle.scenario.approval = {
    actor: 'local-test-harness',
    approvedAt: new Date().toISOString(),
    contentSha256: modules.core.scenarioApprovalHash(bundle.scenario)
  };
  bundle.manifest.operation = { id: bundle.operation.id, version: bundle.operation.version, sha256: modules.digest(bundle.operation) };
  bundle.manifest.scenario = { id: bundle.scenario.id, version: bundle.scenario.version, sha256: modules.digest(bundle.scenario) };
  bundle.manifest.fixtureSha256 = modules.digest(contract);
  bundle.manifest.environment.id = contract.environmentId;
  return { bundle, contract };
}

// --- Проверки и вывод ----------------------------------------------------------------------
export function check(checks, name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  return Boolean(ok);
}

export async function expectCode(checks, name, fn, code) {
  try {
    const value = await fn();
    check(checks, name, false, { expectedCode: code, actual: 'исключения нет', value: brief(value) });
    return false;
  } catch (error) {
    const ok = error.code === code;
    check(checks, name, ok, ok ? { code } : { expectedCode: code, actualCode: error.code || null, message: String(error.message || error) });
    return ok;
  }
}

export async function expectRejectsWithCode(checks, name, fn, code) {
  return expectCode(checks, name, fn, code);
}

export function brief(value) {
  if (value === undefined) return 'undefined';
  try {
    const text = JSON.stringify(value);
    return text.length > 400 ? text.slice(0, 400) + '…' : text;
  } catch { return String(value); }
}

export function evidenceOf(modules, root, runId) {
  const store = new modules.store.RunStore(root);
  return store.readEvidence(store.runPath(runId));
}

export function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }

export function findText(dir, needle) {
  const result = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.size <= 4 * 1024 * 1024 && fs.readFileSync(full).includes(Buffer.from(needle))) result.push(full);
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return result;
}

// Основной вход скрипта: цель, мир, проверки, стабильность целевой ревизии, JSON и exit code.
export async function caseMain({ id, title, risk = null, targetDir = null, body }) {
  const checks = [];
  const argv = process.argv.slice(2);
  const pinned = argv.includes('--pinned');
  const shaOverride = (argv.find(item => item.startsWith('--sha=')) || '').slice('--sha='.length) || null;
  const liveDir = targetDir || parseTarget();
  const target = pinned
    ? { dir: path.resolve(liveDir), live: path.resolve(liveDir), head: shaOverride || '', dirty: false, diffHash: '', stable: true, key: 'pinned' }
    : prepareSnapshot(liveDir);
  const cleanups = [];
  let modules = null;
  let verdictOverride = null;
  let fatal = null;
  try {
    if (!target.dir) throw new Error('Не удалось снять стабильный снимок целевой ветки (она меняется)');
    modules = await loadTarget(target.dir);
    const result = await body({ modules, target, cleanup: fn => cleanups.push(fn), checks });
    if (result && typeof result.verdict === 'string') verdictOverride = result.verdict;
  } catch (error) {
    check(checks, 'скрипт завершился без аварии', false, { code: error.code || null, message: String(error.message || error), stack: String(error.stack || '').split(String.fromCharCode(10)).slice(0, 6).join(' | ') });
    fatal = error;
  } finally {
    for (const fn of cleanups.reverse()) { try { await fn(); } catch { /* уборка временного мира */ } }
  }
  const stable = Boolean(target.stable);
  check(checks, 'снимок целевой ветки снят стабильно (HEAD+diff)', stable, { head: target.head, dirty: target.dirty, diffHash: target.diffHash });
  const computed = checks.every(item => item.ok) ? 'PASS' : 'FAIL';
  let verdict = verdictOverride || computed;
  if (!stable && !fatal) verdict = 'INCONCLUSIVE';
  const result = {
    tool: 'REDTEAM-W2',
    id,
    title,
    target: { liveDir: target.live, snapshotDir: target.dir, head: target.head, dirtyAtStart: target.dirty, diffHashAtStart: target.diffHash, stringDiffHash: target.diffHash, snapshotKey: target.key, stable },
    verdict,
    exitCode: verdict === 'PASS' ? 0 : verdict === 'FAIL' ? 1 : 3,
    checks,
    platform: process.platform,
    node: process.version,
    createdAt: new Date().toISOString()
  };
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exitCode = result.exitCode;
  return result;
}

// Простой HTTP-сервер для E-01/E-07: зеркало /environment и урезанный /attest.
export function startRogueServer({ port, environmentId, fingerprint, attestation = null, sourceRevision = 'rogue' }) {
  const state = { mutationCount: 0, attestCount: 0, requests: [] };
  const server = http.createServer((request, response) => {
    state.requests.push({ method: request.method, url: request.url });
    if (request.method === 'GET' && request.url === '/environment') {
      const body = Buffer.from(JSON.stringify({ environmentId, fingerprint, sourceRevision }));
      response.writeHead(200, { 'content-type': 'application/json', 'content-length': body.length });
      response.end(body);
      return;
    }
    if (request.method === 'POST' && request.url === '/attest') {
      state.attestCount++;
      if (!attestation) { response.writeHead(404, { 'content-type': 'application/json' }); response.end('{}'); return; }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(attestation));
      return;
    }
    if (request.method === 'POST' && request.url === '/records') {
      state.mutationCount++;
      const body = Buffer.from(JSON.stringify({ id: 'rogue-record', fixtureId: 'rogue' }));
      response.writeHead(201, { 'content-type': 'application/json', 'content-length': body.length });
      response.end(body);
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end('{}');
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({
      baseUrl: 'http://127.0.0.1:' + server.address().port + '/',
      state,
      close: () => new Promise(done => server.close(done))
    }));
  });
}
// --- Общие проверки волны 2 ----------------------------------------------------------------
export function checkTrustedDenial(checks, result, expected = {}) {
  const verdict = expected.verdict || 'BLOCKED';
  const codes = expected.reasonCodes || (expected.reasonCode ? [expected.reasonCode] : null);
  const actualVerdict = result?.verdict?.verdict || null;
  const actualCode = result?.verdict?.reasonCode || null;
  const ok = actualVerdict === verdict && (!codes || codes.includes(actualCode));
  return check(checks, 'доверенный вход отказал ' + verdict + (codes ? ' ' + codes.join('/') : ''), ok, { verdict: actualVerdict, reasonCode: actualCode });
}

export function checkNoMutation(checks, world, expected = 0) {
  return check(checks, 'стенд получил ' + expected + ' POST', world.stand.mutationCount === expected, { mutationCount: world.stand.mutationCount });
}

export function checkNoEvidence(checks, modules, world, runId, kinds = ['mutation-intent', 'request', 'verdict']) {
  let items = [];
  try { items = evidenceOf(modules, world.root, runId); } catch { items = []; }
  const found = items.filter(item => kinds.includes(item.envelope.kind)).map(item => item.envelope.kind);
  return check(checks, 'в журнале нет ' + kinds.join('/'), found.length === 0, { found });
}

export async function runTrusted(modules, world, bundle, approval, extra = {}) {
  return modules.trusted.startTrusted(bundle, world.trustedOptions(approval, extra));
}

// Хелпер: создать дополнительный процесс/файл в каталоге прогона (для атак на публикацию).
export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function trustedContext(modules, world, approval, signer, extra = {}) {
  return modules.trusted.createTrustContext({
    trust: world.trust,
    trustRoot: world.trustRoot,
    approvalId: approval.approvalId,
    approval,
    issuer: world.cards.owner,
    subject: world.cards.operator,
    sid: world.sid,
    standPublicKey: world.stand.standPublicKey,
    signer,
    credentials: world.record ? { [world.record.credentialRef]: world.stand.authToken } : {},
    fixtureToken: world.stand.authToken,
    ...extra
  });
}

export async function runWithContext(modules, world, bundle, context) {
  return modules.run.start(bundle, { root: world.root, trust: context, fixtureToken: world.stand.authToken });
}

export async function connectSigner(modules, world) {
  return modules.anchorSigner.connectAnchorSigner(world.signer.pipePath);
}

export function runDirOf(modules, world, runId) {
  const store = new modules.store.RunStore(world.root);
  return store.runPath(runId);
}

export function writeTrustProfile(trustRoot, anchorBudgetMs) {
  fs.writeFileSync(path.join(trustRoot, 'profile.json'), JSON.stringify({ schemaVersion: '0.2.0', domain: 'trust-profile', anchorBudgetMs }) + '\n');
}
export function runChildProcess(script, requestFile, timeoutMs = 60000) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [script, requestFile], { windowsHide: true });
    const stderr = [];
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* уже мёртв */ } }, timeoutMs);
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.on('error', error => { clearTimeout(timer); resolve({ status: -1, stderr: String(error.message) }); });
    child.on('exit', code => { clearTimeout(timer); resolve({ status: code, stderr: Buffer.concat(stderr).toString('utf8') }); });
  });
}
export async function waitFile(filePath, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(filePath)) {
    if (Date.now() > deadline) throw new Error('Не дождались файла ' + filePath);
    await sleep(10);
  }
}