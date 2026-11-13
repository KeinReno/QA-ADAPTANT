// run-matrix.mjs — каркас Red Team для матрицы приёмки docs/wp-00/06-ACCEPTANCE-MATRIX.md.
// Запуск: node tests/redteam/run-matrix.mjs <путь-к-worktree-интеграции> [--only=E,V,L,B] [--out=file.json]
//
// Матрица E-01..E-08, V-01..V-12, L-01..L-09, B-01..B-05 (ровно набор волны 1) описывается таблицей ниже.
// Для каждой строки указано, какие модули/экспорты нужны. Если их нет на проверяемой ревизии — строка
// получает статус UNVERIFIABLE с точной причиной (что именно отсутствует). Реализованные проверки
// выполняются только при наличии зависимостей; остальные строки помечаются TODO (каркас волны 1).
// Продуктовый код проверяемой ветки не изменяется: все данные — во временных каталогах %TEMP%.
//
// Коды выхода: 0 — нет FAIL; 1 — есть FAIL; 2 — некорректный аргумент/каталог.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

const argv = process.argv.slice(2);
const target = argv.find(item => !item.startsWith('--'));
const onlyArg = argv.find(item => item.startsWith('--only='));
const only = onlyArg ? onlyArg.split('=')[1].split(',').map(item => item.trim().toUpperCase()).filter(Boolean) : null;
const outArg = argv.find(item => item.startsWith('--out='));
if (!target || !fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
  process.stderr.write('Использование: node tests/redteam/run-matrix.mjs <путь-к-worktree-интеграции> [--only=E,V,L,B] [--out=file.json]\n');
  process.exit(2);
}
const LIVE_TARGET = path.resolve(target);
const liveState = { head: '', dirty: false, diffHash: '' };
function captureLiveState() {
  const head = git(['rev-parse', 'HEAD']);
  const status = git(['status', '--porcelain']);
  const diff = spawnSync('git', ['-C', LIVE_TARGET, 'diff'], { encoding: 'utf8', windowsHide: true }).stdout || '';
  const digest = createHash('sha256').update(diff, 'utf8').digest('hex');
  return { head: head || 'UNKNOWN', dirty: status !== '', diffHash: digest };
}
function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
function pinnedSnapshot() {
  for (let attempt = 0; attempt < 3; attempt++) {
    const before = captureLiveState();
    const key = sha256(before.head + '\n' + before.diffHash).slice(0, 16);
    const dir = path.join(os.tmpdir(), 'qa-rt-matrix-pin-' + key);
    if (!fs.existsSync(path.join(dir, 'package.json'))) {
      try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* кэш */ }
      fs.cpSync(LIVE_TARGET, dir, { recursive: true, force: true, filter: source => !['node_modules', '.git'].includes(path.basename(source)) });
      const liveModules = path.join(LIVE_TARGET, 'node_modules');
      if (fs.existsSync(liveModules)) fs.symlinkSync(liveModules, path.join(dir, 'node_modules'), 'junction');
    }
    const after = captureLiveState();
    if (before.head === after.head && before.diffHash === after.diffHash) {
      return { dir, head: before.head, dirty: before.dirty, diffHash: before.diffHash, stable: true };
    }
  }
  return { dir: null, head: 'UNKNOWN', dirty: false, diffHash: '', stable: false };
}
const PIN = pinnedSnapshot();
const ROOT = PIN.dir;

function git(args) {
  const result = spawnSync('git', ['-C', LIVE_TARGET, ...args], { encoding: 'utf8', windowsHide: true });
  return result.status === 0 ? result.stdout.trim() : '';
}
const revision = PIN.head || 'UNKNOWN';
const file = rel => path.join(ROOT, rel);
const exists = rel => fs.existsSync(file(rel));
const read = rel => fs.readFileSync(file(rel), 'utf8');
const importModule = rel => import(pathToFileURL(file(rel)).href);
const tempDirs = [];
function temp(prefix) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-rt-matrix-' + prefix + '-')); tempDirs.push(dir); return dir; }
function removeAll() { for (const dir of tempDirs) { try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* временный каталог */ } } }

// Минимальная копия фикстур approval для проверок L-07/L-09 (строится от модулей target).
async function approvalEnvironment(prefix) {
  const identity = await importModule('packages/trust/identity.mjs');
  const approvalModule = await importModule('packages/trust/approval.mjs');
  const canonicalModule = await importModule('packages/core/canonical.mjs');
  const crypto = await import('node:crypto');
  const root = temp(prefix);
  const secretsDir = path.join(root, 'secrets');
  const trustRoot = path.join(root, 'trust-root');
  const created = await identity.createTrustRoot({ secretsDir, trustRoot });
  const trust = identity.loadTrustRoot(trustRoot);
  const ownerKey = await identity.unwrapPrivateKey(path.join(secretsDir, 'owner.key'));
  const digest = value => canonicalModule.digest(value);
  const inputs = { comment: 'заметка', executorId: 'operator-1', title: 'запись' };
  const effects = [
    { id: 'title-saved', field: 'title', equals: inputs.title },
    { id: 'executor-saved', field: 'executorId', equals: inputs.executorId },
    { id: 'comment-saved', field: 'comment', equals: inputs.comment }
  ];
  const operation = { id: 'local-create-record', version: '1.0.0', effects };
  const scenarioContentSha256 = digest({ schemaVersion: '0.1.0', id: 'local-create', status: 'APPROVED' });
  const approvalFields = id => ({
    approvalId: id, issuerPrincipalId: 'local-owner', subjectPrincipalId: 'local-operator',
    operationId: operation.id, operationVersion: operation.version,
    scenarioContentSha256, operationSha256: digest(operation), approvedInputsHash: digest(inputs),
    fixtureId: 'fixture-local', targetEnvironmentId: 'local-stand', environmentGeneration: 1,
    targetResource: { method: 'POST', path: '/records' }, allowedEffects: effects,
    approvalNonce: digest(id + crypto.randomUUID()), keyId: created.ownerKeyId,
    issuedAt: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 10 * 60_000).toISOString()
  });
  const issuer = identity.signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-owner', roles: ['owner', 'operator'],
    keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-owner', status: 'active'
  });
  const subject = identity.signTrustedDocument(ownerKey, {
    schemaVersion: '0.2.0', domain: 'principal', principalId: 'local-operator', roles: ['operator'],
    keyId: created.ownerKeyId, windowsSid: 'S-1-5-21-operator', status: 'active'
  });
  const expected = { operation, inputs, effects, scenarioContentSha256, fixtureId: 'fixture-local', environmentId: 'local-stand', environmentGeneration: 1, resource: { method: 'POST', path: '/records' } };
  const dispatch = (approval, runId, decisionId) => ({ trustRoot, approval, issuer, subject, windowsSid: 'S-1-5-21-operator', expected, runId, decisionId });
  const approve = id => approvalModule.signApproval(ownerKey, approvalFields(id), trust, trustRoot);
  return { root, secretsDir, trustRoot, trust, ownerKey, created, approvalModule, identity, approve, dispatch };
}

// Дочерний воркер матрицы: импортирует approval.mjs проверяемой ветки по абсолютному URL.
function writeWorker(dir) {
  const moduleUrl = pathToFileURL(file('packages/trust/approval.mjs')).href;
  const identityUrl = pathToFileURL(file('packages/trust/identity.mjs')).href;
  const worker = path.join(dir, 'matrix-worker.mjs');
  fs.writeFileSync(worker, [
    "import fs from 'node:fs';",
    "import { consumeDispatch } from " + JSON.stringify(moduleUrl) + ";",
    "const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));",
    "try {",
    "  const result = consumeDispatch(request.dispatch);",
    "  fs.writeFileSync(request.resultFile, JSON.stringify({ ok: true, ack: result.ack === true, code: result.code }));",
    "} catch (error) {",
    "  fs.writeFileSync(request.resultFile, JSON.stringify({ ok: false, ack: false, code: error.code || 'ERROR', message: String(error.message || error) }));",
    "}",
    "void " + JSON.stringify(identityUrl) + ";"
  ].join('\n') + '\n');
  return worker;
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFile(filePath, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(filePath)) { if (Date.now() > deadline) throw new Error('нет файла ' + filePath); await sleep(10); }
}
function runNode(script, args) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [script, ...args], { cwd: ROOT, windowsHide: true });
    const out = []; const err = [];
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* мёртв */ } }, 60_000);
    child.stdout.on('data', chunk => out.push(chunk));
    child.stderr.on('data', chunk => err.push(chunk));
    child.on('error', error => { clearTimeout(timer); resolve({ code: -1, stdout: '', stderr: String(error.message) }); });
    child.on('exit', code => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }); });
  });
}

// Реализованные проверки (волна 1). Каждая возвращает {status, evidence}.
const checks = {
  // L-07: CREATE_NEW создал имя consumption, процесс упал до полного bodySha256.
  'L-07': async () => {
    const env = await approvalEnvironment('l07');
    const approval = env.approve('approval-l07');
    let tornCode = null;
    try {
      env.approvalModule.consumeDispatch({ ...env.dispatch(approval, 'run-l07', 'dec-l07'), fault: 'after-create' });
    } catch (error) { tornCode = error.code || null; }
    const consumptionFile = path.join(env.trustRoot, 'consumption', 'approval-l07.json');
    const tornBytes = fs.existsSync(consumptionFile) ? fs.readFileSync(consumptionFile) : null;
    const dir = path.dirname(consumptionFile);
    const worker = writeWorker(env.root);
    const requestFile = path.join(env.root, 'l07-request.json');
    const resultFile = path.join(env.root, 'l07-result.json');
    fs.writeFileSync(requestFile, JSON.stringify({ dispatch: env.dispatch(approval, 'run-l07', 'dec-l07'), resultFile }));
    const child = await runNode(worker, [requestFile]);
    await waitFile(resultFile);
    const second = JSON.parse(fs.readFileSync(resultFile, 'utf8'));
    const afterBytes = fs.readFileSync(consumptionFile);
    const pass = tornCode === 'CONSUMPTION_INCOMPLETE' && second.ack === false && second.code === 'CONSUMPTION_INCOMPLETE' && tornBytes !== null && tornBytes.equals(afterBytes) && !afterBytes.includes(Buffer.from('bodySha256'));
    return { status: pass ? 'PASS' : 'FAIL', evidence: { tornCode, second, childExit: child.code, unchanged: tornBytes !== null && tornBytes.equals(afterBytes), tornFile: afterBytes.toString('utf8').slice(0, 120) } };
  },
  // L-09: два процесса, один approval, разные runId, одновременный CREATE_NEW.
  'L-09': async () => {
    const env = await approvalEnvironment('l09');
    const approval = env.approve('approval-l09');
    const worker = writeWorker(env.root);
    const jobs = ['p1', 'p2'].map(tag => {
      const requestFile = path.join(env.root, tag + '-request.json');
      const resultFile = path.join(env.root, tag + '-result.json');
      fs.writeFileSync(requestFile, JSON.stringify({ dispatch: env.dispatch(approval, 'run-l09-' + tag, 'dec-l09-' + tag), resultFile }));
      return { requestFile, resultFile };
    });
    await Promise.all(jobs.map(job => runNode(worker, [job.requestFile])));
    for (const job of jobs) await waitFile(job.resultFile);
    const results = jobs.map(job => JSON.parse(fs.readFileSync(job.resultFile, 'utf8')));
    const acks = results.filter(result => result.ack === true).length;
    const consumptionFile = path.join(env.trustRoot, 'consumption', 'approval-l09.json');
    const body = fs.existsSync(consumptionFile) ? JSON.parse(fs.readFileSync(consumptionFile, 'utf8')) : null;
    const pass = acks === 1 && body && results.filter(result => result.ack !== true).every(result => ['APPROVAL_REPLAY', 'APPROVAL_CONSUMED'].includes(result.code));
    return { status: pass ? 'PASS' : 'FAIL', evidence: { acks, results, consumption: body ? { approvalId: body.approvalId, runId: body.runId, hasBodySha256: typeof body.bodySha256 === 'string' } : null } };
  },
  // E-08: монополия порта живого стенда (базовая часть; аттестация — при наличии WP-04).
  'E-08': async () => {
    const { serveLocalFixture } = await importModule('adapters/local/server.mjs');
    const fixture = await serveLocalFixture();
    try {
      const port = Number(new URL(fixture.baseUrl).port);
      const intruder = http.createServer(() => {});
      const bindError = await new Promise(resolve => { intruder.once('error', resolve); intruder.listen(port, '127.0.0.1', () => resolve(null)); });
      if (!bindError) await new Promise(resolve => intruder.close(resolve));
      const stillAlive = (await fetch(new URL('/environment', fixture.baseUrl))).status === 200;
      const attested = Boolean(fixture.standKeyId) && exists('packages/trust/environment.mjs');
      const pass = Boolean(bindError) && bindError.code === 'EADDRINUSE' && stillAlive;
      return { status: pass ? (attested ? 'PASS' : 'PARTIAL') : 'FAIL', evidence: { bindCode: bindError?.code || null, stillAlive, attested, missing: attested ? [] : ['standKeyId/аттестация (WP-04)'] } };
    } finally { await fixture.close(); }
  }
};

// Строки, реализованные отдельными воспроизводимыми скриптами tests/redteam/rt2-*.mjs.
// F-WP08-05: PASS строки выдаётся ТОЛЬКО по строко-специфичной проверке этого сценария,
// а не по общему вердикту скрипта. Один скрипт может обслуживать несколько строк (алиасинг):
// у каждой строки свой набор обязательных check-name, которые должны быть ok=true.
const SCRIPT_CASES = {
  'B-01': { script: 'rt2-b01-registry.mjs', checks: ['доверенный вход отказал BLOCKED CONTRACT_INVALID'] },
  'B-03': { script: 'rt2-b03-effects-mismatch.mjs', checks: ['доверенный вход отказал BLOCKED CONTRACT_INVALID'] },
  'B-04': { script: 'rt2-b04-fixture-mismatch.mjs', checks: ['доверенный вход отказал BLOCKED CONTRACT_INVALID/AUTH_UNAVAILABLE'] },
  'B-05': { script: 'rt2-b05-http-200-existing.mjs', checks: ['доверенный прогон не даёт PASS на HTTP 200'] },
  // E-01/E-07 обслуживаются одним скриптом, но подтверждаются разными проверками.
  'E-01': { script: 'rt2-attack-env-substitution.mjs', checks: ['(A) зеркало получило запрос аттестации, но не POST'] },
  'E-07': { script: 'rt2-attack-env-substitution.mjs', checks: ['(B) сервер без ключа не получил POST'] },
  'E-02': { script: 'rt2-e02-unknown-environment.mjs', checks: ['доверенный вход отказал BLOCKED ENVIRONMENT_CHANGED/CONTRACT_INVALID'] },
  'E-03': { script: 'rt2-e03-generation-change.mjs', checks: ['доверенный вход отказал BLOCKED ENVIRONMENT_CHANGED'] },
  'E-04': { script: 'rt2-e04-credential-ref.mjs', checks: ['секрет не выдан: reasonCode среда/credentialRef'] },
  'E-05': { script: 'rt2-e05-registry-unreadable.mjs', checks: ['фактический код отказа зафиксирован'] },
  'E-06': { script: 'rt2-e06-dev-environment.mjs', checks: ['доверенный вход отказал BLOCKED ENVIRONMENT_CHANGED/CONTRACT_INVALID'] },
  // V-01/V-02 обслуживаются одним скриптом, ожидания разделены по строкам.
  'V-01': { script: 'rt2-attack-false-pass.mjs', checks: ['(V-01) подменённый терминальный коммит не даёт PASS при старом анкере'] },
  'V-02': { script: 'rt2-attack-false-pass.mjs', checks: ['(V-02) подменённый verdict после публикации не даёт PASS'] },
  'V-03': { script: 'rt2-v03-signer-unavailable.mjs', checks: ['выбран исход budget-inconclusive'] },
  'V-04': { script: 'rt2-v04-two-anchors.mjs', checks: ['второе заявление для runId отвергнуто ANCHOR_CONFLICT'] },
  'V-07': { script: 'rt2-v07-anchor-before-verdict.mjs', checks: ['дописан ровно один verdict'] },
  // V-11: падение процесса должно происходить ПОСЛЕ записи terminal-choice. Сценарий
  // rt2-v07 падает до выбора исхода и создаёт его вручную, поэтому строку подтвердить нечем.
  'V-11': { script: 'rt2-v07-anchor-before-verdict.mjs', unverifiable: 'нет сценария, где terminal-choice записан до падения процесса' },
  'V-08': { script: 'rt2-v08-owner-as-anchor.mjs', checks: ['owner-подпись анкера отвергнута ANCHOR_SIGNATURE_INVALID'] },
  'V-09': { script: 'rt2-v09-budget-race.mjs', checks: ['выбран один исход budget-inconclusive'] },
  'L-03': { script: 'rt2-l03-crash-after-consumption.mjs', checks: ['расход связан с runId'] },
  'L-06': { script: 'rt2-l06-used-approval.mjs', checks: ['первый доверенный прогон PASS'] },
  'L-08': { script: 'rt2-l08-old-start-rejects-trust.mjs', checks: ['start() с аргументом'] }
};
const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));

function runScriptCase(id) {
  const spec = SCRIPT_CASES[id];
  const script = path.join(here, spec.script);
  const child = spawnSync(process.execPath, [script, '--target=' + ROOT, '--pinned', '--sha=' + revision], { encoding: 'utf8', windowsHide: true, timeout: 180000 });
  let parsed = null;
  try { const start = (child.stdout || '').indexOf('{'); parsed = start === -1 ? null : JSON.parse(child.stdout.slice(start)); } catch { parsed = null; }
  if (!parsed) return { status: 'FAIL', reason: 'нераспознанный JSON-вердикт скрипта', evidence: { exit: child.status, stderr: String(child.stderr || '').slice(0, 400) } };
  const checks = Array.isArray(parsed.checks) ? parsed.checks : [];
  const missing = (spec.checks || []).filter(fragment => !checks.some(check => check.ok === true && String(check.name || '').includes(fragment)));
  if (parsed.verdict === 'INCONCLUSIVE') return { status: 'UNVERIFIABLE', reason: 'скрипт-проверка вернул INCONCLUSIVE', evidence: { script: spec.script } };
  if (parsed.verdict !== 'PASS') return { status: 'FAIL', reason: 'сценарий не прошёл: ' + (checks.filter(check => !check.ok).map(check => check.name).join('; ') || parsed.verdict), evidence: { script: spec.script, checks } };
  if (missing.length) return { status: 'FAIL', reason: 'строко-специфичная проверка не подтверждена: ' + missing.join('; '), evidence: { script: spec.script, expectedChecks: spec.checks, confirmed: spec.checks.filter(f => !missing.includes(f)) } };
  return { status: 'PASS', reason: null, evidence: { script: spec.script, target: parsed.target || null, confirmedChecks: spec.checks } };
}

// Таблица матрицы: needs — обязательные файлы/экспорты на проверяемой ревизии.
const CASES = [
  ['E-01', 'Копирование environmentId/fingerprint и любого ранее виденного ответа', ['packages/trust/environment.mjs']],
  ['E-02', 'environmentId отсутствует в реестре', ['packages/trust/environment.mjs']],
  ['E-03', 'Поколение стенда сменилось между T-A и T-B', ['packages/trust/environment.mjs', 'apps/control/trusted.mjs']],
  ['E-04', 'credentialRef указывает секрет другой среды', ['packages/trust/environment.mjs', 'apps/control/trusted.mjs']],
  ['E-05', 'Реестр сред не читается (fail-closed)', ['packages/trust/environment.mjs', 'packages/trust/policy.mjs']],
  ['E-06', 'Среда kind=dev даже при status=active', ['packages/trust/environment.mjs', 'packages/trust/policy.mjs']],
  ['E-07', 'Стенд остановлен, порт занял процесс без ключа стенда', ['packages/trust/environment.mjs', 'apps/control/trusted.mjs']],
  ['E-08', 'Монополия порта живого стенда', ['adapters/local/server.mjs']],
  ['V-01', 'Локальный терминальный коммит заменён, анкер старый', ['packages/trust/anchor.mjs']],
  ['V-02', 'Подменён verdict в каталоге прогона', ['packages/trust/anchor.mjs']],
  ['V-03', 'Подписант недоступен дольше anchorBudgetMs', ['packages/trust/anchor.mjs', 'packages/trust/anchor-signer.mjs']],
  ['V-04', 'Два разных заявления на один runId', ['packages/trust/anchor.mjs']],
  ['V-05', 'Повторная публикация тех же байт анкера', ['packages/trust/anchor.mjs']],
  ['V-06', 'Падение после локального response и до анкера', ['packages/trust/anchor.mjs', 'apps/control/trusted.mjs']],
  ['V-07', 'Анкер записан, процесс падает до verdict', ['packages/trust/anchor.mjs']],
  ['V-08', 'Ключ owner предъявлен как подпись анкера', ['packages/trust/anchor.mjs', 'packages/trust/identity.mjs']],
  ['V-09', 'Гонка бюджета и уже созданного анкера PASS', ['packages/trust/anchor.mjs']],
  ['V-10', 'Подложный PASS-candidate без связки approval/consumption', ['packages/trust/anchor-signer.mjs']],
  ['V-11', 'Выбор anchor записан, verdict ещё нет, падение', ['packages/trust/anchor.mjs']],
  ['V-12', 'Неполный terminal-choice.json блокирует PASS', ['packages/trust/anchor.mjs']],
  ['L-01', 'Два процесса, один approval, разные runId', ['apps/control/trusted.mjs', 'packages/trust/approval.mjs']],
  ['L-02', 'Cancel до INTENT', ['apps/control/trusted.mjs', 'packages/trust/policy.mjs']],
  ['L-03', 'Падение после consumption и до POST', ['apps/control/trusted.mjs']],
  ['L-04', 'Падение после POST: reconcile без второго POST', ['apps/control/trusted.mjs']],
  ['L-05', 'Повторный reconcile терминального прогона', ['apps/control/trusted.mjs']],
  ['L-06', 'Новая попытка с использованным approval', ['packages/trust/approval.mjs', 'apps/control/trusted.mjs']],
  ['L-07', 'Обрыв после CREATE_NEW расхода', ['packages/trust/approval.mjs']],
  ['L-08', 'Старый start() не принимает approval/адаптер', ['apps/control/run.mjs']],
  ['L-09', 'Гонка CREATE_NEW расхода на Windows', ['packages/trust/approval.mjs']],
  ['B-01', 'Операция не из реестра 0.1', ['apps/control/trusted.mjs', 'packages/trust/policy.mjs']],
  ['B-02', 'Повторный POST на уже созданный fixture', ['apps/control/trusted.mjs']],
  ['B-03', 'Набор эффектов в approval не совпал', ['apps/control/trusted.mjs', 'packages/trust/policy.mjs']],
  ['B-04', 'Снимок fixtureId не совпал с approval', ['apps/control/trusted.mjs', 'packages/trust/policy.mjs']],
  ['B-05', 'HTTP 200 на существующий объект не PASS', ['apps/control/trusted.mjs']]
];

const rows = [];
for (const [id, subject, needs] of CASES) {
  if (only && !only.includes(id[0])) continue;
  const missing = needs.filter(rel => !exists(rel));
  const capabilities = {
    environment: exists('packages/trust/environment.mjs'),
    anchor: exists('packages/trust/anchor.mjs'),
    anchorSigner: exists('packages/trust/anchor-signer.mjs'),
    policy: exists('packages/trust/policy.mjs'),
    trustedControl: exists('apps/control/trusted.mjs'),
    approval: exists('packages/trust/approval.mjs'),
    control: exists('apps/control/run.mjs')
  };
  let status; let evidence; let reason = null;
  if (missing.length) {
    status = 'UNVERIFIABLE';
    reason = 'на ревизии отсутствуют: ' + missing.join(', ');
    evidence = { missing };
  } else if (SCRIPT_CASES[id]?.unverifiable) {
    status = 'UNVERIFIABLE';
    reason = SCRIPT_CASES[id].unverifiable;
    evidence = { script: SCRIPT_CASES[id].script };
  } else if (SCRIPT_CASES[id]) {
    try {
      const result = runScriptCase(id);
      status = result.status; evidence = result.evidence;
      if (result.reason) reason = result.reason;
    } catch (error) {
      status = 'FAIL'; evidence = { message: String(error.message || error) };
    }
  } else if (checks[id]) {
    try {
      const result = await checks[id]();
      status = result.status; evidence = result.evidence;
      if (status === 'PARTIAL') reason = 'доверенная часть строки требует WP-04 (аттестация стенда)';
    } catch (error) {
      status = 'FAIL'; evidence = { message: String(error.message || error), code: error.code || null };
    }
  } else {
    status = 'TODO';
    reason = 'зависимости есть, проверка каркаса волны 1 ещё не реализована';
    evidence = { note: 'реализовать в волне 2 на SHA интеграции' };
  }
  rows.push({ id, subject, status, reason, evidence });
}

const counts = rows.reduce((acc, row) => { acc[row.status] = (acc[row.status] || 0) + 1; return acc; }, {});
const summary = {
  tool: 'REDTEAM-MATRIX',
  target: LIVE_TARGET,
  revision,
  pinnedSnapshot: PIN.dir,
  targetStable: PIN.stable,
  generatedAt: new Date().toISOString(),
  node: process.version,
  platform: process.platform,
  total: rows.length,
  counts,
  exitCode: rows.some(row => row.status === 'FAIL') ? 1 : 0,
  rows
};
removeAll();
const text = JSON.stringify(summary, null, 2);
if (outArg) fs.writeFileSync(outArg.slice('--out='.length), text + '\n');
process.stdout.write(text + '\n');
process.exitCode = summary.exitCode;