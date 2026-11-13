// WP-08-REAUDIT — агрегатор матрицы независимого аудита исправлений.
//
// Жёсткие правила доказательности (жёстче, чем у npn-агрегаторов WP-07, где был fallback PASS):
//   1. Строка PASS ставится только по распарсенному JSON-вердикту, где tool=WP08-REAUDIT,
//      scenario совпадает с проверяемой строкой матрицы и target.head совпадает с ревизией прогона.
//   2. Exit code НЕ превращается в PASS: при непарсибельном/чужом/несогласованном JSON строка
//      получает INVALID или UNVERIFIABLE, а сводный вердикт не может быть PASS.
//   3. Строка не может получить PASS по вердикту другого сценария (scenario id сверяется).
//   4. Если проверяемая ветка грязная (tracked-диффы), сводный PASS не выдаётся: INCONCLUSIVE.
//
// Запуск: node tests/audit-remediation/run-matrix.mjs [--target=<worktree>] [--only=ID,...] [--out=file.json]
// Коды выхода: 0 — все строки PASS; 1 — есть FAIL (дефект); 3 — нет FAIL, но есть INVALID/UNVERIFIABLE.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gitInfo } from './audit-lib.mjs';

export const SCENARIOS = [
  { id: 'AUD-P0-01', script: 'p0-01-forge-candidate.mjs', title: 'P0-01: подложный candidate + годный анкер' },
  { id: 'AUD-P0-01B', script: 'p0-01b-key-provenance.mjs', title: 'P0-01B: происхождение ключа Verification' },
  { id: 'AUD-P0-02-A', script: 'p0-02a-swap-after-post.mjs', title: 'P0-02-A: подмена стенда после POST' },
  { id: 'AUD-P0-02-B', script: 'p0-02b-window-swap.mjs', title: 'P0-02-B: подмена в окне T-C→POST, утечка Bearer' },
  { id: 'AUD-P0-02C', script: 'p0-02c-replay-pinned.mjs', title: 'P0-02C: pinned-соединение, гибель стенда, replay подписанных ответов' },
  { id: 'AUD-P1-01', script: 'p1-01-weak-observer.mjs', title: 'P1-01: наблюдатель слабее 0.1' },
  { id: 'AUD-P1-02', script: 'p1-02-v07-recovery.mjs', title: 'P1-02: V-07 потеря анкерованного PASS' },
  { id: 'AUD-P1-03', script: 'p1-03-substitution-after-anchor.mjs', title: 'P1-03: подмена candidate/read-set/attestation после подписи' },
  { id: 'AUD-P2-R02', script: 'p2-r02-junction.mjs', title: 'P2: R-02 junction в runs' },
  { id: 'AUD-P2-APPROVALID', script: 'p2-approval-id-only.mjs', title: 'P2: путь только approvalId' },
  { id: 'AUD-P2-PUBLICATION', script: 'p2-publication-no-choice.mjs', title: 'P2: verdict без terminal-choice' },
  { id: 'AUD-P2-E04', script: 'p2-e04-credential-ref.mjs', title: 'P2: E-04 credentialRef' },
  { id: 'AUD-P2-OLDENTRY', script: 'p2-old-entry-trust.mjs', title: 'P2: обход через старый вход start()' }
];

export const VERDICT_EXIT = { PASS: 0, FAIL: 1, INCONCLUSIVE: 3 };

// Строгий разбор JSON-документа из stdout: первый сбалансированный объект, без eval и без
// «первой скобки». Непарсибельный вывод не становится вердиктом.
export function parseVerdictDocument(text) {
  if (typeof text !== 'string') return null;
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let index = start; index < text.length; index++) {
    const char = text[index];
    if (inString) {
      if (escape) escape = false;
      else if (char === '\\') escape = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; continue; }
    if (char === '{') depth++;
    else if (char === '}') {
      depth--;
      if (depth === 0) {
        try { return JSON.parse(text.slice(start, index + 1)); }
        catch { return null; }
      }
    }
  }
  return null;
}

export function classifyRow({ row, parsed, childExit, targetInfo, timedOut }) {
  if (timedOut) return { status: 'UNVERIFIABLE', reason: 'таймаут сценария', parsedVerdict: null };
  if (!parsed) return { status: 'INVALID', reason: 'нераспарсибельный JSON-вердикт (exit code ' + childExit + ' не является доказательством)', parsedVerdict: null };
  if (parsed.tool !== 'WP08-REAUDIT') return { status: 'INVALID', reason: 'чужой документ: tool=' + String(parsed.tool), parsedVerdict: null };
  if (parsed.scenario !== row.id) return { status: 'INVALID', reason: 'чужой вердикт: scenario=' + String(parsed.scenario) + ' вместо ' + row.id, parsedVerdict: null };
  if (!parsed.target || typeof parsed.target.head !== 'string') return { status: 'INVALID', reason: 'в вердикте нет ревизии target.head', parsedVerdict: null };
  if (parsed.target.head !== targetInfo.head) return { status: 'INVALID', reason: 'вердикт относится к другой ревизии: ' + parsed.target.head + ' вместо ' + targetInfo.head, parsedVerdict: null };
  if (parsed.target.dirty !== targetInfo.dirty) return { status: 'INVALID', reason: 'расхождение признака dirty между вердиктом и ревизией', parsedVerdict: null };
  if (!(parsed.verdict in VERDICT_EXIT)) return { status: 'INVALID', reason: 'вердикт вне enum: ' + String(parsed.verdict), parsedVerdict: null };
  if (parsed.exitCode !== VERDICT_EXIT[parsed.verdict]) return { status: 'INVALID', reason: 'exitCode в документе не согласован с verdict', parsedVerdict: null };
  if (childExit !== parsed.exitCode) return { status: 'INVALID', reason: 'фактический exit code ' + childExit + ' расходится с документом ' + parsed.exitCode, parsedVerdict: null };
  if (parsed.verdict === 'PASS') return { status: 'PASS', reason: null, parsedVerdict: parsed };
  if (parsed.verdict === 'FAIL') return { status: 'FAIL', reason: parsed.actual || 'дефект воспроизведён', parsedVerdict: parsed };
  return { status: 'UNVERIFIABLE', reason: parsed.actual || 'прогон не доказателен', parsedVerdict: parsed };
}

export function runMatrix({ target, scenarioDir, scenarios = SCENARIOS, timeoutMs = 300000, only = null } = {}) {
  if (!target) throw new TypeError('Нужен target');
  const targetAbs = path.resolve(target);
  const dir = scenarioDir ? path.resolve(scenarioDir) : path.dirname(fileURLToPath(import.meta.url));
  const targetInfo = gitInfo(targetAbs);
  const rows = [];
  for (const row of scenarios) {
    if (only && !only.includes(row.id)) continue;
    const script = path.isAbsolute(row.script) ? row.script : path.join(dir, row.script);
    const startedAt = Date.now();
    let child;
    try {
      child = spawnSync(process.execPath, [script, '--target=' + targetAbs], { cwd: path.dirname(script), encoding: 'utf8', windowsHide: true, timeout: timeoutMs });
    } catch (error) {
      rows.push({ id: row.id, title: row.title, script: path.basename(script), status: 'UNVERIFIABLE', reason: 'сценарий не запущен: ' + String(error.message || error), exitCode: null, ms: Date.now() - startedAt });
      continue;
    }
    const timedOut = child.error && child.error.code === 'ETIMEDOUT';
    const parsed = parseVerdictDocument(String(child.stdout || ''));
    const classified = classifyRow({ row, parsed, childExit: child.status, targetInfo, timedOut });
    rows.push({
      id: row.id,
      title: row.title,
      script: path.basename(script),
      status: classified.status,
      reason: classified.reason,
      exitCode: child.status,
      ms: Date.now() - startedAt,
      expected: classified.parsedVerdict?.expected || null,
      actual: classified.parsedVerdict?.actual || null,
      defect: classified.parsedVerdict?.defect || null,
      checks: Array.isArray(classified.parsedVerdict?.checks)
        ? classified.parsedVerdict.checks.map(item => ({ name: item.name, ok: item.ok }))
        : [],
      evidence: classified.parsedVerdict?.evidence || null,
      stderr: parsed ? null : String(child.stderr || '').slice(0, 400)
    });
  }
  const counts = rows.reduce((acc, row) => { acc[row.status] = (acc[row.status] || 0) + 1; return acc; }, {});
  const hasFail = counts.FAIL > 0;
  const hasInvalid = (counts.INVALID || 0) + (counts.UNVERIFIABLE || 0) > 0;
  const allPass = rows.length > 0 && counts.PASS === rows.length;
  let verdict;
  if (hasFail) verdict = 'FAIL';
  else if (hasInvalid) verdict = 'INCONCLUSIVE';
  else if (!allPass) verdict = 'INCONCLUSIVE';
  else if (targetInfo.dirty) verdict = 'INCONCLUSIVE';
  else verdict = 'PASS';
  return {
    tool: 'WP08-REAUDIT-MATRIX',
    target: targetAbs,
    revision: targetInfo.head,
    targetDirty: targetInfo.dirty,
    generatedAt: new Date().toISOString(),
    node: process.version,
    total: rows.length,
    counts,
    verdict,
    exitCode: verdict === 'PASS' ? 0 : verdict === 'FAIL' ? 1 : 3,
    rows
  };
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invoked) {
  const argv = process.argv.slice(2);
  const value = name => { const prefix = '--' + name + '='; const found = argv.find(item => item.startsWith(prefix)); return found ? found.slice(prefix.length) : null; };
  const target = value('target') || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const only = value('only') ? value('only').split(',').map(item => item.trim()).filter(Boolean) : null;
  const out = value('out');
  const summary = runMatrix({ target, only });
  const text = JSON.stringify(summary, null, 2) + '\n';
  if (out) fs.writeFileSync(out, text, 'utf8');
  process.stdout.write(text);
  process.exitCode = summary.exitCode;
}
