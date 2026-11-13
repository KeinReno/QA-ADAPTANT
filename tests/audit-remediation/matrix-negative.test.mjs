// Стресс/негатив на агрегатор матрицы независимого аудита.
//
// Проверяемые инварианты:
//   * нераспарсибельный JSON при exit 0 НЕ даёт PASS (exit code — не доказательство);
//   * вердикт чужого сценария (другой scenario id) НЕ ставит PASS проверяемой строке;
//   * вердикт с чужой ревизией/признаком dirty НЕ ставит PASS;
//   * расхождение exit code и вердикта НЕ ставит PASS;
//   * FAIL-вердикт даёт FAIL строки, таймаут — UNVERIFIABLE;
//   * положительный контроль: честный PASS-вердикт даёт PASS.
//
// Запуск: node --test tests/audit-remediation/matrix-negative.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runMatrix, parseVerdictDocument } from './run-matrix.mjs';
import { gitInfo } from './audit-lib.mjs';

const HERE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function writeFixture(dir, name, source) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, source, 'utf8');
  return file;
}

function documentOf({ scenario, head, dirty = false, verdict, exitCode, actual = 'test fixture' }) {
  return {
    tool: 'WP08-REAUDIT', scenario, title: 'fixture', target: { path: HERE, head, dirty, diffSha256: null },
    generatedAt: new Date().toISOString(), node: process.version, platform: process.platform,
    expected: 'ожидание', actual, defect: verdict === 'FAIL' ? 'REPRODUCED' : 'NOT_REPRODUCED',
    verdict, exitCode, checks: [], evidence: null
  };
}

function fixtureSource(document, exitCode, extra = '') {
  return "process.stdout.write(" + JSON.stringify(JSON.stringify(document)) + " + '\\n');\n" + extra + "process.exitCode = " + exitCode + ";\n";
}

test('агрегатор: exit 0 без JSON не даёт PASS', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp08-aggr-'));
  try {
    const head = 'f'.repeat(40);
    const script = writeFixture(dir, 'garbage.mjs', "process.stdout.write('это не json, но exit 0');\nprocess.exitCode = 0;\n");
    const summary = runMatrix({ target: HERE, scenarioDir: dir, timeoutMs: 30000, scenarios: [{ id: 'AUD-P0-01', script, title: 'garbage' }] });
    assert.equal(summary.rows[0].status, 'INVALID');
    assert.notEqual(summary.rows[0].status, 'PASS');
    assert.notEqual(summary.verdict, 'PASS');
    assert.equal(summary.exitCode, 3);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('агрегатор: вердикт чужого сценария не ставит PASS строке', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp08-aggr-'));
  try {
    // Строка запрашивает AUD-P0-02-A, а документ объявляет AUD-P0-01 (чужой вердикт).
    const realHead = gitInfo(HERE).head;
    const doc = documentOf({ scenario: 'AUD-P0-01', head: realHead, verdict: 'PASS', exitCode: 0 });
    const script = writeFixture(dir, 'foreign.mjs', fixtureSource(doc, 0));
    const summary = runMatrix({ target: HERE, scenarioDir: dir, timeoutMs: 30000, scenarios: [{ id: 'AUD-P0-02-A', script, title: 'foreign' }] });
    assert.equal(summary.rows[0].status, 'INVALID');
    assert.match(String(summary.rows[0].reason), /чужой вердикт/);
    assert.notEqual(summary.verdict, 'PASS');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('агрегатор: чужая ревизия и расхождение exit code не дают PASS', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp08-aggr-'));
  try {
    const realHead = gitInfo(HERE).head;
    const wrongHead = realHead.split('').reverse().join('');
    const docWrongHead = documentOf({ scenario: 'AUD-P0-01', head: wrongHead, verdict: 'PASS', exitCode: 0 });
    const wrongHeadScript = writeFixture(dir, 'wrong-head.mjs', fixtureSource(docWrongHead, 0));
    const docExitMismatch = documentOf({ scenario: 'AUD-P0-01', head: realHead, verdict: 'PASS', exitCode: 0 });
    const exitMismatchScript = writeFixture(dir, 'exit-mismatch.mjs', fixtureSource(docExitMismatch, 1));
    const summary = runMatrix({
      target: HERE, scenarioDir: dir, timeoutMs: 30000,
      scenarios: [
        { id: 'AUD-P0-01', script: wrongHeadScript, title: 'wrong head' },
        { id: 'AUD-P0-01', script: exitMismatchScript, title: 'exit mismatch' }
      ]
    });
    assert.equal(summary.rows[0].status, 'INVALID');
    assert.equal(summary.rows[1].status, 'INVALID');
    assert.notEqual(summary.verdict, 'PASS');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('агрегатор: FAIL, таймаут и положительный PASS классифицируются строго', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp08-aggr-'));
  try {
    const realHead = gitInfo(HERE).head;
    const failDoc = documentOf({ scenario: 'AUD-P1-01', head: realHead, verdict: 'FAIL', exitCode: 1 });
    const failScript = writeFixture(dir, 'fail.mjs', fixtureSource(failDoc, 1));
    const passDoc = documentOf({ scenario: 'AUD-P2-R02', head: realHead, verdict: 'PASS', exitCode: 0 });
    const passScript = writeFixture(dir, 'pass.mjs', fixtureSource(passDoc, 0));
    const hangScript = writeFixture(dir, 'hang.mjs', "setTimeout(() => {}, 60000);\n");
    const summary = runMatrix({
      target: HERE, scenarioDir: dir, timeoutMs: 1500,
      scenarios: [
        { id: 'AUD-P1-01', script: failScript, title: 'fail' },
        { id: 'AUD-P2-R02', script: passScript, title: 'pass' },
        { id: 'AUD-P2-E04', script: hangScript, title: 'hang' }
      ]
    });
    assert.equal(summary.rows[0].status, 'FAIL');
    assert.equal(summary.rows[1].status, 'PASS');
    assert.equal(summary.rows[2].status, 'UNVERIFIABLE');
    assert.equal(summary.verdict, 'FAIL');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('агрегатор: строгий разбор не принимает обрезанный/вложенный мусор как вердикт', () => {
  assert.equal(parseVerdictDocument(''), null);
  assert.equal(parseVerdictDocument('{обрыв'), null);
  assert.equal(parseVerdictDocument('{"a":1} trailing')?.a, 1);
  const parsed = parseVerdictDocument('log line\n{"tool":"X","nested":{"a":1}}\nmore');
  assert.equal(parsed.tool, 'X');
  assert.equal(parsed.nested.a, 1);
});
