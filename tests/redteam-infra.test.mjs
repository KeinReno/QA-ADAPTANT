// F-WP08-04/F-WP08-05: тесты инфраструктуры доказательств.
// 1) агрегатор не может выдать PASS по exit 0 без распознанного JSON-вердикта;
// 2) агрегатор сохраняет полный JSON/сырой вывод каждого скрипта в артефакт;
// 3) каркас матрицы требует строко-специфичных проверок и разделяет алиасы строк.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const REPO = path.resolve('.');

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-redteam-infra-'));
  const redteam = path.join(dir, 'tests', 'redteam');
  fs.mkdirSync(redteam, { recursive: true });
  fs.symlinkSync(path.join(REPO, 'packages'), path.join(dir, 'packages'), 'junction');
  fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(dir, 'node_modules'), 'junction');
  fs.copyFileSync(path.join(REPO, 'tests', 'redteam', 'run-all.mjs'), path.join(redteam, 'run-all.mjs'));
  fs.copyFileSync(path.join(REPO, 'tests', 'redteam', '_lib.mjs'), path.join(redteam, '_lib.mjs'));
  return { dir, redteam };
}

function writeScript(redteam, name, body) { fs.writeFileSync(path.join(redteam, name), body); }

function runAggregator(box) {
  const artifacts = path.join(box.dir, 'artifacts');
  const result = spawnSync(process.execPath, [path.join(box.redteam, 'run-all.mjs'), '--artifacts=' + artifacts], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  const summary = JSON.parse(result.stdout.slice(result.stdout.indexOf('{')));
  return { result, summary, artifacts };
}

test('агрегатор: exit 0 без JSON-вердикта — это INVALID/FAIL, а не PASS', () => {
  const box = sandbox();
  try {
    writeScript(box.redteam, 'rt-001-broken.mjs', 'process.stdout.write("no json here\\n"); process.exitCode = 0;\n');
    writeScript(box.redteam, 'rt-002-ok.mjs', 'process.stdout.write(JSON.stringify({ id: "RT-OK", title: "ok", verdict: "PASS", checks: [] }) + "\\n"); process.exitCode = 0;\n');
    const { result, summary, artifacts } = runAggregator(box);
    const broken = summary.results.find(row => row.script === 'rt-001-broken.mjs');
    assert.equal(broken.verdict, 'INVALID');
    assert.equal(summary.invalid, 1);
    assert.equal(summary.verdict, 'FAIL');
    assert.equal(result.status, 1, 'exit code агрегатора должен быть 1');
    const artifactFile = path.join(artifacts, 'rt-001-broken.json');
    assert.equal(fs.existsSync(artifactFile), true, 'нераспознанный вывод сохраняется в артефакт');
    const artifact = JSON.parse(fs.readFileSync(artifactFile, 'utf8'));
    assert.equal(artifact.unparsed, true);
    assert.match(artifact.stdout, /no json here/);
    assert.equal(fs.existsSync(path.join(artifacts, 'summary.json')), true);
    const okRow = summary.results.find(row => row.script === 'rt-002-ok.mjs');
    assert.equal(okRow.verdict, 'PASS');
    assert.equal(fs.existsSync(path.join(artifacts, 'rt-002-ok.json')), true, 'полный JSON каждого скрипта сохранён');
  } finally {
    fs.rmSync(box.dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('агрегатор: PASS с ненулевым exit code — INVALID (fail-closed)', () => {
  const box = sandbox();
  try {
    writeScript(box.redteam, 'rt-001-lie.mjs', 'process.stdout.write(JSON.stringify({ id: "RT-LIE", verdict: "PASS", checks: [] }) + "\\n"); process.exitCode = 1;\n');
    const { result, summary } = runAggregator(box);
    assert.equal(summary.results[0].verdict, 'INVALID');
    assert.equal(result.status, 1);
  } finally {
    fs.rmSync(box.dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('матрица: у каждой строки есть строко-специфичная проверка, алиасы разделены', () => {
  const source = fs.readFileSync(path.join(REPO, 'tests', 'redteam', 'run-matrix.mjs'), 'utf8');
  const block = source.slice(source.indexOf('const SCRIPT_CASES = {'), source.indexOf('const here ='));
  assert.ok(block.length > 0);
  assert.equal(/['"]V-11['"]: \{[^}]*unverifiable:/.test(block), true, 'V-11 должен быть помечен UNVERIFIABLE с причиной');
  for (const id of ['E-01', 'E-07', 'V-01', 'V-02']) {
    assert.match(block, new RegExp("['\"]" + id + "['\"]: \\{[^}]*checks: \\[[^\\]]+\\]"), id + ' должен иметь список обязательных check-name');
  }
  const aliased = (a, b) => {
    const row = id => { const m = new RegExp(id + "['\"]: \\{ script: '([^']+)', checks: \\[([^\\]]*)\\]").exec(block); return m ? { script: m[1], checks: m[2] } : null; };
    const left = row(a); const right = row(b);
    assert.ok(left && right, 'алиасы должны быть описаны');
    assert.equal(left.script, right.script, 'алиасы используют один сценарий');
    assert.notEqual(left.checks, right.checks, 'ожидания алиасов должны различаться');
  };
  aliased('E-01', 'E-07');
  aliased('V-01', 'V-02');
  assert.match(source, /confirmedChecks/, 'PASS строки должен ссылаться на подтверждённые строко-специфичные проверки');
});
