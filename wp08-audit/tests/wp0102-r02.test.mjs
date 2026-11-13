// wp0102: независимая проверка R-02 (keygen не создаёт секреты в каталоге прогонов).
// Внимание: тест 4/5 фиксируют фактическое поведение и воспроизводят обход.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { generateKeys } from '../../packages/trust/keygen.mjs';
import { createTrustRoot } from '../../packages/trust/identity.mjs';
import { tempDir } from './wp0102-fixture.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const keygenCli = path.join(repoRoot, 'packages', 'trust', 'keygen.mjs');
// Примечание: при node --test с изоляцией процессов Node v24.16.0 теряет отчёт о первых
// подтестах этого файла (счётчик 3 вместо 7). Запуск с --experimental-test-isolation=none
// либо прямым node <file> даёт полный отчёт 7/7; это артефакт раннера, не продукта.

function cli(args, cwd) {
  return spawnSync(process.execPath, [keygenCli, ...args], { cwd, encoding: 'utf8', windowsHide: true });
}

async function quietGenerateKeys(secrets, trustRoot) {
  const original = process.stdout.write;
  process.stdout.write = () => true;
  try { return await generateKeys(secrets, trustRoot); }
  finally { process.stdout.write = original; }
}

test('R-02 контроль: абсолютный путь с сегментом runs отвергается и файлов не создаёт', () => {
  const base = tempDir('wp0102-r02-abs-');
  const runDir = path.join(base, 'runs', 'run-1');
  fs.mkdirSync(runDir, { recursive: true });
  const result = cli(['--secrets', path.join(runDir, 'secrets'), '--trust-root', path.join(base, 'trust')], base);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /TRUST_STORE_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(runDir, 'secrets')), false);
  assert.equal(fs.existsSync(path.join(base, 'trust')), false);
  fs.rmSync(base, { recursive: true, force: true });
});

test('R-02 контроль: сегмент RUNS в верхнем регистре и trust root внутри runs отвергаются', () => {
  const base = tempDir('wp0102-r02-case-');
  const upper = path.join(base, 'RUNS', 'run-2');
  fs.mkdirSync(upper, { recursive: true });
  const first = cli(['--secrets', path.join(base, 'safe-secrets'), '--trust-root', path.join(upper, 'trust')], base);
  assert.equal(first.status, 1);
  assert.match(first.stderr, /TRUST_STORE_UNAVAILABLE/);
  const second = cli(['--secrets', path.join(base, 'runs', 'run-2', 'secrets'), '--trust-root', path.join(base, 'trust')], base);
  assert.equal(second.status, 1);
  assert.match(second.stderr, /TRUST_STORE_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(base, 'safe-secrets')), false);
  fs.rmSync(base, { recursive: true, force: true });
});

test('R-02 контроль: каталог внутри репозитория отвергается', () => {
  const outside = tempDir('wp0102-r02-repo-');
  const result = cli(['--secrets', path.join(repoRoot, 'wp0102-must-not-create'), '--trust-root', path.join(outside, 'trust')], repoRoot);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /TRUST_STORE_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(repoRoot, 'wp0102-must-not-create')), false);
  fs.rmSync(outside, { recursive: true, force: true });
});

test('F-WP01-01: junction с именем вне runs обходит R-02 и кладёт секреты в каталог прогона', async () => {
  const base = tempDir('wp0102-r02-junction-');
  const runDir = path.join(base, 'store', 'runs', 'run-1');
  fs.mkdirSync(runDir, { recursive: true });
  const link = path.join(base, 'safe-link');
  fs.symlinkSync(runDir, link, 'junction');
  let created = null;
  try {
    created = await quietGenerateKeys(path.join(link, 'secrets'), path.join(base, 'trust'));
  } catch { /* отказ тоже информация */ }
  const leaked = fs.existsSync(path.join(runDir, 'secrets', 'owner.key'));
  assert.equal(created !== null, true, 'keygen принял junction-путь внутрь runs (ожидался отказ)');
  assert.equal(leaked, true, 'приватный ключ создан внутри каталога прогона');
  assert.deepEqual(fs.readdirSync(path.join(runDir, 'secrets')).sort(), ['anchor.key', 'owner.key']);
  fs.rmSync(base, { recursive: true, force: true });
});

test('F-WP01-01: trust root через junction внутрь runs также принимается', async () => {
  const base = tempDir('wp0102-r02-junction-trust-');
  const runDir = path.join(base, 'store', 'runs', 'run-2');
  fs.mkdirSync(runDir, { recursive: true });
  const link = path.join(base, 'safe-trust');
  fs.symlinkSync(runDir, link, 'junction');
  let created = null;
  try {
    created = await quietGenerateKeys(path.join(base, 'secrets'), path.join(link, 'trust'));
  } catch { /* отказ тоже информация */ }
  assert.equal(created !== null, true, 'keygen принял trust root через junction внутрь runs');
  assert.equal(fs.existsSync(path.join(runDir, 'trust', 'owner.pub')), true);
  fs.rmSync(base, { recursive: true, force: true });
});

test('R-02: при явно переданном runDir физическое разрешение junction работает', async () => {
  const base = tempDir('wp0102-r02-rundir-');
  const runDir = path.join(base, 'runs', 'run-3');
  fs.mkdirSync(runDir, { recursive: true });
  const link = path.join(base, 'safe-secrets');
  fs.symlinkSync(runDir, link, 'junction');
  await assert.rejects(
    () => createTrustRoot({ secretsDir: path.join(link, 'secrets'), trustRoot: path.join(base, 'trust'), runDir }),
    error => error.code === 'TRUST_STORE_UNAVAILABLE'
  );
  assert.equal(fs.existsSync(path.join(runDir, 'secrets')), false);
  fs.rmSync(base, { recursive: true, force: true });
});

test('нестандартные имена: "runs." не обходит проверку, но оставляет пустой каталог и невнятную ошибку', () => {
  const base = tempDir('wp0102-r02-dot-');
  const dotted = path.join(base, 'runs.', 'run-4');
  fs.mkdirSync(dotted, { recursive: true });
  const result = cli(['--secrets', path.join(dotted, 'secrets'), '--trust-root', path.join(base, 'trust')], base);
  // Node создаёт имя "runs." буквально; PowerShell Get-Acl нормализует точку и не находит путь,
  // поэтому ключи не создаются (отказ), но созданный каталог secrets не убирается (наблюдение P3).
  assert.equal(result.status, 1);
  assert.match(result.stderr, /TRUST_STORE_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(dotted, 'secrets', 'owner.key')), false);
  assert.equal(fs.existsSync(path.join(dotted, 'secrets')), true, 'пустой каталог остался после отказа');
  assert.equal(fs.existsSync(path.join(base, 'runs')), false);
  fs.rmSync(base, { recursive: true, force: true });
});