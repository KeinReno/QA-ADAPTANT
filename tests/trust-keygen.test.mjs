import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { generateKeys } from '../packages/trust/keygen.mjs';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

function temp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'qa-keygen-' + prefix + '-'));
}

test('R-02: ключи не создаются внутри каталога прогонов', async () => {
  const base = temp('runs');
  const runDir = path.join(base, 'runs', 'run-1');
  fs.mkdirSync(runDir, { recursive: true });
  await assert.rejects(
    () => generateKeys(path.join(runDir, 'secrets'), path.join(base, 'trust')),
    error => error.code === 'TRUST_STORE_UNAVAILABLE'
  );
  assert.equal(fs.existsSync(path.join(runDir, 'secrets')), false);
  assert.equal(fs.existsSync(path.join(base, 'trust')), false);
});

test('R-02: trust root внутри каталога прогонов отвергается', async () => {
  const base = temp('runs-trust');
  const runDir = path.join(base, 'runs', 'run-2');
  fs.mkdirSync(runDir, { recursive: true });
  await assert.rejects(
    () => generateKeys(path.join(base, 'secrets'), path.join(runDir, 'trust')),
    error => error.code === 'TRUST_STORE_UNAVAILABLE'
  );
});

test('R-02: CLI генератора отвергает каталог прогонов и не оставляет файлов', () => {
  const base = temp('cli');
  const secrets = path.join(base, 'runs', 'x', 'secrets');
  const result = spawnSync(process.execPath, ['packages/trust/keygen.mjs', '--secrets', secrets, '--trust-root', path.join(base, 'trust')], { encoding: 'utf8', cwd: repoRoot, windowsHide: true });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /TRUST_STORE_UNAVAILABLE/);
  assert.equal(fs.existsSync(secrets), false);
});

test('R-02: обычный каталог вне прогонов и репозитория работает как раньше', async () => {
  const base = temp('ok');
  const created = await generateKeys(path.join(base, 'secrets'), path.join(base, 'trust'));
  assert.match(created.ownerKeyId, /^[a-f0-9]{64}$/);
  assert.equal(fs.existsSync(path.join(base, 'secrets', 'owner.key')), true);
  assert.equal(fs.existsSync(path.join(base, 'trust', 'owner.pub')), true);
  await assert.rejects(() => generateKeys(path.join(repoRoot, 'secrets'), path.join(base, 'trust2')), error => error.code === 'TRUST_STORE_UNAVAILABLE');
});
