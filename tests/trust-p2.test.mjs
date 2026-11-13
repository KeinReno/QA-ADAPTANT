// WP-08 P2-регрессии: R-02 (junction в keygen), approvalId-only, E-04, публикация.
// Каждый тест воспроизводит дефект аудита WP-08 и падает, если дефект вернётся.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { RunStore } from '../packages/core/store.mjs';

const KEYGEN = path.resolve('packages/trust/keygen.mjs');

function work(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'qa-p2-' + prefix + '-'));
}

function runKeygen(secrets, trustRoot) {
  return spawnSync(process.execPath, [KEYGEN, '--secrets', secrets, '--trust-root', trustRoot], {
    cwd: path.resolve('.'), encoding: 'utf8', windowsHide: true, timeout: 60000
  });
}

// R-02: реальный путь (junction) в каталог прогонов обходит строковую проверку сегмента "runs".
test('R-02: keygen отвергает junction внутрь каталога прогонов', () => {
  const base = work('r02-junction');
  try {
    const store = new RunStore(path.join(base, 'store'));
    const runDir = store.runPath('run-02');
    fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
    const alias = path.join(base, 'aliased-run');
    // junction не требует прав администратора на Windows и разрешается как реальный каталог.
    fs.symlinkSync(runDir, alias, 'junction');
    const secrets = path.join(alias, 'secrets');
    const result = runKeygen(secrets, path.join(base, 'trust'));
    assert.notEqual(result.status, 0, 'keygen не должен принимать путь секретов через junction в runs');
    assert.match(String(result.stderr), /TRUST_STORE_UNAVAILABLE/);
    assert.equal(fs.existsSync(path.join(runDir, 'secrets')), false, 'секреты не должны появиться в каталоге прогона');
    assert.equal(fs.existsSync(path.join(secrets, 'owner.key')), false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('R-02: keygen отвергает junction для trust root внутрь каталога прогонов', () => {
  const base = work('r02-junction-trust');
  try {
    const store = new RunStore(path.join(base, 'store'));
    const runDir = store.runPath('run-03');
    fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
    const alias = path.join(base, 'aliased-trust');
    fs.symlinkSync(runDir, alias, 'junction');
    const result = runKeygen(path.join(base, 'secrets'), path.join(alias, 'trust'));
    assert.notEqual(result.status, 0);
    assert.match(String(result.stderr), /TRUST_STORE_UNAVAILABLE/);
    assert.equal(fs.existsSync(path.join(runDir, 'trust')), false);
  } finally {
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});
