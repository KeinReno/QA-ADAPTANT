// AUD-P2-R02: keygen обязан проверять физический путь (realpath), а не строковый сегмент.
// junction <tmp>\aliased-run -> <store>\runs\run-02 подсовывается как --secrets.
//
// FAIL = дефект воспроизводится: ключи созданы внутри каталога прогонов (junction обошёл защиту).
// PASS = keygen отказал, секретов в runDir нет.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { loadModules, runScenario, check, targetRoot, tempDir, removeDir } from './audit-lib.mjs';

function findKeyFiles(dir) {
  const found = [];
  const walk = current => {
    let entries = [];
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (['owner.key', 'anchor.key'].includes(entry.name)) found.push(full);
    }
  };
  walk(dir);
  return found;
}

await runScenario({
  id: 'AUD-P2-R02',
  title: 'R-02: keygen обходится junction/symlink в каталог прогонов',
  expected: 'keygen отвергает физический путь внутрь runs; секреты в runDir не появляются',
  async body() {
    const checks = [];
    const M = await loadModules(targetRoot());
    const work = tempDir('wp08-r02-');
    try {
      const keygen = path.join(targetRoot(), 'packages', 'trust', 'keygen.mjs');
      check(checks, 'keygen.mjs присутствует на проверяемой ревизии', fs.existsSync(keygen));
      if (!fs.existsSync(keygen)) return { defectObserved: false, actual: 'keygen.mjs отсутствует', evidence: {}, checks };

      const run = (args) => spawnSync(process.execPath, [keygen, ...args], { encoding: 'utf8', windowsHide: true, timeout: 60000 });

      // Положительный контроль: обычные пути работают.
      const control = run(['--secrets', path.join(work, 'ok-secrets'), '--trust-root', path.join(work, 'ok-trust')]);
      const controlOk = control.status === 0 && fs.existsSync(path.join(work, 'ok-secrets', 'owner.key'));
      check(checks, 'положительный контроль: keygen работает на обычных путях', controlOk, { status: control.status, stderr: String(control.stderr || '').slice(0, 300) });
      if (!controlOk) return { defectObserved: false, actual: 'положительный контроль keygen не прошёл: атака не доказательна', evidence: {}, checks };

      // Атака через junction.
      const storeRoot = path.join(work, 'store');
      const runDir = path.join(storeRoot, 'runs', 'run-02');
      fs.mkdirSync(runDir, { recursive: true });
      const alias = path.join(work, 'aliased-run');
      let junctionCreated = true;
      try { fs.symlinkSync(runDir, alias, 'junction'); } catch { junctionCreated = false; }
      check(checks, 'junction на каталог прогона создан', junctionCreated);
      if (!junctionCreated) return { defectObserved: false, actual: 'junction не создан: атака не выполнена', evidence: {}, checks };

      const attack = run(['--secrets', path.join(alias, 'secrets'), '--trust-root', path.join(work, 'attack-trust')]);
      const secretsInRunDir = findKeyFiles(runDir);
      const evidence = {
        junction: alias,
        runDir,
        attackExit: attack.status,
        attackStdout: String(attack.stdout || '').slice(0, 300),
        attackStderr: String(attack.stderr || '').slice(0, 300),
        secretsInRunDir,
        realpathRunDir: fs.realpathSync(runDir)
      };
      const defect = attack.status === 0 && secretsInRunDir.length > 0;
      if (!defect) {
        check(checks, 'keygen отказал (ненулевой exit)', attack.status !== 0, { status: attack.status });
        check(checks, 'секретов внутри каталога прогона нет', secretsInRunDir.length === 0, { secretsInRunDir });
      }
      return {
        defectObserved: defect,
        actual: defect
          ? 'R-02 обойдён: ключи созданы внутри runs через junction (' + secretsInRunDir.length + ' файлов)'
          : 'keygen отверг физический путь внутрь runs (exit=' + attack.status + ')',
        evidence,
        checks
      };
    } finally {
      removeDir(work);
    }
  }
});
