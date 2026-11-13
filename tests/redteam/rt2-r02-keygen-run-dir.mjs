// R-02 на целевой ветке: keygen без runDir не должен создавать ключи в каталоге прогона.
// На интеграции риск закрыт: любой путь с сегментом "runs" отвергается до записи.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { caseMain, makeWorld, check } from './_w2.mjs';

await caseMain({ id: 'R-02', title: 'keygen и каталоги прогонов', risk: 'R-02', async body({ modules, cleanup, target, checks }) {
  const world = await makeWorld(modules, { withSigner: false, withRecord: false });
  cleanup(world.cleanup);
  const base = world.base;
  const fakeRun = path.join(base, 'runs', 'run-r02');
  fs.mkdirSync(path.join(fakeRun, 'evidence'), { recursive: true });
  fs.writeFileSync(path.join(fakeRun, 'events.jsonl'), '');
  fs.writeFileSync(path.join(fakeRun, 'evidence.jsonl'), '');
  fs.writeFileSync(path.join(fakeRun, 'owner.json'), JSON.stringify({ pid: 1 }));
  const keygen = path.join(target.dir, 'packages', 'trust', 'keygen.mjs');
  const insideRun = spawnSync(process.execPath, [keygen, '--secrets', path.join(fakeRun, 'secrets'), '--trust-root', path.join(base, 'trust-r02')], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  check(checks, 'R-02 закрыт: --secrets внутри каталога прогона отвергнут exit != 0', insideRun.status !== 0, { exit: insideRun.status, stderr: String(insideRun.stderr || '').trim().slice(0, 200) });
  check(checks, 'каталог секретов внутри runDir не создан', !fs.existsSync(path.join(fakeRun, 'secrets')));
  check(checks, 'код отказа TRUST_STORE_UNAVAILABLE', /TRUST_STORE_UNAVAILABLE/.test(String(insideRun.stderr || '')));

  const uppercaseRun = path.join(base, 'RUNS', 'run-r02b');
  fs.mkdirSync(uppercaseRun, { recursive: true });
  const upper = spawnSync(process.execPath, [keygen, '--secrets', path.join(uppercaseRun, 'secrets'), '--trust-root', path.join(base, 'trust-r02b')], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  check(checks, 'сегмент RUNS в верхнем регистре тоже отвергнут', upper.status !== 0, { exit: upper.status });

  const inRepoSecrets = path.join(target.dir, 'rt2-in-repo-' + Date.now());
  const rejected = spawnSync(process.execPath, [keygen, '--secrets', inRepoSecrets, '--trust-root', path.join(base, 'trust-repo')], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  check(checks, 'secretsDir внутри репозитория отвергнут', rejected.status !== 0 && !fs.existsSync(inRepoSecrets), { exit: rejected.status });

  // Контроль: обычный временный путь вне runs/ и репозитория работает.
  const goodSecrets = path.join(base, 'control', 'secrets');
  const goodTrust = path.join(base, 'control', 'trust');
  const good = spawnSync(process.execPath, [keygen, '--secrets', goodSecrets, '--trust-root', goodTrust], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  check(checks, 'контроль: безопасный каталог принимается (exit 0)', good.status === 0 && fs.existsSync(path.join(goodSecrets, 'owner.key')), { exit: good.status, stderr: String(good.stderr || ''), stdout: String(good.stdout || ''), base, goodSecrets, goodTrust });
  check(checks, 'в git нет *.key', spawnSync('git', ['-C', target.dir, 'ls-files'], { encoding: 'utf8' }).stdout.split('\n').every(file => !/(^|[\/\\])(owner|anchor)\.key$/.test(file)));
  return { checks };
} });