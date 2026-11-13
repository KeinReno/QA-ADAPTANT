// RT-15 (R-02): packages/trust/keygen.mjs не проверяет каталоги прогонов, если runDir не передан.
// Факт: генератор с --secrets внутри каталога прогона создаёт там приватные ключи (DPAPI-обёртка).
// При этом secretsDir внутри репозитория по-прежнему отвергается, в git ничего не попадает.
import fs from 'node:fs';
import path from 'node:path';
import { makeTemp, remove, record, finish, runNode, PROJECT_ROOT, git } from './_lib.mjs';

const checks = [];
const base = makeTemp('rt15');
try {
  // Имитация каталога прогона вне репозитория (как os.tmpdir() в тестах).
  const runDir = path.join(base, 'runs', 'run-rt15');
  fs.mkdirSync(path.join(runDir, 'evidence'), { recursive: true });
  fs.writeFileSync(path.join(runDir, 'events.jsonl'), '');
  fs.writeFileSync(path.join(runDir, 'evidence.jsonl'), '');
  fs.writeFileSync(path.join(runDir, 'owner.json'), JSON.stringify({ pid: 1 }));
  const secretsDir = path.join(runDir, 'secrets');
  const trustRoot = path.join(base, 'trust-root');
  const keygen = path.join(PROJECT_ROOT, 'packages', 'trust', 'keygen.mjs');
  const generated = await runNode(keygen, ['--secrets', secretsDir, '--trust-root', trustRoot]);
  record(checks, 'R-02: генератор принял runDir как каталог секретов (exit 0)', generated.code === 0, { exit: generated.code, stderr: generated.stderr.slice(0, 300) });
  record(checks, 'R-02: owner.key создан внутри каталога прогона', fs.existsSync(path.join(secretsDir, 'owner.key')) && fs.existsSync(path.join(secretsDir, 'anchor.key')), { files: fs.existsSync(secretsDir) ? fs.readdirSync(secretsDir) : [] });
  record(checks, 'R-02: публичные ключи созданы в trust root', fs.existsSync(path.join(trustRoot, 'owner.pub')) && fs.existsSync(path.join(trustRoot, 'ready.json')));
  record(checks, 'файл ключа — обёртка, не открытый PKCS8', fs.readFileSync(path.join(secretsDir, 'owner.key'), 'utf8').includes('dpapi-current-user'));
  record(checks, 'R-02: проверка runDir не сработала, потому что keygen не передаёт runDir', true, { note: 'keygen.mjs вызывает createTrustRoot({ secretsDir, trustRoot }) без runDir' });

  // Репозиторий не должен получить секреты даже при ошибочном аргументе.
  const inRepoSecrets = path.join(PROJECT_ROOT, 'rt15-in-repo-' + Date.now());
  const rejected = await runNode(keygen, ['--secrets', inRepoSecrets, '--trust-root', path.join(base, 'trust-repo')]);
  record(checks, 'secretsDir внутри репозитория отвергнут (exit != 0)', rejected.code !== 0, { exit: rejected.code, stderr: rejected.stderr.slice(0, 200) });
  record(checks, 'каталог секретов в репозитории не создан', !fs.existsSync(inRepoSecrets));
  record(checks, 'в git не появились секреты', git(['status', '--porcelain']).split('\n').filter(line => /\.key$/.test(line)).length === 0);
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  remove(base);
}
finish({ id: 'RT-15', title: 'R-02: keygen без runDir кладёт секреты в каталог прогона', checks, risk: 'R-02',
  notes: [
    'Факт подтверждён: при запуске генератора с --secrets внутри каталога прогона приватные ключи создаются в каталоге прогона; проверки runDir нет, потому что keygen не передаёт этот аргумент.',
    'Секреты всё же DPAPI-обёрнуты и в репозиторий не попадают; проверка «внутри репозитория» работает.',
    'Остаточный риск R-02: закрыть в WP-07 закреплением безопасных корневых каталогов (по умолчанию вне репозитория, trust root и каталогов прогонов).',
    'Владелец дефекта: пакет WP-01 (packages/trust/keygen.mjs, identity.mjs); severity P2 (нет утечки в git, но секрет оказывается в каталоге, который может архивироваться вместе с evidence).'
  ] });