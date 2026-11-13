// RT-14: старые инварианты 0.1 не нарушены принятыми WP-01/WP-02.
// Ожидание: packages/core, packages/contracts, schemas, contract-freeze.json и рабочие входы приложений
// не менялись относительно тега v0.1.0-stable; старые тесты не редактировались.
import fs from 'node:fs';
import path from 'node:path';
import { record, finish, git, PROJECT_ROOT } from './_lib.mjs';

const checks = [];
const stable = 'v0.1.0-stable';
try {
  const protectedPaths = [
    'packages/core', 'packages/contracts', 'schemas', 'docs/contract-freeze.json',
    'apps/control/run.mjs', 'apps/browser/worker.mjs', 'apps/verification/worker.mjs',
    'adapters/local/server.mjs', 'scripts/run-tests.mjs'
  ];
  const diff = git(['diff', '--name-only', stable + '..HEAD', '--', ...protectedPaths]);
  record(checks, 'замороженные и рабочие файлы 0.1 не изменены относительно ' + stable, diff === '', { changed: diff ? diff.split('\n') : [] });

  const testsDiff = git(['diff', '--name-only', stable + '..HEAD', '--', 'tests/']).split('\n').filter(Boolean);
  const allowed = /^tests\/(trust-identity\.test\.mjs|trust-approval\.test\.mjs|approval-consume-worker\.mjs|redteam\/.*)$/;
  record(checks, 'старые тесты 0.1 не изменены', testsDiff.every(file => allowed.test(file)), { changed: testsDiff });
  record(checks, 'новые тестовые файлы относятся только к trust', testsDiff.every(file => allowed.test(file)));

  const runtimeFiles = ['apps/control/run.mjs', 'apps/browser/worker.mjs', 'apps/verification/worker.mjs', 'adapters/local/server.mjs'];
  record(checks, 'рабочие входы не импортируют packages/trust', runtimeFiles.every(file => !fs.readFileSync(path.join(PROJECT_ROOT, file), 'utf8').includes('packages/trust')));

  const schemasCount = fs.readdirSync(path.join(PROJECT_ROOT, 'schemas')).length;
  record(checks, 'каталог schemas присутствует и непуст', schemasCount > 0, { schemasCount });
  record(checks, 'contract-freeze.json не изменён', git(['diff', '--name-only', stable + '..HEAD', '--', 'docs/contract-freeze.json']) === '');

  const HEAD = git(['rev-parse', 'HEAD']);
  record(checks, 'ревизия базы соответствует ожидаемой', HEAD === '0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31', { HEAD });
  const trustFiles = git(['ls-files', 'packages/trust']).split('\n').filter(Boolean).sort();
  record(checks, 'в 0.2 добавлены только ожидаемые trust-модули', trustFiles.every(file => ['packages/trust/acl.mjs', 'packages/trust/approval.mjs', 'packages/trust/dpapi.mjs', 'packages/trust/identity.mjs', 'packages/trust/keygen.mjs'].includes(file)), { trustFiles });
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
}
finish({ id: 'RT-14', title: 'Старые инварианты 0.1 не нарушены', checks });
