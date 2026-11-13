// RT-09: утечка секретов до разрешения.
// Проверяем: приватные файлы только DPAPI-обёртка + ACL текущего SID; секретов в репозитории нет;
// ключи не кладутся в runDir/trust root; тот же SID может развернуть ключ (граница R-04),
// выдача секрета до разрешения (T-A) на базе не реализована и не проверяется.
import fs from 'node:fs';
import path from 'node:path';
import { makeTemp, remove, record, finish, PROJECT_ROOT, git, makeTrust } from './_lib.mjs';
import { createTrustRoot } from '../../packages/trust/identity.mjs';
import { readAcl } from '../../packages/trust/acl.mjs';

const checks = [];
const env = await makeTrust('rt09');
try {
  for (const name of ['owner.key', 'anchor.key']) {
    const file = path.join(env.secretsDir, name);
    const value = JSON.parse(fs.readFileSync(file, 'utf8'));
    record(checks, name + ' — DPAPI-обёртка, не открытый ключ', value.domain === 'wrapped-private-key' && value.wrapping === 'dpapi-current-user' && typeof value.protectedPkcs8 === 'string' && value.protectedPkcs8.length > 100);
    const raw = fs.readFileSync(file);
    record(checks, name + ' не содержит PEM/DER открытого ключа', !raw.includes(Buffer.from('BEGIN PRIVATE KEY')) && !raw.includes(Buffer.from('BEGIN RSA PRIVATE KEY')));
  }
  for (const target of [env.secretsDir, path.join(env.secretsDir, 'owner.key')]) {
    const acl = await readAcl(target);
    record(checks, 'ACL защищён и только текущий SID: ' + path.basename(target), acl.protected === true && acl.aces.length > 0 && acl.aces.every(ace => ace === acl.current + '|Allow'), { aces: acl.aces, current: acl.current });
  }

  // Ключи не должны попасть в репозиторий, trust root или runDir.
  const emptyRoot = makeTemp('rt09-reject');
  try {
    await attemptReject(checks, 'secretsDir внутри репозитория', () => createTrustRoot({ secretsDir: path.join(PROJECT_ROOT, 'rt09-secret-' + Date.now()), trustRoot: path.join(emptyRoot, 'trust') }));
    record(checks, 'в репозитории не создан каталог секретов', fs.readdirSync(PROJECT_ROOT).every(name => !name.startsWith('rt09-secret-')));
    await attemptReject(checks, 'trustRoot внутри secretsDir', () => createTrustRoot({ secretsDir: path.join(emptyRoot, 'a', 'b'), trustRoot: path.join(emptyRoot, 'a', 'b', 'trust') }));
    const fakeRun = path.join(emptyRoot, 'runs', 'run-x');
    fs.mkdirSync(fakeRun, { recursive: true });
    await attemptReject(checks, 'secretsDir внутри runDir (когда runDir передан)', () => createTrustRoot({ secretsDir: path.join(fakeRun, 'secrets'), trustRoot: path.join(emptyRoot, 'trust2'), runDir: fakeRun }));
    record(checks, 'после отказов каталог секретов в runDir не создан', !fs.existsSync(path.join(fakeRun, 'secrets')));
  } finally { remove(emptyRoot); }

  // Секреты не в git.
  const tracked = git(['ls-files']).split('\n');
  record(checks, 'в git нет owner.key/anchor.key', tracked.every(file => !/(^|\/)(owner|anchor)\.key$/.test(file)), { candidates: tracked.filter(file => /(owner|anchor)\.key$/.test(file)) });
  record(checks, 'в git нет PEM-приватных ключей', git(['grep', '-l', 'BEGIN PRIVATE KEY']).trim() === '');
  const secretLike = tracked.filter(file => {
    if (!file || /.(png|jpg|zip|exe)$/i.test(file)) return false;
    try {
      const value = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, file), 'utf8'));
      return value && value.domain === 'wrapped-private-key';
    } catch { return false; }
  });
  record(checks, 'в git нет файлов формата wrapped-private-key', secretLike.length === 0, { files: secretLike });

  record(checks, 'тот же SID может развернуть owner.key (граница R-04, принятый остаточный риск)', fs.existsSync(env.secretsDir) && env.ownerKey.type === 'private');
  record(checks, 'T-A (выдача секрета только после ALLOW) на базе отсутствует', !fs.existsSync(path.join(PROJECT_ROOT, 'apps', 'control', 'trusted.mjs')));
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  env.cleanup();
}
finish({ id: 'RT-09', title: 'Секреты: хранение, ACL, репозиторий, граница SID', checks,
  verdict: 'INCONCLUSIVE',
  notes: [
    'Хранение и отсутствие секретов в репозитории подтверждены.',
    'Строка «секрет не выдан до разрешения» (T-A) на базе не проверяется: доверенного входа apps/control/trusted.mjs нет.',
    'R-04: ACL/DPAPI не изолируют Control от произвольного кода той же учётной записи — это явная граница локальной 0.2.'
  ] });

async function attemptReject(checks, name, fn) {
  try {
    await fn();
    record(checks, name + ' отвергнут', false, { actual: 'операция прошла' });
  } catch (error) {
    record(checks, name + ' отвергнут', error.code === 'TRUST_STORE_UNAVAILABLE', { code: error.code || null, message: error.message });
  }
}