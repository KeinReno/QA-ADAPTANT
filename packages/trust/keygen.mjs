import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createTrustRoot } from './identity.mjs';

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

// R-02: без явного runDir генератор не знал о каталогах прогонов и мог создать ключи
// внутри runDir. Ключи не должны попадать ни в один путь, проходящий через каталог runs.
function assertOutsideRunStore(label, value) {
  const resolved = path.resolve(value);
  if (resolved.split(path.sep).filter(Boolean).some(segment => segment.toLowerCase() === 'runs')) {
    fail('TRUST_STORE_UNAVAILABLE', label + ' не может находиться внутри каталога прогонов');
  }
}

export async function generateKeys(secretsDir, trustRoot) {
  if (typeof secretsDir !== 'string' || secretsDir.length === 0) fail('TRUST_STORE_UNAVAILABLE', 'Нужен каталог секретов');
  if (typeof trustRoot !== 'string' || trustRoot.length === 0) fail('TRUST_STORE_UNAVAILABLE', 'Нужен каталог trust root');
  assertOutsideRunStore('Каталог секретов', secretsDir);
  assertOutsideRunStore('Trust root', trustRoot);
  const created = await createTrustRoot({ secretsDir: path.resolve(secretsDir), trustRoot: path.resolve(trustRoot) });
  process.stdout.write(`owner ${created.ownerKeyId}\nanchor-signer ${created.anchorKeyId}\n`);
  return created;
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const secrets = argument('--secrets');
  const trustRoot = argument('--trust-root');
  if (!secrets || !trustRoot) {
    process.stderr.write('Нужны --secrets и --trust-root\n');
    process.exit(1);
  }
  generateKeys(secrets, trustRoot).catch(error => {
    process.stderr.write(`${error.code || 'TRUST_STORE_UNAVAILABLE'}\n`);
    process.exit(1);
  });
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? '' : process.argv[index + 1] || '';
}
