import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createTrustRoot } from './identity.mjs';

export async function generateKeys(secretsDir, trustRoot) {
  const created = await createTrustRoot({ secretsDir: path.resolve(secretsDir), trustRoot: path.resolve(trustRoot) });
  process.stdout.write(`owner ${created.ownerKeyId}\nanchor-signer ${created.anchorKeyId}\n`);
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
