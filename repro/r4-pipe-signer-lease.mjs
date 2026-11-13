// WP-08 QWEN independent audit — repro R4.
// Legacy named-pipe подписант (startAnchorSigner, inProcess:true) принимает подключение любого
// процесса того же SID и позволяет register-verification-key; lease для sign в этом режиме
// не требуется (anchor-signer.mjs:352). Продуктовые доверенные входы signerPipe отвергают
// (apps/control/trusted.mjs:770-790), поэтому поверхность доступна только тестам/внешним
// вызовам startAnchorSigner. Демонстрируется: регистрация чужого ключа проходит, а sign без
// lease доходит до проверок привязки (не отклоняется по отсутствию lease).
// Запуск: node repro/r4-pipe-signer-lease.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createTrustRoot } from '../packages/trust/identity.mjs';
import { connectAnchorSigner, startAnchorSigner } from '../packages/trust/anchor-signer.mjs';

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-r4-'));
const out = { repro: 'R4', sha: '1a510a5d5929534d400dc965f58c78cf468bc270' };
let server = null;
try {
  const trustRoot = path.join(base, 'trust');
  const secretsDir = path.join(base, 'secrets');
  await createTrustRoot({ secretsDir, trustRoot });
  server = startAnchorSigner({ trustRoot, secretsDir });
  await server.ready;
  out.pipePath = server.pipePath;
  const client = connectAnchorSigner(server.pipePath);

  // 1. Регистрация ключа Verification произвольным подключением того же SID принимается.
  const { publicKey } = generateKeyPairSync('ed25519');
  const nonce = randomBytes(32).toString('hex');
  const registration = await client.registerVerificationKey('r4-run', publicKey, process.pid, nonce);
  out.foreignKeyRegistration = { accepted: true, keyId: registration.keyId };

  // 2. sign БЕЗ lease: в fork-топологии это немедленный отказ (anchor-signer.mjs:352),
  //    в pipe-режиме запрос проходит дальше — до проверок привязки/runDir.
  try {
    await client.sign({ runDir: path.join(base, 'no-such-run'), approvalId: 'approval-x', anchorId: 'anchor-x', attestation: {} });
    out.signWithoutLease = { rejected: false };
  } catch (error) {
    out.signWithoutLease = { rejected: true, code: error.code, message: error.message };
  }
  out.leaseNotRequiredInPipeMode = out.signWithoutLease.rejected && !/lease/i.test(out.signWithoutLease.message || '');
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = out.foreignKeyRegistration.accepted && out.leaseNotRequiredInPipeMode ? 0 : 1;
} catch (error) {
  out.error = { code: error.code || null, message: String(error.message || error) };
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = 2;
} finally {
  if (server) await server.close().catch(() => {});
  fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}