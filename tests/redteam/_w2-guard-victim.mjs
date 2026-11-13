// Жертва R-01 для целевой ветки: входит в реальный withGuard approval.mjs и гибнет по SIGKILL.
// Proxy над trust перехватывает чтение ключа уже ВНУТРИ guard, даёт сигнал готовности и блокируется.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const imp = rel => import(pathToFileURL(path.join(request.targetDir, rel)).href);
const identity = await imp('packages/trust/identity.mjs');
const approvalModule = await imp('packages/trust/approval.mjs');
const trustRoot = identity.loadTrustRoot(request.trustRoot);
let blocked = false;
const trust = new Proxy(trustRoot, {
  get(target, property) {
    if (!blocked && (property === 'owner' || property === 'anchor-signer')) {
      blocked = true;
      fs.writeFileSync(request.readyFile, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 3_600_000);
    }
    return target[property];
  }
});
try {
  approvalModule.consumeDispatch({ ...request, trust });
} catch (error) {
  fs.writeFileSync(request.errorFile, JSON.stringify({ code: error.code || null, message: String(error.message || error) }));
}
