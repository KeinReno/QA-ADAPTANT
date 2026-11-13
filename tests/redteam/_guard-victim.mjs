// Жертва для R-01: процесс входит в guard approval.mjs и умирает по SIGKILL.
// Блокировка создаётся самим withGuard (openSync(..., 'wx')), затем код заходит в verifyApproval.
// Proxy над trust перехватывает первое чтение ключа ('owner') уже ВНУТРИ guard: даёт сигнал
// готовности и остаётся там до убийства процесса. Так остаётся реальный guards/<approvalId>.lock.
import fs from 'node:fs';
import { loadTrustRoot } from '../../packages/trust/identity.mjs';
import { consumeDispatch } from '../../packages/trust/approval.mjs';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const trustRoot = loadTrustRoot(request.trustRoot);
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
  consumeDispatch({ ...request, trust });
} catch (error) {
  fs.writeFileSync(request.errorFile, JSON.stringify({ code: error.code || null, message: error.message }));
}
