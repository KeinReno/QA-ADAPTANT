import fs from 'node:fs';
import path from 'node:path';
import { consumeDispatch, revokeApproval } from '../packages/trust/approval.mjs';
import { unwrapPrivateKey } from '../packages/trust/identity.mjs';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
try {
  if (request.mode === 'revoke') {
    const key = await unwrapPrivateKey(path.join(request.secretsDir, 'owner.key'));
    revokeApproval(key, request.trustRoot, request);
    fs.writeFileSync(request.resultFile, JSON.stringify({ ack: false, code: 'REVOKED_STORED' }));
  } else {
    if (request.goFile) {
      fs.writeFileSync(request.readyFile, 'ready');
      while (!fs.existsSync(request.goFile)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
    const result = consumeDispatch(request);
    fs.writeFileSync(request.resultFile, JSON.stringify({ ack: result.ack === true, code: result.code }));
  }
} catch (error) {
  fs.writeFileSync(request.resultFile, JSON.stringify({ ack: false, code: error.code || 'ERROR' }));
  process.exitCode = request.mode === 'revoke' ? 1 : 0;
}
