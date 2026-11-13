// wp0102: независимый дочерний процесс для гонок расхода/отзыва approval.
import fs from 'node:fs';
import path from 'node:path';
import { consumeDispatch, revokeApproval } from '../../packages/trust/approval.mjs';
import { unwrapPrivateKey } from '../../packages/trust/identity.mjs';
import { waitForFile } from './wp0102-fixture.mjs';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let result;
try {
  if (request.readyFile) fs.writeFileSync(request.readyFile, 'ready');
  if (request.goFile) waitForFile(request.goFile, 20000);
  if (request.mode === 'revoke') {
    const ownerKey = await unwrapPrivateKey(path.join(request.secretsDir, 'owner.key'));
    const document = revokeApproval(ownerKey, request.trustRoot, request.revoke);
    result = { mode: 'revoke', code: 'REVOKED_STORED', approvalId: document.approvalId };
  } else {
    const consumed = consumeDispatch(request.dispatch);
    result = { mode: 'consume', ack: consumed.ack, code: consumed.code, runId: consumed.consumption ? consumed.consumption.runId : null };
  }
} catch (error) {
  result = { mode: request.mode || 'consume', ack: false, code: error.code || 'ERROR', message: error.message };
}
fs.writeFileSync(request.resultFile, JSON.stringify(result) + '\n');
if (request.exitCode) process.exit(request.exitCode);
