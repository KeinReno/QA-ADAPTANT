// Дочерний процесс для гонок approval: один запрос dispatch/revoke, результат в файл.
import fs from 'node:fs';
import { consumeDispatch, revokeApproval } from '../../packages/trust/approval.mjs';
import { unwrapPrivateKey } from '../../packages/trust/identity.mjs';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
try {
  if (request.mode === 'revoke') {
    const key = await unwrapPrivateKey(request.ownerKeyFile);
    const document = revokeApproval(key, request.trustRoot, request.revoke);
    fs.writeFileSync(request.resultFile, JSON.stringify({ mode: 'revoke', ok: true, approvalId: document.approvalId }));
  } else {
    const result = consumeDispatch(request.dispatch);
    fs.writeFileSync(request.resultFile, JSON.stringify({ mode: 'consume', ok: true, ack: result.ack === true, code: result.code }));
  }
} catch (error) {
  fs.writeFileSync(request.resultFile, JSON.stringify({ mode: request.mode || 'consume', ok: false, ack: false, code: error.code || 'ERROR', message: String(error.message || error) }));
}
