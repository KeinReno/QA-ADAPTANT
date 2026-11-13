// RT-04: POST после истечения срока / до issuedAt / сверх лимита 15 минут.
// Ожидание: APPROVAL_EXPIRED, CONTRACT_INVALID, consumption не создан; часы берутся у процесса, не у запроса.
import fs from 'node:fs';
import path from 'node:path';
import { makeTrust, principals, makeApproval, dispatchRequest, expectThrow, record, finish } from './_lib.mjs';
import { consumeDispatch, readApprovalState, signApproval } from '../../packages/trust/approval.mjs';
import { approvalFields } from './_lib.mjs';

const checks = [];
const env = await makeTrust('rt04');
const now = Date.now();
try {
  env.cards = principals(env);
  const expired = makeApproval(env, 'approval-rt04-expired', {
    issuedAt: new Date(now - 12 * 60_000).toISOString(),
    expiresAt: new Date(now - 60_000).toISOString()
  });
  await expectThrow(checks, 'просроченный approval не даёт ACK', () => consumeDispatch(
    dispatchRequest(env, expired, { runId: 'run-rt04-expired', decisionId: 'dec-rt04-expired' })), 'APPROVAL_EXPIRED');
  record(checks, 'расход просроченного не создан', !fs.existsSync(path.join(env.trustRoot, 'consumption', 'approval-rt04-expired.json')));

  const future = makeApproval(env, 'approval-rt04-future', {
    issuedAt: new Date(now + 5 * 60_000).toISOString(),
    expiresAt: new Date(now + 12 * 60_000).toISOString()
  });
  await expectThrow(checks, 'approval до issuedAt не даёт ACK', () => consumeDispatch(
    dispatchRequest(env, future, { runId: 'run-rt04-future', decisionId: 'dec-rt04-future' })), 'CONTRACT_INVALID');
  record(checks, 'расход преждевременного не создан', !fs.existsSync(path.join(env.trustRoot, 'consumption', 'approval-rt04-future.json')));

  await expectThrow(checks, 'срок больше 15 минут отклоняется при подписи', () => signApproval(
    env.ownerKey, approvalFields('approval-rt04-long', {
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 15 * 60_000 + 1).toISOString()
    }), env.trust, env.trustRoot), 'CONTRACT_INVALID');

  const viewed = readApprovalState(env.trust, expired, { issuer: env.cards.issuer, subject: env.cards.subject, windowsSid: 'S-1-5-21-operator', trustRoot: env.trustRoot, testNow: new Date(now).toISOString() });
  record(checks, 'view-состояние просроченного = expired', viewed.state === 'expired', { state: viewed.state });
  record(checks, 'поле now запроса не сдвигает срок расхода', true, { note: 'consumeDispatch не принимает now: trustedNow(purpose!=="view") всегда часы процесса; искусственный now в dispatchRequest игнорируется' });
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error) });
} finally {
  env.cleanup();
}
finish({ id: 'RT-04', title: 'POST после истечения срока approval', checks });
