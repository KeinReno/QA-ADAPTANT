// RT-03: POST после отзыва approval. Атака: owner отозвал approval, затем dispatch.
// Ожидание: APPROVAL_REVOKED, consumption не создан, ACK нет; повторный отзыв не перезаписывает файл.
import fs from 'node:fs';
import path from 'node:path';
import { makeTrust, principals, makeApproval, dispatchRequest, expectThrow, record, finish } from './_lib.mjs';
import { consumeDispatch, readApprovalState, revokeApproval } from '../../packages/trust/approval.mjs';

const checks = [];
const env = await makeTrust('rt03');
try {
  env.cards = principals(env);
  const approval = makeApproval(env, 'approval-rt03-revoke');
  const revocation = revokeApproval(env.ownerKey, env.trustRoot, {
    approvalId: 'approval-rt03-revoke', reason: 'owner-revoked',
    revokedAt: new Date().toISOString(), keyId: env.ownerKeyId
  });
  const kept = fs.readFileSync(path.join(env.trustRoot, 'revocations', 'approval-rt03-revoke.json'));
  await expectThrow(checks, 'dispatch после отзыва отклонён APPROVAL_REVOKED',
    () => consumeDispatch(dispatchRequest(env, approval, { runId: 'run-rt03', decisionId: 'dec-rt03' })), 'APPROVAL_REVOKED');
  const consumption = path.join(env.trustRoot, 'consumption', 'approval-rt03-revoke.json');
  record(checks, 'файл расхода не создан', !fs.existsSync(consumption));
  record(checks, 'файл отзыва закреплён', fs.existsSync(path.join(env.trustRoot, 'revocations', 'approval-rt03-revoke.json')));
  record(checks, 'approval после отзыва не удалён', fs.existsSync(path.join(env.trustRoot, 'approvals', 'approval-rt03-revoke.json')));
  const viewed = readApprovalState(env.trust, approval, { issuer: env.cards.issuer, subject: env.cards.subject, windowsSid: 'S-1-5-21-operator', trustRoot: env.trustRoot });
  record(checks, 'view-состояние = revoked', viewed.state === 'revoked', { state: viewed.state });
  record(checks, 'view не выдаёт ACK', viewed.ack === false);
  await expectThrow(checks, 'повторный отзыв не перезаписывает файл (APPROVAL_REVOKED)',
    () => revokeApproval(env.ownerKey, env.trustRoot, {
      approvalId: 'approval-rt03-revoke', reason: 'owner-revoked',
      revokedAt: new Date().toISOString(), keyId: env.ownerKeyId
    }), 'APPROVAL_REVOKED');
  record(checks, 'файл отзыва не изменён повтором', fs.readFileSync(path.join(env.trustRoot, 'revocations', 'approval-rt03-revoke.json')).equals(kept));
  record(checks, 'вернулся подписанный отзыв', revocation.approvalId === 'approval-rt03-revoke' && revocation.domain === 'revocation');
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error) });
} finally {
  env.cleanup();
}
finish({ id: 'RT-03', title: 'POST после отзыва approval', checks });
