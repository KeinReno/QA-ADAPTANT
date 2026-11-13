// RT-05: подделка/изменение approval и чужой ключ.
// Ожидание: подпись проверяется по owner.pub; любое изменение тела даёт APPROVAL_SIGNATURE_INVALID;
// keyId анкера не подписывает approval; закреплённый документ не перезаписывается и не подменяется на диске.
import fs from 'node:fs';
import path from 'node:path';
import { makeTrust, principals, makeApproval, expectThrow, record, finish, approvalFields } from './_lib.mjs';
import { signApproval, verifyApproval } from '../../packages/trust/approval.mjs';

const checks = [];
const env = await makeTrust('rt05');
try {
  env.cards = principals(env);
  const approval = makeApproval(env, 'approval-rt05');
  const storedFile = path.join(env.trustRoot, 'approvals', 'approval-rt05.json');
  const storedBefore = fs.readFileSync(storedFile);
  const context = { issuer: env.cards.issuer, subject: env.cards.subject, windowsSid: 'S-1-5-21-operator', trustRoot: env.trustRoot };

  await expectThrow(checks, 'изменённый approvedInputsHash отклонён подписью',
    () => verifyApproval(env.trust, { ...approval, approvedInputsHash: 'f'.repeat(64) }, context), 'APPROVAL_SIGNATURE_INVALID');
  await expectThrow(checks, 'изменённый approvalId отклонён подписью',
    () => verifyApproval(env.trust, { ...approval, approvalId: 'approval-other' }, context), 'APPROVAL_SIGNATURE_INVALID');
  await expectThrow(checks, 'изменённый fixtureId отклонён подписью',
    () => verifyApproval(env.trust, { ...approval, fixtureId: 'fixture-other' }, context), 'APPROVAL_SIGNATURE_INVALID');

  // Подмена закреплённого файла на диске.
  fs.writeFileSync(storedFile, JSON.stringify({ ...approval, fixtureId: 'fixture-other' }) + '\n');
  await expectThrow(checks, 'подменённый на диске approval не проходит verify',
    () => verifyApproval(env.trust, null, { ...context, approvalId: 'approval-rt05' }), 'APPROVAL_SIGNATURE_INVALID');
  fs.writeFileSync(storedFile, storedBefore);
  record(checks, 'закреплённый approval восстановлен байт-в-байт', fs.readFileSync(storedFile).equals(storedBefore));

  await expectThrow(checks, 'approval, подписанный ключом анкера, не принимается trust root',
    () => signApproval(env.anchorKey, { ...approvalFields('approval-rt05-anchor'), keyId: env.anchorKeyId }, env.trust, env.trustRoot), 'APPROVAL_SIGNATURE_INVALID');

  const foreignTrust = await makeTrust('rt05-foreign');
  try {
    await expectThrow(checks, 'approval, подписанный чужим owner-ключом, отвергается в этом trust root',
      () => signApproval(foreignTrust.ownerKey, { ...approvalFields('approval-rt05-foreign'), keyId: foreignTrust.ownerKeyId }, env.trust, env.trustRoot), 'APPROVAL_SIGNATURE_INVALID');
  } finally { foreignTrust.cleanup(); }

  await expectThrow(checks, 'повтор approvalId с другим содержимым не перезаписывает закреплённый файл',
    () => signApproval(env.ownerKey, { ...approvalFields('approval-rt05', { approvalNonce: 'a'.repeat(64) }), keyId: env.ownerKeyId }, env.trust, env.trustRoot), 'CONTRACT_INVALID');
  record(checks, 'закреплённый approval не изменён', fs.readFileSync(storedFile).equals(storedBefore));
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error) });
} finally {
  env.cleanup();
}
finish({ id: 'RT-05', title: 'Подделка и изменение approval', checks,
  notes: ['Подмена owner.pub/ready.json до старта — принятый остаточный риск корня (04-THREAT-MODEL); проверяется отдельно в RT-09.'] });