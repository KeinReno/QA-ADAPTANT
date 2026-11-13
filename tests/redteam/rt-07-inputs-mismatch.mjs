// RT-07: подписанные входы не совпадают с фактической мутацией.
// Ожидание: APPROVAL_MISMATCH до любого ACK, расход не создан; точное совпадение даёт ACK.
import fs from 'node:fs';
import path from 'node:path';
import { makeTrust, principals, makeApproval, dispatchRequest, expectedOf, expectThrow, record, finish, EFFECTS, OPERATION, INPUTS } from './_lib.mjs';
import { consumeDispatch } from '../../packages/trust/approval.mjs';

const checks = [];
const env = await makeTrust('rt07');
try {
  env.cards = principals(env);
  const approval = makeApproval(env, 'approval-rt07');
  const consumption = path.join(env.trustRoot, 'consumption', 'approval-rt07.json');
  const cases = [
    ['inputs (title)', { inputs: { ...INPUTS, title: 'подмена' } }],
    ['inputs (comment)', { inputs: { ...INPUTS, comment: 'иная заметка' } }],
    ['operation.version', { operation: { ...OPERATION, version: '1.0.1' } }],
    ['operation.effects', { effects: [EFFECTS[0]] }],
    ['fixtureId', { fixtureId: 'fixture-other' }],
    ['environmentId', { environmentId: 'other-stand' }],
    ['environmentGeneration', { environmentGeneration: 2 }],
    ['resource.path', { resource: { method: 'POST', path: '/other' } }],
    ['scenarioContentSha256', { scenarioContentSha256: 'a'.repeat(64) }]
  ];
  for (const [name, overrides] of cases) {
    const expected = expectedOf(overrides);
    await expectThrow(checks, 'несовпадение ' + name + ' -> APPROVAL_MISMATCH', () => consumeDispatch(
      dispatchRequest(env, approval, { runId: 'run-rt07', decisionId: 'dec-rt07', overrides: { expected } })), 'APPROVAL_MISMATCH');
    record(checks, 'расход не создан после ' + name, !fs.existsSync(consumption));
  }
  const ok = consumeDispatch(dispatchRequest(env, approval, { runId: 'run-rt07-ok', decisionId: 'dec-rt07-ok' }));
  record(checks, 'точные входы дают ACK (контроль)', ok.ack === true, { ack: ok.ack, code: ok.code });
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error) });
} finally {
  env.cleanup();
}
finish({ id: 'RT-07', title: 'Несовпадение подписанных входов и фактической мутации', checks });
