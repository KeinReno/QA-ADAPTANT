// RT-06: повтор approvalId и повторный dispatch.
// Ожидание: один runId -> ack=false APPROVAL_CONSUMED без изменения файла; другой runId -> APPROVAL_REPLAY;
// два процесса одновременно не создают два ACK и не заменяют расход.
import fs from 'node:fs';
import path from 'node:path';
import { makeTrust, principals, makeApproval, dispatchRequest, record, finish, runNode, waitForFile, expectThrow, PROJECT_ROOT } from './_lib.mjs';
import { consumeDispatch } from '../../packages/trust/approval.mjs';

const checks = [];
const env = await makeTrust('rt06');
try {
  env.cards = principals(env);
  const approval = makeApproval(env, 'approval-rt06');
  const consumptionFile = path.join(env.trustRoot, 'consumption', 'approval-rt06.json');
  const first = consumeDispatch(dispatchRequest(env, approval, { runId: 'run-rt06-a', decisionId: 'dec-rt06-a' }));
  record(checks, 'первый dispatch даёт ACK', first.ack === true && first.code === 'TRUST_OK', { ack: first.ack, code: first.code });
  const kept = fs.readFileSync(consumptionFile);
  const second = consumeDispatch(dispatchRequest(env, approval, { runId: 'run-rt06-a', decisionId: 'dec-rt06-b' }));
  record(checks, 'повтор того же runId не даёт второго ACK', second.ack === false && second.code === 'APPROVAL_CONSUMED', { ack: second.ack, code: second.code });
  record(checks, 'файл расхода не изменён повтором', fs.readFileSync(consumptionFile).equals(kept));
  await expectThrow(checks, 'другой runId с тем же approval отклонён APPROVAL_REPLAY',
    () => consumeDispatch(dispatchRequest(env, approval, { runId: 'run-rt06-b', decisionId: 'dec-rt06-c' })), 'APPROVAL_REPLAY');

  // Два процесса, один approval, разные runId: ровно один ACK, один полный файл.
  const approvalParallel = makeApproval(env, 'approval-rt06-race');
  const parallelFile = path.join(env.trustRoot, 'consumption', 'approval-rt06-race.json');
  const requests = ['p1', 'p2'].map(tag => {
    const requestFile = path.join(env.root, tag + '-request.json');
    const resultFile = path.join(env.root, tag + '-result.json');
    const { trust, ...wire } = dispatchRequest(env, approvalParallel, { runId: 'run-rt06-' + tag, decisionId: 'dec-rt06-' + tag });
    fs.writeFileSync(requestFile, JSON.stringify({ mode: 'consume', dispatch: wire, resultFile }));
    return { requestFile, resultFile };
  });
  const worker = path.join(PROJECT_ROOT, 'tests', 'redteam', '_consume-worker.mjs');
  const children = requests.map(item => runNode(worker, [item.requestFile]));
  await Promise.all(children);
  for (const item of requests) await waitForFile(item.resultFile, 10_000);
  const results = requests.map(item => JSON.parse(fs.readFileSync(item.resultFile, 'utf8')));
  const acks = results.filter(result => result.ack === true).length;
  record(checks, 'в гонке двух процессов ровно один ACK', acks === 1, { results });
  record(checks, 'в гонке создан ровно один полный файл расхода', fs.existsSync(parallelFile) && JSON.parse(fs.readFileSync(parallelFile, 'utf8')).approvalId === 'approval-rt06-race');
  record(checks, 'второй процесс получил APPROVAL_REPLAY или APPROVAL_CONSUMED', results.filter(result => result.ack !== true).every(result => ['APPROVAL_REPLAY', 'APPROVAL_CONSUMED'].includes(result.code)), { results });
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error) });
} finally {
  env.cleanup();
}
finish({ id: 'RT-06', title: 'Повтор approvalId / повторный dispatch / гонка', checks });