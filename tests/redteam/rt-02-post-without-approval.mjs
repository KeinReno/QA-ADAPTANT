// RT-02: POST без approval — что реально проверяется на базе 0e7e6c2.
// Модуль approval отказывает без закреплённого документа; старый вход start() доверенного режима не имеет.
// Доверенный путь 0.2 (T-A/T-B) на базе отсутствует, поэтому строка матрицы A-01/A-10 не проверяется.
import fs from 'node:fs';
import path from 'node:path';
import { makeTrust, makeApproval, approvalFields, dispatchRequest, expectThrow, record, finish, PROJECT_ROOT } from './_lib.mjs';
import { consumeDispatch } from '../../packages/trust/approval.mjs';
import { prepareRun, run } from './_run.mjs';

const checks = [];
const env = await makeTrust('rt02');
const context = await prepareRun({ runId: 'rt02-post-without-approval' });
try {
  const uncommitted = await import('../../packages/trust/approval.mjs').then(module => module.signApproval(env.ownerKey, { ...approvalFields('approval-never-committed'), keyId: env.ownerKeyId }));
  await expectThrow(checks, 'dispatch с подписанным, но незакреплённым approval -> APPROVAL_MISSING',
    () => consumeDispatch(dispatchRequest(env, uncommitted, { runId: 'run-rt02', decisionId: 'dec-rt02' })), 'APPROVAL_MISSING');
  await expectThrow(checks, 'dispatch без документа и без approvalId -> CONTRACT_INVALID',
    () => consumeDispatch(dispatchRequest(env, null, { runId: 'run-rt02', decisionId: 'dec-rt02' })), 'CONTRACT_INVALID');
  record(checks, 'файл расхода не создан', !fs.existsSync(path.join(env.trustRoot, 'consumption', 'approval-never-committed.json')));

  const controlSource = fs.readFileSync(path.join(PROJECT_ROOT, 'apps', 'control', 'run.mjs'), 'utf8');
  record(checks, 'Control не импортирует packages/trust (доверенного входа на базе нет)', !controlSource.includes('packages/trust'));
  record(checks, 'run() принимает только root/headed/fault/fixtureToken', !/\bapproval\b|\btrustRoot\b/.test(controlSource), { note: 'в run.mjs нет полей approval/trustRoot' });

  // Старый вход 0.1 исполняет мутацию без approval — это его штатный контракт.
  const oldPath = await run(context.bundle, { root: context.root, fixtureToken: context.fixtureToken });
  record(checks, 'старый run() исполняет прогон без approval (штатное поведение 0.1)', oldPath.verdict.verdict === 'PASS' && context.fixture.mutationCount === 1, { verdict: oldPath.verdict.verdict, mutationCount: context.fixture.mutationCount });
  record(checks, 'старый PASS не содержит полей доверенного режима', !('anchorId' in oldPath.verdict) && !('approvalId' in oldPath.verdict));
  record(checks, 'документ доверенного режима (TrustDecision) на базе отсутствует', !fs.existsSync(path.join(PROJECT_ROOT, 'packages', 'trust', 'policy.mjs')) && !fs.existsSync(path.join(PROJECT_ROOT, 'packages', 'trust', 'facts.mjs')));
} catch (error) {
  record(checks, 'скрипт завершился без аварии', false, { message: String(error.message || error), code: error.code || null });
} finally {
  env.cleanup();
  await context.close();
}
finish({ id: 'RT-02', title: 'POST без approval: модуль против старого входа', checks,
  verdict: 'INCONCLUSIVE',
  notes: [
    'Строки матрицы «POST без approval» для доверенного режима (A-01..A-03, T-A/T-B) на ревизии 0e7e6c2 проверить нечем: consumer trust path ещё не собран (WP-06).',
    'Модульный отказ consumeDispatch без approval подтверждён; старый run() не является обходом доверенного режима, потому что доверенного режима на базе нет.',
    'Повторная проверка обязательна после интеграции WP-06 на переданном SHA.'
  ] });