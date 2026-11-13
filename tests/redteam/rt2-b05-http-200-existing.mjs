// B-05: ответ стенда 200 на уже существующий объект не является PASS этой операции.
// Атака: до доверенного прогона создать объект с тем же fixtureId и теми же полями; POST вернёт 200.
// Ожидание: не PASS (правило 0.1 про 201), нового объекта и второй мутации нет.
import { caseMain, makeWorld, check, checkNoMutation } from './_w2.mjs';

await caseMain({ id: 'B-05', title: 'HTTP 200 на существующий объект не PASS', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-b05' });
  const seed = await fetch(new URL('/records', world.stand.baseUrl), {
    method: 'POST',
    headers: { authorization: 'Bearer ' + world.stand.authToken, 'content-type': 'application/json' },
    body: JSON.stringify({ ...bundle.operation.inputs, fixtureId: contract.fixtureId })
  });
  check(checks, 'объект заранее создан прямым POST (201)', seed.status === 201, { status: seed.status });
  check(checks, 'стенд насчитал 1 мутацию до прогона', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
  const approval = world.approvalFor({ bundle, contract });
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  check(checks, 'доверенный прогон не даёт PASS на HTTP 200', result.verdict.verdict !== 'PASS', { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode });
  check(checks, 'новой мутации не было (POST вернул 200, mutationCount не вырос)', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
  check(checks, 'второго объекта не создано', world.stand.recordCount === 1, { recordCount: world.stand.recordCount });
  const observed = await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId: bundle.manifest.runId });
  check(checks, 'observeTrusted не показывает PASS', observed.passed === false, { passed: observed.passed, verdict: observed.verdict?.verdict || null });
  return { checks };
} });