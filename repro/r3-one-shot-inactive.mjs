// WP-08 QWEN independent audit — repro R3.
// Одноразовость мутации и привязка к runId на локальном стенде включаются ТОЛЬКО заголовком
// x-qa-run-id (adapters/local/server.mjs:152-161, 203). Доверенный Browser Worker этот заголовок
// не отправляет (apps/browser/trusted-worker.mjs:88-107) => на доверенном пути стенд принимает
// повторные POST одним Bearer-токеном. В рамках A2 Bearer недоступен противнику (память процессов),
// поэтому это дефект defense-in-depth, а не самостоятельный вектор ложного PASS.
// Запуск: node repro/r3-one-shot-inactive.mjs
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { serveLocalFixture } from '../adapters/local/server.mjs';

const out = { repro: 'R3', sha: '1a510a5d5929534d400dc965f58c78cf468bc270' };
const stands = [];
const post = async (stand, fixtureId, runIdHeader) => {
  const headers = {
    'content-type': 'application/json',
    connection: 'close',
    authorization: 'Bearer ' + stand.authToken,
    'idempotency-key': 'key-' + fixtureId
  };
  if (runIdHeader) headers['x-qa-run-id'] = runIdHeader;
  const response = await fetch(new URL('/records', stand.baseUrl), {
    method: 'POST', headers,
    body: JSON.stringify({ fixtureId, title: 't', executorId: 'e', comment: 'c' })
  });
  return { status: response.status, body: await response.json() };
};
try {
  // Без x-qa-run-id: два POST одним токеном принимаются (две разные записи).
  const unbound = await serveLocalFixture({}); stands.push(unbound);
  const first = await post(unbound, 'fixture-unbound-1', null);
  const second = await post(unbound, 'fixture-unbound-2', null);
  out.withoutRunId = { first: first.status, second: second.status, mutationCount: unbound.mutationCount };

  // С x-qa-run-id: второй POST тем же токеном отвергается (token_revoked).
  const bound = await serveLocalFixture({}); stands.push(bound);
  const bFirst = await post(bound, 'fixture-bound-1', 'run-bound');
  const bSecond = await post(bound, 'fixture-bound-2', 'run-bound');
  out.withRunId = { first: bFirst.status, second: bSecond.status, secondError: bSecond.body?.error ?? null, mutationCount: bound.mutationCount };

  // Исходник доверенного Browser Worker: заголовок x-qa-run-id в postMutation отсутствует.
  const source = fs.readFileSync(fileURLToPath(new URL('../apps/browser/trusted-worker.mjs', import.meta.url)), 'utf8');
  const postMutation = source.slice(source.indexOf('async function postMutation'), source.indexOf('async function execute'));
  out.workerSendsRunIdHeader = /x-qa-run-id/.test(postMutation);
  out.workerHeaders = [...postMutation.matchAll(/^\s{4}'?([a-z-]+)'?:/gm)].map(m => m[1]);

  out.oneShotInactiveOnTrustedPath = out.withoutRunId.mutationCount === 2 && out.withRunId.second === 403 && out.workerSendsRunIdHeader === false;
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = out.oneShotInactiveOnTrustedPath ? 0 : 1;
} catch (error) {
  out.error = { code: error.code || null, message: String(error.message || error) };
  console.log(JSON.stringify(out, null, 2));
  process.exitCode = 2;
} finally {
  for (const stand of stands) await stand.close().catch(() => {});
}