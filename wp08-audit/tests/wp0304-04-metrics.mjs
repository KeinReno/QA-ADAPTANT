// Метрики для отчёта WP-08: длительность проверки владельца порта и параметры E-04.
import { loadModules, makeWorld, startControlledStand } from './wp0304-lib.mjs';

const modules = await loadModules();
const env = modules.environment;
const out = {};

const stand = await startControlledStand(modules, {});
const world = await makeWorld(modules, { standalone: stand, recordOverrides: { credentialRef: 'prod:foreign-secret-7' } });
try {
  const durations = [];
  for (let i = 0; i < 5; i++) {
    const started = process.hrtime.bigint();
    const pid = await env.portOwnerPid(stand.baseUrl);
    durations.push(Number(process.hrtime.bigint() - started) / 1e6);
    if (pid !== process.pid) throw new Error('portOwnerPid вернул не тот PID: ' + pid);
  }
  out.portOwnerCheckMs = { samples: durations.map(value => Math.round(value * 100) / 100), average: Math.round((durations.reduce((a, b) => a + b, 0) / durations.length) * 100) / 100 };

  const other = await makeWorld(modules);
  try {
    const { bundle, contract } = world.prepare({ runId: 'wp08-e04-metrics' });
    const approval = world.approvalFor({ bundle, contract });
    const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { fixtureToken: other.stand.authToken }));
    out.e04 = {
      verdict: result.verdict.verdict,
      reasonCode: result.verdict.reasonCode,
      message: String(result.verdict.message).slice(0, 180),
      standPostCount: stand.state.postCount,
      foreignSecretDeliveredToStand: stand.state.posts.length > 0 && stand.state.posts[0].headers.authorization === 'Bearer ' + other.stand.authToken,
      recordCredentialRef: world.record.credentialRef,
      standRejectedToken: stand.state.posts.length > 0 && stand.state.posts[0].authorized === false
    };
  } finally { await other.cleanup(); }

  out.atestCount = stand.attestCount;
} finally { await world.cleanup(); }

process.stdout.write(JSON.stringify(out, null, 2) + '\n');
