// E-04: credentialRef среды обязан участвовать в выдаче секрета.
// Запись реестра указывает prod:foreign-secret-7, а вызывающий передаёт секрет,
// зарегистрированный под другим credentialRef (и сырой fixtureToken).
// Ожидание: DENY ENVIRONMENT_CHANGED до мутации, секрет не доставлен (0 POST), Browser не запускался.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence } from './_w2.mjs';

await caseMain({ id: 'E-04', title: 'credentialRef указывает секрет другой среды', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules, { recordOverrides: { credentialRef: 'prod:foreign-secret-7' } });
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-e04' });
  const approval = world.approvalFor({ bundle, contract });
  const foreignCredentials = { 'local:fixture-token': world.stand.authToken };
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { credentials: foreignCredentials }));
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED', reasonCodes: ['ENVIRONMENT_CHANGED'] });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, bundle.manifest.runId, ['mutation-intent', 'request']);
  const runDir = path.join(world.root, 'runs', bundle.manifest.runId);
  const events = fs.existsSync(path.join(runDir, 'events.jsonl')) ? fs.readFileSync(path.join(runDir, 'events.jsonl'), 'utf8') : '';
  check(checks, 'Browser не запускался (нет READY)', !events.includes('"READY"'), { hasReady: events.includes('"READY"') });
  check(checks, 'секрет не выдан: reasonCode среда/credentialRef', result.verdict.reasonCode === 'ENVIRONMENT_CHANGED', { reasonCode: result.verdict.reasonCode });
  check(checks, 'approval не израсходован', !fs.existsSync(path.join(world.trustRoot, 'consumption', approval.approvalId + '.json')));
  return { checks };
} });
