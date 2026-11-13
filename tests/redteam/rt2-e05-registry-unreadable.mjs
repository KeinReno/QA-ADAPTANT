// E-05: реестр сред не читается. Ожидание: fail-closed без POST (по матрице — INDETERMINATE AUTH_UNAVAILABLE).
// Проверяются два фактических варианта: битая запись среды и нечитаемый trust root.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, checkTrustedDenial, checkNoMutation, checkNoEvidence, expectCode } from './_w2.mjs';

await caseMain({ id: 'E-05', title: 'Реестр сред не читается (fail-closed)', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-e05' });
  const approval = world.approvalFor({ bundle, contract });
  // Вариант 1: повреждённая запись среды в реестре.
  const registryDir = path.join(world.trustRoot, 'environments', world.stand.environmentId);
  const registryFile = fs.existsSync(registryDir) && fs.statSync(registryDir).isDirectory()
    ? path.join(registryDir, fs.readdirSync(registryDir).filter(name => /^\d+\.json$/.test(name)).sort((a, b) => Number(a.split('.')[0]) - Number(b.split('.')[0])).at(-1))
    : path.join(registryDir, world.stand.generation + '.json');
  check(checks, 'запись среды существует до атаки', fs.existsSync(registryFile), { registryFile });
  const original = fs.readFileSync(registryFile);
  fs.writeFileSync(registryFile, '{повреждено');
  const result = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  fs.writeFileSync(registryFile, original);
  checkTrustedDenial(checks, result, { verdict: 'BLOCKED' });
  checkNoMutation(checks, world);
  checkNoEvidence(checks, modules, world, bundle.manifest.runId, ['mutation-intent', 'request']);
  check(checks, 'фактический код отказа зафиксирован (fail-closed важнее точной проекции)', Boolean(result?.verdict?.reasonCode), { verdict: result?.verdict?.verdict || null, reasonCode: result?.verdict?.reasonCode || null });

  // Вариант 2: нечитаемый корень доверия — доверенный старт не начинается.
  const broken = fs.readFileSync(path.join(world.trustRoot, 'owner.pub'));
  fs.writeFileSync(path.join(world.trustRoot, 'owner.pub'), '{"domain":"broken"}');
  await expectCode(checks, 'битый owner.pub -> TRUST_STORE_UNAVAILABLE (старт не начат)', () => modules.trusted.startTrusted(bundle, world.trustedOptions(approval)), 'TRUST_STORE_UNAVAILABLE');
  fs.writeFileSync(path.join(world.trustRoot, 'owner.pub'), broken);
  checkNoMutation(checks, world);
  return { checks };
} });