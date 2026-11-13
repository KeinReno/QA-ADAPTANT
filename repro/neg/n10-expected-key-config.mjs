// N10: подмена конфигурации ожидаемых ключей.
// (а) лишние аргументы API (expectedKeyId/trust/ownerKeyId/anchorKeyId) при неповреждённом корне;
// (б) переменные окружения с ожидаемыми keyId;
// (в) указатель trustRoot на корень атакующего (без перезаписи файлов жертвы) — конфигурационный вектор.
// Ожидание на исправленном продукте: (а)/(б) игнорируются или отвергаются; (в) закрыт внешним закреплением.
import { world, victimWorld, attackerWorld, runTrusted, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const rogueStand = await w.stand();
  const forgedArgs = {
    root: v.root, trustRoot: v.trustRoot, signTrust: a.trust, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
    issuerId: 'attacker-owner', subjectId: 'attacker-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
    registerRecord: true
  };
  const variantA = await runTrusted({ ...forgedArgs, extraOptions: { expectedKeyId: a.created.ownerKeyId, trust: a.trust, ownerKeyId: a.created.ownerKeyId, anchorKeyId: a.created.anchorKeyId } }).catch(error => ({ error: err(error) }));
  const savedEnv = {};
  const envNames = ['QA_ADAPTANT_EXPECTED_OWNER_KEY_ID', 'QA_ADAPTANT_OWNER_KEY_ID', 'QA_ADAPTANT_EXPECTED_ANCHOR_KEY_ID', 'QA_ADAPTANT_TRUST_ROOT'];
  for (const name of envNames) { savedEnv[name] = process.env[name]; process.env[name] = name === 'QA_ADAPTANT_TRUST_ROOT' ? a.trustRoot : a.created.ownerKeyId; }
  let variantB;
  try { variantB = await runTrusted(forgedArgs).catch(error => ({ error: err(error) })); }
  finally { for (const name of envNames) { if (savedEnv[name] === undefined) delete process.env[name]; else process.env[name] = savedEnv[name]; } }
  const variantC = await runTrusted({
    root: v.root, trustRoot: a.trustRoot, signTrust: a.trust, commitApprovalTo: a.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId, issuer: a.owner, subject: a.operator,
    issuerId: 'attacker-owner', subjectId: 'attacker-operator', stand: rogueStand, anchorKeyPath: a.anchorKeyPath,
    registerRecord: true
  }).catch(error => ({ error: err(error) }));
  const reached = [variantA, variantB, variantC].map(r => r.observer?.trusted === true && r.observer?.passed === true && r.observer?.verdict === 'PASS');
  report('N10', 'Подмена конфигурации ожидаемых ключей', {
    boundaryReached: reached[2] ? 'trustRoot-аргумент указал на корень атакующего (файлы жертвы не перезаписывались)' : 'все конфигурационные векторы отвергнуты',
    verdict: variantC.result?.verdict ?? null, reasonCode: variantC.result?.reasonCode ?? variantC.error?.code ?? null,
    observer: variantC.observer || null, observerError: variantC.observerError || variantC.error || null,
    mutations: { victim: v.stand.mutationCount, rogue: rogueStand.mutationCount },
    falseTrustedPass: reached.some(Boolean),
    details: {
      extraApiArgs: { result: variantA.result || variantA.error || null, observer: variantA.observer || variantA.observerError || null, reachedTrustedPass: reached[0] },
      envVars: { names: envNames, result: variantB.result || variantB.error || null, observer: variantB.observer || variantB.observerError || null, reachedTrustedPass: reached[1] },
      trustRootPointer: { result: variantC.result || variantC.error || null, observer: variantC.observer || variantC.observerError || null, reachedTrustedPass: reached[2] }
    },
    notes: 'Продукт читает только QA_ADAPTANT_FIXTURE_TOKEN и QA_ADAPTANT_DEBUG; ожидаемые keyId из аргументов/env не принимаются. Вектор (в) — указатель на чужой корень в конфигурации/аргументах: закрепление обязано проверять идентичность корня, а не только файлы.'
  });
} catch (error) {
  report('N10', 'Подмена конфигурации ожидаемых ключей', { infraError: err(error) });
} finally { await w.cleanup(); }