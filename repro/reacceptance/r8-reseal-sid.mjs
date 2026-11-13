// WP08 ре-приёмка QWEN-F1 — R8. Несанкционированное перезакрепление: resealTrustRootPin().
// Проверка: отделено ли «владение owner.key» от возможностей исходной A2, включая
// исполнение кода тем же SID.
// Часть A (в пределах A2, только запись файлов + свой процесс): подмена публичных файлов,
//   затем штатная процедура перезакрепления с СЕКРЕТАМИ АТАКУЮЩЕГО. Процедура читает
//   owner.pub из (подменённого) корня и сравнивает с ключом из переданного secretsDir —
//   обе стороны сравнения подконтрольны атакующему. Извлечение ключей жертвы не требуется.
// Часть B (зонд возможности, ВНЕ исходной A2): процесс того же SID раскрывает DPAPI-обёртку
//   owner.key жертвы. Исходная A2 явно исключает «извлекает ключи через DPAPI», поэтому
//   это не новое нарушение A2, а демонстрация того, что «владение owner.key» опирается ровно
//   на то же допущение DPAPI, без отдельной границы. Материал ключа не выводится никогда.
// Запуск: node repro/reacceptance/r8-reseal-sid.mjs
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fs, path, world, victimWorld, attackerWorld, substitute, runTrusted, report, err, loadTrustRoot } from '../neg/_world.mjs';
import { resealTrustRootPin, unwrapPrivateKey, publicKeyId } from '../../packages/trust/identity.mjs';
import { createPublicKey } from 'node:crypto';

const self = fileURLToPath(import.meta.url);

// Дочерний процесс того же SID: зонд возможности DPAPI-раскрытия (вне исходной A2).
// Выводится только keyId и факт успеха; материал приватного ключа не покидает процесс.
if (process.env.QA_R8_CHILD === '1') {
  const out = { childPid: process.pid };
  try {
    const key = await unwrapPrivateKey(path.join(process.env.QA_R8_SECRETS, 'owner.key'));
    out.unwrapped = true;
    out.keyId = publicKeyId(createPublicKey(key));
    try {
      const reseal = await resealTrustRootPin({ trustRoot: process.env.QA_R8_TRUSTROOT, secretsDir: process.env.QA_R8_SECRETS });
      out.reseal = { accepted: true, ownerKeyId: reseal.ownerKeyId, anchorKeyId: reseal.anchorKeyId };
    } catch (error) { out.reseal = { accepted: false, error: err(error) }; }
  } catch (error) { out.unwrapped = false; out.error = err(error); }
  console.log(JSON.stringify(out));
  process.exit(0);
}

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const rogue = await w.stand();

  // Часть B (зонд, вне исходной A2): неповреждённый корень, секреты жертвы, свой процесс того же SID.
  const child = spawnSync(process.execPath, [self], {
    env: { ...process.env, QA_R8_CHILD: '1', QA_R8_SECRETS: v.secretsDir, QA_R8_TRUSTROOT: v.trustRoot },
    encoding: 'utf8', timeout: 120000
  });
  let probe = null;
  try { probe = JSON.parse(child.stdout); } catch { probe = { parseError: String(child.stderr || child.stdout || '').slice(-2000) }; }

  // Часть A (в пределах A2): подмена публичных файлов + штатное перезакрепление с секретами атакующего.
  substitute(v, a);
  let resealAttacker = null;
  try {
    const reseal = await resealTrustRootPin({ trustRoot: v.trustRoot, secretsDir: a.secretsDir });
    resealAttacker = { accepted: true, ownerKeyId: reseal.ownerKeyId, anchorKeyId: reseal.anchorKeyId };
  } catch (error) { resealAttacker = { accepted: false, error: err(error) }; }
  let loadAfter = null;
  try {
    const trust = loadTrustRoot(v.trustRoot);
    loadAfter = { accepted: true, ownerKeyId: trust.owner.keyId, matchesAttacker: trust.owner.keyId === a.created.ownerKeyId };
  } catch (error) { loadAfter = { accepted: false, error: err(error) }; }

  // Полный доверенный прогон под корнем жертвы после «санкционированной» процедуры перезакрепления.
  const run = await runTrusted({
    root: v.root, trustRoot: v.trustRoot,
    signTrust: a.trust, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId,
    issuer: a.owner, subject: a.operator, issuerId: 'attacker-owner', subjectId: 'attacker-operator',
    stand: rogue, anchorKeyPath: a.anchorKeyPath, registerRecord: true, recordTrust: a.trust
  });

  report('R8', 'Перезакрепление: владение owner.key против возможностей того же SID', {
    boundaryReached: resealAttacker.accepted ? 'RESEAL_ACCEPTED_ATTACKER_SECRETS' : 'RESEAL_REJECTED',
    verdict: run.result?.verdict ?? null, reasonCode: run.result?.reasonCode ?? null,
    observer: run.observer, observerError: run.observerError,
    mutations: { rogue: rogue.mutationCount, victim: v.stand.mutationCount },
    details: {
      resealWithAttackerSecretsAfterSubstitution: resealAttacker,
      loadAfterSubstitution: loadAfter,
      run,
      sameSidDpapiProbe: probe,
      probeClassification: 'ВНЕ исходной A2: раскрытие DPAPI-обёртки ключа жертвы явно исключено моделью («не извлекает ключи через DPAPI»). Зонд показывает, что защита reseal опирается на то же допущение, а не на отдельную границу.',
      victimPrivateKeysTouchedByAttack: false
    },
    notes: 'Часть A — чистая A2: запись файлов + свой процесс. resealTrustRootPin сравнивает ключ из secretsDir с owner.pub ИЗ ТОГО ЖЕ подменённого корня; обе стороны подконтрольны атакующему, поэтому «санкционированная ротация» принимает чужие ключи без извлечения ключей жертвы. Часть B — зонд вне A2 (DPAPI-раскрытие тем же SID).'
  });
} catch (error) {
  report('R8', 'Перезакрепление: владение owner.key против возможностей того же SID', { infraError: err(error) });
} finally {
  await w.cleanup();
}