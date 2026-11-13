// WP08 ре-приёмка QWEN-F1 — R5. DPAPI CurrentUser под тем же SID: изготовление валидного
// trust-pin для подменённого корня БЕЗ извлечения приватных ключей жертвы.
// Исходная A2 (docs/harness/WP08-REMEDIATION-ARCHITECTURE.md:36): противник пишет файлы в
// runDir и trust root (кроме приватных ключей), поднимает свои процессы того же Windows SID,
// публичные локальные каналы, HTTP. Исключены: отладка/инъекция в доверенные процессы и
// ИЗВЛЕЧЕНИЕ ключей через DPAPI. Создание НОВОГО DPAPI-конверта для собственных данных
// извлечением ключей не является и остаётся внутри исходной A2.
// Запуск: node repro/reacceptance/r5-dpapi-sid-pin-forge.mjs
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { fs, path, world, victimWorld, attackerWorld, substitute, runTrusted, report, err, loadTrustRoot, currentUserSid } from '../neg/_world.mjs';
import { canonical } from '../../packages/core/canonical.mjs';
import { protectSync } from '../../packages/trust/dpapi.mjs';

const self = fileURLToPath(import.meta.url);

// Дочерний процесс того же SID (A2: «поднимать свои процессы того же Windows SID»).
// Использует только публичные данные: путь корня жертвы и keyId СВОИХ ключей.
// Приватные ключи жертвы не читаются и не извлекаются.
if (process.env.QA_R5_CHILD === '1') {
  const trustRoot = process.env.QA_R5_TRUSTROOT;
  const physical = fs.realpathSync(trustRoot);
  const body = {
    schemaVersion: '0.2.1',
    domain: 'trust-root-pin',
    trustRootPathHash: createHash('sha256').update(process.platform === 'win32' ? physical.toLowerCase() : physical).digest('hex'),
    ownerKeyId: process.env.QA_R5_OWNER_KEYID,
    anchorKeyId: process.env.QA_R5_ANCHOR_KEYID
  };
  const sealed = protectSync(Buffer.from(canonical(body), 'utf8'));
  fs.writeFileSync(process.env.QA_R5_OUT, `${JSON.stringify({ ...body, sealing: 'dpapi-current-user', sealed: sealed.toString('base64') })}\n`);
  console.log(JSON.stringify({ childPid: process.pid, sid: currentUserSid(), forgedPinWritten: true }));
  process.exit(0);
}

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const rogue = await w.stand();
  const parentSid = currentUserSid();

  // 1. A2-действие: свой процесс того же SID изготавливает DPAPI-конверт закрепления
  //    для пути корня жертвы с keyId атакующего. Ключи жертвы не извлекаются.
  const pinDir = w.tmp('qa-r5-pin-');
  const pinFile = path.join(pinDir, 'trust-pin.json');
  const child = spawnSync(process.execPath, [self], {
    env: { ...process.env, QA_R5_CHILD: '1', QA_R5_TRUSTROOT: v.trustRoot, QA_R5_OWNER_KEYID: a.created.ownerKeyId, QA_R5_ANCHOR_KEYID: a.created.anchorKeyId, QA_R5_OUT: pinFile },
    encoding: 'utf8', timeout: 120000
  });
  if (child.status !== 0) {
    report('R5', 'DPAPI Same-SID: изготовление закрепления для подменённого корня', { infraError: { code: 'CHILD_FAILED', message: String(child.stderr || child.stdout || '').slice(-2000), exitCode: child.status } });
  } else {
    const childInfo = JSON.parse(child.stdout);
    // 2. A2-действие: подмена трёх публичных файлов + изготовленного закрепления.
    substitute(v, a);
    fs.copyFileSync(pinFile, path.join(v.trustRoot, 'trust-pin.json'));
    let taken = null;
    let loadError = null;
    try { taken = loadTrustRoot(v.trustRoot); } catch (error) { loadError = err(error); }
    const details = {
      parentSid, child: childInfo, sameSid: childInfo.sid === parentSid,
      victimPrivateKeysTouched: false,
      forgedPinAccepted: Boolean(taken && taken.owner.keyId === a.created.ownerKeyId),
      substitutedRoot: taken ? { ownerKeyId: taken.owner.keyId, anchorKeyId: taken['anchor-signer'].keyId } : null,
      loadError
    };
    // 3. Полный доверенный прогон под корнем жертвы ключами атакующего.
    const run = await runTrusted({
      root: v.root, trustRoot: v.trustRoot,
      signTrust: a.trust, commitApprovalTo: v.trustRoot,
      ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId,
      issuer: a.owner, subject: a.operator, issuerId: 'attacker-owner', subjectId: 'attacker-operator',
      stand: rogue, anchorKeyPath: a.anchorKeyPath, registerRecord: true, recordTrust: a.trust
    });
    details.run = run;
    report('R5', 'DPAPI Same-SID: изготовление закрепления для подменённого корня', {
      boundaryReached: details.forgedPinAccepted ? 'FORGED_PIN_ACCEPTED' : 'PIN_REJECTED',
      verdict: run.result?.verdict ?? null, reasonCode: run.result?.reasonCode ?? null,
      observer: run.observer, observerError: run.observerError,
      mutations: { rogue: rogue.mutationCount, victim: v.stand.mutationCount },
      details,
      notes: 'Создание нового DPAPI-конверта своим процессом того же SID — внутри исходной A2 (извлечение ключей жертвы не выполняется). Если falseTrustedPass=true, закрепление не является границей против исходной A2.'
    });
  }
} catch (error) {
  report('R5', 'DPAPI Same-SID: изготовление закрепления для подменённого корня', { infraError: err(error) });
} finally {
  await w.cleanup();
}