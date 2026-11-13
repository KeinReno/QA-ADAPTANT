// Атака WP-06: выдача секрета до ALLOW (T-A).
// Ожидание: при отказе preflight Chromium не запускается, Bearer стенда и ключи не попадают в runDir;
// в успешном доверенном прогоне Bearer тоже не пишется в артефакты.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, findText, expectCode } from './_w2.mjs';

await caseMain({ id: 'WP06-SECRET', title: 'Секрет не выдан до ALLOW', async body({ modules, cleanup, checks }) {
  // Отказ до T-A: отозванный approval.
  const deniedWorld = await makeWorld(modules);
  cleanup(deniedWorld.cleanup);
  const denied = deniedWorld.prepare({ runId: 'rt2-secret-denied' });
  const deniedApproval = deniedWorld.approvalFor({ bundle: denied.bundle, contract: denied.contract });
  modules.approval.revokeApproval(deniedWorld.ownerKey, deniedWorld.trustRoot, { approvalId: deniedApproval.approvalId, reason: 'owner-revoked', revokedAt: new Date().toISOString(), keyId: deniedWorld.created.ownerKeyId });
  const result = await modules.trusted.startTrusted(denied.bundle, deniedWorld.trustedOptions(deniedApproval));
  check(checks, 'preflight отказал (BLOCKED)', result.verdict.verdict === 'BLOCKED', { verdict: result.verdict.verdict, reasonCode: result.verdict.reasonCode });
  check(checks, 'POST не было', deniedWorld.stand.mutationCount === 0);
  const runDir = new modules.store.RunStore(deniedWorld.root).runPath(denied.bundle.manifest.runId);
  const eventsFile = path.join(runDir, 'events.jsonl');
  const events = fs.existsSync(eventsFile) ? fs.readFileSync(eventsFile, 'utf8') : '';
  check(checks, 'Browser не дошёл до READY/INTENT', !events.includes('"READY"') && !events.includes('INTENT_DURABLE'));
  check(checks, 'файл browser.pid не оставлен', !fs.existsSync(path.join(runDir, 'browser.pid')));
  check(checks, 'Bearer стенда не записан в runDir', findText(runDir, deniedWorld.stand.authToken).length === 0, { files: findText(runDir, deniedWorld.stand.authToken) });
  check(checks, 'приватные ключи не записаны в runDir', findText(runDir, 'protectedPkcs8').length === 0);

  // Успешный прогон: секрет тоже не должен оказаться в артефактах.
  const okWorld = await makeWorld(modules);
  cleanup(okWorld.cleanup);
  const okRun = okWorld.prepare({ runId: 'rt2-secret-ok' });
  const okApproval = okWorld.approvalFor({ bundle: okRun.bundle, contract: okRun.contract });
  const ok = await modules.trusted.startTrusted(okRun.bundle, okWorld.trustedOptions(okApproval));
  check(checks, 'успешный прогон PASS', ok.verdict.verdict === 'PASS');
  const okRunDir = new modules.store.RunStore(okWorld.root).runPath(okRun.bundle.manifest.runId);
  check(checks, 'Bearer стенда не записан в артефакты PASS-прогона', findText(okRunDir, okWorld.stand.authToken).length === 0, { files: findText(okRunDir, okWorld.stand.authToken) });
  check(checks, 'owner.key/anchor.key не попали в runDir', findText(okRunDir, 'protectedPkcs8').length === 0);
  return { checks };
} });
