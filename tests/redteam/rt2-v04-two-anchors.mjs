// V-04: новый anchorId не может получить подпись при уже существующем receipt для runId.
// Точный ANCHOR_CONFLICT для разных подписанных statements покрывается tests/trust-anchor.test.mjs.
import fs from 'node:fs';
import path from 'node:path';
import { caseMain, makeWorld, check, runDirOf, sleep } from './_w2.mjs';

await caseMain({ id: 'V-04', title: 'Повторный finalize отклонён по receipt binding', async body({ modules, cleanup, checks }) {
  const world = await makeWorld(modules);
  cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'rt2-v04' });
  const approval = world.approvalFor({ bundle, contract });
  const anchorsDir = path.join(world.trustRoot, 'anchors');
  const initial = new Set(fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')) : []);
  const runPromise = modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { fault: 'pauseAfterAnchorBeforeTerminalChoiceForCancelTest' }));

  let newAnchor = null;
  const deadline = Date.now() + 45000;
  while (!newAnchor && Date.now() < deadline) {
    const current = fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')) : [];
    newAnchor = current.find(name => !initial.has(name)) || null;
    if (!newAnchor) await sleep(10);
  }
  const runDir = runDirOf(modules, world, bundle.manifest.runId);
  const anchorPath = newAnchor ? path.join(anchorsDir, newAnchor) : null;
  const firstAnchorBytes = anchorPath && fs.existsSync(anchorPath) ? fs.readFileSync(anchorPath) : null;
  const candidate = modules.anchor.readCandidate(runDir);
  check(checks, 'доверенный прогон остановлен после durable anchor до terminal-choice', Boolean(newAnchor && firstAnchorBytes && !fs.existsSync(path.join(runDir, 'trust', 'terminal-choice.json'))), { newAnchor, candidateVerdict: candidate?.candidate?.verdict || null });
  check(checks, 'durable candidate PASS существует', candidate?.candidate?.verdict === 'PASS', { verdict: candidate?.candidate?.verdict || null });
  const verificationRecord = JSON.parse(fs.readFileSync(path.join(world.trustRoot, 'verification', bundle.manifest.runId + '.json'), 'utf8'));
  const leaseFile = path.join(world.root, 'leases', modules.digest({ environmentId: bundle.manifest.environment.id, fixtureId: contract.fixtureId }) + '.json');
  const durableLease = JSON.parse(fs.readFileSync(leaseFile, 'utf8'));
  const lease = { runId: durableLease.runId, pid: durableLease.pid, token: durableLease.token };

  const signer = await modules.anchorSigner.connectAnchorSigner(world.signer.pipePath);
  try {
    await signer.sign({ runDir, approvalId: approval.approvalId, anchorId: 'anchor-second-attempt', attestation: verificationRecord.attestation, lease });
    check(checks, 'новый anchorId отклонён именно из-за несовпадения durable receipt', false, { actual: 'подпись выдана' });
  } catch (error) {
    check(checks, 'новый anchorId отклонён именно из-за несовпадения durable receipt', error.code === 'ANCHOR_BINDING_REJECTED' && String(error.message).includes('Подписанный receipt не совпадает'), { code: error.code || null, message: error.message });
  } finally {
    if (typeof signer.close === 'function') signer.close();
  }
  const anchorsAfter = fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')) : [];
  check(checks, 'в trust root остался один анкер', anchorsAfter.length === 1, { anchors: anchorsAfter });
  check(checks, 'первый анкер не изменён', Boolean(firstAnchorBytes && fs.readFileSync(anchorPath).equals(firstAnchorBytes)));
  const result = await runPromise;
  check(checks, 'исходный trusted run завершил тот же PASS после паузы', result.verdict.verdict === 'PASS', { verdict: result.verdict.verdict });
  return { checks };
} });
