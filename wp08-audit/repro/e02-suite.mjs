// E-02: независимые негативные проверки аудитора (не входят в набор Luna).
// Обвязка мира берётся из _w2.mjs (стенд/trust root), сами атаки — собственные:
// прямые мутации durable-состояния, Trust Root, sidecar, evidence и IPC подписанта.
import fs from 'node:fs';
import path from 'node:path';

const REM = 'C:/Users/gvi/Desktop/QA-ADAPTANT-harness/remediation';
const H = await import('file:///' + REM + '/tests/redteam/_w2.mjs');

const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const safeObserve = async (modules, world, runId) => {
  try { return await modules.trusted.observeTrusted({ root: world.root, trustRoot: world.trustRoot, runId }); }
  catch (error) { return { passed: false, emission: 'throw', code: error.code || String(error.message || error) }; }
};

// E02-01: повреждение анкера после доверенного PASS.
await H.caseMain({ id: 'E02-01', title: 'Повреждённый анкер не даёт PASS', async body({ modules, cleanup, checks }) {
  const world = await H.makeWorld(modules); cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'e02-01' });
  const approval = world.approvalFor({ bundle, contract });
  const run = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  H.check(checks, 'эталонный PASS получен', run.verdict.verdict === 'PASS', { verdict: run.verdict.verdict });
  const anchorsDir = path.join(world.trustRoot, 'anchors');
  const anchorFile = path.join(anchorsDir, fs.readdirSync(anchorsDir).sort().at(-1));
  const original = fs.readFileSync(anchorFile);
  fs.writeFileSync(anchorFile, Buffer.from('{"tampered":true}'));
  const obs = await safeObserve(modules, world, bundle.manifest.runId);
  H.check(checks, 'повреждённый анкер не даёт доверенный PASS', obs.passed !== true, { passed: obs.passed, code: obs.code || obs.reasonCode || null });
  fs.writeFileSync(anchorFile, original);
  const restored = await safeObserve(modules, world, bundle.manifest.runId);
  H.check(checks, 'восстановление анкера возвращает PASS (контроль)', restored.passed === true, { passed: restored.passed });
}});

// E02-02: два одновременных trusted-запуска одного bundle/approval.
await H.caseMain({ id: 'E02-02', title: 'Конкурентные trusted-run не дают второй POST/PASS', async body({ modules, cleanup, checks }) {
  const world = await H.makeWorld(modules); cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'e02-02' });
  const approval = world.approvalFor({ bundle, contract });
  const settle = async fn => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, code: error.code || String(error.message || error) }; } };
  const results = await Promise.allSettled([
    modules.trusted.startTrusted(bundle, world.trustedOptions(approval)),
    modules.trusted.startTrusted(bundle, world.trustedOptions(approval))
  ]);
  const fulfilled = results.filter(item => item.status === 'fulfilled');
  const passes = fulfilled.filter(item => item.value?.verdict?.verdict === 'PASS').length;
  H.check(checks, 'не более одного доверенного PASS', passes <= 1, { passes });
  H.check(checks, 'не более одного POST', world.stand.mutationCount <= 1, { mutationCount: world.stand.mutationCount });
  const rejected = results.filter(item => item.status === 'rejected');
  H.check(checks, 'второй запуск завершился отказом, а не тихим успехом', rejected.length + (fulfilled.length - passes) >= 1, { rejected: rejected.map(item => String(item.reason?.code || item.reason?.message || item.reason)).slice(0, 2) });
  const obs = await safeObserve(modules, world, bundle.manifest.runId);
  H.check(checks, 'наблюдение не показывает PASS при неполном конкурентном состоянии', obs.passed !== true || passes === 1, { passed: obs.passed });
}});

// E02-03: повреждение verification-записи после PASS + recovery.
await H.caseMain({ id: 'E02-03', title: 'Recovery не подтверждает PASS по повреждённой verification-записи', async body({ modules, cleanup, checks }) {
  const world = await H.makeWorld(modules); cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'e02-03' });
  const approval = world.approvalFor({ bundle, contract });
  const run = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  H.check(checks, 'эталонный PASS получен', run.verdict.verdict === 'PASS', { verdict: run.verdict.verdict });
  const recordFile = path.join(world.trustRoot, 'verification', bundle.manifest.runId + '.json');
  const record = readJson(recordFile);
  record.attestation.readSetSha256 = '0'.repeat(64);
  fs.writeFileSync(recordFile, JSON.stringify(record));
  let error = null;
  try { await modules.trusted.reconcileTrusted({ ...world.trustedOptions(approval), runId: bundle.manifest.runId }); }
  catch (caught) { error = caught; }
  H.check(checks, 'reconcile отказал по повреждённой записи', Boolean(error), { code: error?.code || null, message: String(error?.message || '').slice(0, 160) });
  const obs = await safeObserve(modules, world, bundle.manifest.runId);
  H.check(checks, 'наблюдение не выдаёт PASS по повреждённому происхождению', obs.passed !== true, { passed: obs.passed });
  H.check(checks, 'повторного POST не было', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
}});

// E02-04: повреждение trusted-run sidecar.
await H.caseMain({ id: 'E02-04', title: 'Повреждённый sidecar закрывает доверенный вход', async body({ modules, cleanup, checks }) {
  const world = await H.makeWorld(modules); cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'e02-04' });
  const approval = world.approvalFor({ bundle, contract });
  const run = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  H.check(checks, 'эталонный PASS получен', run.verdict.verdict === 'PASS', { verdict: run.verdict.verdict });
  const runDir = new modules.store.RunStore(world.root).runPath(bundle.manifest.runId);
  const sidecar = path.join(runDir, 'trust', 'trusted-run.json');
  fs.writeFileSync(sidecar, '{broken');
  let genericError = null;
  try { await modules.run.observe({ root: world.root, runId: bundle.manifest.runId }); }
  catch (caught) { genericError = caught; }
  H.check(checks, 'generic API отвергает повреждённый sidecar', Boolean(genericError), { code: genericError?.code || null, message: String(genericError?.message || '').slice(0, 140) });
  const trusted = await safeObserve(modules, world, bundle.manifest.runId);
  H.check(checks, 'fail-closed: sidecar не даёт generic-пути обойти доверенный вход', genericError?.code === 'INTEGRITY_ERROR' || genericError?.code === 'TRUSTED_RUN_REQUIRES_TRUSTED_ENTRY', { code: genericError?.code || null, trustedPassed: trusted.passed });
}});

// E02-05: нарушение порядка durable-записей (усечение хвоста журнала).
await H.caseMain({ id: 'E02-05', title: 'Усечённый evidence-хвост не подтверждает PASS', async body({ modules, cleanup, checks }) {
  const world = await H.makeWorld(modules); cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'e02-05' });
  const approval = world.approvalFor({ bundle, contract });
  const run = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  H.check(checks, 'эталонный PASS получен', run.verdict.verdict === 'PASS', { verdict: run.verdict.verdict });
  const runDir = new modules.store.RunStore(world.root).runPath(bundle.manifest.runId);
  const evidenceFile = path.join(runDir, 'evidence.jsonl');
  const lines = fs.readFileSync(evidenceFile, 'utf8').split('\n').filter(Boolean);
  fs.writeFileSync(evidenceFile, lines.slice(0, -1).join('\n') + '\n');
  const obs = await safeObserve(modules, world, bundle.manifest.runId);
  H.check(checks, 'усечённый evidence-хвост не даёт PASS', obs.passed !== true, { passed: obs.passed, code: obs.code || obs.reasonCode || null });
  const commitDir = path.join(runDir, 'evidence-commits');
  const commits = fs.existsSync(commitDir) ? fs.readdirSync(commitDir).sort() : [];
  H.check(checks, 'evidence-commits существуют', commits.length > 0, { commits: commits.length });
}});

// E02-06: частично повреждённый Trust Root — удалённая verification-запись при recovery.
await H.caseMain({ id: 'E02-06', title: 'Частично повреждённый Trust Root не восстанавливает PASS', async body({ modules, cleanup, checks }) {
  const world = await H.makeWorld(modules); cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'e02-06' });
  const approval = world.approvalFor({ bundle, contract });
  const run = await modules.trusted.startTrusted(bundle, world.trustedOptions(approval));
  H.check(checks, 'эталонный PASS получен', run.verdict.verdict === 'PASS', { verdict: run.verdict.verdict });
  const recordFile = path.join(world.trustRoot, 'verification', bundle.manifest.runId + '.json');
  fs.rmSync(recordFile, { force: true });
  let error = null;
  try { await modules.trusted.reconcileTrusted({ ...world.trustedOptions(approval), runId: bundle.manifest.runId }); }
  catch (caught) { error = caught; }
  H.check(checks, 'reconcile без verification-записи отказал', Boolean(error), { code: error?.code || null, message: String(error?.message || '').slice(0, 160) });
  H.check(checks, 'повторного POST не было', world.stand.mutationCount === 1, { mutationCount: world.stand.mutationCount });
}});

// E02-07: повтор старого IPC-запроса к подписанту (тот же anchorId, другая аттестация).
await H.caseMain({ id: 'E02-07', title: 'Повтор IPC-подписи для использованного anchorId отклонён', async body({ modules, cleanup, checks }) {
  const world = await H.makeWorld(modules); cleanup(world.cleanup);
  const { bundle, contract } = world.prepare({ runId: 'e02-07' });
  const approval = world.approvalFor({ bundle, contract });
  const runDir = new modules.store.RunStore(world.root).runPath(bundle.manifest.runId);
  const anchorsDir = path.join(world.trustRoot, 'anchors');
  const before = new Set(fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir) : []);
  const pending = modules.trusted.startTrusted(bundle, world.trustedOptions(approval, { fault: 'pauseAfterAnchorBeforeTerminalChoiceForCancelTest' }));
  let anchorName = null;
  const deadline = Date.now() + 40000;
  while (!anchorName && Date.now() < deadline) {
    const fresh = (fs.existsSync(anchorsDir) ? fs.readdirSync(anchorsDir) : []).filter(name => !before.has(name));
    if (fresh.length) anchorName = fresh[0]; else await H.sleep(20);
  }
  H.check(checks, 'доверенный анкер записан до terminal-choice', Boolean(anchorName), { anchorName });
  const anchorDoc = readJson(path.join(anchorsDir, anchorName));
  const anchorId = anchorDoc.anchorId || anchorDoc.statement?.anchorId;
  const record = readJson(path.join(world.trustRoot, 'verification', bundle.manifest.runId + '.json'));
  const leaseDir = path.join(world.root, 'leases');
  let lease = null;
  for (let i = 0; i < 200 && !lease; i++) {
    const names = fs.existsSync(leaseDir) ? fs.readdirSync(leaseDir).filter(name => name.endsWith('.json')) : [];
    if (names.length) lease = readJson(path.join(leaseDir, names.sort().at(-1))); else await H.sleep(20);
  }
  H.check(checks, 'lease доступен для попытки повтора IPC', Boolean(lease), { lease: Boolean(lease) });
  const signer = await modules.anchorSigner.connectAnchorSigner(world.signer.pipePath);
  let error = null;
  try {
    await signer.sign({ runDir, approvalId: approval.approvalId, anchorId, attestation: record.attestation,
      lease: { runId: bundle.manifest.runId, pid: lease.pid, token: lease.token } });
  } catch (caught) { error = caught; }
  const after = fs.readdirSync(anchorsDir).filter(name => !before.has(name) && name !== anchorName);
  H.check(checks, 'повтор IPC не создал второй анкер', after.length === 0, { newAnchors: after });
  H.check(checks, 'повтор отклонён или идемпотентен', Boolean(error) || after.length === 0, { code: error?.code || null, message: String(error?.message || '').slice(0, 160) });
  await signer.close();
  let run = null;
  let runError = null;
  try { run = await pending; } catch (caught) { runError = caught; }
  H.check(checks, 'исходный прогон завершился PASS ровно один раз', run?.verdict?.verdict === 'PASS', { verdict: run?.verdict?.verdict || null, code: runError?.code || null });
  const verdicts = modules.store ? new modules.store.RunStore(world.root).readEvidence(runDir).filter(item => item.envelope.kind === 'verdict') : [];
  H.check(checks, 'опубликован ровно один verdict', verdicts.length === 1, { count: verdicts.length });
}});
