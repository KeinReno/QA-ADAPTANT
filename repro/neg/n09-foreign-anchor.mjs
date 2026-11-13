// N09: поддельный Anchor от чужого signer при НЕПОВРЕЖДЁННОМ корне жертвы.
// Легитимный PASS → заявление анкера переподписывается ключом атакующего (keyId заменён) → observer.
// Ожидание (и на базовом SHA): fail-closed — ANCHOR_SIGNATURE_INVALID / trusted:false.
import { world, victimWorld, attackerWorld, runTrusted, observe, signTrustedDocument, fs, path, report, err } from './_world.mjs';

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const legit = await runTrusted({
    root: v.root, trustRoot: v.trustRoot, signTrust: v.trust, commitApprovalTo: v.trustRoot,
    ownerKey: v.ownerKey, ownerKeyId: v.created.ownerKeyId, issuer: v.owner, subject: v.operator,
    issuerId: 'victim-owner', subjectId: 'victim-operator', stand: v.stand, anchorKeyPath: v.anchorKeyPath
  });
  const anchorId = legit.observer?.anchorId;
  if (!anchorId) throw Object.assign(new Error('Легитимный прогон не дал анкера: ' + JSON.stringify(legit.error || legit.observerError || legit.result)), { code: 'INFRA' });
  const anchorsDir = path.join(v.trustRoot, 'anchors');
  const anchorFile = path.join(anchorsDir, anchorId + '.json');
  const countBefore = fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')).length;
  const original = JSON.parse(fs.readFileSync(anchorFile, 'utf8'));
  const body = { ...original };
  delete body.signature;
  delete body.signatureAlgorithm;
  body.keyId = a.created.anchorKeyId;
  const forgedStatement = signTrustedDocument(a.anchorKey, body);
  fs.writeFileSync(anchorFile, JSON.stringify(forgedStatement) + '\n');
  const observed = await observe({ root: v.root, trustRoot: v.trustRoot, runId: legit.runId });
  const countAfter = fs.readdirSync(anchorsDir).filter(name => name.endsWith('.json')).length;
  report('N09', 'Поддельный Anchor от чужого signer (корень не повреждён)', {
    boundaryReached: 'observeTrustedVerdict: проверка подписи заявления анкера ключом корня',
    verdict: legit.result?.verdict ?? null, reasonCode: observed.observer?.reasonCode ?? observed.observerError?.code ?? null,
    observer: observed.observer || null, observerError: observed.observerError || null,
    mutations: { victim: v.stand.mutationCount, rogue: 0 },
    falseTrustedPass: observed.observer?.trusted === true && observed.observer?.passed === true && observed.observer?.verdict === 'PASS',
    details: { anchorId, originalKeyId: original.keyId, forgedKeyId: forgedStatement.keyId, anchorCountBefore: countBefore, anchorCountAfter: countAfter, legitObserverBefore: legit.observer },
    notes: 'Анкер, подписанный чужим ключом, не должен приниматься наблюдателем; второй анкер не создаётся.'
  });
} catch (error) {
  report('N09', 'Поддельный Anchor от чужого signer (корень не повреждён)', { infraError: err(error) });
} finally { await w.cleanup(); }