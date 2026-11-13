// WP08 ре-приёмка QWEN-F1 — R6. Кэш закреплений (verifiedPins): подмена публичных файлов
// после успешной загрузки корня с восстановлением исходных mtimeMs и размеров.
// Сигнатура кэша — только метаданные (mtimeMs:size) четырёх файлов; содержимое не хешируется.
// A2: запись файлов в trust root. Восстановление mtime — тоже файловая операция (utimes).
// Запуск: node repro/reacceptance/r6-pin-cache-mtime.mjs
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fs, path, world, victimWorld, attackerWorld, substitute, runTrusted, report, err, loadTrustRoot } from '../neg/_world.mjs';

const self = fileURLToPath(import.meta.url);
const FILES = ['trust-pin.json', 'owner.pub', 'anchor.pub', 'ready.json'];

// Контрольный дочерний процесс: холодный кэш, тот же подменённый корень.
if (process.env.QA_R6_CHILD === '1') {
  try {
    const trust = loadTrustRoot(process.env.QA_R6_TRUSTROOT);
    console.log(JSON.stringify({ coldCache: true, accepted: true, ownerKeyId: trust.owner.keyId }));
  } catch (error) {
    console.log(JSON.stringify({ coldCache: true, accepted: false, error: err(error) }));
  }
  process.exit(0);
}

const stats = dir => FILES.map(name => {
  const s = fs.statSync(path.join(dir, name));
  return { name, mtimeMs: s.mtimeMs, size: s.size };
});

const w = world();
try {
  // load:true — корень жертвы успешно загружен, кэш процесса прогрет.
  const v = await victimWorld(w, { load: true });
  const a = await attackerWorld(w);
  // Нормализация mtime до целых секунд ДО прогрева кэша: utimes на Windows теряет
  // субмикросекундную точность исходных значений, целые секунды воспроизводятся точно.
  const T = Math.floor(Date.now() / 1000);
  for (const name of FILES) fs.utimesSync(path.join(v.trustRoot, name), T, T);
  loadTrustRoot(v.trustRoot); // прогрев кэша сигнатурой с нормализованными mtime
  const before = stats(v.trustRoot);

  // A2-действие: подмена трёх публичных файлов (размеры совпадают по построению:
  // keyId/spki фиксированной длины), затем восстановление тех же целых секунд mtime.
  substitute(v, a);
  const afterSub = stats(v.trustRoot);
  const sizesPreserved = afterSub.every((s, i) => s.size === before[i].size);
  for (const name of ['owner.pub', 'anchor.pub', 'ready.json']) {
    fs.utimesSync(path.join(v.trustRoot, name), T, T);
  }
  const restored = stats(v.trustRoot);
  const metadataRestored = restored.every((s, i) => s.mtimeMs === before[i].mtimeMs && s.size === before[i].size);

  // 1. Повторная загрузка в том же процессе: попадает ли loadTrustRoot в кэш по метаданным?
  let warm = null;
  try {
    const trust = loadTrustRoot(v.trustRoot);
    warm = { accepted: true, ownerKeyId: trust.owner.keyId, matchesAttacker: trust.owner.keyId === a.created.ownerKeyId };
  } catch (error) { warm = { accepted: false, error: err(error) }; }

  // 2. Контроль: холодный кэш в отдельном процессе того же SID.
  const child = spawnSync(process.execPath, [self], {
    env: { ...process.env, QA_R6_CHILD: '1', QA_R6_TRUSTROOT: v.trustRoot },
    encoding: 'utf8', timeout: 120000
  });
  let cold = null;
  try { cold = JSON.parse(child.stdout); } catch { cold = { parseError: String(child.stderr || child.stdout || '').slice(-2000) }; }

  // 3. Попытка полного доверенного прогона в процессе с прогретым кэшем.
  //    Дочерние процессы (worker/signer) имеют холодный кэш — фиксируем фактическое поведение.
  const rogue = await w.stand();
  const run = await runTrusted({
    root: v.root, trustRoot: v.trustRoot,
    signTrust: a.trust, commitApprovalTo: v.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId,
    issuer: a.owner, subject: a.operator, issuerId: 'attacker-owner', subjectId: 'attacker-operator',
    stand: rogue, anchorKeyPath: a.anchorKeyPath, registerRecord: true, recordTrust: a.trust
  });

  report('R6', 'Кэш закреплений: подмена с восстановлением mtimeMs и размеров', {
    boundaryReached: warm.matchesAttacker ? 'PIN_CACHE_BYPASS_METADATA' : 'CACHE_HELD',
    verdict: run.result?.verdict ?? null, reasonCode: run.result?.reasonCode ?? null,
    observer: run.observer, observerError: run.observerError,
    mutations: { rogue: rogue.mutationCount, victim: v.stand.mutationCount },
    details: { normalizedMtimeSec: T, before, afterSub, restored, sizesPreserved, metadataRestored, warmLoad: warm, coldCacheControl: cold, run },
    notes: 'Сигнатура кэша — mtimeMs:size без хеширования содержимого. Обход в процессе с прогретым кэшем фиксируется отдельно от полного прогона: дочерние процессы начинают с холодным кэшем.'
  });
} catch (error) {
  report('R6', 'Кэш закреплений: подмена с восстановлением mtimeMs и размеров', { infraError: err(error) });
} finally {
  await w.cleanup();
}