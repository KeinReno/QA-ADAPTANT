// WP08 ре-приёмка QWEN-F1 — R7. Конфигурационный обход: публичный startTrusted получает
// trustRoot, указывающий на полностью новый корень атакующего с корректным закреплением
// (createTrustRoot создаёт валидный pin для любого нового корня). Корень жертвы не изменяется.
// A2: противник управляет входами публичного API (конфигурация/параметры вызова).
// Вопрос ре-приёмки: где и кем должна быть закреплена идентичность разрешённого trustRoot.
// Запуск: node repro/reacceptance/r7-config-new-root.mjs
import { createHash } from 'node:crypto';
import { fs, path, world, victimWorld, attackerWorld, runTrusted, report } from '../neg/_world.mjs';

const snapshot = dir => {
  const files = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else files.push({ name: path.relative(dir, full), sha256: createHash('sha256').update(fs.readFileSync(full)).digest('hex') });
    }
  };
  walk(dir);
  return files.sort((x, y) => x.name.localeCompare(y.name));
};

const w = world();
try {
  const v = await victimWorld(w);
  const a = await attackerWorld(w);
  const rogue = await w.stand();
  const before = snapshot(v.trustRoot);

  // Ни одной записи в корень жертвы: меняется только параметр trustRoot публичного вызова.
  // Корень атакующего создан штатной процедурой и имеет валидное DPAPI-закрепление.
  const run = await runTrusted({
    root: v.root, trustRoot: a.trustRoot,
    signTrust: a.trust, commitApprovalTo: a.trustRoot,
    ownerKey: a.ownerKey, ownerKeyId: a.created.ownerKeyId,
    issuer: a.owner, subject: a.operator, issuerId: 'attacker-owner', subjectId: 'attacker-operator',
    stand: rogue, anchorKeyPath: a.anchorKeyPath, registerRecord: true, recordTrust: a.trust
  });
  const after = snapshot(v.trustRoot);
  const victimRootUntouched = JSON.stringify(before) === JSON.stringify(after);

  report('R7', 'Конфигурация: доверенный прогон под полностью новым корнем атакующего', {
    boundaryReached: 'CONFIG_TRUSTROOT_POINTER',
    verdict: run.result?.verdict ?? null, reasonCode: run.result?.reasonCode ?? null,
    observer: run.observer, observerError: run.observerError,
    mutations: { rogue: rogue.mutationCount, victim: v.stand.mutationCount },
    details: {
      victimRootUntouched, victimRootFiles: before.map(f => f.name),
      attackerRoot: { ownerKeyId: a.created.ownerKeyId, anchorKeyId: a.created.anchorKeyId, pinnedBy: 'createTrustRoot (штатная процедура)' },
      run
    },
    notes: 'Закрепление самореферентно: каждый корень подтверждает сам себя. Идентичность разрешённого trustRoot должна быть закреплена ВНЕ корня (конфигурация владельца/политика запуска), иначе указатель на чужой корень с валидным pin принимается. Ложный trusted PASS публикуется в хранилище жертвы.'
  });
} catch (error) {
  report('R7', 'Конфигурация: доверенный прогон под полностью новым корнем атакующего', { infraError: { code: error.code || null, message: String(error.message || error) } });
} finally {
  await w.cleanup();
}