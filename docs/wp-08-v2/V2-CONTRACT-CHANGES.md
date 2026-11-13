# TRUST FOUNDATION V2 — ИЗМЕНЯЕМЫЕ КОНТРАКТЫ

Все изменения — через `docs/changes` и новый минорный контракт; замороженные форматы
0.1/0.2 (ключи, approval, anchor, evidence, схемы) не переписываются.

## 1. Публичный API (поведенческое изменение)

| Было (0.2 / 41043ad) | Станет (v2) |
|---|---|
| `startTrusted(bundle, { trustRoot, secretsDir, anchorKeyPath, ... })` | `startTrusted(bundle, { trustRootId?, ... })`; путь корня не принимается |
| `observeTrusted({ root, trustRoot, ... })` | `observeTrusted({ root, runId, trustRootId? })` |
| `reconcileTrusted({ trustRoot, anchorKeyPath, credentials, ... })` | без путей корня/ключей; секреты — через grant TAS |
| `loadTrustRoot(trustRoot)` (публичный) | удаляется из публичного экспорта; внутренний вызов TAS |
| `resealTrustRootPin({ trustRoot, secretsDir })` | удаляется; ротация — `kaiden-trust-admin rotate` (elevated) |
| `createTrustRoot({ secretsDir, trustRoot })` | остаётся для тестов/локального bootstrap, но созданный корень не доверенный, пока не enrolled через TAS |

## 2. Новые контракты (аддитивно)

1. **Trust Registry Record v1** (`trust-registry-record`): trustRootId, ownerKeyId,
   anchorKeyId, paths, status, registryVersion, createdAt, ownerSignature, adminSignature.
2. **Verification Grant v1** (`verification-grant`): grantId, runId, approvalId,
   manifestSha256, evidenceHead, ttl, issuedBy, signature(TAS).
3. **Anchor Receipt extension**: `trustRegistryVersion` + `anchorKeyId` (аддитивные поля,
   schemaVersion 0.2.2, обратная совместимость чтения).
4. **IPC-протокол TAS v1**: named pipe, JSON-запросы, коды ошибок
   (`TAS_UNAVAILABLE`, `TRUST_ROOT_NOT_ENROLLED`, `GRANT_INVALID`, `GRANT_EXPIRED`).
5. **CLI**: `kaiden-trust-admin enroll|rotate|revoke|status`; exit-коды и `--json`.

## 3. Ошибки/поведение при отсутствии доверия

- Нет TAS / нет enrolled root → отказ `TRUST_ROOT_NOT_ENROLLED` (fail-closed).
- Grant истёк/чужой → `GRANT_INVALID`/`GRANT_EXPIRED`; мутация не выполняется.
- Реестр повреждён/нечитаем → `TAS_REGISTRY_UNAVAILABLE` (fail-closed).
- Кэш по mtime/size запрещён контрактом; допускается content-hash кэш внутри TAS.

## 4. Совместимость с ADAPTANT 0.3

- Feature-ветка 0.3 не меняется этим предложением; интеграция — через стабильные
  публичные контракты (bundle, approval, anchor, evidence).
- Схемы 0.1 остаются; новые поля аддитивны, чтение старых артефактов поддерживается.
- Исторические PASS проверяются по registryVersion, действовавшей на момент выпуска.

## 5. Замороженные гарантии, которые нельзя ослаблять

- PASS только после независимых чтений и подписанного анкера.
- Approval одноразов; повторная мутация запрещена.
- Recovery идемпотентен и fail-closed.
- Никакой публичный вызов не выбирает произвольный trust root.
