# TRUST FOUNDATION V2.1 — КОНТРАКТЫ (публичный API, IPC, grant/receipt)

## 1. Изменения публичного Trust API (база 1a510a5)

| 1a510a5 | v2.1 | Причина |
|---|---|---|
| `startTrusted(bundle, {root, trustRoot, approvalId, approval, issuer, subject, anchorKeyPath, ...})` | `startTrusted(bundle, {root, approval, requestId})` + внутри TAS | M02/M10: пути корня/ключей не принимаются |
| `observeTrusted({root, trustRoot, runId, approvalId})` | `observeTrusted({root, runId, approvalId?})` | N18: клиент не выбирает корень |
| `cancelTrusted({root, trustRoot, runId, subject, approvalId})` | `cancelTrusted({root, runId, subject, approvalId})` | то же |
| `reconcileTrusted({root, trustRoot, approvalId, anchorKeyPath, signerPipe, credentials, ...})` | `reconcileTrusted({root, runId, approvalId})` | recovery через TAS |
| `loadTrustRoot(trustRoot)` (публичный) | **удаляется** из публичного экспорта | M01/M06 |
| `createTrustRoot({secretsDir, trustRoot, runDir})` | только в admin-CLI/тестах; корень не доверенный до enrollment | M05/M08 |
| `resealTrustRootPin` (41043ad) | **не переносится** | отклонено Qwen |

`trustRootId` — непрозрачный идентификатор записи реестра, не путь. Клиент может передать
его только если enrolled-корней несколько; по умолчанию используется единственный.

## 2. IPC v1 — кадры и ошибки

Транспорт: Windows named pipe `\\.\pipe\kaiden-tas-v1`, `FILE_FLAG_FIRST_PIPE_INSTANCE`.
Кадр: `uint32 length (LE)` + UTF-8 JSON (≤1 MiB). Порядок: handshake → authenticated frames.

Handshake:
1. `hello` {protocol, clientNonce(32B), clientEcdhPub}
2. `serverAuth` {serverNonce, serverEcdhPub, sessionId, capabilities, signature(TAS)} —
   подпись ключом TAS над canonical({clientNonce, serverNonce, serverEcdhPub, sessionId}).
3. `clientAuth` {signatureHMAC(sessionKey, canonical(transcript))}, sessionKey = HKDF(ECDH).
После handshake все кадры: `{seq, mac}` HMAC-SHA256(sessionKey).

Ошибки: `TAS_UNAVAILABLE`, `TAS_AUTH_FAILED`, `TAS_VERSION_MISMATCH`,
`TRUST_ROOT_NOT_ENROLLED`, `APPROVAL_REPLAY`, `APPROVAL_EXPIRED`, `APPROVAL_REVOKED`,
`GRANT_INVALID`, `GRANT_EXPIRED`, `GRANT_REVOKED`, `ATTESTATION_INVALID`,
`EVIDENCE_UNTRUSTED`, `REGISTRY_UNAVAILABLE`, `REGISTRY_ROLLBACK`, `LEGACY_UNVERIFIED`.
Любая ошибка → отказ; автоматического перехода на другой канал/корень нет.

## 3. Глаголы IPC

| Глагол | Кто | Назначение |
|---|---|---|
| `status` | любой | версия, registryVersion, capabilities; без секретов |
| `verify-approval` | Control | проверка подписи/полномочий по enrolled ownerKeyId |
| `prepare-run` | Control | bind approval→runId, создание trusted-run и evidence-каталога, spawn Worker |
| `worker-ready` | Worker (TAS-канал) | регистрация эфемерного ключа уже при spawn (внешний вызов запрещён) |
| `submit-attestation` | Worker (TAS-канал) | attestation + candidate bytes для проверки |
| `anchor-sign` | Worker (TAS-канал) | подпись receipt/anchor при выполненных инвариантах |
| `observe` | Control/CLI | чтение статуса; PASS только при полном подтверждении |
| `cancel` | Control | отзыв grant/исполнения (атомарно) |
| `reconcile` | Control | recovery; без повторной мутации |

Пользовательский клиент не имеет глаголов, возвращающих grant/ключи; `anchor-sign`
отклоняется, если сессия не является TAS-Verifier сессией.

## 4. Grant v1 (только в памяти TAS/Worker)

```json
{
  "schemaVersion": "1.0.0", "domain": "verification-grant",
  "grantId": "<uuid>", "audience": "tas-verifier",
  "sessionId": "<uuid>", "runId": "<uuid>", "approvalId": "<uuid>",
  "manifestSha256": "<64hex>", "approvalBindingHash": "<64hex>",
  "nonce": "<32B b64>", "issuedAt": "<iso>", "expiresAt": "<iso>",
  "capabilities": ["verify", "anchor"], "singleUse": true
}
```
Свойства: audience-связан; single-use; TTL ≤ budget прогона; отзывается cancel;
не сериализуется на диск; проверяется при каждом `anchor-sign`.

## 5. Verification Attestation v0.3 (расширение 0.2.1)

```json
{
  "schemaVersion": "0.3.0", "domain": "verification-attestation",
  "runId": "...", "approvalId": "...", "manifestSha256": "...",
  "candidateSha256": "...", "readSetSha256": "...",
  "evidenceChainHead": { "sequence": 7, "envelopeSha256": "..." },
  "verificationKeyId": "...", "sessionId": "...", "pid": 1234,
  "startedAt": "...", "nonce": "...",
  "decision": { "verdict": "PASS", "reasonCode": "TRUST_OK" },
  "signature": "<hex Ed25519 ephemeral>", "signatureAlgorithm": "Ed25519"
}
```
Attestation принимается только по TAS-каналу соответствующей сессии; ключ — эфемерный,
зарегистрирован при spawn; повтор ключа между сессиями запрещён.

## 6. Receipt/Anchor extension

Аддитивные поля: `verificationKeyId`, `verificationAttestationSha256`,
`sessionId`, `trustRegistryVersion`. Старые артефакты читаются; PASS по legacy —
`LEGACY_UNVERIFIED` (M08), не PASS.

## 7. Ошибки жизненного цикла (не PASS)

`CANCELED`, `PUBLICATION_PENDING`, `INCONCLUSIVE`, `EVIDENCE_MISSING` сохраняются;
при любой неопределённости TAS не подписывает anchor.
