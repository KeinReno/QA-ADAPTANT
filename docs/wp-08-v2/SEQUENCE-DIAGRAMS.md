# SEQUENCE DIAGRAMS — TRUST FOUNDATION V2.1

## S-1. Запуск trusted-run (M01/M02)
```
Control            TAS                         Verification Worker
  │ hello/nonce      │                                   │
  │◄ serverAuth(SID+sign)│                              │
  │ verify pinned key │                                   │
  │ verify-approval   │                                   │
  │──────────────────►│ проверка подписи по enrolled key  │
  │◄ BOUND/refuse     │                                   │
  │ prepare-run       │ bind approval→runId               │
  │──────────────────►│ создать trusted-run + evidence ACL│
  │◄ trustedRunId     │ spawn ────────────────────────────►│
  │                   │ ephemeral priv via inherited handle│
  │                   │◄────────────── worker-ready(keyId) │
```

## S-2. Verification + attestation
```
Worker → стенд: независимые чтения (pinned)
Worker → TAS: evidence artifacts в каталог ACL службы
Worker → TAS: submit-attestation(подписана эфемерным ключом)
TAS: verify signature/nonce/session; пересчёт readSet; byte-identity candidate;
     паритет assertEvidenceRefs/assertTerminalEvidence/validateVerdictCoverage
TAS: принять → состояние ATTESTED; иначе INCONCLUSIVE/ATTESTATION_INVALID
```

## S-3. Anchor
```
Worker → TAS: anchor-sign(grantId, attestationSha256)
TAS: grant валиден? attestation принята? cancel нет?
TAS → Registry: registryVersion (чтение)
TAS: подпись receipt ключом анкера; anchor statement + verificationKeyId/sessionId
TAS → Control: receipt/anchor (публично проверяемо)
```

## S-4. Cancel
```
Control → TAS: cancel(runId/approvalId)
TAS: если состояние < CONSUMED → REVOKED, grant отозван, POST запрещён
      если CONSUMED/ANCHORED → фиксирует факт, подпись не отзывается
TAS → Worker: stop; Worker → TAS: подтверждение остановки
```

## S-5. Recovery
```
Control → TAS: reconcile(runId)
TAS: читает свой журнал + durable state (TAS-зона) + registryVersion
     нет валидного grant/attestation → INCONCLUSIVE/LEGACY, без POST
     есть receipt → продолжает тот же anchorId; повторная подпись запрещена
TAS → Control: статус (идемпотентно)
```

## S-6. Enrollment
```
admin (secure desktop) → CLI: enroll --root --fingerprint(offline)
CLI → TAS: adminAuth (elevated token SID + signature)
TAS: сверка fingerprint с вычисленным; повторный enroll → отказ
TAS → Registry: append record v1 (ownerSignature/adminSignature)
TAS → CLI: результат; журнал аудита
```

## S-7. Rotation
```
owner (offline) → новый expected keyId/fingerprint
admin → CLI: rotate --new-fingerprint
TAS: сверка с внешним ожидаемым keyId; HWM; append registry vN+1
старые версии остаются для исторической проверки (M08)
```
