# STATE MACHINE — APPROVAL / GRANT / TRUSTED RUN

Состояние живёт только в TAS (single-writer, append-only журнал + HWM). Файлы пользователя
на состояние не влияют.

## 1. Approval

```
                 prepare-run (первый)
 AVAILABLE ─────────────────────────► BOUND(runId)
    │  cancel/revoke                         │ grant issued
    ▼                                        ▼
 REVOKED                               GRANTED(ttl,nonce)
                                             │ attestation принята
                                             ▼
                                          CONSUMED
                                             │ anchor подписан
                                             ▼
                                          ANCHORED
```
- `AVAILABLE → BOUND`: атомарно, первый выигрывает; другой runId → `APPROVAL_REPLAY`.
- `GRANTED`: single-use, TTL; cancel → `REVOKED` до подписи (и после — только
  `PUBLICATION_PENDING`, без новой подписи).
- `CONSUMED`: подпись receipt возможна только в этом состоянии.
- Повторный `anchor-sign` → `GRANT_INVALID`; повторный POST → стенд/контроль отвергают.

## 2. Trusted Run (TAS-side)

`PREPARING → WORKER_SPAWNED → VERIFYING → ATTESTED → ANCHORED → FINISHED`;
боковые: `CANCELED`, `FAILED`, `RECOVERING`, `LEGACY_UNVERIFIED`.

## 3. Сериализация

Одна очередь транзакций на approvalId/runId. Cancel имеет приоритет до состояния
`CONSUMED`; после `ANCHORED` отмена только фиксирует статус, но не меняет подписанный факт.
Race-гарантии: нет двух grant; нет grant после revoke; нет anchor без attestation;
нет второго POST; recovery идемпотентен.

## 4. DoS через перехват approval

Атакующий, вызвав `prepare-run` первым, блокирует легитимный прогон (bind на его runId).
Это DoS, **не** ложный PASS: без TAS-исполнения аттестации/подписи нет. Меры: видимый
bind-журнал, revoke/rebind владельцем, политика D4 (OWNER-DECISIONS.md).
