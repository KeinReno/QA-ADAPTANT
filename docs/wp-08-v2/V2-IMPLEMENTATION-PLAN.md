# TRUST FOUNDATION V2.1 — ПЛАН РЕАЛИЗАЦИИ (S0–S8)

Предусловие: архитектурный ACCEPT Qwen на этот пакет. Реализация — в новой изолированной
ветке; продукт/main не меняются до приёмки этапов.

| Этап | Содержание | Критерий | Артефакты |
|---|---|---|---|
| S0 | Архитектура v2.1, контракты, инварианты, матрица (пакет) | ARCHITECTURE ACCEPT | docs/wp-08-v2 |
| S1 | Каркас TAS (NT SERVICE\KAIDEN-TAS), IPC с mutual auth, install dir pin ключа, ACL | T12/N15 + INV-16 | service, harness |
| S2 | Registry v1: append-only, HWM, ACL, подписи, backup/restore, rollback-отказ | T15/N18 + INV-03 | registry, admin-CLI enroll |
| S3 | TAS state: approval bind, grant, TTL, revoke, cancel, recovery; удаление файлового consumption | T01/T02/T06/T07/T08/T11 | state, race-тесты |
| S4 | TAS-Verifier: spawn Worker, эфемерный ключ, TAS-канал, evidence ACL, attestation, пересчёт readSet/candidate, паритет | T03/T04/T09/T10/T20 + P01 | verifier |
| S5 | Anchor в TAS: ключ с ACL службы, receipt/anchor extension, registryVersion | INV-06/INV-10 | anchor |
| S6 | Enrollment/rotation: офлайн fingerprint, повторный enroll, внешний keyId, secure desktop | T14/N17, R8' | admin-CLI |
| S7 | Legacy-политика: LEGACY_UNVERIFIED, переаттестация владельцем; миграция установок | T16/N20 + миграция | migration |
| S8 | M11/M12: fake-провайдер отделён; полная исполненная матрица + R-D из дерева; публикация | INV-17/INV-19 | gates, logs |

## Обязательные gates после каждого этапа

`npm test`, `test:races`, `test:attacks`, `schemas`, целевые сценарии этапа; журналы
с кодом выхода. P01 обязателен после S4/S5/S8.

## Запреты

- Не включать F3/one-shot без контракта стенда (регрессия GAP-01).
- Не переносить отклонённый trust-pin как защиту.
- Не объявлять PASS для проектных статусов.
