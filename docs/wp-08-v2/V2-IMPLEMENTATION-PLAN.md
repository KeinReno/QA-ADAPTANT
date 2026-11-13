# TRUST FOUNDATION V2 — ПЛАН РЕАЛИЗАЦИИ (малыми этапами)

Предусловие: архитектурный ACCEPT Qwen. До него реализация не начинается.
Каждый этап — отдельный коммит в отдельной ветке; продукт/main не меняются до приёмки этапа.

| Этап | Содержание | Выход/критерий | Риск отката |
|---|---|---|---|
| S0 | Архитектура, границы, контракты, матрица (этот пакет) | ACCEPT Qwen | нет кода |
| S1 | Каркас TAS: служба под выделенным SID, ACL ProgramData, named pipe, `status`, health | служба не меняет доверие, только живёт; интеграция не включена | удалить службу |
| S2 | Registry v1 + enrollment CLI (elevated) + подписи владельца/админа; read-only `status --json` | enroll/повторный enroll отказ; R5/R8 сценарии fail-close (без wiring) | удалить registry |
| S3 | Read-path: `observeTrusted`/verify через TAS; удаление `trustRoot` из публичных параметров; `TRUST_ROOT_NOT_ENROLLED` | R7 (N10в) NO_TRUSTED_PASS; исторические PASS по registryVersion | вернуть прежний loader |
| S4 | Anchor signing в TAS: ключ анкера у службы, grant на подпись, receipt с `trustRegistryVersion` | P01 legitPass; V-04/V-07/recovery зелёные | вернуть anchor-signer |
| S5 | Rotation/revoke + внешний ожидаемый keyId + история версий; удаление `resealTrustRootPin` | R8 NO_TRUSTED_PASS; ротация только elevated | откат версии реестра |
| S6 | Кэш: удалить mtime/size; допускается content-hash + registryVersion внутри TAS | R6 NO_TRUSTED_PASS | выключить кэш |
| S7 | Миграция существующих установок + полный gate + публикация всех инструментов R-D матрицы в репозиторий | 305+/312 gate, races, W2, R-D 15/15 воспроизводимо из SHA | откат ветки |

## Обязательные тесты после каждого этапа

`npm test`, `test:races`, `test:attacks`, `schemas`, целевые R1/N01–N12/P01/R5–R8,
recovery/cancel. Сырые журналы с кодом выхода — в репозиторий.

## Критерий готовности v2 к ре-приёмке

- R5, R7, R8, R6 → NO_TRUSTED_PASS на v2-SHA; R1 и N01–N12 закрыты.
- P01 (легитимный прогон) работает; идемпотентный recovery; нет повторной мутации.
- Публичный API не принимает произвольный корень; reseal отсутствует.
- A2 не сужена; остаточные риски приняты владельцем отдельным решением.
- R-D матрица воспроизводима из опубликованного дерева (инструмент и сценарии в репо).
