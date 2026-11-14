# ADAPTANT 0.3.2 — Security Review

Изменения изолированы в inference/provider, PlannerResponse storage, orchestrator integration и UI. Trust Foundation 0.2, WP-08, Dev, ЦИЗ и Trust Root не изменялись. Luna приняла response storage contract, но независимый review реализации вынес **REJECT**.

Локальные проверки охватывают: loopback-only endpoint; отсутствие tools и fallback; prompt с недоверенным поручением; host registry ограничения и отказ по неизвестному executionRef; owner approval остаётся обязательным; mismatch модели, неверный content type, oversized response, raw response tamper; recovery без повторного inference. Planner suite — 10/10 PASS.

Luna ранее вынесла REJECT с P0/P1. После review были исправлены hash binding через host-нормализованный plan output, store ACL/byte caps, проверка текущего approval target до callback, запрет публичного Ollama parse-before-save, orphan-plan reconciliation и строгая типизация новых planner events. Повторная независимая оценка этих последних изменений ожидается.

В текущей Windows-среде `fsync` каталога staging PlannerResponse завершается `EPERM`. Production default fail-closed и не публикует артефакт; контролируемые HTTP integration tests подставляют sync hook только для изоляции протокола и не доказывают durability. Кроме того, после rename staging-каталога parent directory не синхронизируется. Поэтому реальный MODEL planning на этой Windows-конфигурации недоступен до реализации и проверки durable directory publication. Полный Trusted/Trust regression gate также не может подтвердить поведение: базовый `packages/trust/acl.mjs` вызывает отсутствующий `Get-Acl` из `Microsoft.PowerShell.Security`. Trust Foundation не менялась. Ограничение trustRoot identity остаётся открытым исходным риском и вынесено за рамки пакета.
