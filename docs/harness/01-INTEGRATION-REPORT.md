# 01 — INTEGRATION REPORT (KAIDEN QA ADAPTANT 0.2, Trust Foundation)

Составлен Lead-оркестратором DeepSeek Harness. Документ описывает, что реализовано, кем и на каких ревизиях.
Статус пакета: INTEGRATED. Это не внешняя приёмка.

## База

| Параметр | Значение |
|---|---|
| Stable 0.1 | тег v0.1.0-stable = 88fc1d7b46e898b9d1ac85996042798fe55a2619 |
| WP-00 архитектура | 2815666 |
| WP-01 Identity | 2beff571f733028ff85ff241b70a756894862f34 (ACCEPT внешнего статического ревью) |
| WP-02 Approval | 0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31 (ACCEPT внешнего статического ревью) |
| База разработки 0.2 | 0e7e6c2 |
| Интеграционная ветка | feat/adaptant-02-trust-integration |
| PR #1 / master / main | не менялись, merge в main не выполнялся |

## Компоненты

| WP | Содержание | Ветка | Ревизия | Файлы |
|---|---|---|---|---|
| WP-01 | Два ключа Ed25519, DPAPI, ACL, Principal, trust root | feat/qa-adaptant-02-trust-foundation | 2beff57 | packages/trust/identity.mjs, acl.mjs, dpapi.mjs |
| WP-02 | Approval, immutable storage, consumption CREATE_NEW, guard | feat/qa-adaptant-02-trust-foundation | 0e7e6c2 | packages/trust/approval.mjs, keygen.mjs |
| WP-03 | Чистый PDP decide(facts), projectToVerdict | feat/adaptant-02-wp03-policy | fc2a593 | packages/trust/policy.mjs |
| WP-04 | Реестр сред по поколениям, challenge-response аттестация стенда | feat/adaptant-02-wp04-environment | 9fc9de4 | packages/trust/environment.mjs, adapters/local/server.mjs |
| WP-05 | Candidate, terminal-choice, единственный verdict, подписант анкера | feat/adaptant-02-wp05-anchor | 5c02063 | packages/trust/anchor.mjs, anchor-signer.mjs |
| WP-06 | startTrusted/observeTrusted/cancelTrusted/reconcileTrusted, PEP T-A…T-E | feat/adaptant-02-trust-integration | текущий HEAD | apps/control/run.mjs, trusted.mjs, packages/trust/facts.mjs, windows-sid.mjs |
| Red Team | 16 атак и каркас матрицы E/V/L/B | test/adaptant-02-trust-verification | 81171a8 | tests/redteam/, docs/harness/REDTEAM-* |

## Документы решений

- docs/harness/BASELINE-AND-CONTRACTS.md — замороженные интерфейсы и инварианты.
- docs/changes/004 — раскладка доверенных файлов, коды, профиль бюджета, наблюдения ревью WP-03.
- docs/changes/005 — поколенческая раскладка реестра сред и отзыв.
- docs/changes/006 — область утверждения анкера (связка и неизменность, не бизнес-истина).
- docs/changes/007 — отзыв среды и доверенное чтение.

## Что доказывает доверенный путь

- Подписанный approval на точные входы, операцию, fixture, среду и поколение; роль и SID вызывающего.
- Аттестация среды свежим challenge ключом стенда, проверка поколения, pid и владельца порта; dev/production всегда DENY.
- Одноразовый расход approval, затем mutation-intent, затем ACK; второй POST невозможен.
- PASS публикуется только при годном анкере; без анкера — единственный INCONCLUSIVE/EVIDENCE_MISSING.
- observeTrusted показывает PASS только при полной связке; start/reconcile доверенного входа не показывают PASS без анкера.
- Старый вход 0.1 не принимает аргументы доверия и не выпускает доверенный PASS.

## Что в 0.2 сознательно не сделано

Циз/Dev не подключались, адаптер не создавался, новых операций реестра нет, профиль бюджета не подписан
(R-05), мультипользовательская аутентификация не проектировалась.
