# 06 — FINAL HANDOFF (кандидат на внешнюю приёмку)

Статус: кандидат интеграции 0.2 Trust Foundation. Это **не** приёмка: внешний контур (WP-08) проверяет сам.

## Что передаётся

| Параметр | Значение |
|---|---|
| Репозиторий | https://github.com/KeinReno/QA-ADAPTANT |
| Интеграционная ветка | feat/adaptant-02-trust-integration |
| Интеграционная ревизия | фиксируется в 02-TEST-EVIDENCE (последний SHA ветки) |
| База разработки | 0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31 |
| Stable 0.1 | тег v0.1.0-stable → 88fc1d7b46e898b9d1ac85996042798fe55a2619 (не изменён) |
| Merge в main | не выполнялся, требует решения владельца |
| PR #1 (Grok) | не изменялся |

## Ветки пакетов (для построчной проверки)

| Пакет | Ветка | Ревизия |
|---|---|---|
| WP-03 Policy | feat/adaptant-02-wp03-policy | 0731f8f (fix 104ae7c) |
| WP-04 Environment | feat/adaptant-02-wp04-environment | 9fc9de4 (fix 648a2f2) |
| WP-05 Anchor | feat/adaptant-02-wp05-anchor | 5c02063 (fix c168465) |
| WP-06 Integration | feat/adaptant-02-trust-integration | HEAD ветки |
| Red Team | test/adaptant-02-trust-verification | 81171a8 + волна 2 |

Worktree'ы агентов: C:\Users\gvi\Desktop\QA-ADAPTANT-harness\{wp03,wp04,wp05,integration,redteam}.
node_modules в них — junction на корневой, npm install не нужен.

## Как воспроизвести

Требования: Windows, Node.js v24.16.0, npm 11.13.0, Chromium из playwright 1.63.0 (ставится вместе с зависимостями).

    cd C:\Users\gvi\Desktop\QA-ADAPTANT-harness\integration
    npm test                  # весь набор набора 0.1 + 0.2
    npm run test:races        # гонки 0.1
    npm run schemas           # экспорт схем, должен быть без диффа
    node --test tests/trust-integration.test.mjs   # сквозной доверенный прогон
    node tests/redteam/run-all-w2.mjs              # атаки Red Team (после слияния ветки)

Доверенный прогон требует DPAPI текущего пользователя и изолированного стенда 127.0.0.1: тесты создают
временный trust root и каталог прогонов в %TEMP%, секреты не попадают в репозиторий.

## Пакет доказательств

- 01-INTEGRATION-REPORT.md — что реализовано и на каких ревизиях.
- 02-TEST-EVIDENCE.md — команды, окружение, коды выхода, числа.
- 03-NEGATIVE-TEST-REPORT.md — негативные сценарии и вердикты.
- 04-COMPATIBILITY-REPORT.md — сохранность Stable 0.1.
- 05-KNOWN-RISKS.md — открытые ограничения и их влияние.
- 07-HARNESS-STATUS.md — статус каждого пакета и ревью-цепочка.

## Что проверяющему важно знать

- Доверенный PASS доказывается только observeTrusted: PASS без годного анкера не показывается ни одним
  доверенным входом (start/reconcile/observe).
- В evidence журнале PASS появляется только при исходе anchor; без подписанта — один INCONCLUSIVE/EVIDENCE_MISSING.
- Открытых P0 по состоянию передачи нет; R-01, R-03…R-07 — принятые P2-ограничения локальной 0.2 (05-KNOWN-RISKS).
- Внешняя приёмка должна повторить: npm test, сквозной доверенный прогон, негативные пробы (ложный PASS,
  второй POST, второй verdict, обход approval, подмена среды), сохранность 0.1.
