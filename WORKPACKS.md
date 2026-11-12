# Автономные рабочие пакеты

Начать с HANDOFF.md и ACCEPTANCE-REPORT.md. Ни один внешний Grok/Kimi/DeepSeek пока не запускался; эти пакеты предназначены для передачи, не изображают участие моделей. Обязательный общий ввод: docs/sources/master-plan.ru.txt, AGENTS.md, шесть корневых контрактов, packages/contracts/index.mjs. Изменение схем — только через основной агент + Luna. Не трогать архивы/ЦИЗ.

| Пакет | Исполнитель | Зависимости | Владеет |
|---|---|---|---|
| WP-01 | Luna / Grok | contract gate | packages/core, apps/control, apps/browser, adapters/local, tests/runtime* |
| WP-02 | Luna / независимый reviewer | WP-01 | apps/verification, tests/verification*, tests/faults* |
| WP-03 | Kimi | WP-01/02, source audit | adapters/ciz, tests/ciz*, docs/CIZ-* |
| WP-04 | DeepSeek | source audit, WP-03 observations | packages/intelligence, tests/intelligence* |
| WP-05 | Kimi | WP-01 public API, WP-04 | apps/workbench, tests/ui* |
| WP-06 | основной агент + Luna | все | docs/acceptance, ACCEPTANCE-REPORT.md |

Подробности: workpacks/WP-01-core.md, WP-03-ciz.md, WP-04-intelligence.md, WP-05-workbench.md. До независимого review статус REVIEW, не ACCEPTED. Отчёт пакета: changed files, команды, фактический exit/result, новые риски, ограничения, следующий шаг. Пользовательский результат и критерии важнее количества файлов.
