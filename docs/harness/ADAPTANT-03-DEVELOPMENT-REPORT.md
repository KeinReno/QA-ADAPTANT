# KAIDEN QA ADAPTANT 0.3 — Development report

Дата: 13 ноября 2026

## Статус

**PARTIAL — локальный Execution Foundation реализован и принят по этапам C/D; автономное планирование реальной моделью не подтверждалось.** Пользовательское поручение проходит через Task, явный `MOCK` Planner, approval, локальный trusted run, Verification, evidence refs и результат. Универсального исполнителя и сценариев авторизации нет.

Источник: опубликованный репозиторий `KeinReno/QA-ADAPTANT`, база `1a510a5d5929534d400dc965f58c78cf468bc270`. Работа выполнена только в worktree `C:\Users\gvi\.codex\worktrees\adaptant-03-execution\QA-ADAPTANT` на `feat/adaptant-03-execution-foundation`.

## Поставка по этапам

| Этап | Commit | Результат | Независимая проверка |
|---|---|---|---|
| A — архитектура | `f1490c26864c99ceed6bf0c9e0235aba6547f37e` | Архитектура, lifecycle и planner contract | Luna review завершён до B |
| B — Task/Planner foundation | `7eb4f4b296a985ca8d67754f58f5588667bcf0e4` | TaskStore, планы, PlannerProvider, валидация, journal/recovery | Luna ACCEPT; `tests/execution.test.mjs` 10/10 |
| C — trusted execution | `c9974502bb005d8635c9025b333fd847dc86b999` | Публичный trusted adapter, точная привязка approved plan/step/ref, recovery/cancel и fail-closed результат | Luna ACCEPT; E2E 5/5 |
| D — локальный UI и сквозная проверка | `a65237daaf93dcd7df5ef2ef34a03338d026c098` | Loopback HTTP UI, owner-gated API и browser путь | Luna ACCEPT; UI 2/2 |

Эти коммиты следуют за указанной базой. Merge в `main`, WP-08/remediation и аудиторские worktrees не выполнялся. Trust Foundation файлы не изменялись.

## Реализация

- Task и immutable ExecutionPlan хранятся в отдельном journal/snapshot namespace; исходный текст не нормализуется поверх оригинала.
- PlannerProvider ограничивает размер и время ответа; `MODEL`/`MOCK` provenance сохраняется. Отсутствующий provider не приводит к скрытому fallback.
- TaskStore сериализует разрешение владельца и dispatch intent; PASS требует независимой повторной проверки trusted observer и evidence IDs.
- Trusted adapter вызывает только публичные фасадные функции. Prepared digest связывает Task, canonical plan SHA, owner approval ref, шаг, executionRef и bundle digest. Trust approval остаётся отдельной областью.
- Неопределённый dispatch восстанавливается только по исходному runId. Отмена после dispatch не запускает повторную мутацию. Конкурирующая финализация возвращает исход, сохранённый в TaskStore.
- UI привязывается только к loopback; host authentication предоставляется владельцем приложения, операция подтверждения вызывает host callback. UI не обращается к privileged Trust функциям.

## Проверки

| Проверка | Результат |
|---|---|
| `tests/execution.test.mjs` | PASS 10/10 на финальном коде |
| `tests/adaptant03-e2e.test.mjs` | PASS 5/5 на финальном коде |
| `tests/adaptant03-ui.test.mjs` | PASS 2/2 на финальном коде |
| Полный `npm test` gate | PASS 319/319 на snapshot перед последними небольшими изменениями E2E-разделения и path guards; после них повторены все затронутые suites выше |
| `git diff --check` | PASS до Stage C и Stage D commit |
| Настоящий Dev/ЦИЗ | NOT RUN |
| IPv6 socket E2E | NOT RUN: среда вернула `connect EACCES ::1`; формат authority unit-tested |

Stage C локальный E2E использует временный test Trust root и реальный локальный fixture. Planner явно `MOCK`; успешный маршрут — интеграционное доказательство исполнительного контура, но не автономного AI планирования. Подробные шаги и результаты: [E2E report](ADAPTANT-03-E2E-REPORT.md).

## Оставшиеся ограничения

- Реальная модель и её provider не подключались; качество автономного plan generation не проверялось.
- Поддерживается один заранее зарегистрированный локальный create-record scenario. Запросы с неизвестными операциями блокируются.
- Полноценная отмена/восстановление проверены на локальном fixture; настоящий Dev и пользовательские аккаунты не использовались.
- Независимый аудит DeepSeek Trust Foundation 0.2 продолжается отдельно. Этот этап не меняет его исходную ревизию.

Итоговый SHA разработки и отчётов находится в истории этой feature-ветки; текущий последний кодовый commit — `a65237daaf93dcd7df5ef2ef34a03338d026c098`.
