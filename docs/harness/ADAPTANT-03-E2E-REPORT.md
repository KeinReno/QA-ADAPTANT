# KAIDEN QA ADAPTANT 0.3 — E2E report

Дата: 13 ноября 2026
Ветка: `feat/adaptant-03-execution-foundation`
База: `1a510a5d5929534d400dc965f58c78cf468bc270`
Stage C commit: `c9974502bb005d8635c9025b333fd847dc86b999`
Stage D code commit: `a65237daaf93dcd7df5ef2ef34a03338d026c098`
Результат: **локальный сквозной сценарий ACCEPT; автономное планирование реальной моделью не проверялось**

## Проверенный маршрут

Playwright browser UI → точное исходное поручение → TaskStore → локальный test Planner (`MOCK`) → валидированный версионированный план → host-issued owner approval → отдельный owner-signed Trust approval → публичный trusted facade → локальный HTTP стенд → trusted observer → TaskResult.

Локальный стенд реально принимает одну `POST /records` мутацию и независимое чтение. Временный Trust root, identity, environment attestation и approvals создаются только тестом в отдельном каталоге ОС; секреты и ключи не включаются в Task journal или отчёт. Временные каталоги удаляются после теста.

Task хранит исходный запрос дословно. Успешный исход имеет `plannerMode: MOCK`, trusted Verification `PASS`, существующий runId и evidence refs. TaskStore перед сохранением PASS повторно обращается к trusted observer и сверяет полный набор evidence IDs с тем же runId. Browser Worker/runner сообщение само по себе PASS не устанавливает.

## Проверки и результат

| Команда / сценарий | Результат |
|---|---|
| `node --test --test-timeout=180000 tests/adaptant03-e2e.test.mjs` | PASS 5/5 на финальном дереве |
| `node --test --test-timeout=180000 tests/adaptant03-ui.test.mjs` | PASS 2/2 на финальном дереве |
| Успешный browser → Task → trusted execution → independent verification | PASS; ровно 1 мутация, evidence refs привязаны к runId |
| Перезапуск/recovery после durable intent | PASS; прежний runId, ровно 1 мутация |
| Отмена после dispatch при задержанном ответе | PASS; новый dispatch не создаётся, неподтверждённый итог не превращается в PASS |
| Гонка терминализации PASS и отмены | PASS; ответ API и TaskStore возвращают один сохранённый CANCELED исход |
| Подмена planId, executionRef, содержимого/hash плана и owner approval | Отклонена до dispatch |
| Symlink/junction prepared/launch каталога за пределы run root | Отклонены |
| Локальный HTTP UI по IPv4 loopback | Browser PASS; ввод, подтверждение, запуск и показ результата |
| IPv6 loopback authority | Unit PASS (`http://[::1]`); фактический IPv6 socket E2E не выполнен: среда вернула `connect EACCES ::1` |
| `node --test --test-timeout=45000 tests/execution.test.mjs` | PASS 10/10 на финальном дереве |
| Полный `npm test` gate | PASS 319/319 на snapshot до финального разбиения E2E-файла и небольших защитных изменений; Trust Foundation в этой работе не менялась. После изменений повторены целевые suites 5/5, 2/2 и unit suite 10/10 |

## Пределы доказательства

- План в E2E фиксирован тестовой функцией и маркирован `MOCK`; это подтверждает исполнительную интеграцию, не автономное планирование модели.
- Сценарий ограничен заранее зарегистрированной локальной `create-record` операцией. Запросы про произвольное приложение/авторизацию остаются BLOCKED, пока нет утверждённого Scenario/Operation/Fixture.
- Никакая среда Dev/ЦИЗ не подключалась. Проверка независимого аудита DeepSeek относится к другой ветке и остаётся отдельным процессом.
- IPv6 loopback разрешён и корректно форматируется; сетевой прогон IPv6 здесь невозможен из-за запрета подключения к `::1` в среде.
