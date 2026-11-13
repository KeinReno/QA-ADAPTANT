# 02 — TEST EVIDENCE

Все числа получены фактическим прогоном Lead на финальной интеграционной ревизии.

| Параметр | Значение |
|---|---|
| Ревизия | 21edda60fb9ab2c0815efba775038db52af1f585 (feat/adaptant-02-trust-integration) |
| ОС | Windows (локальная машина) |
| Node.js | v24.16.0 |
| npm | 11.13.0 |
| git | 2.55.0.windows.2 |
| Рабочее дерево на момент прогона | чистое (git status пуст) |

## Обязательные команды

| # | Команда | Фактический результат | Exit |
|---|---|---|---|
| 1 | npm test | 258 tests, 258 pass, 0 fail | 0 |
| 2 | npm run test:races | 3 tests, 3 pass, 0 fail | 0 |
| 3 | npm run schemas | экспортированы шесть схем, диффа файлов schemas/ нет | 0 |
| 4 | node --test tests/trust-integration.test.mjs | 13 tests, 13 pass, 0 fail | 0 |
| 5 | node tests/redteam/run-all-w2.mjs --target=. | 24 атаки, все PASS, 0 FAIL | 0 |
| 6 | node tests/redteam/run-matrix.mjs . | 34 строки: 24 PASS, 10 TODO, 0 FAIL, 0 PARTIAL | 0 |
| 7 | git diff 0e7e6c2..HEAD -- packages/contracts schemas docs/contract-freeze.json packages/core apps/browser apps/verification | пусто | 0 |

## Состав набора (npm test)

- Старые тесты 0.1: contracts, contract-links, runtime, faults, lifecycle, audit-wp, evidence-readers, review-grok — без правок.
- WP-01/WP-02: tests/trust-identity.test.mjs (5), tests/trust-approval.test.mjs (11).
- WP-03: tests/trust-policy.test.mjs (106).
- WP-04: tests/trust-environment.test.mjs (32).
- WP-05: tests/trust-anchor.test.mjs (22).
- WP-06: tests/trust-integration.test.mjs (13, живой стенд и Chromium).
- R-01/R-02: tests/trust-r01.test.mjs (3), tests/trust-keygen.test.mjs (4).
- Прочее: контрактные и аудиторские тесты базы.

## Сквозной доверенный прогон (тест T-01)

Живой локальный стенд 127.0.0.1, настоящий Chromium, настоящий подписант анкера в named pipe:

- ровно один POST (счётчик стенда mutationCount=1);
- независимый GET Verification и один entry independent-read;
- один durable candidate, один terminal-choice с исходом anchor, один терминальный verdict PASS;
- анкер в trustRoot/anchors/<id>.json проверяется подписью anchor-signer;
- observeTrusted возвращает passed=true и verdict PASS;
- повторный observeTrusted не меняет счётчик POST.

## Замечания о среде

- Тестовый раннер Node использует piped stdio; в confined-режиме DSH-песочницы это даёт spawn EPERM.
  Прогоны выполнялись в режиме полного доступа к файловой системе (danger-full-access, выдан владельцем сессии).
- Один невоспроизведённый флейк T-08 (13 s) наблюдался у ревьюера WP-06 под высокой нагрузкой; повторные
  изолированные и полные прогоны зелёные. Зафиксировано как наблюдение WP-07, не дефект F-01.
- Полный npm test занимает ~5 минут на загруженной машине (Chromium-тесты), test:races ~30-60 с.
