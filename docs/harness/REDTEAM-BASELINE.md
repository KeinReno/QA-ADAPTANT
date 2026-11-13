# REDTEAM-BASELINE — база независимой проверки 0.2 (волна 1)

Документ Red Team (Agent D). Фиксирует, на какой ревизии и какими командами получены факты.
Не является приёмкой и не заменяет решение Lead/Luna.

## 1. Зафиксированная база

| Параметр | Значение |
|---|---|
| Ревизия базы | `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31` |
| Ветка базы | `feat/qa-adaptant-02-trust-foundation` (PR #1) |
| Ветка проверки | `test/adaptant-02-trust-verification` |
| Worktree проверки | `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\redteam` |
| Stable 0.1 | тег `v0.1.0-stable` = `88fc1d7b46e898b9d1ac85996042798fe55a2619` |
| Окружение | Windows, Node.js v24.16.0, git 2.55.0, `core.autocrlf=false` |
| Дата волны 1 | 13.11.2026 |
| Продуктовый код | **не менялся** (Red Team не разработчик пакетов) |

## 2. Что прочитано до кода (закон и контекст)

1. `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\integration\docs\harness\BASELINE-AND-CONTRACTS.md` — §3 запреты, §5 интерфейсы, §6 инварианты, §8 риски R-01…R-04, §9 сдача.
2. `docs/wp-00/02-TRUST-ARCHITECTURE.md`, `03-CONTRACT-PROPOSALS.md`, `04-THREAT-MODEL.md`, `05-IMPLEMENTATION-ROADMAP.md`, `06-ACCEPTANCE-MATRIX.md`, `08-OPEN-QUESTIONS.md`.
3. Фактический код базы: `packages/trust/{identity,approval,acl,dpapi,keygen}.mjs`, `packages/core/{store,canonical,evidence-policy,bundle,approved-registry}.mjs`, `apps/control/run.mjs`, `apps/browser/worker.mjs`, `apps/verification/worker.mjs`, `adapters/local/{server,bundle}.mjs`, `packages/contracts/index.mjs`, `tests/trust-*.test.mjs`, `tests/approval-consume-worker.mjs`.

## 3. Фактическая карта ревизии (по коду, а не по отчётам)

| Есть на 0e7e6c2 | Нет на 0e7e6c2 |
|---|---|
| `packages/trust/identity.mjs` (WP-01, 193 строки) | `packages/trust/environment.mjs` (WP-04) |
| `packages/trust/approval.mjs` (WP-02, 375 строк) | `packages/trust/anchor.mjs`, `anchor-signer.mjs` (WP-05) |
| `packages/trust/acl.mjs`, `dpapi.mjs`, `keygen.mjs` | `packages/trust/policy.mjs` (WP-03) |
| `tests/trust-identity.test.mjs`, `tests/trust-approval.test.mjs` | `packages/trust/facts.mjs`, `windows-sid.mjs`, `apps/control/trusted.mjs` (WP-06) |
| Ядро 0.1 без изменений относительно `v0.1.0-stable` | Схемы/домены TrustDecision, анкер, аттестация среды |

Важно: **файлов отчётов WP-01/WP-02 на ревизии 0e7e6c2 нет** (проверено `git log --all --name-only -- docs/harness/*`:
только `BASELINE-AND-CONTRACTS.md`). Поэтому утверждения проверялись не по текстам отчётов, а по:
сообщениям коммитов `217818a`, `2beff57`, `1a79239`, `0e7e6c2`, диффам `docs/wp-00/*` и фактическому коду/тестам.
Это процессное замечание к сдаче пакетов (P3), а не дефект кода.

## 4. Команды и фактический результат (только свои прогоны)

| Команда | Результат | Exit |
|---|---|---|
| `node --test tests/trust-identity.test.mjs tests/trust-approval.test.mjs` | 19 tests, 19 pass, 0 fail, duration_ms 10344 | 0 |
| `node tests/redteam/run-all.mjs` | 16 скриптов: 12 PASS, 4 INCONCLUSIVE, 0 FAIL | 0 |
| `node tests/redteam/run-matrix.mjs .` | 34 строки: 2 PASS, 1 PARTIAL, 1 TODO, 30 UNVERIFIABLE | 0 |
| `git diff --name-only v0.1.0-stable..HEAD -- <замороженные пути>` | пусто (RT-14) | 0 |
| R-01: SIGKILL внутри guard, затем revoke/consume | lock остаётся; отказ через 5003/5009 мс; ACK и consumption нет | 0 (RT-16) |
| R-02: `keygen --secrets <runDir>/secrets --trust-root <tmp>` | exit 0; owner.key/anchor.key созданы внутри каталога прогона | 0 (RT-15) |
| R-02: `keygen --secrets <repo>/rt15-in-repo-*` | exit 1, TRUST_STORE_UNAVAILABLE, каталог в репозитории не создан | 1 (ожидаемо) |
| Smoke матрицы против `integration` (`399d441`) | 34 строки: 3 PASS (E-08, L-07, L-09), 31 TODO; это только проверка работоспособности каркаса, не приёмка | 0 |

### 4.1. Примечание о среде (CRLF), не дефект кода

В начале волны в worktree был `core.autocrlf=true`, файлы выкладывались с CRLF, и тест
`tests/trust-approval.test.mjs` («просмотр состояния не расходует approval…», сравнение `split('\n')`)
падал с `AssertionError` на `\r` в конце строки. После нормализации Lead (LF, `core.autocrlf=false`)
те же тесты дают 19/19 pass, exit 0. Это была среда, а не содержательный дефект; в отчёте не считается дефектом.

## 5. Проверка утверждений пакета WP-01 (Identity)

Источник утверждения — коммит `217818a`/`2beff57`, диффы `docs/wp-00/04,05,06` и тесты пакета.

| Утверждение | Метод проверки (свой прогон) | Факт |
|---|---|---|
| Owner и anchor-signer — раздельные ключи, домены не пересекаются | RT-05: ключом анкера подписывается approval и проверяется в trust root; ожидается APPROVAL_SIGNATURE_INVALID | подтверждено |
| Приватные файлы закрыты DPAPI и ACL текущего пользователя | RT-09: разбор owner.key/anchor.key (domain=wrapped-private-key, wrapping=dpapi-current-user), `readAcl` для secretsDir и owner.key | подтверждено: 1 ACE, текущий SID, Allow, AreAccessRulesProtected=true |
| Control по-прежнему не получает ключи | RT-14: рабочие входы не импортируют `packages/trust` | подтверждено |
| Ключи не попадают в репозиторий, runDir, trust root и не заменяют существующие | RT-09: createTrustRoot с secretsDir в репозитории/runDir/вложенном trust root; RT-15: git-сканирование | подтверждено (когда runDir передан) |
| loadTrustRoot загружает только публичные ключи | RT-09/код: trust = `{owner, anchor-signer}` из `.pub`; приватные не читаются | подтверждено |
| Principal: роли, запрет owner+runner, отзыв, SID | тесты пакета 19/19 (включая trust-identity) + RT-07 | подтверждено |

## 6. Проверка утверждений пакета WP-02 (Approval и consumption)

| Утверждение | Метод проверки (свой прогон) | Факт |
|---|---|---|
| Подпись на точные входы; изменение любого поля ломает подпись | RT-05, RT-07 | подтверждено: APPROVAL_SIGNATURE_INVALID / APPROVAL_MISMATCH |
| CREATE_NEW закрепление approval; повтор id с другим содержимым не перезаписывает | RT-05 | подтверждено: CONTRACT_INVALID, файл байт-в-байт прежний |
| Расход читает неизменяемый файл trust root, часы процесса | RT-04/RT-06/код `readStoredApproval`, `trustedNow`; `now` запроса не принимается | подтверждено |
| Отзыв, прочитанный до расхода, не открывает ACK | RT-03; гонка отзыва — тест пакета 19/19 | подтверждено: APPROVAL_REVOKED, consumption нет |
| Неполный файл расхода не заменяется и ACK не даёт | RT-16/L-07 (матрица), тест пакета | подтверждено: CONSUMPTION_INCOMPLETE, файл `{` не перезаписан |
| Один runId — идемпотентно без второго ACK; другой runId — APPROVAL_REPLAY | RT-06 | подтверждено |
| Два процесса, один approval, разные runId — не больше одного ACK (L-09) | матрица `run-matrix` L-09, тест пакета | подтверждено: 1 ACK, второй APPROVAL_REPLAY |
| Срок 15 минут, issuedAt/expiresAt | RT-04 | подтверждено |

Вывод baseline: утверждения принятых WP-01/WP-02 **воспроизводятся** на ревизии 0e7e6c2 своими прогонами.
Это не отменяет открытые риски R-01/R-02 (см. REDTEAM-REPORT.md).

## 7. Границы baseline

- Только Windows, только изолированный локальный стенд 127.0.0.1, временные каталоги %TEMP%.
- ЦИЗ/Dev не подключались; бизнес-мутаций вне стенда нет.
- Полный `npm test` и `npm run test:races` Red Team не запускал (это шаг Lead на интеграции, ~2 мин/27 с);
  проверялись trust-тесты пакетов и собственные атаки.
- Секреты (owner.key, anchor.key, ключ стенда, Bearer) не записывались в отчёты, снапшоты, evidence и сообщения.
