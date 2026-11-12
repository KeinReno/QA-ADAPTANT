# Приёмка — рабочее состояние 12 ноября 2026

Режим CI и приёмки набора: `npm test` (`--test-concurrency=1`). Гонки остаются в `npm run test:races`. Подробности: `docs/ci-test-mode.md`.

Общая готовность: **CONDITIONAL ACCEPT** локального изолированного ядра, не Stable и не интеграция с ЦИЗ. Дельта-приёмка Evidence Store это подтвердила. Исполнитель закрывает остаточные D-01–D-04 и не объявляет Stable сам. Набор тестов — 59. Локальный реестр не авторизует операции ЦИЗ. Проверенные схемы, браузерный localhost-стенд и настоящий Dev — разные уровни подтверждения.

| Задача | Исполнитель | Статус | Фактическое доказательство | Граница |
|---|---|---|---|---|
| Автономный каталог и исходный мастер-план | Astra | ACCEPTED | SHA256 master-plan `98a938237c305f20695e8b3582c3da427e2c7f08f54a41e3c39eed184ed52050` | исходный файл не изменён |
| Аудит архивов и локальных исходников ЦИЗ | Astra, Luna | ACCEPTED как source audit | `docs/ARCHIVE-AUDIT.md`, `docs/CIZ-SOURCE-AUDIT.md` | deployed Dev не подтверждён |
| Шесть контрактов и schemas | Astra; review Luna | ACCEPTED для реализации | `packages/contracts`, `schemas`, `docs/CONTRACT-REVIEW.md` | изменения только через процедуру review |
| Машинные guards контрактов | Astra | REVIEW | 12/12 unit-тестов | не браузерная приёмка |
| Control / Browser / Verification / Evidence Store | Kimi, затем Grok как исполнитель | REJECT, исправления на повторной проверке | независимый отчёт REJECT; затем пять прогонов 47/47 и исходные репродукторы владельца, замка, fixture, отмены и аварии | исполнитель свой результат не принимает; ЦИЗ не открыт |
| START / OBSERVE / CANCEL / RECONCILE | Kimi, затем Grok | REVIEW | повторный START, observe, cancel в процессе и из другого процесса, lease fixture, reconcile после гибели Control | один локальный Control Plane, не распределённый консенсус |
| Локальный стенд из 12 обязательных отказов и 7 регрессий аудита | Kimi, затем Grok | REVIEW | матрица ниже; 40/40, exit code 0 | не Dev и не CIZ Adapter |
| Автономная demo | Grok, повторный прогон | REVIEW | `node scripts/demo-local.mjs`: exit 0, PASS/NONE, mutationCount=1, independentReadCount=1 | каталог `data/demo-1794491933469`; не приёмка |
| Безопасный Dev fixture и OP-B | WP-03 | TODO | не запускался | мутации Dev не выполнялись |
| Intelligence, полный OP-A…F, Workbench | WP-04/05 | TODO | не реализованы | полный 23-шаговый сценарий остаётся обязательством |

## Команды и фактический результат

```text
node --version                         → v24.16.0
node --test --test-timeout=45000 tests/*.test.mjs
                                       → пять раз подряд: 47 passed, 0 failed, exit code 0
npm run schemas                        → exit 0, схемы без diff
```

Исходные репродукторы из `C:\Users\gvi\AppData\Local\Temp\kaiden-audit` после исправления: гонка START больше не публикует чужой INCONCLUSIVE и не ломает журнал; удаление locks и leases не создаёт второй объект; повторный fixtureId блокируется; CANCEL во время VERIFYING даёт INCONCLUSIVE / CANCELED; 8/8 инъекций аварии остаются INCONCLUSIVE; подмена хвоста evidence даёт INTEGRITY_ERROR; десять одновременных пар START не отдают сырой EEXIST и делают один POST. Скрипт самоутверждения падает у себя на отсутствии independent-read; те же данные дают BLOCKED и ноль мутаций. Каталог `pristine-a` для полного набора атак evidence отсутствует, этот скрипт не переигрывался. Подробности — `HANDOFF.md` и `docs/changes/002-ownership-evidence-trust.md`.

Прогон 12 ноября 2026 на этой машине. Состав: 12 контрактных unit-тестов, 12 fault-тестов, 8 lifecycle/integrity-тестов, 1 runtime и 7 регрессий аудита. Для fault-кейсов проверяется фактическое число POST на стенде. Recovery-кейс завершает Control после mutation evidence, запускает новый процесс CLI и подтверждает отсутствие повторного POST.

Предыдущая запись «33 passed» относилась к прогону Kimi на Node v24.21.0. На Node v24.16.0 до сегодняшнего исправления тот же runtime давал `INCONCLUSIVE` / `WORKER_LOST`: Verification Worker падал утверждением libuv `UV_HANDLE_CLOSING` (`src/win/async.c:94`) после отправки PASS. Ненулевой код не скрывался и не превращался в PASS. После замены `process.exit` на `exitCode` и `process.disconnect()` рабочий прогон завершается кодом 0, и только тогда публикуется PASS.

## Обязательные отказы §13

| № | Сценарий | Фактический результат |
|---|---|---|
| 1 | Тело response потеряно после сохранения | INCONCLUSIVE; объект найден независимым GET; POST=1 |
| 2 | Основной объект создан, comment=null | FAIL; `comment-saved=VIOLATED`; POST=1 |
| 3 | Read-model запаздывает | PASS после bounded polling; повторного POST нет |
| 4 | Назначен неверный исполнитель | FAIL; `executor-saved=VIOLATED`; POST=1 |
| 5 | Две одинаковые кнопки | BLOCKED / ELEMENT_AMBIGUOUS; POST=0 |
| 6 | Browser crash после мутации | INCONCLUSIVE / WORKER_LOST; POST=1 |
| 7 | Evidence пропущено или повреждено | INCONCLUSIVE либо integrity-отказ; PASS запрещён |
| 8 | Другой scenario/snapshot при повторном запуске | CONTRACT_INVALID; старый терминальный результат не переписывается; POST не повторяется |
| 9 | Fingerprint среды изменился | INCONCLUSIVE / ENVIRONMENT_CHANGED |
| 10 | Неподтверждённый/чужой entity ID | INCONCLUSIVE; чужая запись не принимается |
| 11 | Обязательный эффект отсутствует | FAIL только при авторитетно прочитанном несоответствии; неполные данные → INCONCLUSIVE |
| 12 | Cleanup получает чужой объект | UNSUPPORTED; удаление отсутствует, запись сохраняется |

Дополнительно проверены: duplicate INTENT с одним durable intent, потерянный ACK без click, drift тела POST без отправки, повторный START, OBSERVE без записи, CANCEL до/после dispatch, fixture lock, tamper frozen snapshot до Browser, повреждение evidence после завершения и настоящий restart Control.

## Исправленные дефекты Astra/промежуточного кода

- Windows `fsync` read-only descriptor и утечка directory descriptor.
- Response artifact без entity, из-за которого даже нормальный путь был INCONCLUSIVE.
- Смешивание identityFields с бизнес-эффектами и невозможность доказанного FAIL.
- Повторное сетевое воспроизведение fault lost-response в стенде заменено потерей тела response после commit.
- Read-only reconciliation теперь сохраняет обнаруженную сущность даже без response evidence.
- Browser crash больше не даёт PASS.
- Worker-exit race, зависания ожидания процесса и ранняя регистрация ACK waiter.
- Browser сам проверяет frozen bundle и manifest hash до запуска Chromium.
- Терминальный результат идемпотентен; Verifier IPC reads сверяются с durable storage.

## Уровни подтверждения

- **Unit/схемы:** 12/12 в составе общего прогона 40/40.
- **Реальный браузер на локальном стенде:** fault, lifecycle, runtime и demo; demo PASS с одним POST и одним независимым GET.
- **Регрессии аудита:** поддельный терминальный PASS отклоняется; cross-process CANCEL не публикует вердикт и не оставляет POST; reconcile после гибели Control без intent даёт `INCONCLUSIVE` / `WORKER_LOST` и ноль POST; удаление файла lock не даёт второй POST; временный HTTP 503 не обрывает budget; неполная цепочка не получает `integrityVerified: true`; fixture требует bearer, фильтр `fixtureId`, идемпотентность и не считает отклонённое тело мутацией.
- **Исходники ЦИЗ:** изучены ранее; локальные ревизии зафиксированы в source audit.
- **Dev:** не открывался, бизнес-мутации и приёмка не выполнялись.
- **Независимый reviewer:** контракты ранее приняла Luna. Исправления этого прогона сделал Grok, ранее бывший аудитором. Он свой результат не принимает. Нужен другой проверяющий, который эти правки не писал.
- **Предложенная правка пункта 7:** DRAFT, пользователь не утверждал.
- **Контракты:** схемы 0.1.0 не менялись. Токен локального fixture живёт только в памяти стенда и в окружении дочернего процесса, в snapshot не пишется.

## Незакрытые риски и следующий gate

Production URL намеренно отклоняется контрактом localhost 0.1. Следующий этап — WP-03: read-only Dev preflight, подтверждение deployment/version/data, явно разрешённые accounts/fixtures и reviewed CIZ Adapter. До отдельного подтверждения владельца никаких Dev-мутаций. После доказанного OP-B возможна приёмка 0.1; Intelligence, Workbench и полный 23-шаговый сценарий относятся к следующим этапам 1.0.
