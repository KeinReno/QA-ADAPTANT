# WP-06 — внутреннее независимое ревью: интеграция доверенного входа

Ревьюер: Agent B (автор WP-05, код WP-06 не писал). Код интеграции не изменялся.
Проверяемая ревизия: `feat/adaptant-02-trust-integration`, SHA `077bca4420049ba767ab5a0c62d1e4d21f0aaa84`, worktree `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\integration`.
Дата: 13.11.2026.
Метод: чтение `git diff 0e7e6c2..077bca4` и фактический запуск кода. Ветка уехала вперёд во время ревью, поэтому все заявленные ниже прогоны выполнены в **отдельном detached-worktree ровно на 077bca4** (`git worktree add --detach ... 077bca4`), после прогонов worktree удалён. Пробы — во временных каталогах вне репозитория.

## 1. Проверенные файлы

`apps/control/run.mjs` (65 строк diff, врезки T-A/T-B/T-C/T-D и запрет старых аргументов), `apps/control/trusted.mjs` (301 строка, новый), `packages/trust/facts.mjs` (81 строка, новый), `packages/trust/windows-sid.mjs` (33 строки, новый), `tests/trust-integration.test.mjs` (256 строк, 10 тестов).

`git diff 0e7e6c2..077bca4` затрагивает 25 файлов; `packages/contracts/`, `schemas/`, `docs/contract-freeze.json`, `packages/core/*`, `apps/browser/worker.mjs`, `apps/verification/worker.mjs` не изменены. `apps/control/run.mjs` не содержит импортов `packages/trust` (0 совпадений).

## 2. Фактические прогоны (detached worktree, ровно 077bca4)

| Команда | Факт |
|---|---|
| `node --test tests/trust-integration.test.mjs` | **10 tests / 10 pass / 0 fail**, exit 0, ~66 s |
| `npm test` | **248 tests / 248 pass / 0 fail**, exit 0, ~292 s |
| `npm run schemas` | exit 0, диффа схем 0.1 нет; дерево чистое |
| `node apps/control/...` (пробы ниже) | см. §3 |

HEAD на момент фиксации ревизии: `077bca4`; `git status --porcelain` в detached worktree пуст.

## 3. Независимые пробы и ответы на обязательные вопросы

| # | Вопрос | Факт |
|---|---|---|
| 1 | T-A: отказ до Chromium и токена | С просроченным approval: verdict `BLOCKED`, `mutationCount=0`, events = только `STATE` (PREFLIGHT/FINISHED), `READY` нет, `browser.pid` нет, `consumption` нет, request evidence 0, verdict 1, число chrome.exe до/после не изменилось (34→34). Тест T-10 проверяет те же факты + отсутствие `REQUEST_DURABLE`. |
| 2 | T-B: порядок и ACK без расхода | Successful PASS: `consumption.consumedAt <= intent.observedAt <= request.observedAt` (11 мс и 180 мс), decision-файлы `preflight`+`dispatch`. Подложен неполный `consumption` после preflight: dispatch вернул `BLOCKED/AUTH_UNAVAILABLE`, intent 0, ACK не ушёл, mutation 0, файл расхода не заменён. По коду `trust.dispatch` вызывает `consumeDispatch`, требует `ack===true` и только затем run.mjs пишет mutation-intent и ACK. Обратный случай: расход durable до intent/ACK; при падении Control после расхода расход остаётся (проба crash: consumption есть, повторный вход → INCONCLUSIVE, mutation 0, один consumption, один verdict, расход не изменён и не переигран). |
| 3 | T-C: гибель стенда между INTENT и HTTP_REQUEST | Стенд погашен сразу после durable `mutation-intent`: verdict `INCONCLUSIVE/ENVIRONMENT_CHANGED`, `mutationCount=0`, request evidence 0, verdict ровно 1 (`evidence = mutation-intent, verdict`). POST не ушёл, второго POST нет (счётчик стенда 0). |
| 4 | T-D: PASS только с анкером; без подписанта | T-01: PASS, choice `anchor`, анкер проверен, 1 request, 1 verdict, `observeTrusted.passed=true`. T-08 (`signerPipe=null`): `INCONCLUSIVE/EVIDENCE_MISSING`, `mutationCount=1`, choice `budget-inconclusive`, verdict ровно 1. Повторный `startTrusted` после терминального результата вернул тот же INCONCLUSIVE, mutation 1, verdict 1, consumption 1. `publishTerminalVerdict` получает `trust/trustRoot` и проверяет анкер (интегрирован WP-05 D-01, SHA `c168465`). |
| 5 | T-E: observe без PASS и без расхода | Для INCONCLUSIVE: `passed=false`, `verdict=INCONCLUSIVE`, `publication=terminal`, байты consumption до/после `observeTrusted` идентичны, mutation не изменился. После удаления анкера у терминального PASS: `observeTrusted` даёт `passed=false`, `verdict=null`, `publication=inconsistent`, `reason=ANCHOR_MISSING`, consumption не изменён. |
| 6 | Старый start() и доверенные аргументы | `start()` отвергает `approvalId`, `approval`, `trustRoot`, `adapter`, `adapterId`, `standPublicKey`, `signerPipe` кодом `CONTRACT_INVALID` (все 7 проверены), mutation 0. |
| 7 | Подмены → 0 мутаций | Чужой SID — T-03 `BLOCKED/AUTH_UNAVAILABLE`, 0; отозванный approval — T-05, 0; approval на другие входы — T-06 `CONTRACT_INVALID`, 0; `kind=dev` — T-07 `ENVIRONMENT_CHANGED`, 0; чужой `standPublicKey` — проба: `BLOCKED/ENVIRONMENT_CHANGED`, 0. |
| 8 | Форма facts §5.3 | `buildFacts` даёт ровно 11 ключей: `approval, authenticatedSid, environment, expected, issuer, now, phase, principal, registry, run, trustStore`. Лишний верхний ключ, отсутствующий `registry`, лишнее поле в `run`, лишнее поле в `environment.attestation` → `decide` возвращает `DENY/CONTRACT_INVALID` (не ALLOW). |
| 9 | Инварианты 0.1 | `npm test` 248/248 exit 0; `npm run schemas` exit 0, диффа нет; в `apps/control/run.mjs` 0 импортов `packages/trust`; запрещённые каталоги/файлы не изменены. |

## 4. Дефекты

### WP06-F-01 — HIGH (блокирующий для ревизии 077bca4). Доверенные входы возвращают PASS без проверки анкера на уже терминальном прогоне

Где: `apps/control/trusted.mjs` — `startTrusted()` возвращает результат `start()`, `reconcileTrusted()` — результат `reconcile()`, без `observeTrustedVerdict`. В `apps/control/run.mjs` `terminalResult`/`verifyAndPersist` отдают уже записанный терминальный verdict до обращения к `trust.publish`.

Факты (две независимые пробы на 077bca4):

1. **Adopt старого прогона.** Прогон выполнен старым `start()` (путь 0.1) до PASS. Затем `startTrusted` с тем же bundle/runId и валидным approval вернул `verdict=PASS`, хотя `terminal-choice.json` нет, анкеров 0, consumption по approval нет, `observeTrusted` даёт `passed=false`, `publication=inconsistent`, `reason=INTEGRITY_ERROR`. mutationCount=1 (это старая мутация старого входа; новых нет).
2. **Потеря анкера после публикации.** Легитимный доверенный PASS опубликован с анкером; файл `trustRoot/anchors/<id>.json` удалён. Повторный `startTrusted` вернул `PASS` (reason `NONE`), `reconcileTrusted` тоже вернул `PASS`; `observeTrusted` при этом `passed=false`, `reason=ANCHOR_MISSING`. mutation/verdict те же (новых нет).

Нарушение: инвариант §6.2 «Ни одного PASS без годного анкера»; требование T-E «PASS только при полной связке»; рекомендация R-01 ревью WP-05 (единственный источник PASS — `observeTrustedVerdict`). Severity HIGH по границе доверия: вызывающий `startTrusted` получает PASS, который доверенный наблюдатель отвергает.

Примечание (вне проверяемой ревизии): в более позднем HEAD `8674816` уже добавлен `assertTrustedPass`, и та же проба adopt на нём завершается `INTEGRITY_ERROR` (проверено). В ревизии `077bca4` этого guard нет. Требование к финальной интеграции: сохранить этот guard (или эквивалент) и регрессию на adopt старого PASS + потерю анкера.

### WP06-F-02 — LOW. Мёртвый код

`apps/control/trusted.mjs:` переменная `dispatchApproved` объявляется и присваивается (`line 86, 170`), но нигде не читается. Не влияет на безопасность, удалить.

### WP06-F-03 — INFO. Preflight-отказ обрабатывается общим catch run()

При DENY на T-A `trust.preflight` бросает, и run.mjs обрабатывает это общим catch: verdict корректен (`BLOCKED`), но событие `TRUST_DENIED`/`phase` для preflight не пишется, `trustDenial.phase` не используется. На доказательность и инварианты не влияет.

### WP06-F-04 — INFO. Внутренний `trust`-контекст доступен старым публичным функциям

`start/observe/cancel/reconcile` принимают `options.trust`, и `assertOldEntryOptions` это поле не запрещает. Это in-process мост для `*Trusted`, а не внешний вход; старый вход сам по себе не обещает доверенный PASS, а `startTrusted` отдельно проверяет анкер (после исправления F-01). Зафиксировать как границу локальной 0.2.

### WP06-F-05 — INFO. `startTrusted` не требует `standPublicKey`

Без `standPublicKey` аттестация среды падает (fail-closed), доверенный прогон не начнётся. Это не обход, но ошибка конфигурации выглядит как `ENVIRONMENT_CHANGED`; желательно явное требование аргумента.

## 5. Что подтверждено и не является дефектом

- Порядок T-B: `decide → consumeDispatch → mutation-intent → ACK`; ACK без полного расхода не выдаётся (подложенный неполный consumption → отказ, 0 intent, 0 мутаций).
- T-C: гибель стенда после INTENT до HTTP_REQUEST → POST не уходит, 0 мутаций, один INCONCLUSIVE; второго POST нет.
- T-D: без подписанта PASS не публикуется, ровно один INCONCLUSIVE/EVIDENCE_MISSING; повторный вход не пишет второй verdict.
- T-E (наблюдение): `observeTrustedVerdict` не показывает PASS без анкера и не расходует право; байты consumption не меняются.
- Старый `start()` отвергает все доверенные аргументы; чужие SID/ключ стенда/входы/вид `dev`/отзыв дают 0 мутаций.
- Форма facts строго 11 ключей; расхождения → DENY CONTRACT_INVALID.
- Полный `npm test` 248/248, `npm run schemas` без диффа, `run.mjs` без импортов `packages/trust`.

## 6. Вердикт

**FIX REQUIRED** по ревизии `077bca4420049ba767ab5a0c62d1e4d21f0aaa84`: один блокирующий дефект WP06-F-01 (доверенные `startTrusted`/`reconcileTrusted` возвращают PASS без полной связки анкера на уже терминальном прогоне). Остальные обязательные вопросы 1–9 подтверждены фактами, P0 не найдено.

Обязательно до ACCEPT: guard уровня `assertTrustedPass` (PASS из `start`/`reconcile`/`terminalResult` допустим только после `observeTrustedVerdict.trusted && passed`) + регрессии: «adopt старого PASS-прогона через startTrusted → отказ, не PASS» и «анкер удалён после публикации → startTrusted/reconcileTrusted не возвращают PASS» (в более позднем HEAD уже реализовано, проверить в финальной интеграции).

Желательно: WP06-F-02 (мёртвый код), F-03/F-05 (диагностика/конфигурация), F-04 зафиксировать в отчёте как границу.

## 7. Воспроизводимость

Все прогоны и пробы — на detached worktree `077bca4` (node_modules — junction на корневой). Код интеграции не изменялся; после ревью временный worktree удалён. Пробы хранились во временных каталогах вне репозитория.
