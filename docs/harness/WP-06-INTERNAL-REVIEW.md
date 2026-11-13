# WP-06 — внутреннее независимое ревью: интеграция доверенного входа

Ревьюер: Agent B (автор WP-05, код WP-06 не писал). Код интеграции не изменялся.
Проверяемая ревизия: `feat/adaptant-02-trust-integration`, SHA `53b1115b5efd4c9c2be48452c3fc523b19b56df8`.
Предыдущая проверенная ревизия: `077bca4` (FIX REQUIRED по F-01). Дата повторной проверки: 13.11.2026.

**Вердикт по ревизии `53b1115`: ACCEPT (в границах внутреннего ревью WP-06).**

Метод: чтение `git diff 077bca4..53b1115` по файлам WP-06 и фактический запуск кода в отдельном detached-worktree ровно на `53b1115` (ветка может уезжать вперёд; прогоны сделаны на зафиксированном SHA). Код интеграции не изменялся; worktree после проверки удалён. Пробы — во временных каталогах вне репозитория.

## 1. Что изменилось с 077bca4

- `apps/control/trusted.mjs`: добавлен `assertTrustedPass` — PASS из общего терминального результата `start()`/`reconcile()` проверяется через `observeTrustedVerdict`; без годного анкера выбрасывается `INTEGRITY_ERROR`. `dispatchApproved` удалён.
- `tests/trust-integration.test.mjs`: регрессии T-11 (adopt старого PASS) и T-12 (потеря анкера для start и reconcile).
- Изменения `packages/trust/policy.mjs`/доков — из соседних пакетов, в границы WP-06 не входят; полный `npm test` покрывает их регрессии.

## 2. Фактические прогоны (detached worktree, ровно 53b1115)

| Команда | Факт |
|---|---|
| `node --test tests/trust-integration.test.mjs` | **12 tests / 12 pass / 0 fail**, exit 0, ~72 s (повторный прогон — 12/12, ~69 s) |
| `npm test` | **257 tests / 257 pass / 0 fail**, exit 0, ~298 s |
| `npm run schemas` | exit 0, диффа схем 0.1 нет |
| `apps/control/run.mjs` | 0 импортов `packages/trust`; `dispatchApproved` в trusted.mjs — 0 совпадений |
| `git status --porcelain` | пусто; HEAD = `53b1115` |

Примечание о стабильности: один промежуточный полный прогон `npm test` на этой же ревизии дал один флейк T-08 (13 s; деталь не сохранена, повторный полный прогон 257/257 exit 0, изолированный T-08 и два прогона файла зелёные). Это не воспроизводится и не связано с F-01; помечено как среда/нагрузка, рекомендуется наблюдение в WP-07.

## 3. Повторная проверка F-01 (обе пробы, независимо)

| Проба | Факт на 53b1115 |
|---|---|
| Adopt старого PASS: старый `start()` доводит прогон до PASS, затем `startTrusted` на том же runId | `startTrusted` выбрасывает `INTEGRITY_ERROR` («PASS доверенного прогона не подтверждён анкером»); PASS не возвращён; anchor/consumption/terminal-choice отсутствуют; `observeTrusted.passed=false` (inconsistent/INTEGRITY_ERROR); mutationCount не вырос (1 старая), verdict 1. |
| Потеря анкера: доверенный PASS, удалён `anchors/<id>.json`; повторные `startTrusted` и `reconcileTrusted` | Оба выбрасывают `INTEGRITY_ERROR`; PASS не возвращён; `observeTrusted.passed=false`, `verdict=null`, `reason=ANCHOR_MISSING`; mutationCount не вырос (1), verdict 1. |

F-01 закрыт. Регрессии T-11/T-12 проходят в составе файла и полного набора.

## 4. Повторно подтверждённые факты по вопросам 1–9

| # | Факт на 53b1115 |
|---|---|
| 1 | T-A: просроченный/подменённый approval → verdict `BLOCKED`, `mutationCount=0`, `READY` нет, `browser.pid` нет, consumption нет, request evidence 0, число chrome.exe до/после не изменилось (34→34); T-10 подтверждает отсутствие `REQUEST_DURABLE`. |
| 2 | T-B: `consumption.consumedAt ≤ intent.observedAt ≤ request.observedAt` (20 мс и 129 мс), decision-файлы `preflight`+`dispatch`. Неполный consumption после preflight → `BLOCKED/AUTH_UNAVAILABLE`, intent 0, mutation 0, ACK не ушёл, файл расхода не заменён. Расход durable до intent/ACK; crash после расхода → повторный вход `INCONCLUSIVE`, mutation 0, один consumption, один verdict, расход не переигран. |
| 3 | T-C: стенд погашен сразу после durable `mutation-intent` → `INCONCLUSIVE/ENVIRONMENT_CHANGED`, `mutationCount=0`, request evidence 0, verdict ровно 1. Второго POST нет. |
| 4 | T-D: PASS только с анкером (T-01); без подписанта — `INCONCLUSIVE/EVIDENCE_MISSING`, mutation 1, choice `budget-inconclusive`, verdict 1; повторный reconcile второй verdict не пишет; `publishTerminalVerdict` получает `trust/trustRoot` и проверяет анкер (WP-05 D-01 интегрирован). |
| 5 | T-E: `observeTrusted` не показывает PASS без анкера; для INCONCLUSIVE `passed=false`, consumption до/после идентичен, mutation не меняется. После удаления анкера observe даёт `verdict=null`, `ANCHOR_MISSING`; startTrusted/reconcileTrusted при этом отказывают (F-01). |
| 6 | Старый `start()` отвергает `approvalId`, `approval`, `trustRoot`, `adapter`, `adapterId`, `standPublicKey`, `signerPipe` → `CONTRACT_INVALID`, mutation 0. |
| 7 | Чужой SID (T-03), отозванный approval (T-05), approval на другие входы (T-06), `kind=dev` (T-07), чужой `standPublicKey` (проба) → 0 мутаций; коды `AUTH_UNAVAILABLE`/`CONTRACT_INVALID`/`ENVIRONMENT_CHANGED`. |
| 8 | `buildFacts` — ровно 11 ключей §5.3; лишний/недостающий/вложенный ключ и лишнее поле attestation → `DENY/CONTRACT_INVALID` (не ALLOW). |
| 9 | `npm test` 257/257 exit 0; `npm run schemas` exit 0 без диффа; `run.mjs` без импортов `packages/trust`; запрещённые файлы не изменены. |

## 5. Статус замечаний предыдущего ревью

| ID | Статус |
|---|---|
| WP06-F-01 (HIGH) | **Закрыт**: `assertTrustedPass`, пробы adopt и потеря анкера дают `INTEGRITY_ERROR`, регрессии T-11/T-12 зелёные. |
| WP06-F-02 (LOW) | **Закрыт**: мёртвый `dispatchApproved` удалён (0 совпадений). |
| WP06-F-03/F-04/F-05 (INFO) | Приняты Lead как границы и зафиксированы в WP-06-REPORT: preflight-DENY через общий catch; `options.trust` — in-process мост внутри границы R-04; `standPublicKey` обязателен по факту (fail-closed). |

## 6. Остаточные риски и границы

- L-01: один невоспроизведённый флейк T-08 в полном прогоне под нагрузкой; в WP-07 держать под наблюдением (повторные прогоны зелёные).
- L-02: границы локальной 0.2 действуют: ACL/DPAPI одного SID не изолируют Control от произвольного кода той же учётной записи (R-04); `options.trust` не является внешним входом.
- L-03: анкер удостоверяет связку и неизменность candidate, не бизнес-истину; candidate обязан строиться доверенным Verification (D-02, docs/changes/004).

## 7. Вердикт

**ACCEPT** для ревизии `53b1115b5efd4c9c2be48452c3fc523b19b56df8` в границах внутреннего ревью WP-06: F-01 закрыт и покрыт регрессиями, обязательные вопросы 1–9 подтверждены фактическими прогонами, инварианты 0.1 не ослаблены. Это внутреннее ревью, не внешняя приёмка WP-08; остаточный флейк T-08 и границы R-04/D-02 остаются зафиксированными.
