# WP-06 — интеграция Trust Layer в Control Plane

Исполнитель: Lead (DeepSeek Harness). Ветка: `feat/adaptant-02-trust-integration`.
База: `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31`. Продуктовый код старых модулей 0.1 не переписывался.

## Что сделано

| Файл | Роль |
|---|---|
| `apps/control/run.mjs` | точки врезки T-A, T-B, T-C, T-D; передача `trust` в `run/verifyAndPersist/reconcile`; запрет аргументов доверия на старом входе |
| `apps/control/trusted.mjs` | `startTrusted`, `observeTrusted`, `cancelTrusted`, `reconcileTrusted`, `createTrustContext` (PEP и публикация) |
| `packages/trust/facts.mjs` | сборщик фактов PDP: expected, principal, approval, environment, базовая форма 11 ключей |
| `packages/trust/windows-sid.mjs` | SID текущего Windows-токена (PowerShell WindowsIdentity, резерв `whoami`), сравнение с карточкой субъекта |

## Маршрут доверенного прогона

1. `startTrusted` читает trust root, SID вызывающего и подключает подписанта анкера по named pipe.
2. **T-A** (`preflight`): запись среды из реестра + живая аттестация (свежий challenge, ключ стенда, pid, владелец порта), проверка связки approval и реестра операций, `decide(preflight)`. Отказ → `BLOCKED` до запуска Chromium и до выдачи токена стенда.
3. **T-B** (`INTENT`): повторная живая аттестация, `decide(dispatch)`, затем durable `consumeDispatch`, и только после этого запись `mutation-intent` и ACK.
4. **T-C** (`HTTP_REQUEST`): ещё одна живая аттестация перед `EVIDENCE_ACK`; при отказе POST не подтверждается, второй POST не появляется.
5. **T-D** (публикация): durable candidate → запрос анкера в бюджет → `terminal-choice` через `CREATE_NEW` → ровно один терминальный verdict. PASS без анкера невозможен: при отсутствии подписанта или отказа связки публикуется единственный `INCONCLUSIVE`/`EVIDENCE_MISSING`. Бизнес-FAIL публикуется как `fail-without-anchor`, бизнес-INCONCLUSIVE — как `inconclusive-without-anchor`.
6. **T-E** (`observeTrusted`): PASS показывается только при полной связке (выбор `anchor`, единственный PASS-verdict, байты равны `candidateSha256`, анкер подписан ключом anchor-signer). Чтение не расходует право и не порождает POST.

Старый вход `start/observe/cancel/reconcile` отвергает `approvalId/approval/trustRoot/adapter/standPublicKey/signerPipe` кодом `CONTRACT_INVALID` и не выпускает доверенный PASS (L-08).

## Проверенные сценарии (`tests/trust-integration.test.mjs`, 9/9, живой стенд и Chromium)

| Тест | Ожидание | Факт |
|---|---|---|
| T-01 | PASS только с анкером, 1 POST, 1 verdict, observeTrusted.passed | pass |
| T-02 | тот же approval на другом runId → BLOCKED, мутаций 1 | pass |
| T-03 | чужой SID → BLOCKED `AUTH_UNAVAILABLE`, мутаций 0 | pass |
| T-04 | просроченный approval → BLOCKED, мутаций 0 | pass |
| T-05 | отозванный approval → BLOCKED, мутаций 0 | pass |
| T-06 | approval на другие входы → BLOCKED, мутаций 0 | pass |
| T-07 | `kind=dev` → BLOCKED `ENVIRONMENT_CHANGED`, мутаций 0 | pass |
| T-08 | без подписанта → один INCONCLUSIVE/`EVIDENCE_MISSING`, POST=1, PASS не публикуется | pass |
| T-09 | старый `start()` с аргументами доверия → отказ, мутаций 0 | pass |

## Ограничения и риски

- **R-03** остаточная гонка между последней проверкой процесса стенда и отправкой уже разрешённого пакета. Не лечится повтором POST; в 0.2 принимается как ограничение.
- **R-04** DPAPI/ACL одного SID не отделяют Control от другого кода той же учётной записи; граница локальной 0.2, не для Dev/ЦИЗ.
- **R-05** `anchorBudgetMs` из `profile.json` не подписан криптографически (docs/changes/004 §2.6).
- Публичный ключ стенда передаётся в доверенный вход из регистрации (W-01 WP-04): подделка ключа не проходит сверку `standKeyId` и подписи, но источник ключа — вне 0.2.
- `observe` старого входа не выполняет проверку анкера: доверенный PASS доказывается только через `observeTrusted`.

## Внутреннее ревью WP-06 (Agent B) и исправления

Ревью на ревизии 077bca4: FIX REQUIRED по F-01 (HIGH) — startTrusted/reconcileTrusted возвращали PASS из уже
терминального результата start()/terminalResult без проверки анкера (adopt старого PASS; потеря анкера после публикации).
F-02 (мёртвый dispatchApproved) удалён. F-03/F-04/F-05 — INFO, зафиксированы ниже.

Исправления:
- guard `assertTrustedPass`: любой PASS из общего терминального результата проходит observeTrustedVerdict;
  без годного анкера возвращается INTEGRITY_ERROR, PASS не показывается.
- регрессии T-11 (adopt старого PASS) и T-12 (потеря анкера, start и reconcile) в tests/trust-integration.test.mjs.
- E2E доверенного прогона: 12/12.

Подтверждено ревьюером фактами на 077bca4 (до guard): T-A без Browser и без consumption, T-B порядок
расход → intent → ACK, T-C гибель стенда после INTENT → INCONCLUSIVE с 0 POST, T-D PASS только с анкером и
один verdict, T-E чтение без расхода, старый вход отвергает все доверенные аргументы, facts ровно 11 ключей.

## Границы (INFO ревью)

- F-04: старые публичные функции принимают внутренний `options.trust`. Это in-process мост, а не внешний вход:
  он не даёт возможностей мутации сверх уже доступного коду того же процесса (граница R-04) и не меняет
  поведение без переданного контекста. SID и approval проверяются внутри доверенного контекста.
- F-05: `standPublicKey` фактически обязателен — без него аттестация fail-closed.
- R-07: анкер удостоверяет связку и неизменность candidate, не бизнес-истину (docs/changes/006).

## Статус

CODE COMPLETE, INTEGRATED. Независимое внутреннее ревью WP-06: FIX REQUIRED по F-01 → исправлено, повторная
проверка на ревизии 53b1115 запрошена.