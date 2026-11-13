# WP08-09 — ЭТАП I: КАРТА ПУТЕЙ К TRUSTED PASS, ГРАНИЦЫ ДОВЕРИЯ, КОНФЛИКТ НЕЗАВИСИМОСТИ

## 1. Входы доверенного контура (`apps/control/trusted.mjs`)

| Вход | Строка | Назначение |
|---|---|---|
| `startTrusted` | 792 | единственный запуск доверенного прогона, требует root/trustRoot/approvalId/issuer/subject + `anchorKeyPath` |
| `observeTrusted` | 815 | чтение состояния; PASS проходит `assertTrustedPass` |
| `cancelTrusted` | 848 | отмена через capability (`createTrustedCancelCapability`) |
| `reconcileTrusted` | 859 | восстановление; отдельный внутренний путь |

Legacy-вход `signerPipe` явно отвергается (`CONTRACT_INVALID`, строки 771, 788) — старый обход подписанта закрыт.
Generic API не может продолжить trusted-run без capability: `isTrustedRunnerContext` (строки 36–40),
проверки в run.mjs (905, 978, 1024), `TRUSTED_RUN_REQUIRES_TRUSTED_ENTRY` (run.mjs 95, 99, 103, 492, 876).

## 2. Точки PEP перед мутацией

- `preflight` — `decide()` по facts, решение durable (`persistDecision`).
- `dispatch` — повторная аттестация среды непосредственно перед POST (`attestLiveEnvironment`).
- Pinned dispatch: `preparePinnedDispatch` / `verifyDispatchResponse` — привязка ответа к соединению.
- `consumeDispatch` — расход approval с ACK; без подтверждения расхода ACK не выдаётся (строка 599).

## 3. Путь к PASS (`publish`, строки 629–748)

PASS возможен только при одновременном выполнении:
1. Наличие mutation-intent; кандидат принимается **только** от `verifyWithTrustedWorker` (строка 639), а не извне.
2. `canceled && PASS` → отказ (646). Наличие `cancel.request` при восстановлении → PASS запрещён (491).
3. `prepareVerificationReceipt` подписантом: регистрация ключа Verification только по приватному каналу с PID (655–664).
4. Повторная сверка evidence head после остановки Worker (678–680) — новые evidence после receipt запрещены.
5. Анкер: `anchorWithinBudget`, сверка `candidateSha256` (685–695); нет анкера → PASS не публикуется (704).
6. Terminal-choice пишется через `publishTerminalChoiceWithCancellationBoundary` (50–60) — граница с отменой.
7. `publishTerminalVerdict` проверяет анкер (735).
8. `assertTrustedPass` (777–785): даже если verdict=PASS получен, он перепроверяется через `observeTrustedVerdict` до выдачи наружу.

## 4. Recovery (`recoverPendingPublication`)

- Предыдущий подписант: если процесс жив и identity совпала — `PUBLICATION_PENDING` (459);
  если identity неизвестна — отказ (462). Аналогично для Verification Worker (505–509).
- Receipt 0.2.2 сверяется по runId/manifest/approval/anchorId/candidate/evidenceChainHead/readSetSha256/
  processIdentity/PID/parentPid/creationTime/lease token (522–533).
- Durable candidate без receipt → PASS не восстанавливается (515); candidate конфликт → `CANDIDATE_CONFLICT` (538).
- `cancel.request` блокирует восстановление PASS (491).

## 5. Конфликт независимости (обязательная маркировка)

По `git log --author` в проверяемом репозитории DeepSeek Harness — автор коммитов, затронувших:

`apps/control/run.mjs`, `apps/control/trusted.mjs`, `apps/browser/trusted-worker.mjs`,
`apps/verification/trusted-worker.mjs`, `packages/trust/facts.mjs`, `packages/trust/keygen.mjs`,
`packages/trust/windows-sid.mjs`.

Это ядро доверенного контура. Следовательно, заключение по этим файлам — **самопроверка**, не независимая
сертификация. Компоненты Luna (`anchor.mjs`, `environment.mjs`, `approval.mjs`, `anchor-signer.mjs`,
тесты W2) проверяются как внешние, но их взаимодействие с self-audit-кодом требует второго проверяющего.
Владельцу предлагается сохранить дополнительный обзор (заявлено владельцем).

## 6. Модель угроз (A1–A3, `docs/harness/WP08-REMEDIATION-ARCHITECTURE.md`)

A1: Control, Verification Worker, anchor-signer — доверенные процессы.
A2: противник пишет любые файлы в runDir и trust root, кроме приватных ключей.
A3: происхождение — только ключами в памяти доверенных процессов и приватными каналами.
Риски вне A1–A3 (изоляция процессов одного SID, компрометация родительского Control, злоупотребление
fault-хуками) аудит обязан документировать отдельно от нарушений заявленных гарантий.

## 7. Наблюдения для этапа II (не дефекты до проверки)

- **OBS-01.** В продуктовом коде `publish` есть fault-хуки (`afterVerificationReceiptBeforeCandidate`,
  `afterAnchorBeforeTerminalChoice`, `afterTerminalChoiceBeforeVerdict`) с паузами 30 с, доступные через
  публичные `startTrusted({fault})` / `reconcileTrusted({fault})` и переменную `QA_ADAPTANT_FAULT`.
  Проверить в этапе II: могут ли они создать состояние, из которого recovery выдаёт PASS некорректно,
  и является ли это нарушением A1–A3 или риском вне модели.
- **OBS-02.** Кандидат в `publish` берётся из результата Worker, но проверка `validateVerdictCoverage` применима
  только к verdict Worker (строка 238) — проверить покрытие для FAIL/INCONCLUSIVE путей.
- **OBS-03.** `environment.processAlive` и identity-проверки зависят от ОС; на не-Windows поведение не проверялось.

## 8. Вывод этапа I

Все заявленные входы и точки PEP присутствуют в коде на ожидаемых местах; legacy-обход подписанта закрыт.
Вопрос «можно ли получить ложный PASS» не решён — переносится в этап II с конкретными атаками.
