# WP08-QWEN-CORE-AUDIT — независимый аудит ядра KAIDEN QA ADAPTANT 0.2

**Аудитор:** Qoder / Qwen4-Max-Preview — Independent Security & Architecture Auditor (WP-08, P0).
**Репозиторий:** https://github.com/KeinReno/QA-ADAPTANT
**Проверяемый SHA:** `1a510a5d5929534d400dc965f58c78cf468bc270` (точный продуктовый SHA задания).
**Изоляция:** отдельный worktree `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\qwen-core-audit`, ветка `audit/wp08-qwen-independent-core`. Продуктовый код не изменялся (git status: только untracked-файлы аудита; package-lock.json, задетый npm install, возвращён к продуктовому состоянию). Merge в main и другие ветки не выполнялся. Dev/ЦИЗ не подключались. Файлы и отчёты других агентов не изменялись. Уязвимости не исправлялись.
**Дата:** 2026-11-13…14. **Окружение:** Windows, Node v24.22.1, локальный стенд 127.0.0.1, временное хранилище %TEMP%.
**Независимость:** этапы A/B выполнены до чтения материалов прежних проверок; отчёты Luna (WP08-01…15), R-D (WP08-REAUDIT), R-A/R-B прочитаны только на этапе C. Настоящий отчёт не продолжает и не подтверждает отчёт DeepSeek — анализ исходный, по коду.

---

## 1. Финальный статус

# ACCEPT — локальная 0.2 в рамках утверждённой модели A1–A3, с обязательными замечаниями

Основание:
- Новых P0/P1 внутри модели A1–A3 не обнаружено (этапы A/B/D). Все 10 угроз задания разобраны; пути к доверенному PASS (нормальный, ошибки, отмена, recovery, legacy) проверены по исходникам и воспроизведением.
- Исходные AUD-P0-01/AUD-P0-02 (REJECT Luna на 07c21c4) закрыты механизмами, которые я независимо подтвердил чтением кода: verification-attestation + session nonce + WMI-происхождение + приватный fork IPC подписанта; закреплённый сокет + stand-response подписи + переаттестация перед POST + аттестованные независимые чтения.
- Полный gate `npm test` независимо прогнан на точном SHA: **305/305 PASS, 0 fail, exit 0** (~460 с). Это unit + локальный браузер/стенд в общем итоге; отдельный подытог runner не публикует. **Настоящий Dev/ЦИЗ: НЕ ЗАПУСКАЛСЯ.**
- Независимая матрица R-D (rem-d) на том же SHA: 15/15 PASS, targetDirty=false (прочитано на этапе C; мой gate — самостоятельный прогон).

Обязательные замечания (не блокируют локальную 0.2, блокируют перенос на Dev/ЦИЗ без решения владельца):
1. **QWEN-F1 (P2):** ложный доверенный PASS воспроизведён end-to-end подменой трёх файлов публичных ключей корня доверия до старта — в рамках возможностей A2, без DPAPI-извлечения и инъекции. Это принимаемый остаточный риск WP-00 (04-THREAT-MODEL.md:18), но в перечне остаточных рисков A1–A3 он явно не перечислен, а A2 разрешает запись в trust root. Требуется явное решение владельца: перечислить компрометацию корня в остатках A1–A3 и/или ввести внешний пиннинг keyId; для Dev/ЦИЗ — отдельный Windows SID.
2. QWEN-F2…F7 (P3): тавтологичные проверки fingerprint, неактивный one-shot стенда на trusted POST, legacy pipe-поверхность, гранулярность WMI, роль для отмены, само-referential expectedKeyId — подробнее в WP08-QWEN-SECURITY-FINDINGS.md.

Статус не является: утверждением новой версии сценария владельцем, приёмкой на настоящем Dev/ЦИЗ, доказательством изоляции процессов одного SID (A1–A3 прямо называет это допущением).

## 2. Этап A — архитектура и карта путей к PASS (самостоятельно)

Полная карта границ и путей: **WP08-QWEN-TRUST-BOUNDARIES.md**. Кратко:

Двойная топология входов: legacy start/observe/cancel/reconcile (без доверия, доверенный PASS не выпускают; arity guard + assertOldEntryOptions + assertRunMode) и startTrusted/observeTrusted/cancelTrusted/reconcileTrusted (PEP T-A…T-E; контексты брендируются module-level WeakSet; экспортируемый createTrustContext намеренно не брендируется).

Цепочка доверенного PASS: preflight PDP (fail-closed, чистый decide(facts)) → закреплённый сокет стенда (createPinnedAgent никогда не открывает новый TCP) → PINNED_JOB+handle+Bearer одним IPC-сообщением → INTENT/consumeDispatch (эксклюзивный durable расход под withGuard) → HTTP_REQUEST/beforeRequestAck (живость pid + netstat-владелец порта) → переаттестация /attest на том же сокете → единственный POST → HTTP_RESPONSE/verifyDispatchResponse (stand-response Ed25519) → trust.publish → Verification Worker (эфемерный ключ, session nonce только по IPC, аттестованные чтения) → RESULT сверен с durable → anchor-signer (fork, приватный IPC, WMI-происхождение, lease, подписанный receipt 0.2.2) → signAndPublish (подписант сам перечитывает связку + паритет 0.1) → terminal-choice под publication.lock с границей cancel.request → publishTerminalVerdict → assertTrustedPass/observeTrustedVerdict (независимая перепроверка наблюдателем).

Recovery (recoverPendingPublication) не повторяет мутацию: только идемпотентное переиздание candidate/анкера после полной валидации подписанного receipt и идентичности процессов; cancel.request блокирует PASS; PUBLICATION_PENDING/WORKER_STOP_UNCONFIRMED — fail-closed.

Прочитаны полностью: apps/control/trusted.mjs (877), apps/control/run.mjs (1050), apps/browser/trusted-worker.mjs (208), apps/verification/trusted-worker.mjs (314), packages/trust/{anchor (1099), anchor-signer (736), identity (193), approval (379), policy (419), environment (883), facts (102), keygen (63), windows-sid (33), acl, dpapi}, packages/core/{store (334), bundle, canonical, evidence-policy, file-mutex, approved-registry}, packages/contracts/index.mjs (193), adapters/local/{server (254), bundle}.

## 3. Этап B — анализ угроз (10 пунктов + предпосылки A1–A3)

Предпосылки (WP08-REMEDIATION-ARCHITECTURE.md §3, утверждены §10):
- **A1:** Control/Verification/подписант — доверенные компоненты; код и память не под контролем противника.
- **A2:** противник может писать любые файлы в runDir и trust root (кроме приватных ключей), поднимать процессы того же SID, подключаться к публичным локальным каналам, делать HTTP-запросы; НЕ имеет прав отладки/инъекции и не извлекает DPAPI-ключи.
- **A3:** происхождение — ключи в памяти доверенных процессов + каналы, созданные доверенным родителем (fork IPC).

| № | Угроза | Результат |
|---|---|---|
| 1 | Происхождение/подлинность Verification | закрыто в модели: аттестация+nonce+регистрация+WMI; остаток QWEN-F5/F7 |
| 2 | Защита IPC/подписей/эфемерных ключей | закрыто: приватный fork IPC, ключи на диск не пишутся; чтение памяти — вне модели |
| 3 | Подделка verification-attestation | закрыто: зарегистрированный ключ+nonce, сверка с durable, паритет 0.1, независимый наблюдатель; обход только через QWEN-F1 (корень) |
| 4 | PID/parentPid/идентичность | закрыто с замечаниями: WMI defense-in-depth, гранулярность/PID-reuse (QWEN-F5) |
| 5 | Обход через generic/privileged API | закрыто: WeakSet, arity guard, assertOldEntryOptions, assertRunMode, signerPipe запрещён; legacy pipe — тестовая поверхность (QWEN-F4) |
| 6 | Повторный POST после краха | закрыто: durable consumption, Worker не повторяет POST, reconcile без intent не перезапускает браузер; one-shot стенда не активен на trusted пути (QWEN-F3) |
| 7 | Параллельные прогоны на одном approval | закрыто: withGuard, APPROVAL_REPLAY/CONSUMED, lease; R-01 fail-closed принят |
| 8 | Гонки CANCEL/POST/Verification/Anchor | закрыто: publication.lock + cancel.request, CREATE_NEW terminal-choice, INCONCLUSIVE при canceled/browserUncertain; R-03 микроокно принято |
| 9 | Целостность durable/Trust Root | runDir защищён связкой анкер+аттестация; **trust root — нет: QWEN-F1 воспроизведён E2E** |
| 10 | Ложный PASS через recovery | закрыто: полная валидация receipt, идентичность, cancel.request; R-D p1-02 PASS |

Разграничение: QWEN-F1 — внутренняя граница модели (принятый риск WP-00, пробел формулировки A1–A3); инъекция/DPAPI/чтение памяти — вне A1–A3 (явный остаток); расхождение WP-00:65 (DPAPI доступен того же SID) и A2 (DPAPI вне модели) зафиксировано.

## 4. Этап C — сопоставление с прежними проверками (только после собственного анализа)

- **Luna (WP08-01…15, SHA 07c21c4):** REJECT; AUD-P0-01 (подложный candidate → валидный анкер), AUD-P0-02 (подмена стенда после T-C/POST, утечка Bearer), AUD-P1-01 (слабый наблюдатель), AUD-P1-02 (V-07 recovery), P2×7. Среди P3-наблюдений Luna уже значилась «trust root не имеет целостностной привязки public-ключей (граница модели)» — мой R1 независимо подтверждает это и добавляет E2E-воспроизведение и анализ A1–A3.
- **R-A/R-B/R-C (исправления):** отчёты WP08-P0-01/02-REPORT.md описывают именно те механизмы, которые я подтвердил в коде (аттестация 0.2.1, nonce, WMI, pinned socket, stand-response 0.2.1, receipt 0.2.2). Заявления соответствуют исходникам на проверяемом SHA.
- **R-D (rem-d, WP08-REAUDIT):** базовая матрица на 07c21c4 — 11 FAIL + 2 INCONCLUSIVE; финальная на **1a510a5 — 15/15 PASS**, targetDirty=false; агрегатор без fallback-PASS; INCONCLUSIVE не считается PASS. R-D не выдаёт ACCEPT. Ограничение R-D: атаки на происхождение ключа шли через legacy pipe (в fork-топологии канал недоступен) — совпадает с моим QWEN-F4.
- **Что доказано:** закрытие исходных P0/P1/P2 на интегрированной ревизии (source + R-D + мой gate 305/305).
- **Что недостаточно/не покрыто прежними тестами:** E2E-подмена корня (QWEN-F1), тавтология fingerprint (QWEN-F2), отсутствие x-qa-run-id на trusted POST (QWEN-F3), front-running регистрации в pipe-режиме (QWEN-F4, теоретический).
- **Неподтверждённые заявления:** изоляция процессов одного SID (допущение, не доказательство); поведение на Dev/ЦИЗ (никем не проверялось). Устаревший docs/harness/05-KNOWN-RISKS.md на SHA всё ещё содержит «Открытых P0 нет» и R-07 «принят» — до ремедиации; актуальное состояние — REMEDIATION-STATUS.md и отчёты R-A/R-B/R-C (документационное рассогласование, не дефект кода).

## 5. Этап D — воспроизводящие проверки (локальный стенд + %TEMP%)

| Репо | Команда | Результат | Исходный журнал |
|---|---|---|---|
| R1 | `node repro/r1-trustroot-substitution.mjs` | exit 0: rootTakeover=true; forgedRun PASS; observeTrusted trusted=true passed=true; victimStandMutations=0, rogueStandMutations=1 | `repro/logs/r1-trustroot-substitution.log` |
| R2 | `node repro/r2-fingerprint-tautology.mjs` | exit 0: PASS при drift fingerprint; environmentReadsAfterPost=0; tautologyConfirmed=true | `repro/logs/r2-fingerprint-tautology.log` |
| R3 | `node repro/r3-one-shot-inactive.mjs` | exit 0: без x-qa-run-id mutationCount=2; с ним 403 token_revoked; workerSendsRunIdHeader=false | `repro/logs/r3-one-shot-inactive.log` |
| R4 | `node repro/r4-pipe-signer-lease.mjs` | exit 0: foreignKeyRegistration.accepted=true; leaseNotRequiredInPipeMode=true | `repro/logs/r4-pipe-signer-lease.log` |
| Gate | `npm test` | exit 0: **305/305 PASS, 0 fail**, duration ~460 с, SHA 1a510a5, дерево чистое | `repro/logs/gate-npm-test-305.log` |

Журналы — исходный stdout/stderr прогонов на SHA `1a510a5` (локальный стенд 127.0.0.1 + %TEMP%), без секретов: только keyId (хеши публичных ключей), имена pipe и журнал HTTP-запросов. R4 перезапускался для захвата журнала (pipe-имя и эфемерный keyId в логе — нового прогона, результат идентичен).

Отсутствие ошибки в существующих тестах не считалось доказательством безопасности: каждая гипотеза этапа B проверялась по исходникам и, где возможно, минимальным воспроизведением. Невоспроизводимое в рамках A2 (PID-reuse, front-running в продукте) зафиксировано как source-анализ/теоретическое, не PASS.

Разделение результатов: **unit/контракты и локальный браузер/стенд** — 305/305 в общем gate + 4 репо аудита; **настоящий Dev/ЦИЗ** — не запускался, результатов нет.

## 6. Ограничения аудита

- Одна локальная Windows-машина; локальный стенд 127.0.0.1; поведение на Dev/ЦИЗ, другом пользователе Windows, другой ОС не проверялось.
- Вне A1–A3 (инъекция/отладка, DPAPI-извлечение, чтение памяти доверенных процессов) не проверялось — это явные остатки модели.
- R4 front-running регистрации в pipe-режиме — теоретический сценарий тестовой поверхности, полностью не воспроизводился.
- WMI/PID-reuse (QWEN-F5) — source-анализ; полная проверка требует управления планировщиком PID (вне A2).
- Аудит не исправляет продукт и не объявляет утверждение новой версии сценария; внешняя приёмка — за владельцем.

## 7. Артефакты

- WP08-QWEN-CORE-AUDIT.md (этот файл) — архитектура, этапы A–D, финальный статус.
- WP08-QWEN-SECURITY-FINDINGS.md — 7 находок (P2×1, P3×6) с полями Severity/файлы-строки/условия/воспроизведение/ожидаемо-фактически/корневая причина/рекомендация.
- WP08-QWEN-TRUST-BOUNDARIES.md — карта границ B1–B13 и все пути к PASS.
- WP08-QWEN-TEST-MATRIX.json — матрица угроз, репо, сопоставление с прежними проверками, gate.
- repro/r1…r4 — самодостаточные скрипты (только %TEMP% и локальный стенд).
- repro/logs/ — исходные журналы прогонов R1–R4 и gate (305/305), захваченные на SHA 1a510a5.

Все файлы расположены в аудит-worktree `qwen-core-audit` (ветка `audit/wp08-qwen-independent-core`), SHA `1a510a5d5929534d400dc965f58c78cf468bc270`.