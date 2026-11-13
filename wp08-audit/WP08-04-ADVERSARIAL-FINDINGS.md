# WP08-04 — ADVERSARIAL FINDINGS

**SHA:** `07c21c4db936627df9a3c874015327ea992a335a` (продуктовый код `21edda6`).
**Окружение:** Windows, Node v24.16.0, локальный стенд 127.0.0.1, временные каталоги %TEMP%.
**Продуктивный код не изменялся.** Все запуски — собственные артефакты аудиторской команды WP-08 (не разработчиков); exit codes и JSON-логи сохранены в `wp08-audit/evidence/`.

## Сводка

| ID | Severity | Кратко |
|---|---|---|
| AUD-P0-01 | **P0** | Ложный доверенный PASS через подложный candidate/evidence + валидный анкер (= F-WP05-01, R-07) |
| AUD-P0-02 | **P0** | Ложный доверенный PASS через подмену среды после T-C/после POST; Verification не аттестует стенд (= F-WP04-03, R-03) |
| AUD-P1-01 | **P1** | Доверенный наблюдатель не проверяет evidence-покрытие/происхождение (= F-WP05-05) |
| AUD-P1-02 | **P1** | V-07: потеря уже подписанного анкерованного PASS при восстановлении (= F-WP05-02 / F-WP06-01) |
| AUD-P2-01 | P2 | R-02 обходится junction/symlink, секреты в runDir (= F-WP01-01) |
| AUD-P2-02 | P2 | Путь «только approvalId» не работает (fail-closed) (= F-WP02-01) |
| AUD-P2-03 | P2 | V-06: PASS-ветка reconcile недостижима (= F-WP05-07) |
| AUD-P2-04 | P2 | publish-ошибка → verdict без terminal-choice (= F-WP06-02) |
| AUD-P2-05 | P2 | E-04: credentialRef не проверяется, секрет другой среды доставляется |
| AUD-P2-06 | P2 | R-05: неподписанный profile.json (принят как fail-closed) |
| AUD-P2-07 | P2 (принят) | R-01: осиротевший guard-lock, fail-closed |
| AUD-P3-01…12 | P3 | Наблюдения (см. §3) |

---

## AUD-P0-01 — Ложный доверенный PASS через подложный candidate/evidence (R-07)

| Поле | Значение |
|---|---|
| Severity | **P0 (Critical)** — ложный доверенный PASS |
| SHA | 07c21c4db936627df9a3c874015327ea992a335a |
| Файлы | `packages/trust/anchor-signer.mjs:91-139` (signAndPublish), `packages/trust/anchor.mjs:546-586` (inspectEvidenceBinding), `packages/trust/anchor.mjs:605-714,726-750` (analyze/observeTrustedVerdict), `apps/control/trusted.mjs:278-297` |
| Нарушенный инвариант | PASS только после независимого чтения с проверенной цепочкой происхождения (AGENTS.md, VERDICT-POLICY); `docs/wp-00/04-THREAT-MODEL.md`: «код, умеющий править только каталог прогона, эту связку не собирает»; `docs/harness/05-KNOWN-RISKS.md`: «открытых P0 нет» |

**Сценарий (воспроизведён).** Процесс того же Windows SID, имеющий только права на каталог прогона и доступ к named pipe подписанта (R-06), без ключа owner:
1. Владелец уже выписал genuine approval на точные входы (иные входы не нужны).
2. Процесс делает `consumeDispatch` на свой `runId` (SID-строка передаётся в модуль напрямую; owner-ключ не нужен).
3. Через `RunStore.appendEvidence` сам пишет цепочку `mutation-intent → request → response → independent-read` с «успешными» полями (реального POST/GET не было).
4. Пишет durable `trust/candidate.json` = PASS (`checks=SATISFIED`, coverage сходится).
5. Настоящий `anchor-signer` принимает запрос `{runDir, approvalId, anchorId}`: он проверяет approval/consumption/снимки/цепочку/candidate, но **не проверяет происхождение candidate и не пересчитывает бизнес-checks** → **подписывает**.
6. Процесс пишет `terminal-choice=anchor` и `publishTerminalVerdict` → единственный verdict PASS.
7. Публичный `observeTrusted` → `trusted:true, passed:true, verdict:PASS, anchorStatus:ANCHOR_OK`.

**Ожидаемо:** годного анкера для подложного candidate нет; доверенный PASS не показывается.
**Фактически:** `SIGNER_RESULT {"ok":true,"verdict":"PASS"}`; `PUBLIC_OBSERVE_TRUSTED {"trusted":true,"passed":true,"verdict":"PASS","anchorStatus":"ANCHOR_OK"}`; реальная мутация отсутствовала.

**Вариант с реальной аварией (независимо, wp05):** реальный trusted-прогон с настоящим POST (`mutationCount=1`) убит SIGKILL сразу после durable response; approval израсходован (`genuineConsumption=true`), независимых чтений Verification нет (`realIndependentReads=0`). Затем candidate подменён на PASS, подписан настоящим anchor-signer → `observeTrustedVerdict trusted:true passed:true PASS`. При этом старый `observe()` на том же прогоне даёт `INTEGRITY_ERROR: VERDICT_COVERAGE` — **доверенный наблюдатель слабее 0.1-пути**.

**Доказательства:**
- `wp08-audit/tests/wp08-r07-forge-candidate.mjs`, запуск `node …` → exit 0; лог `wp08-audit/evidence/r07-forge.log`.
- Независимый повтор и crash-вариант: `wp08-audit/evidence/wp05/03-r07-lead-repro.log`, `05-v06-crash-forge.log` (exit 0), отчёт `parts/wp05/WP08-02-WP05.md`.
- Grep: ссылок на `validateVerdictCoverage` в `packages/trust/*` — 0.

**Минимальное направление фикса:**
1. **Provenance:** Verification Worker подписывает verdict + набор independent-read отдельным доменом; anchor-signer и observeTrustedVerdict обязаны проверять эту подпись и byte-identity candidate с attested-результатом.
2. **Немедленный паритет:** `observeTrustedVerdict/analyze` и подписант перед подписью вызывают `assertEvidenceRefs` + `assertTerminalEvidence`/`validateVerdictCoverage` по frozen bundle (закрывает AUD-P1-01 и no-read вариант).
3. Для Dev/ЦИЗ — отдельный SID/процесс Verification (R-04), иначе любой код учётной записи может воспроизвести и подпись verifier.

---

## AUD-P0-02 — Ложный доверенный PASS через подмену среды после T-C/после POST (R-03)

| Поле | Значение |
|---|---|
| Severity | **P0 (Critical)** — ложный доверенный PASS + утечка Bearer + мутация в неаттестованный сокет |
| SHA | 07c21c4… |
| Файлы | `apps/verification/worker.mjs:106-108,126-140,169-170` (доверяет публичным `/environment` и `/records`, не аттестует стенд), `apps/control/run.mjs:313-319` (T-C только перед POST), `adapters/local/server.mjs:68-91` (ключ стенда есть, но Verification им не пользуется), `packages/trust/anchor.mjs:546-586` (подписант не перепроверяет business-checks) |
| Нарушенный инвариант | E-07/AD-07: «мутация не уходит на новый сокет»; «Вердикт Verification PASS остаётся candidate, пока не выполнен переход в terminal» — переход опирается на неаттестованные данные; WP-08: PASS только после независимого чтения с проверенной цепочкой происхождения |

**Сценарий A (детерминированный, без гонки T-C):**
- Управляемый стенд сохраняет **неполную** запись (`comment=null`), отвечает 201; `mutationCount=1`.
- После POST (через 40 мс) стенд гасится, порт занимает rogue, который на `GET /environment` возвращает `environmentId+fingerprint`, а на `GET /records` — «полную» запись с тем же id.
- Verification Worker принимает rogue за среду → PASS → anchor → terminal PASS.
- Факт: `verdict=PASS`, `observeTrusted trusted:true passed:true`, `realStoredRecordComment=null` (реальный эффект нарушен), `rogueEnvironmentGets=2, rogueRecordGets=1`.

**Сценарий B (окно T-C→POST):**
- Наблюдатель того же SID видит появление `runDir/evidence/000002-request.json` (пишется **после** `beforeRequestAck`/T-C) — детекция ~1 мс.
- Стенд гасится, rogue поднимается на том же порту за **3 мс**; Browser POST уходит rogue через **5 мс** после детекции: `stand.mutationCount=0`, `roguePosts=1`, **Bearer стенда утёк rogue**.
- Rogue отдаёт `/environment` и `/records` с тем же entity id → Verification PASS → terminal PASS.
- Факт: `verdict=PASS`, `trusted:true passed:true`, `standMutationCount=0` (реальной мутации не было), `bearerLeakedToRogue:true`.

**Измерения (не «микроскопическое» окно):** attest→POST ≈ **147 мс**; T-C→POST ≈ **35 мс**; проверка владельца порта через netstat ≈ **46 мс** (5 замеров 41–55 мс). Подмена порта выполнена за 3 мс.

**Ожидаемо (E-07/AD-07):** DENY `ENVIRONMENT_ATTESTATION_FAILED`, мутация не уходит на новый сокет, PASS не появляется.
**Фактически:** доверенный PASS; в сценарии B мутации не было вовсе; секрет стенда раскрыт rogue-процессу.

**Доказательства:**
- `wp08-audit/tests/wp0304-06-false-pass.mjs` → 2/2 PASS, exit 0; `wp08-audit/evidence/wp0304/06-false-pass.log`, `false-pass-A.json`, `false-pass-B-attempt1.json`.
- Lead независимо перезапустил: `wp08-audit/evidence/r03-false-pass-lead.log` → 2/2 PASS, exit 0.
- Базовые R-03/E-04 атаки: `evidence/wp0304/03-attacks.log` (7/7, exit 0), `04-metrics.log`.
- Отчёт: `wp08-audit/parts/wp0304/WP08-02-WP03-WP04.md` (см. также).

**Минимальное направление фикса:**
1. **Verification обязан аттестовать среду сам**: свежий challenge-response ключом стенда до и после независимых чтений, сверка поколения/PID/владельца порта; иначе — INCONCLUSIVE/ENVIRONMENT_CHANGED, PASS не публикуется.
2. **T-C должна быть атомарна с POST**: держать проверенный дескриптор/сокет до фактической отправки (например, Control открывает соединение сам после ALLOW, либо Browser получает соединение/ capability, а не URL; либо проверять владельца порта непосредственно перед `route.continue` в том же обработчике).
3. **Anchor-signer не должен подписывать candidate без Verification-attestation** (см. AUD-P0-01, provenance).
4. R-03 переклассифицировать из P2 в P0/P1; текущая формулировка KNOWN-RISKS «микроскопическое окно» неверна (147/35 мс, детекция 1 мс, подмена 3 мс).

---

## AUD-P1-01 — Доверенный наблюдатель не проверяет evidence-покрытие и происхождение

- **Severity:** P1. **Файлы:** `packages/trust/anchor.mjs:605-714` (`analyze`), `:726-750` (`observeTrustedVerdict`); сравнить `packages/core/evidence-policy.mjs:76-95` (`assertTerminalEvidence`), `apps/control/run.mjs:421-441`.
- **Факт:** `analyze` ставит `trusted=true` по выбору/подписи/хешу candidate, но не вызывает `assertEvidenceRefs`, `assertTerminalEvidence`, `validateVerdictCoverage`. На прогоне с PASS-candidate без единого independent-read: `observeTrustedVerdict → trusted:true passed:true`; старый `observe()` → `INTEGRITY_ERROR: VERDICT_COVERAGE` (`evidence/wp05/05-v06-crash-forge.log`).
- **Влияние:** доверенный путь слабее 0.1; это один из механизмов AUD-P0-01.
- **Фикс:** вызвать `assertEvidenceRefs`+`assertTerminalEvidence`/`validateVerdictCoverage` в `analyze` (и в подписанте до подписи); при провале — `trusted:false`/INTEGRITY_ERROR. Не закрывает подлог само по себе (артефакты не подписаны), но восстанавливает паритет.

## AUD-P1-02 — V-07: восстановление теряет уже выданный анкерованный PASS

- **Severity:** P1 (матрица V-07 FAIL; «потеря подтверждённого коммита» = REJECT-триггер; поведение fail-closed).
- **Файлы:** `apps/control/trusted.mjs:190-214` (новый случайный `anchorId` при каждом publish), `apps/control/run.mjs:546-566,443-466` (reconcile заново гоняет Verification с browserUncertain), `packages/trust/anchor.mjs:251-284,313-339`.
- **Два воспроизведённых варианта:**
  - падение после записи анкера до terminal-choice: recovery генерирует новый `anchorId` → `ANCHOR_CONFLICT` → INCONCLUSIVE; анкер PASS остаётся `ANCHOR_UNLINKED` (`evidence/wp05/02-wp05-independent.log`, `[V-07-Control]`);
  - падение после anchor/candidate до verdict: `reconcileTrusted` → `CANDIDATE_CONFLICT`, verdict не пишется, автоматическое восстановление невозможно (`evidence/wp06/publication.log`, F-WP06-01).
- **Ожидаемо (V-07):** дописывается ровно выбранный candidate (PASS), бюджет заново не разыгрывается.
- **Фикс:** durable фиксировать `anchorId`/candidate; при восстановлении искать уже подписанный анкер этого runId+candidate и переиспользовать его; не пересчитывать Verification в состоянии candidate-ready; не считать CANDIDATE_CONFLICT фатальным при существующем годном candidate.

## AUD-P2-01 — R-02 обходится junction/symlink: секреты в runDir

- **Severity:** P2. **Файлы:** `packages/trust/keygen.mjs:10-24` (`assertOutsideRunStore` по строковому пути), `packages/trust/identity.mjs:126-133` (`placeTrustRoot` проверяет runDir только если он передан; keygen не передаёт).
- **Сценарий:** junction `<tmp>\aliased-run` → `<store>\runs\run-02`; `node packages/trust/keygen.mjs --secrets <junction>\secrets --trust-root <tmp>\trust` → exit 0, `owner.key` и `anchor.key` созданы в `<store>\runs\run-02\secrets`.
- **Ожидаемо:** отказ, секреты не в runDir.
- **Доказательства:** `wp08-audit/evidence/r02-junction-bypass.log`; независимо `evidence/wp0102/05-r02-junction-cli.log` (owner.key inside runs? true) и `03-r02-tests.log`.
- **Фикс:** проверять `physicalPath()`/realpath, а не строковый сегмент; отклонять любой физический путь с сегментом `runs`; либо передавать runDir/безопасные корни в keygen.

## AUD-P2-02 — Путь «только approvalId» не работает (fail-closed)

- **Severity:** P2. **Файлы:** `packages/trust/approval.mjs:275-277` (`readApprovalState` не пробрасывает `options.approvalId`), `approval.mjs:301-317` (`consumeDispatch` не передаёт approvalId в `verifyApproval`), `packages/trust/facts.mjs:37-51`.
- **Факт:** `startTrusted({approvalId})` без документа `approval` → DENY `CONTRACT_INVALID`; при переданном документе работает. Обхода/ложного PASS нет.
- **Доказательство:** `evidence/wp0102/02-approval-tests.log` (15/15, тест F-WP02-01).
- **Фикс:** пробросить `approvalId` во все пути; тест «только approvalId» в поставке.

## AUD-P2-03 — V-06: PASS-ветка reconcile недостижима

- **Severity:** P2. **Файлы:** `apps/control/run.mjs:565` (reconcile всегда `browserUncertain:true`), `:443-455`, `apps/verification/worker.mjs:184` (INCONCLUSIVE/WORKER_LOST).
- **Факт:** после аварии «durable response → нет кандидата/анкера» reconcile всегда даёт INCONCLUSIVE/WORKER_LOST; даже при живом стенде и durable response PASS не вычисляется/не анкерится. Второго POST нет (безопасно).
- **Доказательство:** `evidence/wp05/04-v06-crash-reconcile.log` (exit 0); V-06 FAIL как сформулировано.
- **Фикс:** отличать подтверждённый durable response + successful independent reads от реальной неизвестности; разрешать PASS и запрашивать анкер в бюджете, иначе INCONCLUSIVE.

## AUD-P2-04 — Ошибка публикации в run() catch пишет verdict без terminal-choice

- **Severity:** P2. **Файлы:** `apps/control/run.mjs:384-396` (catch → `persistVerdict`), `:603-610`; `apps/control/trusted.mjs:190-237`.
- **Факт:** если `trust.publish()` бросает (TERMINAL_CHOICE_INCOMPLETE / CANDIDATE_CONFLICT / ANCHOR_*), общий catch пишет терминальный INCONCLUSIVE/WORKER_LOST напрямую, без terminal-choice; реальный верифицированный результат отбрасывается, `observeTrusted` → inconsistent. PASS не публикуется (fail-closed).
- **Доказательство:** `evidence/wp06/publication.log`, F-WP06-02.
- **Фикс:** для прогонов с `trust` не вызывать `persistVerdict` из catch; закрывать только через `trust.publish` после проверки choice/candidate/анкера, иначе `INTEGRITY_ERROR/PUBLICATION_PENDING`.

## AUD-P2-05 — E-04: credentialRef не проверяется; секрет другой среды доставляется

- **Severity:** P2 (FAIL строки E-04). **Файлы:** `packages/trust/environment.mjs:74-77,83-93` (только форма), `apps/control/trusted.mjs:271` (`fixtureToken` из аргумента/env), `apps/control/run.mjs:263-267,452`.
- **Факт:** запись среды с `credentialRef='prod:foreign-secret-7'` проходит PDP (ALLOW); Browser получает и отправляет стенду `fixtureToken` другой среды; матрица E-04 требует DENY и отсутствия секрета.
- **Доказательство:** `evidence/wp0304/03-attacks.log` (тест E-04), `04-metrics.log` (`foreignSecretDeliveredToStand:true`, `standRejectedToken:true`).
- **Фикс:** реальный resolver credentialRef с привязкой к environmentId/поколению; при несовпадении — DENY `ENVIRONMENT_ATTESTATION_FAILED` до выдачи секрета; тест в матрице.

## AUD-P2-06 — R-05: profile.json не подписан

- **Файлы:** `packages/trust/anchor.mjs:113-125`. Подмена меняет `anchorBudgetMs` (1…60000); следствие — задержка/ANCHOR_TIMEOUT/INCONCLUSIVE; PASS не появляется. Принятый P2, требует подписи домена `trust-profile` отдельным changes-документом. Доказательство: `evidence/wp05/02-wp05-independent.log` [R-05].

## AUD-P2-07 — R-01: осиротевший guard-lock (принят, fail-closed)

`packages/trust/approval.mjs:192-214`: SIGKILL внутри `withGuard` оставляет `trust-root/guards/<approvalId>.lock`; consume/revoke отказывают ~5 с; второго ACK/POST нет. Авто-восстановление не вводить без доказательства отсутствия окна второго dispatch. Доказательство: `evidence/wp0102/04-supply-point-tests.log` (26/26), `tests/trust-r01.test.mjs`.

---

## §3. P3-наблюдения

| ID | Суть | Файл | Влияние |
|---|---|---|---|
| AUD-P3-01 | `publishTerminalChoice` при существующем файле молча возвращает первый выбор вместо конфликта | `anchor.mjs:313-339` | несменяемость соблюдена, но расхождение не сигнализируется |
| AUD-P3-02 | Матрица/документация ссылаются на несуществующий `publishAnchor` | `06-ACCEPTANCE-MATRIX.md:63`, `05-IMPLEMENTATION-ROADMAP.md:124` | дрейф контракта/API |
| AUD-P3-03 | Доверенные отказы (T-A DENY, CANCELED до intent) пишутся старым путём без terminal-choice; `observeTrusted` → inconsistent/INTEGRITY_ERROR вместо причины | `run.mjs:359-376`; `anchor.mjs:605-750` | легитимный отказ не представим через доверенный API |
| AUD-P3-04 | Ошибки публикации reconcile не нормализуются; конкурентные reconcile оба падают CANDIDATE_CONFLICT | `run.mjs:546-566` | автоматизация восстановления ломается; PASS/второго verdict нет |
| AUD-P3-05 | `start()/reconcile()` принимают внутренний `trust` (переключатель доверенного пути), не отвергается `assertOldEntryOptions`; L-08 проверяет 7 имён, не `trust` | `run.mjs:19-23`; `trusted.mjs:271,315` | формулировка «старый вход не умеет trusted» шире факта; не эскалация (R-04) |
| AUD-P3-06 | SID читается через `powershell.exe/whoami.exe`, разрешаемые по PATH/окружению вызывающего | `windows-sid.mjs:17,22` | при контроле PATH источник SID подменяем; в модели 0.2 контроль PATH ≈ выполнение кода; рекомендация — абсолютные пути System32 |
| AUD-P3-07 | Trust root не имеет целостностной привязки public-ключей (замена owner.pub/anchor.pub/ready.json даёт новый «годный» корень) | `identity.mjs:79-98` | граница локальной модели; признать явно/вынести корень |
| AUD-P3-08 | `signTrustedDocument` не связывает домен с назначением ключа (держат verify/commit) | `identity.mjs:53-60` | defense-in-depth |
| AUD-P3-09 | Тестовые fault-хуки `before-guard`/`after-create` остаются в продуктивном `consumeDispatch` | `approval.mjs:216-224,346-349` | можно умышленно «заклинить» approval (доп. прав не даёт) |
| AUD-P3-10 | Trust root (approvals/consumption/revocations/guards) не ужесточён ACL (наследует родителя); anti-replay-хранилище защищено ACL профиля | `identity.mjs:158,169`; `acl.mjs:50-53` | в однопользовательском профиле приемлемо; для много-/Dev — усилить |
| AUD-P3-11 | Слабости тестовой инфраструктуры: `review-grok:136` `mutationCount<=1` допускает 0 POST; тавтологичная проверка E-06; fallback-PASS по exit code в агрегаторах; matrix-алиасинг строк (E-01/E-07, V-01/V-02, V-07/V-11); wave-1 скрипты привязаны к `0e7e6c2`; `npm run schemas` без встроенного контроля дрейфа; mojibake в логе Lead; неверный состав в 02-TEST-EVIDENCE (identity 5 vs 8; 59+199=258 vs 255) | `tests/*`, `scripts/*`, `docs/harness/02-TEST-EVIDENCE.md` | ограничивает доказательность «зелёных» прогонов |
| AUD-P3-12 | Исторические `docs/gates/*` от `df5c99d` (59 тестов) не перегенерированы под финальный SHA | `docs/gates/` | могут быть прочитаны как доказательство финальной ревизии |
| AUD-P3-13 | PDP выдаёт ALLOW на вручную сфабрикованных facts (by design; через публичный вход инъекция невозможна — доказано) | `policy.mjs` | граница должна быть явной |
| AUD-P3-14 | Мёртвая ветка `ENVIRONMENT_KIND_DENIED` в `projectToVerdict` + маскирующее assertion в rt2-e06 | `policy.mjs:415` | неточная проекция/тест |
| AUD-P3-15 | Фазы чтения (observe/reconcile) не прогоняются через PDP в `reconcileTrusted`; read-права approval не проверяются Control | `trusted.mjs:308-320`, `run.mjs:546-566` | read-фаза без TrustDecision |
| AUD-P3-16 | Symbol-маркер «уже проверено» не связан с содержимым записи: мутация проверенной записи проходит повторную проверку | `environment.mjs:29-34,174-189` | fail-closed деградация |

## §4. Не подтверждено / NOT RUN / BLOCKED

| Сценарий | Статус | Причина |
|---|---|---|
| Сквозной одновременный `startTrusted` двух Control-процессов на один approval (L-01 E2E) | **NOT RUN** | механизм consumption проверен (4 процесса → 1 ACK); полный E2E с двумя Control/Chromium не воспроизводился |
| Второй Windows-пользователь для ACL/SID-границы | **BLOCKED** | однопользовательская машина аудита |
| Dev/ЦИЗ, реальные мутации вне локального стенда | **NOT RUN** | запрещено условиями; не требуется 0.2 |
| Реальный merge/main | **NOT RUN** | запрещено |
