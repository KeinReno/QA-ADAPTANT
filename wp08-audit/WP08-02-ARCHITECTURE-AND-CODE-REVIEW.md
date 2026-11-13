# WP08-02 — ARCHITECTURE AND CODE REVIEW

**SHA:** `07c21c4db936627df9a3c874015327ea992a335a` (продуктовый код `21edda6`).
**Метод:** чтение WP-00-архитектуры и всего продуктового кода, трассировка вызовов от публичных входов, независимые тесты и атаки; сверка с `docs/wp-00/02..08`, `docs/harness/*`. Продуктивный код не изменялся.

Детальные покомпонентные отчёты: `parts/wp0102/WP08-02-WP01-WP02.md`, `parts/wp0304/WP08-02-WP03-WP04.md`, `parts/wp05/WP08-02-WP05.md`, `parts/wp06/WP08-02-WP06.md`, `parts/verifier/WP08-03-TEST-REPRODUCTION.md`.

## 0. Итог по пакетам

| Пакет | Вердикт | Ключевое |
|---|---|---|
| WP-01 Identity / trust root | **ACCEPT с P2/P3** | SID из Windows-токена (не из JSON), domain separation owner/anchor, DPAPI+ACL ключей, fail-closed ready.json — подтверждено. **P2:** R-02 обходится junction/symlink (секреты в runDir). P3: trust root без ACL/целостностной привязки, SID через PATH, sign без привязки домена. |
| WP-02 Approval | **ACCEPT с P2** | Immutable approval, CREATE_NEW consumption, привязки/срок/отзыв/гонки/обрыв — подтверждено (L-01/L-07/L-09). **P2:** путь «только approvalId» не работает. R-01 — принятый P2 fail-closed. |
| WP-03 Policy | **ACCEPT с P3** | Чистый PDP без I/O, fail-closed, порядок SID→роль, reasonCode — подтверждено (17/17 независимых). P3: граница «ALLOW на сфабрикованных facts» (by design, но должна быть явной), мёртвая ветка ENVIRONMENT_KIND_DENIED, фазы чтения не прогоняются через PDP в Control. |
| WP-04 Environment | **REJECT (P0)** | Реестр/поколения/подпись/challenge/PID/порт/kind=dev — в основном корректно (8/8), но: **P0** — подмена среды после T-C/после POST даёт ложный доверенный PASS; **P2** — E-04 credentialRef не проверяется. R-03 переклассифицирован P2→P0. |
| WP-05 Anchor | **REJECT (P0)** | Candidate/choice/один verdict/бюджет/поздний анкер/идемпотентность — корректно; **P0** — подложный candidate с валидной связкой подписывается (R-07); **P1** — наблюдатель без coverage/parity; **P2** — V-07 recovery, R-05. |
| WP-06 Control Integration | **REJECT (P0/P1/P2)** | Порядок T-A…T-E соблюдён, инварианты второго POST/секрета/verdict — подтверждены; но доверенный PASS наследует P0 WP-04/05; **P1** V-07; **P2** publish-catch/verdict без choice; P3 отказы/ошибки публикации. |
| WP-07 Verification/Red Team | **CONDITIONAL** | Числа воспроизведены: 258/258, 3/3, 13/13, schemas, matrix 24/34; W2 первый прогон 23/24 (флейк L-06) — заявленное 24/24 нестабильно; покрытие не включает найденные P0 (false-pass без approval/consumption/анкера; замена среды только до POST). Тестовая инфраструктура имеет слабости (P3). |

## 1. WP-01 — Identity & Trust Root

Файлы: `identity.mjs` (174), `acl.mjs` (53), `dpapi.mjs` (42), `keygen.mjs` (41), `windows-sid.mjs` (28).

- **Ответственность/контракт.** Два Ed25519-ключа (owner: approval/revocation/principal/environment-record; anchor-signer: только anchor-statement), `keyId = SHA-256(raw pub)`, канонический JSON, `domain` в подписанных байтах; `loadTrustRoot` читает owner.pub/anchor.pub/ready.json; `createTrustRoot` пишет ключи в DPAPI-обёртке + ACL текущего пользователя; `unwrapPrivateKey` — только для утилиты/подписанта.
- **Граница доверия.** Приватные ключи вне Control; Control импортирует только public-функции; подмена trust root до старта — заявленная компрометация корня (граница R-04).
- **Подтверждено независимо:** SID вызывающего читается из Windows-токена (powershell/whoami), не из JSON/окружения; domain separation и отказ чужого keyId; частичная инициализация ready.json fail-closed; DPAPI-обёртка без открытого ключа, порча отвергается; ACL secrets/ключевых файлов (protected=true, один ACE); Control не держит приватных ключей; `createTrustRoot(runDir)` отвергает secrets внутри runDir (в т.ч. через junction).
- **Дефекты:** **AUD-P2-01** — `keygen.mjs` проверяет только строковый сегмент `runs`; junction/symlink вне сегмента обходит, ключи создаются в runDir. **P3:** trust root (approvals/consumption/revocations/guards) не ужесточён ACL; нет целостностной привязки public-ключей корня; `signTrustedDocument` не сверяет purpose ключа с доменом; CLIXML-диагностика/пустые каталоги после отказа; PATH для powershell/whoami.
- **Совместимость:** пакет новый, Control не импортирует приватный материал.

## 2. WP-02 — Approval Engine

Файл: `approval.mjs` (375).

- **Контракт.** Точный набор полей approval; Ed25519+domain; `approvalId` уникален и не является путём; immutable `trust-root/approvals/<id>.json` (CREATE_NEW); consumption `trust-root/consumption/<id>.json` через `openSync('wx')` + fsync + повторное чтение `bodySha256`; guard-lock сериализует revoke/consume; отзыв/срок/привязки operation/inputs/scenario/fixture/effects/resource/generation/runId; статус не входит в подписанное тело (WP-00).
- **Подтверждено независимо:** 15/15 approval-атак и 26/26 supply-point: подмена входа/операции/fixture/эффектов/runId → без ACK; повтор same runId → без второго ACK; чужой issuer/subject/SID/key; просрочка/отзыв до расхода; отзыв-гонка с барьером; обрыв после CREATE_NEW → `CONSUMPTION_INCOMPLETE`, файл не заменён; L-07 PASS; L-09 PASS (2 процесса → 1 файл/≤1 ACK); L-01 PASS на уровне механизма (4 процесса → 1 ACK).
- **Дефекты:** **AUD-P2-02** — `readApprovalState/consumeDispatch/approvalFact` теряют `options.approvalId`: путь «только approvalId» даёт CONTRACT_INVALID (fail-closed). **R-01** принят (P2, fail-closed ~5 с). P3: fault-хуки в продуктивном consumeDispatch; удаление consumption возможно при праве записи в trust root (документированная граница).
- **HTTP:** модуль не делает сетевых вызовов (проверено).

## 3. WP-03 — Policy Engine

Файл: `policy.mjs` (419), `facts.mjs` (74).

- **Контракт.** `decide(facts) → TrustDecision`; чистый PDP: нет fs/net/http/fetch; строгая форма 11 ключей facts; эффекты ALLOW/DENY/INDETERMINATE; `projectToVerdict` — отдельная таблица.
- **Проверено независимо (17/17):** отсутствие I/O (в т.ч. при заглушенных модулях); невозможность ALLOW без approval/attestation/active principal/SID/реестра; порядок «revoked principal → SID → роль → approval → среда»; fail-closed на противоречивых/неизвестных кодах; точные reasonCode/obligations; `facts` не мутируются.
- **Граница:** CALLER SID и подписи проверяет сборщик в Control, PDP доверяет facts. Прямой вызов `decide` на вручную собранных facts даёт ALLOW — by design; в продуктивном пути facts собирает только Control, внешнего API приёма facts нет. Это должно быть явно зафиксировано (P3).
- **P3:** мёртвая ветка `ENVIRONMENT_KIND_DENIED` в проекции; фазы observe/reconcile/publish не прогоняются через PDP в `reconcileTrusted` (P-03/P-04 читаются без решения). R-09 (поколение при чтении) подтверждён.

## 4. WP-04 — Environment Identity

Файлы: `environment.mjs` (519), `adapters/local/server.mjs` (166).

- **Контракт.** `EnvironmentRecord` подписан owner; поколенческая раскладка `environments/<id>/<gen>.json`; `standKeyId`; fresh challenge, Ed25519-подпись стенда, проверка generation/origin/PID/владельца порта; монопольный bind; `kind=dev/production` → DENY; `credentialRef` — ссылка без секрета.
- **Подтверждено:** реестр/поколения/отзыв/подпись/standKeyId (8/8); E-01 (перехваченная аттестация не переигрывается), E-02, E-03 (смена поколения до POST → BLOCKED), E-05 (fail-closed), E-06 (kind=dev до сети, attestCount=0), E-08 (EADDRINUSE); R-08 (ключ стенда приходит извне) и R-09 — принятые границы; Symbol-маркер «уже проверено» даёт P3-деградацию (мутация после проверки проходит повторную проверку).
- **Критические дефекты:**
  - **AUD-P0-02:** после T-C (и даже после POST) Verification Worker не аттестует стенд, а читает публичные `/environment` и `/records`; rogue, занявший порт, выдаёт себя за среду → PASS. Сценарий B: реальной мутации не было (`mutationCount=0`), Bearer утёк. Окно ~35 мс (T-C→POST)/147 мс (attest→POST), подмена 3 мс.
  - **AUD-P2-05 (E-04):** `credentialRef` не влияет ни на PDP, ни на выдачу секрета; Browser получает `fixtureToken` другой среды.
- **Оценка R-03:** переклассифицировать P2→P0; формулировка «микроскопическое окно» неверна.

## 5. WP-05 — Evidence Anchor

Файлы: `anchor.mjs` (717/764), `anchor-signer.mjs` (261).

- **Контракт.** Candidate = ровно VerdictPolicy 0.1 без anchorId/approvalId; durable `trust/candidate.json` через CREATE_NEW + тело под хешем; `terminal-choice.json` через CREATE_NEW; один verdict после choice; для outcome=anchor — проверка подписи anchor-signer, runId/manifest/candidateSha256/chainHead/связки approval+consumption+снимков; бюджет из profile.json; поздний анкер → ANCHOR_UNLINKED.
- **Подтверждено:** V-03/V-04/V-08/V-09/V-11/V-12; идемпотентность V-05; один терминальный verdict; owner-ключ не подписывает анкер; terminal-choice не заменяется; поздний анкер не повышает INCONCLUSIVE.
- **Критические/высокие:**
  - **AUD-P0-01 (R-07):** подписант проверяет связку, но не происхождение candidate и не business-checks; подложный candidate с genuine approval/consumption подписывается; наблюдатель показывает PASS.
  - **AUD-P1-01:** `observeTrustedVerdict/analyze` не вызывает `assertEvidenceRefs/assertTerminalEvidence/validateVerdictCoverage` — слабее 0.1.
  - **AUD-P1-02 / F-WP05-02:** crash между анкером и choice → новый anchorId → ANCHOR_CONFLICT → INCONCLUSIVE; анкер PASS остаётся UNLINKED.
  - **AUD-P2-03:** V-06 reconcile всегда INCONCLUSIVE.
  - **AUD-P2-06:** R-05 неподписанный profile.json (fail-closed).
  - P3: молчаливый terminal-choice при конфликте; `publishAnchor` отсутствует в API.

## 6. WP-06 — Control Integration

Файлы: `apps/control/run.mjs` (610), `trusted.mjs` (320), `facts.mjs`, `windows-sid.mjs`.

- **Фактический порядок (подтверждён чтением и прогонами):** snapshot/freeze → claimFixture → **preflight T-A** (DENY → BLOCKED, Browser не запущен, секрет не выдан) → INTENT: **dispatch T-B** (decide → consumeDispatch → durable mutation-intent → ACK) → HTTP_REQUEST: **T-C** (attestation → request evidence → EVIDENCE_ACK → route.continue/POST) → response evidence → Verification (independent GET, identity/ownership, env before/after) → candidate → anchor → choice → один verdict → observe T-E. Второго исполнителя мутаций нет.
- **Подтверждено:** нет POST/секрета до ALLOW; нет второго POST; нет второго terminal verdict (append-only + проверка); adopt/старый PASS → INTEGRITY_ERROR; observe/reconcile не мутируют; чужой SID → BLOCKED; L-02/L-04/L-05/B-02 PASS; T-11/T-12 (F-01) зелёные.
- **Дефекты:** **AUD-P1-02** (V-07 recovery), **AUD-P2-04** (publish-ошибка → verdict без choice), **P3** (доверенные отказы без choice; необработанные коды reconcile; `trust` в старом входе; нет PDP для reconcile-read; fault-хук tamperSnapshot доступен через startTrusted).
- **Архитектурное замечание:** две реализации терминального исхода (`trust.publish` и старый `persistVerdict`) — нарушение принципа «один механизм публикации verdict»; на пути ошибок это даёт verdict без choice (AUD-P2-04).

## 7. WP-07 — Independent Verification / Red Team

- **Числа:** `npm test` 258/258 (exit 0); `test:races` 3/3; `schemas` без диффа; `trust-integration` 13/13; `run-matrix` 34 (24 PASS/10 TODO/0 FAIL); Red Team W2 первый прогон **23/24** (L-06 флейк, изолированный повтор PASS). Заявленное «24/24» нестабильно.
- **Покрытие:** 24 атаки не покрывают найденные P0: false-pass-скрипт подделывает цепочку **без** approval/consumption/анкера; подмена среды проверяется только до POST; V-07 проверен на другом crash-point; E-04/V-06/V-10/V-12/L-01/L-02/L-04/L-05/B-02 в matrix — TODO (часть закрыта аудитом).
- **Тестовая инфраструктура (P3):** redteam не входит в npm test; races выбираются хрупким name-pattern; FAIL-по-умолчанию нарушен (exit 0 без JSON → PASS); matrix-алиасинг строк; тавтологичная E-06; `mutationCount<=1`; wave-1 скрипты привязаны к базе 0e7e6c2; schemas без встроенного контроля; неверный состав в 02-TEST-EVIDENCE.

## 8. Сквозные проверки архитектуры

- **Дублирующиеся механизмы авторизации:** один approval/consumption; одна точка PEP в Control; один POST в Browser; **два пути публикации verdict** (`trust.publish` и `persistVerdict` старого пути) — дефект AUD-P2-04/P3.
- **Обходы:** `start()/reconcile()` принимают `trust` (AUD-P3-05) — не эскалация, но контрактная щель; старый вход не выпускает доверенный PASS (T-11/T-12).
- **Границы:** R-04 (один SID) явно принята, но её принятие не отменяет заявлений WP-00 о том, что код с правами только на runDir не получит анкер/не подменит среду — оба заявления опровергнуты (AUD-P0-01/02).
- **Секреты:** Bearer не пишется в runDir/evidence (проверено), но утекает rogue-процессу в окне T-C (AUD-P0-02).
- **Совместимость:** Stable 0.1 не затронут (WP08-06).

## 9. Вывод

Архитектура WP-00 в целом реализована и упорядочена, Stable 0.1 сохранён, большинство контрактов и негативных инвариантов подтверждены. Однако **центральная гарантия 0.2 — достоверность доверенного PASS — не выполнена**: подпись анкера удостоверяет связку артефактов, но не их происхождение и не бизнес-истину; Verification доверяет неаттестованной среде. Пакеты WP-04/WP-05/WP-06 подлежат отклонению до устранения AUD-P0-01/AUD-P0-02 и связанных P1.
