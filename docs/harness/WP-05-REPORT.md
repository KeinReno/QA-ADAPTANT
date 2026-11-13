# WP-05 — Evidence Anchor: отчёт пакета

Статус: **CODE COMPLETE**, пакет не принят самостоятельно; уходит на внутреннее ревью Lead/Red Team.
База: `0e7e6c20f7a839ffe16047fa11006b1a9ab6cd31`.
Ветка: `feat/adaptant-02-wp05-anchor`.
Коммит кода и тестов после исправления D-01: `c168465b966ac1ead42a4a7871981a2373438418`. HEAD сдачи (включая этот отчёт) сообщён Lead отдельно.
Первичная сдача: `10db430ddf96c5dbd673172505961ef14f8ac75d`, проверена ревьюером (`docs/harness/WP-05-INTERNAL-REVIEW.md`, коммит `009c871`): FIX REQUIRED по D-01.

## 1. Contract review до кода

Прочитано до реализации: `integration/docs/harness/BASELINE-AND-CONTRACTS.md` §3, §5.2, §6, §9;
`docs/wp-00/02-TRUST-ARCHITECTURE.md` (разделы «Публикация verdict и анкер», «Ключи и каталоги», таблица доменов подписи);
`03-CONTRACT-PROPOSALS.md` (AnchorStatement, terminal-choice, проекция verdict);
`05-IMPLEMENTATION-ROADMAP.md` (WP-05), `06-ACCEPTANCE-MATRIX.md` (V-01…V-12);
`08-OPEN-QUESTIONS.md` Q-04; фактический код `identity.mjs`, `approval.mjs`, `acl.mjs`, `keygen.mjs`, `store.mjs`, `canonical.mjs`, `bundle.mjs`, `evidence-policy.mjs`, `contracts/index.mjs`, `apps/control/run.mjs`.

Зафиксированные инварианты, которые проверяет пакет:

1. Candidate — ровно объект `VerdictPolicy` 0.1, без `anchorId`/`approvalId` и без новых полей; `candidateSha256 = digest(candidate)`.
2. Пока нет выбора исхода, в evidence нет verdict. PASS появляется только после `outcome=anchor` и годного анкера.
3. Ровно один терминальный verdict; его байты равны байтам выбранного candidate.
4. `runDir/trust/candidate.json` и `terminal-choice.json` создаются через `CREATE_NEW` (`wx`), затем `fsync` дескриптора и повторное чтение; повторная запись не заменяет файл.
5. Истечение бюджета → один `INCONCLUSIVE`/`EVIDENCE_MISSING`; поздний анкер отброшенного PASS остаётся `ANCHOR_UNLINKED`, не конфликт и не переход в PASS.
6. Сбой после выбора `anchor` и до verdict → дописывается ровно выбранный candidate, бюджет заново не разыгрывается.
7. Частично записанный `terminal-choice` блокирует PASS и не перезаписывается.
8. Подписант сам читает trust root, approval, consumption, снапшоты, журнал и candidate; хеш от вызывающего не принимает; подписывает только `domain=anchor-statement`; иначе `ANCHOR_BINDING_REJECTED`.
9. `observeTrustedVerdict` показывает PASS только при полной связке: выбор `anchor`, единственный verdict PASS, байты verdict = `candidateSha256`, анкер на этот хеш подписан ключом `anchor-signer`.
10. Ссылка на анкер не меняет подписанные байты candidate; поля `VerdictPolicy` 0.1 и формат evidence-коммитов не изменены.

## 1.1. Внутреннее ревью и исправления (FIX REQUIRED → исправлено)

Ревью Agent C (`docs/harness/WP-05-INTERNAL-REVIEW.md`, проверенный SHA `03655e0`) нашло блокирующий D-01 и замечания D-03…D-06.
Исправления внесены минимально; D-02 — архитектурное решение Lead (фиксируется в `docs/changes/004`), код не менялся.

| ID | Что сделано в коде/тестах |
|---|---|
| **D-01 (HIGH, блокирующий)** | `publishTerminalVerdict` теперь до записи verdict для `outcome='anchor'` выполняет `loadAnchor` + `verifyAnchorStatement` + сверку `anchorId`, `candidateSha256`, `runId`, `manifestSha256`, вердикта и тела candidate, затем `inspectEvidenceBinding` (`pre-verdict` при записи, `terminal` при существующем verdict) и `verifyAnchorAgainstBinding` (голова цепочки = коммит перед verdict). В ветке уже записанного verdict анкер проверяется повторно; при отсутствии/негодности — `ANCHOR_MISSING`/`ANCHOR_CONFLICT`/`ANCHOR_SIGNATURE_INVALID`/`INTEGRITY_ERROR` и **ни одной новой записи verdict**. В existing-ветке также проверяется соответствие `outcome` типу выбранного тела (`fail-without-anchor`→FAIL, `inconclusive-without-anchor`/`budget-inconclusive`→INCONCLUSIVE, `budget-inconclusive`→`EVIDENCE_MISSING`), иначе `INTEGRITY_ERROR`, а не PASS. Для `outcome='anchor'` обязательны `trust` и `trustRoot`: без них функция fail-closed с `ANCHOR_MISSING`. **Внимание WP-06:** call site `publishTerminalVerdict({store,runDir,frozen})` нужно дополнить `{trust, trustRoot}` — иначе доверенный PASS не опубликуется (это требуемое ужесточение, не регрессия). |
| **D-03 (LOW)** | Подписант повторно проверяет отсутствие `terminal-choice.json` непосредственно перед `CREATE_NEW` и после записи анкера; при появлении выбора — `ANCHOR_CONFLICT`, подпись не считается выпущенной. |
| **D-04 (LOW)** | Поле `id` в протоколе стало действительно необязательным (raw-запрос без `id` принимается; лишние поля по-прежнему `CONTRACT_INVALID`). Клиент `connectAnchorSigner().sign()` больше не отбрасывает неизвестные поля молча, а отвергает их `CONTRACT_INVALID`; хеш candidate вызывающий передать не может. |
| **D-05 (LOW)** | `findUnlinkedAnchor` сообщает `ANCHOR_UNLINKED` только по заявлению с годной подписью `anchor-signer`; синтаксически валидный неподписанный файл метаданные наблюдения не подменяет. |
| **D-06 (INFO)** | `loadAnchor` явно документирован как возвращающий **неверифицированное** заявление; вызывающий обязан применить `verifyAnchorStatement` (так делают `observeTrustedVerdict` и фикс D-01). |
| **D-02 (HIGH-RISK, архитектура)** | Принято решение Lead: анкер удостоверяет **связку и неизменность candidate**, но не бизнес-истину. Бизнес-смысл обеспечивает только доверенный Verification/WP-06 T-D; WP-06 обязан строить candidate из результата Verification и не принимать candidate извне, а PASS отдавать только через `observeTrustedVerdict.passed`. Формулировка R-07 ниже уточнена; фиксация — `docs/changes/004`. |

Новые регрессии (`tests/trust-anchor.test.mjs`): «D-01: исход anchor без подписанного анкера не пишет PASS», «D-01: удалённый анкер не превращает повторную публикацию в PASS», «D-01: подмена outcome в ветке существующего verdict не возвращает PASS», расширение V-09 подложным неподписанным файлом анкера (D-05), raw-протокол без `id` и с лишним полем (D-04).

## 2. Файлы пакета

| Файл | Что |
|---|---|
| `packages/trust/anchor.mjs` (новый) | candidate, terminal-choice, терминальный verdict, проверка анкера, состояния публикации, наблюдение, бюджет, связка для подписанта |
| `packages/trust/anchor-signer.mjs` (новый) | отдельный процесс подписанта через named pipe, протокол — строки JSON |
| `tests/trust-anchor.test.mjs` (новый) | 19 тестов WP-05, включая V-08, V-09, V-10, V-11, V-12 |
| `docs/harness/WP-05-REPORT.md` | этот отчёт |

Запрещённые файлы не менялись: `packages/contracts/`, `schemas/`, `docs/contract-freeze.json`, `packages/core/*`, `apps/control/run.mjs`, `apps/browser/worker.mjs`, `apps/verification/worker.mjs`, `packages/trust/identity.mjs`, `packages/trust/approval.mjs`, старые тесты 0.1.

## 3. Раскладка каталога прогона

| Путь | Содержимое | Правило записи |
|---|---|---|
| `runDir/trust/candidate.json` | бизнес-candidate (ровно `VerdictPolicy`), `canonical(candidate) + "\n"` | `CREATE_NEW` + `fsync` + повторное чтение; повтор с тем же digest идемпотентен, другое тело → `CANDIDATE_CONFLICT` |
| `runDir/trust/candidates/<candidateSha256>.json` | тело каждого опубликованного candidate, включая INCONCLUSIVE-замену | `CREATE_NEW`; имя обязано совпадать с digest тела |
| `runDir/trust/terminal-choice.json` | `schemaVersion, domain('terminal-choice'), outcome, candidateSha256, discardedCandidateSha256|null, anchorId|null, createdAt` | `CREATE_NEW` + `fsync` + повторное чтение; второй писатель читает первый выбор |
| `trustRoot/anchors/<anchorId>.json` | `AnchorStatement` (`domain='anchor-statement'`) | `CREATE_NEW` подписантом + `fsync` + проверка подписи при повторном чтении |

**Принятые уточнения Lead (не менять молча):**

1. `candidates/<candidateSha256>.json` — обязательная раскладка для восстановления выбранных байт после падения. `publishTerminalVerdict` читает тело из этого файла по `terminal-choice.candidateSha256` и **не пересчитывает байты заново**. Это снимает неоднозначность «где durable тело заменяющего INCONCLUSIVE»: и бизнес-candidate, и замена лежат под своими хешами.
2. Четвёртый исход `terminal-choice.outcome = 'inconclusive-without-anchor'` — для бизнес-`INCONCLUSIVE` (не PASS и не FAIL), когда анкер не требуется. `anchorId === null`, `discardedCandidateSha256 === null`, выбранное тело обязано иметь `verdict === 'INCONCLUSIVE'` (reasonCode — любой из enum 0.1), публикуется ровно одно тело без пересчёта байт. Ожидает фиксации Lead в `docs/changes/004` и §5.2.

## 4. Обязательные экспорты `anchor.mjs`

`DEFAULT_ANCHOR_BUDGET_MS = 5000`,
`buildCandidate({frozen, verdict, reasonCode, message, checks, completedAt, ownershipVerified?, integrityVerified?})`,
`buildInconclusiveCandidate({frozen, completedAt})`,
`buildBudgetInconclusiveChoice({runDir, frozen, createdAt?})` (durable-запись тела замены + выбор),
`publishBudgetInconclusiveOutcome({runDir, frozen, createdAt?})` (тело + `terminal-choice`),
`publishCandidate(runDir, candidate)` → `{candidateSha256, created}`,
`publishCandidateBody(runDir, candidate)` → `{candidateSha256, created}`,
`readCandidate(runDir)` → `{candidate, candidateSha256, bytes}` | null,
`readCandidateBody(runDir, candidateSha256)`,
`buildTerminalChoice({outcome, candidateSha256, discardedCandidateSha256?, anchorId?, createdAt?})`,
`publishTerminalChoice(runDir, choice)` → `{choice, created}`,
`readTerminalChoice(runDir)` → choice | null,
`evidenceChainHead(store, runDir)` → `{sequence, envelopeSha256}` | null,
`publishTerminalVerdict({store, runDir, frozen, trust, trustRoot})` → `{verdict, evidenceId, created}` (для `outcome='anchor'` обязательны `trust` и `trustRoot`; иначе `ANCHOR_MISSING`),
`verifyAnchorStatement(trust, statement)` → body,
`loadAnchor(trustRoot, anchorId)` → statement,
`inspectEvidenceBinding({trust, trustRoot, runDir, approvalId, mode})` → `{frozen, approval, consumption, candidate, chainHead, evidence}`,
`publicationState({store, runDir, trust, trustRoot})` → `collecting|candidate-ready|anchor-held|terminal|inconsistent`,
`observeTrustedVerdict({store, runDir, frozen, trust, trustRoot})`,
`loadAnchorBudgetMs(trustRoot)`,
`anchorWithinBudget({signer, trustRoot, runDir, approvalId, anchorId})` → `{ok, statement|code, budgetMs}`.

`observeTrustedVerdict` возвращает
`{runId, runDir, state, trusted, passed, verdict, outcome, candidateSha256, anchorId, anchor, anchorStatus, reasonCode, unlinkedAnchorId}`.
`verdict` равен `null`, если публикация не доказана; `passed=true` только при `trusted && verdict.verdict==='PASS'` с полной связкой. Для `budget-inconclusive` при наличии позднего анкера отброшенного PASS: `anchorStatus='ANCHOR_UNLINKED'`, `unlinkedAnchorId` заполнен, `ANCHOR_CONFLICT` не возникает.

## 5. `anchor-signer.mjs`

`startAnchorSigner({trustRoot, secretsDir, pipePath?})` → `{pipePath, ready, close}`;
`ready` — Promise, который завершается после `listen`. По умолчанию канал
`\\.\pipe\qa-adaptant-anchor-<16 hex>`.
`connectAnchorSigner(pipePath)` → `{sign({runDir, approvalId, anchorId}), close}`.

Протокол — строки JSON. Запрос: `{type:'sign', runDir, approvalId, anchorId}`; `id` — необязательное служебное поле; любое лишнее поле, включая `candidateSha256`, отклоняется кодом `CONTRACT_INVALID`. Клиент `connectAnchorSigner().sign()` принимает только `runDir/approvalId/anchorId` и отвергает неизвестные поля, а не отбрасывает их молча. Ответ: `{id, ok:true, statement}` или `{id, ok:false, code, message}`.

Подписант сам: читает `anchor.key` через DPAPI (`unwrapPrivateKey`); загружает trust root;
проверяет, что `terminal-choice.json` ещё не существует; читает и проверяет approval, полный consumption (`bodySha256`),
отзыв (отзыв до расхода запрещает подпись); сверяет замороженные снапшоты и манифест с approval; проверяет отсутствие verdict
в evidence и голову цепочки; читает candidate и его тело под хешем; только затем подписывает заявление своим ключом.
Домены, отличные от `anchor-statement`, подписант не выпускает. При ошибке связки — `ANCHOR_BINDING_REJECTED`,
файла анкера нет. Повтор того же `anchorId` с теми же смысловыми полями идемпотентен, другое заявление на тот же
`runId` → `ANCHOR_CONFLICT`.

## 6. Коды ошибок пакета

| Код | Когда |
|---|---|
| `CONTRACT_INVALID` | форма candidate/choice/statement/запроса не по контракту 0.2; неизвестное поле; candidate другого прогона |
| `CANDIDATE_CONFLICT` | `candidate.json` уже занят другим телом |
| `CANDIDATE_INCOMPLETE` | durable candidate/тело не создано, не читается или оборвано |
| `TERMINAL_CHOICE_INCOMPLETE` | `terminal-choice.json` существует, но неполон/нечитаем; имя не заменяется |
| `PUBLICATION_PENDING` | выбора исхода ещё нет; verdict не пишется; открытая публикация |
| `ANCHOR_MISSING` | выбран anchor, но заявления/тела нет |
| `ANCHOR_CONFLICT` | второе отличное заявление на runId или расхождение связки |
| `ANCHOR_SIGNATURE_INVALID` | подпись не ключом `anchor-signer` (в т.ч. ключ owner), домен/алгоритм не те |
| `ANCHOR_BINDING_REJECTED` | подписант не собрал полную связку approval/consumption/снапшоты/журнал/candidate |
| `ANCHOR_UNLINKED` | (наблюдение) подпись относится к отброшенному candidate; не PASS и не конфликт |
| `EVIDENCE_MISSING` | бюджет истёк; выбирается INCONCLUSIVE; или у выбранного тела нет durable байт |
| `INTEGRITY_ERROR` | подмена candidate/verdict/цепочки, второй verdict, байты не равны выбору |
| `TRUST_STORE_UNAVAILABLE` | trust root/профиль не читаются или некорректны |
| `APPROVAL_MISMATCH`/`APPROVAL_MISSING`/`APPROVAL_REVOKED`/`CONSUMPTION_INCOMPLETE` | внутренние причины отказа связки (наружу через подписанта проецируются в `ANCHOR_BINDING_REJECTED`) |

## 7. Формальные команды и фактический результат

Рабочий каталог: `C:\Users\gvi\Desktop\QA-ADAPTANT-harness\wp05`, Node.js v24.16.0, Windows.

| Команда | Фактический результат |
|---|---|
| `node --check packages/trust/anchor.mjs` | exit 0 |
| `node --check packages/trust/anchor-signer.mjs` | exit 0 |
| `node --test tests/trust-anchor.test.mjs` | **22/22 passed, 0 failed, exit 0**, duration ~26.9 s |
| `node --test tests/trust-*.test.mjs` (identity + approval + anchor) | **41/41 passed, 0 failed, exit 0**, duration ~20.8 s |

Полный `npm test` и `npm run test:races` пакет не запускал: по правилам §9 и указанию Lead их выполняет Lead на интеграции; пакет не трогает `apps/control` и старые тесты. `npm run schemas` не требуется: `schemas/` не менялись.

## 8. Тестовое покрытие обязательного списка

| Требование | Тест |
|---|---|
| подложный PASS | «V-10: подложный PASS без связки approval/consumption…» |
| подмена candidate | «подмена candidate после анкера не даёт PASS и не перезаписывается» |
| подмена evidence chain | «подмена evidence chain ломает терминальный PASS» |
| несовпадение approval | V-10 (сценарий с `approvedInputsHash`) |
| несовпадение consumption | V-10 (расход связан с чужим `runId`) |
| чужой runId | «чужой runId: candidate и анкер не переносятся…» |
| чужой ключ подписи (owner вместо anchor) | «V-08: ключ owner не создаёт годный анкер» |
| гонка истечения бюджета и анкера (V-09) | «V-09: гонка бюджета и позднего анкера…» |
| два одновременных terminal-choice | «два одновременных publishTerminalChoice…» (два процесса, барьер) |
| частично записанный terminal-choice (V-12) | «V-12: частично записанный terminal-choice блокирует PASS…» |
| crash до анкера | «collecting → candidate-ready…» + V-10 |
| crash после анкера | «V-07/V-11: выбор anchor переживает падение до verdict…» |
| crash после terminal-choice до verdict (V-07/V-11) | там же |
| повторный RECONCILE | «второй терминальный verdict запрещён; повторный RECONCILE…» |
| второй terminal verdict | там же |
| подмена финального verdict после публикации | «подмена финального verdict после публикации…» |
| V-10 | отдельный тест |
| V-11 | «V-07/V-11…» |
| V-12 | отдельный тест |
| доп. | candidate ровно `VerdictPolicy`; идемпотентность анкера (V-04/V-05); бюджета профиля; fail-without-anchor; inconclusive-without-anchor |

Все тесты — модульные, на временном `mkdtemp`-каталоге, с настоящим `RunStore` (`store.snapshot` + `store.appendEvidence`), настоящими Ed25519/DPAPI-ключами, реальным named pipe и реальными отдельными процессами для гонки `terminal-choice`. Playwright/Chromium/HTTP не используются; сквозной доверенный прогон — WP-06 Lead.

## 9. Новые риски и ограничения

| ID | Риск/ограничение | Почему принято / что нужно |
|---|---|---|
| R-05 | `trustRoot/profile.json` (`anchorBudgetMs`) читается как файл trust root, но не проверяется криптографическая подпись профиля: замороженная таблица доменов WP-01 не содержит домена `trust-profile`, а менять `identity.mjs` без реального дефекта запрещено | Значение по умолчанию 5000, диапазон 1…60000, вызывающий его не меняет (нет параметра). Файл лежит внутри trust root и не пишется вызывающим. Требование «подписан в профиле» закрывается отдельным `docs/changes` (домен `trust-profile`) в WP-06/07; до этого — ограничение локальной 0.2 |
| R-06 | ACL named pipe подписанта — стандартный для Windows/Node, отдельно «только текущий пользователь» не сужается низкоуровневым ACL | Совпадает с принятой границей R-04 (`02-TRUST-ARCHITECTURE.md`: DPAPI/ACL одного SID не изолируют от кода той же учётной записи). Для Dev/ЦИЗ границы недостаточно |
| R-07 (уточнено после D-02) | Анкер удостоверяет **связку и неизменность candidate** (approval/consumption/снапшоты/цепочку/байты candidate), но **не бизнес-истину** `checks`. Подписант не пересчитывает business-результат. | Решение Lead: candidate обязан строиться только доверенным Verification/WP-06 T-D и не приниматься извне; WP-06 отдаёт PASS только через `observeTrustedVerdict.passed`. Фиксация — `docs/changes/004`. Это уточняет формулировку, ранее обещавшую больше. |
| R-08 | `publicationState` при повреждении цепочки/кандидата возвращает `inconsistent`, а не отдельный код | Форма функции заморожена строкой состояния; детали доступны через `observeTrustedVerdict.reasonCode` |
| R-09 | `candidates/<sha>.json` и `inconclusive-without-anchor` — расширения раскладки/исхода, принятые Lead в ходе WP-05 | Требуют фиксации в `docs/changes/004` и §5.2; код и тесты уже соответствуют |
| R-10 | `inspectEvidenceBinding` восстанавливает корень `RunStore` как `dirname(dirname(runDir))` | Соответствует раскладке `RunStore` (`root/runs/<runId>`); путь `runDir` обязан быть каталогом, созданным `RunStore` |

## 10. Границы доказательства

- Это **unit/local trust layer**, не сквозной доверенный прогон. `startTrusted`, T-A…T-E, реальный локальный стенд и счётчик POST проверяет Lead в WP-06/07.
- Никаких секретов (owner.key, anchor.key, stand key, Bearer) в candidate, terminal-choice, анкер, события, evidence и отчёт не пишется. Тесты используют только временные DPAPI-обёртки; в репозиторий ключи не попадают.
- Пакет не считается принятым: независимое ревью Lead/Red Team обязательно.
