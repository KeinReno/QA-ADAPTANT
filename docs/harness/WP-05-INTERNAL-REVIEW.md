# WP-05 — внутреннее независимое ревью: Evidence Anchor

Ревьюер: Agent C (автор WP-03 и ревью WP-04; код WP-05 не писал).
Проверяемая ветка: `feat/adaptant-02-wp05-anchor`, worktree `C:\\Users\\gvi\\Desktop\\QA-ADAPTANT-harness\\wp05`.
Проверяемый SHA: `03655e00e2decb03b1332e2e3e624e0ea442f9ea` (реализация+тесты `10db430ddf96c5dbd673172505961ef14f8ac75d`).
Продуктовый код и тесты WP-05 ревьюером **не изменялись**; пробы выполнялись во временных каталогах вне репозитория.
Дата: 13.11.2026.

## 1. Метод

1. Прочитан реальный код: `packages/trust/anchor.mjs` (729 строк), `packages/trust/anchor-signer.mjs` (248 строк),
   `tests/trust-anchor.test.mjs` (645 строк, 19 тестов), отчёт `docs/harness/WP-05-REPORT.md`;
   сверены с `identity.mjs`, `approval.mjs`, `store.mjs`, `bundle.mjs`, `canonical.mjs`, `contracts/index.mjs`
   и с заявлениями `02-TRUST-ARCHITECTURE.md`/03/06.
2. Независимо запущены тесты пакета, trust-набор, старый вход 0.1 и `npm run schemas` на проверяемом SHA.
3. Выполнены собственные адверсариальные пробы вне репозитория: публикация PASS без анкера (свежая и после
   удаления анкера), подложный candidate с фиктивными evidenceIds, гонка двух соединений подписанта.
4. Проверено, что diff не выходит за заявленные файлы и старые тесты 0.1 не менялись.

## 2. Фактические результаты прогонов (независимо, в wp05)

| Команда | Факт | Совпало с отчётом |
|---|---|---|
| `node --test tests/trust-anchor.test.mjs` | **19 tests / 19 pass / 0 fail**, exit 0, 27.4 s | да (числа; длительность на ревью-машине выше из-за нагрузки) |
| `node --test tests/trust-*.test.mjs` | **38 tests / 38 pass / 0 fail**, exit 0, 22.6 s | да |
| старый вход: `node --test tests/runtime.test.mjs tests/contracts.test.mjs tests/contract-links.test.mjs` | **13 tests / 13 pass / 0 fail**, exit 0, 8.1 s | не заявлялось, проверено ревьюером |
| `npm run schemas` | exit 0, диффа схем 0.1 нет | да |
| `git status --porcelain` | пусто; diff `0e7e6c2..HEAD` — только 4 заявленных файла | да |

## 3. Проверенные инварианты и ответы на обязательные вопросы

| # | Вопрос | Результат |
|---|---|---|
| 1 | PASS без годного анкера? | **ДА, через `publishTerminalVerdict`** — дефект D-01. Наблюдатель `observeTrustedVerdict` PASS без анкера не показывает |
| 2 | Бюджет и гонка V-09 | держится: тест воспроизведён; один INCONCLUSIVE/EVIDENCE_MISSING, поздний анкер `ANCHOR_UNLINKED`, перехода в PASS и `ANCHOR_CONFLICT` нет |
| 3 | Ровно один терминальный verdict | держится: последовательные публикации идемпотентны, прямой второй `appendEvidence('verdict')` отвергается; конкурентная защита store — по построению (wx-артефакт на sequence + запрет поверх verdict); межпроцессного теста в WP-05 нет |
| 4 | Частично записанный terminal-choice | держится: V-12, PASS не пишется, файл не заменяется |
| 5 | Свойства подписанта | в основном держится: сам читает trust root/approval/consumption/снапшоты/журнал/candidate, хеш вызывающего не принимает (raw-протокол), подписывает только `anchor-statement`, существующий terminal-choice блокирует подпись; see D-02 (бизнес-смысл candidate не пересчитывается), D-03 (TOCTOU окно), D-04 (протокол id) |
| 6 | Байты verdict = выбранному candidate | держится: `resolveChosenCandidate` читает `candidates/<sha>.json` через `readCandidateBody` (имя=digest, канонические байты), тело не пересчитывается; тест сверяет байты файла evidence |
| 7 | Старый вход и схемы 0.1 | не сломаны: новых импортов в `apps/*` нет, изменены только 3 новых файла + отчёт, `npm run schemas` exit 0, старый subset 13/13 |

Дополнительно подтверждено: candidate — ровно объект VerdictPolicy 0.1 без `anchorId`/`approvalId`; durable candidate
и `candidates/<sha>.json` через `CREATE_NEW`; V-10 (нет approval/consumption/чужой runId) отвергается;
V-08 (ключ owner → `ANCHOR_SIGNATURE_INVALID`); V-04/V-05 (второе отличное заявление → `ANCHOR_CONFLICT`, повтор идемпотентен);
V-07/V-11 (после выбора anchor дописывается ровно candidate, бюджет заново не разыгрывается); подмена candidate/цепочки/финального
verdict → `inconsistent`, PASS не показывается; fail-without-anchor и inconclusive-without-anchor публикуют ровно своё тело.

## 4. Дефекты

### D-01 — HIGH (блокирующий). `publishTerminalVerdict` не проверяет годный анкер для `outcome='anchor'`

- Где: `packages/trust/anchor.mjs:374-401` (`publishTerminalVerdict`), ветка существующего verdict — 382-386,
  `resolveChosenCandidate` — 350-372. Для outcome `anchor` нигде не вызываются `loadAnchor`/`verifyAnchorStatement`/
  `inspectEvidenceBinding`/`verifyAnchorAgainstBinding`; выбранное тело берётся по `candidateSha256` из
  `terminal-choice.json` без проверки анкера.
- Воспроизводимый сценарий A (свежая запись, проба ревьюера): валидный run с candidate PASS, валидным
  approval/consumption; `publishTerminalChoice({outcome:'anchor', candidateSha256, anchorId:'anchor-never-signed'})`
  (анкер для этого `anchorId` никогда не подписывался); `publishTerminalVerdict` →
  `{"created":true,"verdict":"PASS"}`, в evidence ровно один verdict PASS; `apps/control/run.mjs::terminalResult`
  (строка 380) возвращает PASS.
- Воспроизводимый сценарий B (повтор): легитимный PASS опубликован с анкером, затем
  `trustRoot/anchors/<anchorId>.json` удалён; повторный `publishTerminalVerdict` →
  `{"created":false,"verdict":"PASS"}`. `observeTrustedVerdict` в обоих сценариях:
  `passed:false, state:'inconsistent', reasonCode:'ANCHOR_MISSING'`, `verdict:null`.
- Ожидалось по контракту: для `outcome='anchor'` терминальное тело публикуется/возвращается только после
  `loadAnchor` + `verifyAnchorStatement` + `inspectEvidenceBinding` (`pre-verdict` при записи, `terminal` при повторном
  чтении) + `verifyAnchorAgainstBinding`; при отсутствии/негодности анкера — `ANCHOR_MISSING`/`ANCHOR_CONFLICT`/
  `ANCHOR_SIGNATURE_INVALID`/`INTEGRITY_ERROR`, verdict не пишется. Ветка существующего verdict должна также
  проверять соответствие исхода типу выбранного тела (`fail-without-anchor` ↔ FAIL и т.п.), иначе возвращает PASS при
  подмене `terminal-choice.outcome`.
- Нарушаемый инвариант: `BASELINE-AND-CONTRACTS.md` §6 п.2 «Ни одного PASS без годного анкера»;
  `02-TRUST-ARCHITECTURE.md` «PASS только при полной связке»; собственный §1 п.2 отчёта WP-05.
- Последствие: потеря/повреждение анкера после выбора исхода даёт необратимый терминальный PASS в evidence
  (второй verdict запрещён), который видит старый 0.1-путь `terminalResult`; `observeTrustedVerdict` ловит
  расхождение, но публикационная функция возвращает PASS и провоцирует доверенный путь вернуть его вызывающему.
- Severity: HIGH. Фикс + регрессии: «choice anchor без анкера → отказ, 0 verdict»; «легитимный PASS + удалённый
  анкер → повторная публикация отказ, не PASS»; «outcome в existing-ветке не соответствует телу → отказ».

### D-02 — HIGH-RISK / архитектурное расхождение. Подписант связывает область, но не бизнес-истину candidate

- Где: `anchor-signer.mjs:87-130`, `anchor.mjs:512-551` (`inspectEvidenceBinding`); отчёт WP-05 §9 R-07 это частично признаёт.
- Воспроизводимый сценарий (проба ревьюера): run с валидным approval/consumption/снапшотами и цепочкой,
  candidate PASS, у которого все checks `SATISFIED` с несуществующими `evidenceIds` (`['no-such-evidence-id']`).
  `client.sign(...)` → **успешная подпись** `{"ok":true,"verdict":"PASS","reasonCode":"NONE"}`.
- Ожидалось по `02-TRUST-ARCHITECTURE.md`: «Процесс, который меняет только каталог прогона, годный анкер для
  подложного PASS не получает». Фактически: при наличии валидного approval/consumption процесс с записью в
  `runDir` может заменить `candidate.json`/`candidates/<sha>.json` на подложный PASS — подписант подпишет его,
  потому что проверяет только связку scope (approval/consumption/снапшоты/голову цепочки), но не соответствие
  checks/evidenceIds реальному evidence и не пересчитывает бизнес-результат.
- Инвариант: заявление архитектуры о том, что анкер не даёт подложного PASS при правке только `runDir`.
  Не обход `observeTrustedVerdict` (он проверит подпись/связку, но не бизнес-истину candidate), и R-04
  (same-SID код) всё равно читает owner.key; но заявление в 02 в текущем виде неверно.
- Требование: решение Lead через `docs/changes`: (а) явно зафиксировать, что анкер подтверждает связку и
  неизменность candidate, а бизнес-истина обеспечивается только доверенным Verification/WP-06 T-D;
  (б) WP-06 обязан строить candidate только из выхода Verification и не отдавать наружу результат
  `publishTerminalVerdict`/`terminalResult` — только `observeTrustedVerdict`; (в) при желании усилить подписанта
  проверкой существования `checks.evidenceIds` и типов evidence (без пересчёта бизнес-логики).
- Severity: HIGH для заявления о доверии; не является нарушением буквы §5.2 (подписант делает ровно перечисленное).

### D-03 — LOW. Окно TOCTOU между проверкой отсутствия terminal-choice и записью анкера

- Где: `anchor-signer.mjs:90` (`existsSync(terminal-choice.json)`) и запись анкера `anchor-signer.mjs:117-125`.
  После проверки идёт синхронный блок без `await` (внутри одного процесса второй запрос не вклинится), но
  внешний процесс (Control) может создать `terminal-choice.json` в микронном окне между проверкой и
  `fs.openSync(...,'wx')`.
- Ожидалось (02, раздел «Публикация verdict»): после появления `terminal-choice.json` подписант новые
  PASS-заявления не выпускает. Фактически возможен анкер, записанный после выбора исхода.
- Последствие: в сценарии budget-inconclusive поздний анкер корректно распознаётся как `ANCHOR_UNLINKED` (V-09),
  PASS не появляется; в остальных — лишний анкер не выбирается (choice уже фиксирован). Обхода PASS не найдено.
- Severity: LOW (окно крайне узкое, воспроизвести не удалось). Рекомендация: повторная проверка непосредственно
  перед `openSync` и/или отказ `ANCHOR_CONFLICT` при обнаружении choice после записи; либо run-level lock.

### D-04 — LOW. Протокол подписанта и клиент расходятся с отчётом; `id` обязателен, клиент молча теряет лишние поля

- Где: `anchor-signer.mjs:11` (`signRequestKeys` включает `id`), `handleRequest` 132-142; клиент
  `connectAnchorSigner().sign()` — `anchor-signer.mjs:238-241`.
- Факты: raw-запрос ровно из `{type,runDir,approvalId,anchorId}` (без `id`) → `CONTRACT_INVALID` (хотя в отчёте §5
  `id` назван «служебным», т.е. опциональным); `client.sign({... , candidateSha256})` лишнее поле молча
  отбрасывает (тест это использует), тогда как отчёт §5 говорит «любое лишнее поле, включая candidateSha256,
  отклоняется кодом CONTRACT_INVALID». Безопасность не страдает (hash вызывающего не используется), но
  контракт/документация не совпадают с API.
- Severity: LOW. Фикс: сделать `id` опциональным либо зафиксировать обязательность; в клиенте отвергать
  неизвестные поля, а не отбрасывать.

### D-05 — LOW. `findUnlinkedAnchor` отдаёт anchorId без проверки подписи

- Где: `anchor.mjs:425-442`. `listAnchors` парсит файлы, `findUnlinkedAnchor` сравнивает `runId`/`candidateSha256`
  без `verifyAnchorStatement`.
- Сценарий: подложный/повреждённый, но синтаксически валидный файл `anchors/<id>.json` с нужными полями заставляет
  `observeTrustedVerdict` показать `anchorStatus='ANCHOR_UNLINKED'` и `unlinkedAnchorId`. PASS это не даёт,
  но метаданные наблюдения подменяемы.
- Severity: LOW. Фикс: проверять подпись/форму перед тем, как сообщать ANCHOR_UNLINKED.

### D-06 — INFO. `loadAnchor` возвращает неверифицированное заявление

- Где: `anchor.mjs:414-423`. Экспорт `loadAnchor` парсит файл без проверки; проверка отдельная
  (`verifyAnchorStatement`). WP-06 обязан всегда вызывать проверку; стоит явно записать это в отчёте/доке.

### D-07 — INFO. Профиль бюджета не подписан (R-05)

- `anchor.mjs:113-125`: `trustRoot/profile.json` читается без подписи. При записи в trust root под тем же SID
  можно выставить `anchorBudgetMs=1` (форс INCONCLUSIVE/DoS) или 60000 (задержка). Отчёт R-05 это признаёт;
  нужен `docs/changes` на домен `trust-profile`; PASS не подделывает.

## 5. Риски и требования для WP-06/WP-07

| ID | Требование |
|---|---|
| R-01 | WP-06 не должен возвращать бизнес-результат из `publishTerminalVerdict` или 0.1-`terminalResult` доверенного прогона: единственный источник PASS — `observeTrustedVerdict` (`passed===true`). До фикса D-01 это критично |
| R-02 | WP-06 T-D: candidate строит только доверенный Verification; подписант не проверяет бизнес-смысл (D-02) |
| R-03 | T-E: `observeTrustedVerdict` — единственный gate PASS; сверять `passed`, `state==='terminal'`, `trusted`, `anchorStatus==='ANCHOR_OK'`, `candidateSha256` |
| R-04 | Late anchor после budget-inconclusive: показывать `ANCHOR_UNLINKED`, не повышать до PASS, не писать второй verdict (код корректен, тест V-09) |
| R-05 | Бюджет: использовать `anchorWithinBudget`/`loadAnchorBudgetMs`; не передавать бюджет вызывающим; профиль до `docs/changes` — ограничение локальной 0.2 |
| R-06 | Named pipe: ACL по умолчанию Windows/Node, граница R-04 (same SID); для Dev/ЦИЗ не годится (отчёт R-06) |

## 6. Пробелы тестового покрытия

1. Нет теста «`terminal-choice.outcome='anchor'` без анкера → `publishTerminalVerdict` отказывает и не пишет verdict» (D-01).
2. Нет теста «легитимный терминальный PASS + удалённый/повреждённый анкер → повторная публикация не возвращает PASS» (D-01, ветка existing).
3. Нет теста «подложный candidate с валидной связкой approval/consumption/цепочки» (D-02/R-07); V-10 покрывает только отсутствие связки.
4. Нет теста raw-запроса без `id` и с лишними полями через `connectAnchorSigner` (D-04).
5. Нет межпроцессного теста одновременной публикации verdict (Q3); защита store проверена ревьюером по коду.

## 7. Вердикт

**FIX REQUIRED** (блокирует D-01; безопасного PASS-обхода через `observeTrustedVerdict` не найдено).

Обязательно до ACCEPT:
1. **D-01**: `publishTerminalVerdict` для `outcome='anchor'` проверяет годный анкер и его связку с выбранным
   candidate/цепочкой/approval до записи и в ветке существующего verdict; при негодности — отказ без нового
   verdict. Плюс регрессии из §6 п.1-2.
2. **D-02**: решение Lead через `docs/changes` о границе доверия анкера (связка vs бизнес-истина) и
   фиксация требования к WP-06 T-D; иначе заявление 02-ARCHITECTURE остаётся неверным.

Желательно: D-03 (TOCTOU), D-04 (протокол/id/лишние поля), D-05 (проверка подписи unlinked-анкера), D-06/D-07
(документация/подпись профиля).

Повторное ревью — после нового SHA: те же команды из §2 + адверсариальные пробы A/B/C/D из этого отчёта.

## 8. Git ревьюера

- Проверяемый SHA WP-05: `03655e00e2decb03b1332e2e3e624e0ea442f9ea`; дерево wp05 на момент проверки чистое.
- Ревьюер не менял файлы WP-05; отчёт добавлен отдельным коммитом в ветку ревьюера `feat/adaptant-02-wp03-policy`.

## 9. Повторное ревью после fix round (13.11.2026)

Проверяемый SHA: `5c020633f8f4e393739a6fba84e5d0bc4cd3803d` (код+тесты `c168465`), worktree wp05,
дерево чистое. Diff fix round: `packages/trust/anchor.mjs`, `packages/trust/anchor-signer.mjs`,
`tests/trust-anchor.test.mjs`, `docs/harness/WP-05-REPORT.md`.

### 9.1 Независимые прогоны (wp05, проверяемый SHA)

| Команда | Факт |
|---|---|
| `node --test tests/trust-anchor.test.mjs` | **22 tests / 22 pass / 0 fail**, exit 0, 25.2 s |
| `node --test tests/trust-*.test.mjs` | **41 tests / 41 pass / 0 fail**, exit 0, 26.2 s |
| `git status --porcelain` | пусто |

### 9.2 Повтор проб A/B/C/D (собственные пробы ревьюера)

| Проба | Ожидание после фикса | Факт |
|---|---|---|
| A: `outcome='anchor'`, `anchorId` без подписанного анкера | отказ, 0 verdict | `ANCHOR_MISSING`; verdict count 0; observe `passed:false, state:inconsistent, reasonCode:ANCHOR_MISSING`; без `trust/trustRoot` — тоже `ANCHOR_MISSING` (fail-closed) |
| B: PASS опубликован, анкер удалён | повторная публикация не PASS | `ANCHOR_MISSING`; verdict count остался 1 (artifact PASS уже в evidence); observe `passed:false, state:inconsistent, reasonCode:ANCHOR_MISSING` |
| C: подложный candidate с фиктивными evidenceIds | D-02 — решение Lead, код не менялся | подписант по-прежнему подписывает `PASS/NONE` — это зафиксировано в `docs/changes/006` (анкер удостоверяет связку/неизменность, не бизнес-истину); WP-06 обязан строить candidate только из Verification |
| D: подмена `outcome` в existing-ветке | отказ, не PASS | `INTEGRITY_ERROR`, verdict count 1 |

### 9.3 Закрытие замечаний

- **D-01 (HIGH, блокирующий) — закрыт**: `assertAnchoredPublication` проверяет `loadAnchor` +
  `verifyAnchorStatement` + anchorId/candidateSha256/runId/manifestSha256 + вердикт candidate +
  `inspectEvidenceBinding` (pre-verdict при записи, terminal при существующем verdict) +
  `verifyAnchorAgainstBinding` до записи и в ветке existing; новый verdict не пишется. Регрессии в тестах есть.
- **D-02 (HIGH-RISK) — снят решением Lead**: `docs/changes/006-anchor-assertion-scope.md` фиксирует, что анкер
  удостоверяет связку и неизменность candidate, но не бизнес-истину; WP-06 обязан строить candidate только из
  Verification и отдавать PASS только через `observeTrustedVerdict.passed`. Код подписанта менять не требовалось.
- **D-03 (LOW) — закрыт частично**: подписант трижды проверяет отсутствие `terminal-choice` (до, перед и после
  CREATE_NEW). Остаточная неточность: если выбор появился между проверкой и записью, подписант возвращает
  `ANCHOR_BINDING_REJECTED`, но уже записанный файл анкера остаётся на диске, хотя отчёт называет подпись
  «не выпущенной». Влияние низкое (choice уже зафиксирован; поздний анкер не даёт PASS и попадает в
  `ANCHOR_UNLINKED`); рекомендуется удалять только что созданный файл при обнаружении выбора или явно
  описать поведение.
- **D-04 (LOW) — закрыт**: `id` опционален, лишние поля в raw-протоколе и в `connectAnchorSigner().sign()`
  отвергаются `CONTRACT_INVALID`.
- **D-05 (LOW) — закрыт**: `findUnlinkedAnchor` сообщает `ANCHOR_UNLINKED` только по подписи `anchor-signer`.
- **D-06 (INFO) — закрыт документацией** `loadAnchor`.

### 9.4 Изменение интерфейса для WP-06

`publishTerminalVerdict` теперь принимает `{store, runDir, frozen, trust, trustRoot}`; для `outcome='anchor'`
`trust`/`trustRoot` обязательны (без них `ANCHOR_MISSING`, fail-closed). Это отражено в отчёте WP-05 §3/§1.1.
WP-06 обязан обновить call site; иначе доверенный PASS не опубликуется.

Информационно: отчёт WP-05 ссылается на `docs/changes/004` для D-02, фактическое решение по области анкера
лежит в `docs/changes/006-anchor-assertion-scope.md` интеграционной ветки — стоит поправить ссылку.

### 9.5 Вердикт повторного ревью

**ACCEPT.** D-01 закрыт и проверен повторно; D-02 снят решением Lead (`docs/changes/006`); D-03…D-06 закрыты
(с остаточной неточностью D-03, не блокирующей). Остаточные риски R-05/R-06/R-07 прежние и приняты как
границы локальной 0.2.
