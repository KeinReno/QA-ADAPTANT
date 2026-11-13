# WP08-06 — STABLE 0.1 COMPATIBILITY

Аудитор: verifier (WP-08). SHA под проверкой: `07c21c4db936627df9a3c874015327ea992a335a`.
Контрольные точки: тег `v0.1.0-stable` = `88fc1d7b46e898b9d1ac85996042798fe55a2619`, `main` = `59d82d49c01442d463ebab5d5f3d661ca550e504` (локальная ветка называется `master`, remote — `origin/main`).
Ничего в репозитории не изменялось; все проверки — чтение git/файлов и прогоны тестов, запись только в `wp08-audit/**`.

## 1. Неизменность main и тега Stable

Локальные и удалённые refs (сверено с origin через сеть):

| Ref | Значение | Артефакт проверки |
|---|---|---|
| `v0.1.0-stable` (аннотированный тег) | object `fd722ceddf9a81400b447e2684bc6630ec5375dd` → commit `88fc1d7b46e898b9d1ac85996042798fe55a2619` | `git cat-file -p v0.1.0-stable` |
| `refs/tags/v0.1.0-stable` на origin | `fd722ce…`; peeled `refs/tags/v0.1.0-stable^{}` = `88fc1d7…` | `git ls-remote origin 'refs/tags/v0.1.0-stable*'` |
| `main` на origin | `59d82d49c01442d463ebab5d5f3d661ca550e504` | `git ls-remote origin refs/heads/main` |
| `refs/heads/main` локально (`master`) | `59d82d4…` | `git show-ref` |
| `feat/adaptant-02-trust-integration` на origin | `07c21c4…` (совпадает с HEAD) | `git ls-remote` |

Проверки происхождения:
- `git merge-base --is-ancestor 88fc1d7 59d82d4` → 0 (Stable входит в main);
- `git merge-base --is-ancestor 59d82d4 07c21c4` → 0 (main — предок интеграционной ветки);
- дерево коммита main: `60df350a13e73bf2e5e36a960cfa3f26a3199c2d`, дерево коммита Stable — **то же самое** `60df350a…` (main не менял содержимое 0.1, только README-коммит/слияние);
- тег аннотированный, message: «KAIDEN QA ADAPTANT 0.1 Stable… Продуктовый код совпадает с c37817c».

Вывод: **main и v0.1.0-stable не переписаны и совпадают с origin; Stable — предок main, main — предок проверяемого SHA**. PASS.

## 2. Замороженные пути: diff `v0.1.0-stable..07c21c4`

Команда: `git diff --name-status v0.1.0-stable..07c21c4 -- packages/contracts schemas docs/contract-freeze.json packages/core apps/browser apps/verification adapters/local/bundle.mjs` → **пусто** (exit 0).

| Путь | Изменения |
|---|---|
| packages/contracts/ | нет |
| schemas/ | нет |
| docs/contract-freeze.json | нет |
| packages/core/ | нет |
| apps/browser/worker.mjs | нет |
| apps/verification/worker.mjs | нет |
| adapters/local/bundle.mjs | нет |

Дополнительно `git diff 0e7e6c2..07c21c4` по тем же путям — **пусто** (совпадает с заявлением `docs/harness/04-COMPATIBILITY-REPORT.md`). PASS.

## 3. Contract freeze

`docs/contract-freeze.json` (HEAD): 9 записей. Проверены `Get-FileHash -Algorithm SHA256` по каждой:

| Файл | Хеш совпал |
|---|---|
| packages/contracts/index.mjs | да |
| ARCHITECTURE.md | да |
| MODULE-BOUNDARIES.md | да |
| OPERATION-CONTRACT.md | да |
| SCENARIO-SCHEMA.md | да |
| RUN-PROTOCOL.md | да |
| EVIDENCE-SCHEMA.md | да |
| VERDICT-POLICY.md | да |
| FIXTURE-CONTRACT.md | да |

9/9 совпали. Сам `docs/contract-freeze.json` не менялся относительно Stable (§2). PASS.

Ограничение (F-WP08-11): freeze не содержит `schemas/*.json`, `apps/control/run.mjs`, `adapters/local/server.mjs`. Дрейф схем контролируется только внешним `git diff` после `npm run schemas`; для run.mjs/server.mjs freeze заведомо не покрывает изменения 0.2 (они входят в «рабочие входы»).

## 4. Схемы

`npm run schemas` → exit 0. SHA-256 всех 6 файлов `schemas/*.json` до и после запуска идентичны; `git diff -- schemas` пуст; `git status --porcelain schemas` пуст. `evidence/verifier/02-schemas.log`. PASS.

## 5. Старые тесты 0.1 и старые регрессии

`git diff --name-status v0.1.0-stable..07c21c4 -- tests/audit-wp.test.mjs tests/contract-links.test.mjs tests/contracts.test.mjs tests/evidence-readers.test.mjs tests/faults.test.mjs tests/lifecycle.test.mjs tests/review-grok.test.mjs tests/runtime.test.mjs tests/helpers.mjs tests/observe-loop.mjs` → **только `A tests/approval-consume-worker.mjs`** (новый вспомогательный файл). Ни один старый тестовый файл 0.1 не изменён. PASS.

Независимый прогон старого набора отдельно:
`node --test --test-concurrency=1 --test-timeout=45000 tests/{contracts,contract-links,runtime,faults,lifecycle,audit-wp,evidence-readers,review-grok}.test.mjs`
→ **59 tests, 59 pass, 0 fail, exit 0**, 184.4 с (`evidence/verifier/08-old-regressions.log`).

Сверка: 59 — ровно столько же тестов было в старом наборе 0.1 (`docs/gates/suite-1.txt`: «suite-1 | 59 | 0 | 0»), т.е. старый набор не «вырос» за счёт подмены/ослабления. PASS.

## 6. Публичные методы и поведенческая совместимость

`packages/trust/` на `v0.1.0-stable` отсутствует полностью (`git ls-tree v0.1.0-stable packages/trust` пуст) — весь trust-слой новый, старый код не переписан.

Изменены только (относительно Stable): `apps/control/run.mjs`, `adapters/local/server.mjs`; добавлены `packages/trust/*`, `apps/control/trusted.mjs`.

`apps/control/run.mjs`:
- Экспорты и вызываемая форма сохранены: `run(bundle, options)`, `start(bundle, options)`, `observe({root, runId})`, `reconcile(options)`, `cancel({root, runId})`, `cleanup()`. Сигнатуры переведены с деструктуризации в параметрах на деструктуризацию в теле + `options = {}`; для существующих вызовов (объект) поведение то же.
- Добавлен `assertOldEntryOptions(options)` (`run.mjs:19-22`): старые входы отвергают 7 имён (`approvalId, approval, trustRoot, adapter, adapterId, standPublicKey, signerPipe`) кодом `CONTRACT_INVALID` до snapshot/мутации (L-08). Для 0.1-вызовов это no-op.
- Доверенные врезки T-A/T-B/T-C/T-D исполняются только при наличии `options.trust`; при его отсутствии ветки 0.1 не изменены (это подтверждено 59/59 старых тестов).
- Замечание F-WP08-10: `trust` не входит в список отвергаемых имён — это фактический переключатель доверенного пути (его передают `startTrusted`/`reconcileTrusted`, `trusted.mjs:271,315`). Формулировка «старый вход не принимает аргументы доверенного режима» шире факта; эскалацией не является (R-04: произвольный код той же учётной записи вне границы доверия).

`adapters/local/server.mjs` — изменения аддитивные:
- `serveLocalFixture({ fault, environmentId, generation = 1, port = 0 })` — добавлены `generation` и `port` (дефолт 0 = прежнее поведение);
- добавлен `POST /attest` (подпись challenge ключом стенда); `GET /environment` не изменён;
- в возвращаемый объект добавлены `standKeyId, standPublicKey, pid, generation`; старые поля (`baseUrl, environmentId, fingerprint, authToken, mutationCount, readCount, recordCount`) сохранены.

Вывод: поведенческая совместимость 0.1 подтверждена: старые тесты зелёные без правок, старые входы работают как в 0.1, новые аргументы доверия на старом входе отвергаются до мутации. PASS с оговоркой F-WP08-10.

## 7. Дефекты/наблюдения по совместимости

| ID | Severity | Файл:строка | Суть | Влияние |
|---|---|---|---|---|
| F-WP08-10 | P3 | `apps/control/run.mjs:19-22`, `trusted.mjs:271,315`, `tests/redteam/rt2-l08-old-start-rejects-trust.mjs:11-13` | `trust` — фактический переключатель доверенного пути, но не в списке отвергаемых старым входом; L-08 проверяет только 7 имён | формулировка гарантии шире факта; не эскалация (R-04) |
| F-WP08-11 | P3 | `docs/contract-freeze.json` | freeze не покрывает `schemas/*.json` и рабочие входы `run.mjs/server.mjs` | дрейф схем ловится только ручным `git diff`; нет автоматического гейта |
| F-WP08-12 | P3 | `docs/gates/*` | исторические gate-артефакты от `df5c99d` (59 тестов, package 0.0.1), не перегенерированы на финальный SHA | могут быть прочитаны как доказательство финальной ревизии, хотя относятся к ранней базе; в `02-TEST-EVIDENCE` числа уже другие |

## 8. Заявлено / подтверждено / опровергнуто

| Заявление (`04-COMPATIBILITY-REPORT.md` и др.) | Статус | Основание |
|---|---|---|
| `git diff 0e7e6c2..HEAD` по замороженным путям пуст | подтверждено | §2 |
| Тег Stable не переносился: fd722ce → 88fc1d7 | подтверждено | §1 + `git ls-remote` |
| `npm run schemas` без диффа | подтверждено | §4 |
| Старый набор 0.1 остаётся зелёным без правок старых тестов | подтверждено | §5: 59/59, файлы не изменены |
| `run.mjs` изменён точками врезки, не ломая 0.1 | подтверждено (P3-оговорка F-WP08-10) | §6 + 59/59 |
| `server.mjs` изменён аддитивно, `GET /environment` не менялся | подтверждено | §6 |
| main/v0.1.0-stable не изменены | подтверждено | §1 (origin refs + ancestry) |
| freeze покрывает контракты полностью | частично: 9/9 хешей верны, но схемы/рабочие входы вне freeze (F-WP08-11) | §3 |
