# WP-08 REAUDIT — базовое воспроизведение дефектов на 07c21c4

Статус: **BASELINE REPRODUCED**. Ветка `test/wp08-independent-audit`, база `07c21c4db936627df9a3c874015327ea992a335a`.
Продуктовый код не изменялся. Все артефакты — собственный прогон аудитора R-D, не перенос текста отчётов.

## 1. Что сделано

Атакующие сценарии аудита WP-08 перенесены в переиспользуемый каталог `tests/audit-remediation/`:
каждый сценарий — отдельный `.mjs`-файл с машинным JSON-вердиктом и exit code, параметр
`--target=<worktree>` позволяет прогнать его против любой ветки.

| Exit | Вердикт | Значение |
|---|---|---|
| 0 | `PASS` | дефект на проверяемой ревизии **не воспроизводится** (защита сработала) |
| 1 | `FAIL` | дефект **воспроизводится** (ложный PASS / обход / потеря результата) |
| 3 | `INCONCLUSIVE` | прогон не доказателен (обвязка не совместима с ревизией, атака не выполнена) |

Правило доказательности: `PASS` никогда не выводится из exit code. Агрегатор
`run-matrix.mjs` ставит строке `PASS` только по распарсенному JSON, где `tool=WP08-REAUDIT`,
`scenario` совпадает со строкой матрицы, `target.head` совпадает с проверяемой ревизией и
фактический exit code согласован с документом. Непарсибельный JSON, чужой вердикт и чужая
ревизия дают `INVALID`, а не `PASS`. Стресс/негатив на это — `matrix-negative.test.mjs` (5/5).

## 2. Фактический прогон против 07c21c4

Команда:

    node tests/audit-remediation/run-matrix.mjs --target=<worktree на 07c21c4> --out=tests/audit-remediation/baseline-07c21c4.json

Фактический итог: `verdict=FAIL, exitCode=1, counts={FAIL:9}`. Все девять строк матрицы
воспроизводят дефект на базовой ревизии. Ключевые поля:

| ID | Сценарий | Exit | Вердикт | Факт |
|---|---|---|---|---|
| AUD-P0-01 | подложный candidate + годный анкер | 1 | FAIL | `SIGNER_RESULT ok, verdict=PASS`; `observeTrusted passed=true, anchorStatus=ANCHOR_OK`; реальной мутации нет (`standMutationCount=0`) |
| AUD-P0-02-A | подмена стенда после POST | 1 | FAIL | реальная запись неполная (`comment=null`), Verification прочитал rogue, опубликован PASS |
| AUD-P0-02-B | подмена в окне T-C→POST | 1 | FAIL | `standMutationCount=0`, `roguePosts=1`, `bearerLeaked=true`, verdict PASS |
| AUD-P1-01 | наблюдатель слабее 0.1 | 1 | FAIL | 0.1-паритет нарушен (эффект не подтверждён независимым чтением), trusted observer показывает PASS |
| AUD-P1-02 | V-07 потеря анкерованного PASS | 1 | FAIL | восстановление дало `CANDIDATE_CONFLICT`/INCONCLUSIVE, verdict не равен выбранному candidate |
| AUD-P2-R02 | R-02 junction | 1 | FAIL | keygen exit 0, `owner.key`/`anchor.key` созданы внутри `runs/run-02` через junction |
| AUD-P2-APPROVALID | путь только approvalId | 1 | FAIL | `startTrusted({approvalId})` без документа → BLOCKED |
| AUD-P2-PUBLICATION | publish-ошибка → verdict без choice | 1 | FAIL | инъекция `publish()` бросила, появился verdict без `terminal-choice` |
| AUD-P2-E04 | E-04 credentialRef | 1 | FAIL | секрет доставлен стенду (запросы с `Authorization`) при чужом `credentialRef` |

Итог: **оба P0 воспроизводятся на 07c21c4**, что совпадает с воспроизведением Lead
(`remediation/docs/harness/WP08-REPRODUCTION.md`), и дополнительно воспроизводятся P1/P2,
входившие в исходный REJECT.

## 3. Состав сценариев

| Файл | Что проверяет | Атака/обход |
|---|---|---|
| `p0-01-forge-candidate.mjs` | AUD-P0-01: forge candidate при валидной связке approval/consumption; подмена candidate после анкера; второй анкер; второй verdict | публичный канал подписанта, запись runDir |
| `p0-02a-swap-after-post.mjs` | подмена стенда после POST и до независимого чтения; replay захваченной аттестации | rogue на том же порту |
| `p0-02b-window-swap.mjs` | подмена в окне T-C→POST; утечка Bearer; условие владельца `roguePosts=0, bearerLeaked=false` | наблюдение за `runDir/evidence`, rogue в режиме `learn` |
| `p1-01-weak-observer.mjs` | паритет доверенного наблюдателя с 0.1 | PASS-candidate, покрытие которого не подтверждено чтением |
| `p1-02-v07-recovery.mjs` | V-07: восстановление после анкера (инъекция падения через подписант) | гибель Control после подписи анкера до verdict |
| `p2-r02-junction.mjs` | R-02: физический путь внутрь `runs` через junction | junction в `--secrets` |
| `p2-approval-id-only.mjs` | путь «только approvalId» | отсутствие документа approval |
| `p2-publication-no-choice.mjs` | ошибка `trust.publish` не даёт verdict без choice | инъекция контекста с бросающим `publish()` |
| `p2-e04-credential-ref.mjs` | E-04: чужой `credentialRef` не должен выдавать секрет | запись среды с секретом другой среды |

Все временные каталоги — `%TEMP%`; продуктовый код и trust root аудита не затрагиваются.
Аудиторская ветка `audit/wp-08-07c21c4` не изменялась.

## 4. Ограничения базового прогона

- Локальный стенд и локальный браузер (Chromium), проектная среда Windows/Node v24.16.0;
  Dev/ЦИЗ не использовались (запрещены условиями).
- Сценарии A/B/P1-02 содержат честный контроль доверенного пути; если контроль не проходит,
  сценарий возвращает `INCONCLUSIVE`, а не `PASS`.
- P2-сценарии фиксируют исходные дефекты как `FAIL`; на исправленной ревизии ожидается `PASS`.
- Время выполнения полной матрицы на базе: около 2.5 минут (Chromium-прогоны в A/B/P1-02/P2).
