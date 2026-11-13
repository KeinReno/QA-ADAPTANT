# WP-08-REMEDIATION — HANDOFF (остановка по требованию владельца)

Дата остановки: 13.11.2026. Все субагенты остановлены, фоновые задания сняты. Ветки/memory-работа не потеряны.

## Где именно остановились

Ветка интеграции: `fix/adaptant-02-wp08-remediation`, HEAD `8b459ab` (не опубликован; предыдущий опубликован `0686c78`).
Состояние: P0-01 (provenance + session nonce) и P0-02 (закреплённое соединение) слиты; P1/P2 R-C слиты частично.
**Сквозной E2E сейчас красный: 9/14.** Причина установлена:

- T-01/T-02/T-08/T-12/T-14 → `BLOCKED`, decision `ENVIRONMENT_ATTESTATION_FAILED`.
- Источник: включённый E-04 в `createTrustContext → refreshEnvironment` вызывает `resolveCredential({credentialRef, credentials, fixtureToken})` (apps/control/trusted.mjs:237-241). В E2E-тестах запись среды имеет `credentialRef='local:fixture-token'`, а `credentials` не передан — секрет не разрешается, preflight отказывает.
- Это не дефект логики, а незавершённая проводка E-04 в тестах/вызове.

Первое действие при продолжении (20–30 минут):
1) В `tests/trust-integration.test.mjs` в `trustedOptions()` передавать `credentials: { 'local:fixture-token': w.stand.authToken }` и убрать неявную двойственность `fixtureToken`; либо (если так задумано) в `resolveCredential` разрешить `local:fixture-token` из `fixtureToken`.
2) Прогнать `node --test tests/trust-integration.test.mjs` → ожидается 14/14.
3) Прогнать `node --test tests/trust-provenance.test.mjs tests/trust-anchor.test.mjs tests/trust-signed-environment.test.mjs`.

## Состояние потоков

| Поток | Ветка | HEAD | Незакоммичено | Что готово |
|---|---|---|---|---|
| P0-01 | fix/wp08-p0-01-provenance | 96cc958 | нет | аттестация 0.2.1, WMI+session nonce, приватный подписант, observer-паритет, 10 регрессий provenance + 22 anchor |
| P0-02 | fix/wp08-p0-02-stand-channel | 1d80417 | нет | подписанные ответы/чтения, закреплённое соединение, trusted Browser Worker, 15 тестов |
| P1/P2 | fix/wp08-p1-p2-recovery | 9454106 | 7 файлов | P2-01/02/04/05, P1-02/V-06, тест-инфраструктура; незакоммичены run.mjs, trusted.mjs, anchor-signer.mjs, tests/trust-p2, tests/trust-recovery, WP08-P1-P2-REPORT.md, WP08-P1-P2-ANCHOR-PATCH.md |
| Независимый аудит | test/wp08-independent-audit | e44af44 | 20 файлов | 9+ сценариев audit-remediation, матрица; не закоммичены новые p0-01c, p0-02d, обновления lib/matrix и артефакты прогонов |
| Интеграция | fix/adaptant-02-wp08-remediation | 8b459ab | нет | см. выше |

## Что уже доказано (не переделывать)

- Оба P0 воспроизведены на 07c21c4 (логи в docs/harness/evidence аудиторской ветки и в отчёте Lead).
- На исправленной ревизии `1791dec` исходные скрипты WP-08 не дают ложного PASS:
  P0-01 — `SIGNER ok:false`, `VERDICT_FALSE_PASS_SHOWN false`; P0-02 — A и B не воспроизводятся,
  `mutationCount=0`, `roguePosts=0`, `bearerLeaked=false`. Логи: docs/harness/evidence/*.txt.
  Оговорка: контролируемый стенд аудиторского скрипта не подписывает ответы, поэтому отказ происходит раньше атаки.
- P0-01 после session nonce: 32/32 (provenance+anchor), E2E T-01/T-12 зелёные на 96cc958-интеграции до слияния P1/P2.

## Что НЕ доделано

1. **E2E после слияния P1/P2** — красный из-за E-04-проводки (см. выше). Это блокер №1.
2. **Полноценные независимые атаки на живом подписывающем стенде** (требование владельца): сценарии R-D готовы частично,
   но не закоммичены и не прогнаны на финальном SHA. Нужно: p0-02a/b/c/d + p0-01b/c (подмена Worker, ключа, nonce,
   replay подписи) на ревизии после блокера №1.
3. **P1/P2 остаток**: незакоммиченные файлы R-C (включая патч anchor.mjs) не сведены; P1-01 паритет проверить
   на интегрированной ревизии; матрица тестов не прогнана целиком.
4. **Полная Windows-регрессия** (npm test, test:races, schemas, attacks, E2E, Stable 0.1 59/59) — не выполнена на едином SHA.
5. **Финальная ревизия + отчёт на SHA + публикация** — не сделаны; `8b459ab` ещё не в origin.
6. **Повторная WP-08** — не проводилась и не может проводиться до п.1–5.

## Как продолжать

    cd C:\Users\gvi\Desktop\QA-ADAPTANT-harness\remediation
    git log --oneline -3            # 8b459ab
    node --test tests/trust-integration.test.mjs     # сейчас 9/14, причина ENVIRONMENT_ATTESTATION_FAILED

    # после правки E-04-проводки:
    node --test tests/trust-integration.test.mjs
    node --test tests/trust-provenance.test.mjs tests/trust-anchor.test.mjs tests/trust-signed-environment.test.mjs
    npm test; npm run test:races; npm run schemas
    node tests/redteam/run-all-w2.mjs --target=.; node tests/redteam/run-matrix.mjs .

    # независимый аудит (после коммита rem-d):
    cd ..\rem-d && node tests/audit-remediation/run-matrix.mjs <путь к remediation>

Запреты прежние: не менять Stable 0.1, аудиторскую ветку, main; не подключать Dev/ЦИЗ; не объявлять ACCEPT.
