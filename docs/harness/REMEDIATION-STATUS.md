# REMEDIATION STATUS — WP-08-REMEDIATION

Цикл исправлений после REJECT независимой приёмки WP-08. База: 07c21c4 (отклонённый кандидат).
Ветка: fix/adaptant-02-wp08-remediation. Merge в main не выполняется. Stable 0.1 не меняется.

## Исходное состояние

| Дефект | Severity | Воспроизведён Lead | Статус |
|---|---|---|---|
| AUD-P0-01 подложный candidate + годный анкер | P0 | да (exit 0, PASS без мутации) | в работе |
| AUD-P0-02 подмена стенда после T-C/после POST | P0 | да (2/2 сценария) | в работе |
| AUD-P1-01 наблюдатель слабее 0.1 | P1 | подтверждено аудитом | в работе |
| AUD-P1-02 V-07 recovery | P1 | подтверждено аудитом | в работе |
| AUD-P2-01 R-02 junction | P2 | подтверждено аудитом | в работе |
| AUD-P2-02 approvalId-only | P2 | подтверждено аудитом | в работе |
| AUD-P2-03 V-06 | P2 | подтверждено аудитом | в работе |
| AUD-P2-04 публикация без terminal-choice | P2 | подтверждено аудитом | в работе |
| AUD-P2-05 E-04 credentialRef | P2 | подтверждено аудитом | в работе |

## Потоки

| Поток | Ветка | Владелец | Статус |
|---|---|---|---|
| P0-01 provenance | fix/wp08-p0-01-provenance | rem-a | IN PROGRESS |
| P0-02 stand channel | fix/wp08-p0-02-stand-channel | rem-b | IN PROGRESS |
| P1/P2 recovery | fix/wp08-p1-p2-recovery | rem-c | IN PROGRESS |
| Независимый аудит | test/wp08-independent-audit | rem-d | IN PROGRESS |

## Требуется решение владельца

Замена формулировки модели доверия (WP08-REMEDIATION-ARCHITECTURE.md §3): A1–A3 и явный остаточный риск
(код того же Windows SID с правами инъекции/DPAPI — вне модели; для Dev/ЦИЗ нужен отдельный SID).
Это единственное архитектурное решение, которое требуется до финальной ревизии.

## Промежуточный результат: исходные P0-скрипты WP-08 на исправленной ревизии (1791dec)

Проверено запуском **исходных** аудиторских скриптов (копия wp08-audit/tests в рабочем дереве, после прогона удалена;
аудиторская ветка не изменялась). Логи: docs/harness/evidence/.

| Скрипт | Было на 07c21c4 | Стало на исправленной ревизии |
|---|---|---|
| wp08-r07-forge-candidate.mjs (AUD-P0-01) | SIGNER ok:true verdict PASS, trusted observe passed:true, false PASS shown | SIGNER ok:false CONTRACT_INVALID «sign() требует verification-attestation»; observeTrusted trusted:false passed:false; VERDICT_FALSE_PASS_SHOWN false |
| wp0304-06-false-pass.mjs (AUD-P0-02) | A и B воспроизводились: ложный PASS, roguePosts=1, bearerLeaked=true | Ни A, ни B не воспроизводятся: verdict BLOCKED/ENVIRONMENT_CHANGED, standMutationCount=0, roguePosts=0, rogueRecordGets=0, bearerLeakedToRogue=false |

Оговорка: контролируемый стенд аудиторского скрипта не подписывает ответы доменом stand-response, поэтому
доверенный путь отказывает ещё на аттестации закреплённого соединения. Это fail-closed и закрывает дефект,
но сценарий «подмена стенда, который умеет подписывать» проверяется отдельными регрессиями R-B
(tests/trust-signed-environment.test.mjs, сценарий B: roguePosts=0, bearerLeaked=false) и независимым R-D.

## Текущее состояние интеграции

- Ветка fix/adaptant-02-wp08-remediation; P0-01 (R-A) и P0-02 (R-B) слиты, wiring Control выполнен Lead.
- Сквозной доверенный прогон: PASS только с аттестацией Verification; POST только по закреплённому сокету;
  переаттестация перед POST; ответ проверяется подписью стенда; независимые чтения только подписанные.
- Осталось до финальной ревизии: сведение P1/P2 (R-C), независимый прогон R-D, полная регрессия, отчёт на SHA.
