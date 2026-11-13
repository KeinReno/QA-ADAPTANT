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
