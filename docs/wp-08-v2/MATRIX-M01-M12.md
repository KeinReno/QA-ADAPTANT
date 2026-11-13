# MATRIX M01–M12 — ЗАКРЫТИЕ ЗАМЕЧАНИЙ QWEN (аудит 6270128)

| ID | Требование Qwen | Архитектурное решение v2.1 | Инвариант | Критерий приёмки |
|---|---|---|---|---|
| M01 | TAS не подписывает неудостоверённые факты | §4: TAS сама spawn-ит Worker, эфемерный ключ по handle, attestation только по TAS-каналу, пересчёт readSet/candidate, паритет проверок | INV-10/11/12/13 | T03/T04/T09/T10/T20 закрыты проектом; e2e-тесты обязательны |
| M02 | Потребление approval/grant в TAS | STATE-MACHINE + §5: атомарный bind, single-use grant, TTL, revoke, сериализация | INV-07/08/14/15 | T01/T02/T06/T07/T08/T11; DoS назван явно |
| M03 | Аутентификация сервера IPC | §6 + контракты: SID сервера + подпись TAS ключом из install dir + ECDH-сессия | INV-16 | T12/N15; тест с поддельным каналом |
| M04 | Grant не покидает доверенную зону | §7: grant только в памяти TAS/Worker, по inherited handle; публичный IPC без grant-глаголов | INV-09 | T05 |
| M05 | Enrollment/rotation | §8.1: офлайн fingerprint, повторный enroll → отказ, внешний keyId, secure desktop | INV-04/05 | T14/N17, R8' |
| M06 | Registry | §8.2: append-only, HWM, ACL без Admins-писателей, backup/restore, rollback-отказ | INV-03 | T15/N18 |
| M07 | DPAPI LM не граница | §8.3: ACL файла ключа (SID службы) + контекст службы; DPAPI — defense-in-depth | INV-06 | тест доступа из user-процесса |
| M08 | Legacy-анкеры | §9: LEGACY_UNVERIFIED; переаттестация только решением владельца | INV-18 | T16/N20 |
| M09 | owner=админ | OWNER-DECISIONS D1: не-админ владелец + отдельная admin-граница; альтернативы и деградация | INV-20 | решение владельца зафиксировано |
| M10 | База пакета | ADAPTANT-03-COMPAT: перенос на 1a510a5, карта API и вызовов 0.3.1 | — | пакет на полной линии 0.2 |
| M11 | Fake/real TAS | PLAN S8 + INV-17: fake только тестовый, не выбирается env/config | INV-17 | приёмка против реальной службы |
| M12 | Полная матрица на v2-SHA | MATRIX §3: R1,N01–N12,P01,R5–R8,N13–N20 + gates + R-D из дерева | INV-19 | сырые журналы, коды выхода |

## Закрытие двух цепочек Qwen

**Цепочка A (approval replay → fabricated evidence → anchor):** закрывается INV-07
(approval bind в TAS), INV-10/11/12 (анкер только от TAS-спавненного Worker с эфемерной
подписью; evidence в ACL-зоне службы; пересчёт readSet/candidate в TAS), INV-09 (grant
не на диске). Остаток — DoS через перехват bind, назван явно (STATE-MACHINE §4).

**Цепочка B (поддельная TAS):** закрывается INV-16 (SID сервера + подпись TAS ключом,
закреплённым в install dir + FIRST_PIPE_INSTANCE + fail-closed без fallback).

## Чего матрица НЕ утверждает

Статусы «ЗАКРЫТО-ПРОЕКТОМ» не являются PASS. До реализации и независимой приёмки
(INV-19) ни один сценарий не считается пройденным.
