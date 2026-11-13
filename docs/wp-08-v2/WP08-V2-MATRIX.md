# WP08-V2-MATRIX — РАСШИРЕННАЯ МАТРИЦА И ТРАССИРОВКА АТАК (v2.1)

Реализации нет: столбец «v2.1» — **проектное поведение**, не PASS. PASS засчитывается
только после реального исполнения на v2-SHA (M12/INV-19).
Источники: аудит Qwen 4e96cdc (R1/N01–N12/P01/R5–R8), 6270128 (T01–T20, N13–N20).

## 1. Матрица сценариев

| ID | Атака | 1a510a5 | 41043ad | v2.1 (проект) | Механизм/инвариант |
|---|---|---|---|---|---|
| R1 | Подмена трёх публичных файлов без закрепления | ложный trusted PASS | отклонён | NO_TRUSTED_PASS | TAS+Registry (INV-02) |
| N01 | owner.pub only | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-02 |
| N02 | anchor.pub only | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-02 |
| N03 | ready.json only | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-02 |
| N04 | Все три после легитимного прогона | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-02/INV-18 |
| N05 | Подмена до первой загрузки | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-02 |
| N06 | Подмена между загрузкой и стартом | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-02 |
| N07 | Подмена во время Recovery | нет повторной мутации | нет повторной мутации | NO_TRUSTED_PASS, идемпотентно | INV-15 |
| N08 | Чужой approval | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-07 |
| N09 | Чужой Anchor | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-10/INV-06 |
| N10 | Конфигурационный выбор корня (N10в) | ложный trusted PASS | ложный trusted PASS | NO_TRUSTED_PASS | INV-01/INV-02 |
| N11 | Несанкционированная ротация | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-04/INV-05 |
| N12 | Повреждение/отсутствие закрепления | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS | INV-03 |
| P01 | Позитивный контроль (trusted PASS, один POST, recovery) | legitPass | legitPass | legitPass — обязателен | INV-13/INV-15 |
| R5 | DPAPI-конверт тем же SID | — | ложный trusted PASS | NO_TRUSTED_PASS | INV-02/INV-03/INV-07 |
| R6 | Обход кэша по mtime/size | — | частичный обход | NO_TRUSTED_PASS | кэш по метаданным запрещён (INV-03) |
| R7 | Публичный API на новый корень | — | ложный trusted PASS | NO_TRUSTED_PASS | INV-01/INV-02 |
| R8 | resеal с чужими ключами | — | ложный trusted PASS | NO_TRUSTED_PASS | INV-05 |
| N13 | Поддельный IPC-запрос grant/anchor | — | не проверялось | NO_TRUSTED_PASS | INV-09/INV-10/INV-16 |
| N14 | Replay grant / после TTL | — | не проверялось | NO_TRUSTED_PASS | INV-08 |
| N15 | Pipe squatting (поддельная TAS) | — | не проверялось | NO_TRUSTED_PASS | INV-16 |
| N16 | Сфабрикованная attestation без инъекции | — | не проверялось | NO_TRUSTED_PASS | INV-10/INV-11/INV-12 |
| N17 | Enrollment из подменённого каталога | — | не проверялось | NO_TRUSTED_PASS | INV-04 |
| N18 | Rollback/backup Registry | — | не проверялось | NO_TRUSTED_PASS | INV-03 |
| N19 | owner = локальный администратор | — | не проверялось | УСЛОВИЕ РАЗВЁРТЫВАНИЯ (M09) | OWNER-DECISIONS D1 |
| N20 | Legacy-анкеры до v2 | — | не проверялось | LEGACY_UNVERIFIED, не PASS | INV-18 |

## 2. Трассировка T01–T20

| ID | Сценарий Qwen | Механизм v2.1 | Проектный статус |
|---|---|---|---|
| T01 | Grant по поддельному approval | INV-07, атомарный bind в TAS | ЗАКРЫТО-ПРОЕКТОМ (реализация+тест) |
| T02 | Grant по чужому runId | INV-07 | ЗАКРЫТО-ПРОЕКТОМ |
| T03 | Подмена evidenceHead | INV-11/INV-12 | ЗАКРЫТО-ПРОЕКТОМ |
| T04 | Поддельное происхождение Worker | INV-10 (эфемерный ключ, TAS-канал) | ЗАКРЫТО-ПРОЕКТОМ |
| T05 | Использование grant другим процессом | INV-09 (grant только в памяти) | ЗАКРЫТО-ПРОЕКТОМ |
| T06 | Повторное использование grant | INV-08 | ЗАКРЫТО-ПРОЕКТОМ |
| T07 | Повторный запрос подписи | INV-08/INV-10 | ЗАКРЫТО-ПРОЕКТОМ |
| T08 | Race cancel/verification/anchor | INV-14 | ТРЕБУЕТ-РЕАЛИЗАЦИИ (race-тест) |
| T09 | Подпись без независимых чтений | INV-11/INV-13 | ЗАКРЫТО-ПРОЕКТОМ |
| T10 | Анкер через публичный IPC | INV-10/INV-16 | ЗАКРЫТО-ПРОЕКТОМ |
| T11 | Recovery с устаревшим grant | INV-15 | ЗАКРЫТО-ПРОЕКТОМ |
| T12 | Named pipe squatting | INV-16 | ЗАКРЫТО-ПРОЕКТОМ |
| T13 | owner = администратор | M09 / OWNER-DECISIONS D1 | РЕШЕНИЕ ВЛАДЕЛЬЦА |
| T14 | Enrollment из подменённого корня | INV-04 | ЗАКРЫТО-ПРОЕКТОМ |
| T15 | Откат/подмена Registry | INV-03 | ЗАКРЫТО-ПРОЕКТОМ |
| T16 | Исторические анкеры | INV-18 | РЕШЕНИЕ ВЛАДЕЛЬЦА (политика) |
| T17 | Подмена файлов по enrolled-пути | INV-02 (+junction/symlink-проверка) | ЗАКРЫТО-ПРОЕКТОМ |
| T18 | Выбор trustRootId клиентом | INV-01 | ЗАКРЫТО-ПРОЕКТОМ |
| T19 | Fake TAS в приёмке | INV-17 | ТРЕБУЕТ-РЕАЛИЗАЦИИ (harness) |
| T20 | TAS как оракул verify | INV-01/INV-16; утечка только бит валидности | ЗАКРЫТО-ПРОЕКТОМ |

## 3. Требования к будущей исполненной матрице (M12)

- R1, N01–N12, P01, R5–R8, N13–N20 исполнены на точном v2-SHA; сырые журналы и коды выхода
  опубликованы; P01 — legitPass + один POST + идемпотентный recovery.
- R-D 15/15 воспроизводима из опубликованного дерева (инструмент и сценарии в репозитории).
- «ЗАКРЫТО-ПРОЕКТОМ» не является PASS и не закрывает пункт приёмки.
