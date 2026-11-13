# WP08-V2-MATRIX — СОПОСТАВЛЕНИЕ АТАК И ГРАНИЦ

Источники: `audit/wp08-qwen-independent-core` (4e96cdc), `WP08-QWEN-F1-RETEST.md`.
Столбец «v2» — **проектируемое** поведение; реализации ещё нет, PASS не заявляется.

| ID | Атака (по Qwen) | База 1a510a5 | 41043ad (remediation) | v2 (проект) |
|---|---|---|---|---|
| R1 | Подмена трёх публичных файлов без изготовления закрепления | ложный trusted PASS | Отклонён (TRUST_ROOT_KEY_SUBSTITUTION) | NO_TRUSTED_PASS: TAS+реестр |
| N01 | owner.pub only | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS |
| N02 | anchor.pub only | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS |
| N03 | ready.json only | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS |
| N04 | Все три после легитимного прогона | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS: observe через TAS |
| N05 | Подмена до первой загрузки | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS |
| N06 | Подмена между загрузкой и стартом | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS |
| N07 | Подмена во время Recovery | нет повторной мутации | нет повторной мутации | NO_TRUSTED_PASS, recovery fail-closed |
| N08 | Чужой approval | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS: сверка с enrolled ownerKeyId |
| N09 | Чужой Anchor | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS: ключ анкера у TAS |
| N10 | Подмена ожидаемых ключей через конфигурацию (N10в) | ложный trusted PASS (N10в) | **ложный trusted PASS (сохраняется)** | NO_TRUSTED_PASS: trustRootId только enrolled, новый корень не принимается |
| N11 | Несанкционированная ротация | ложный trusted PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS: ротация только elevated+внешний keyId |
| N12 | Повреждение/отсутствие закрепления | NO_TRUSTED_PASS | NO_TRUSTED_PASS | NO_TRUSTED_PASS |
| P01 | Позитивный контроль (легитимный прогон) | legitPass | legitPass | legitPass (обязательно) |
| R5 | DPAPI-конверт, изготовленный процессом того же SID | — | **ложный trusted PASS** | NO_TRUSTED_PASS: DPAPI-конверт не источник истины |
| R6 | Обход кэша по восстановленным mtime/size | — | частичный обход (INCONCLUSIVE) | NO_TRUSTED_PASS: кэш по метаданным запрещён |
| R7 | Публичный API указывает на новый корень атакующего | — | **ложный trusted PASS** | NO_TRUSTED_PASS: корень не выбирается клиентом |
| R8 | reseal с подменёнными owner.pub и секретами атакующего | — | **ложный trusted PASS** | NO_TRUSTED_PASS: reseal удалён, ротация elevated+внешний keyId |

## Как читать таблицу

- Закрыто в 41043ad: R1, N04–N06, N11, N12 (`TRUST_ROOT_KEY_SUBSTITUTION`) — но сам механизм
  оказался обходим (R5/R6/R8), а N10в не закрыт вовсе.
- Блокирующие для v2: **R5, R7, R8**; дополнительно обязательна R6.
- P01 — обязательный позитивный контроль: любая v2-реализация, ломающая легитимный
  trusted PASS/POST/recovery, не принимается независимо от закрытия R5–R8.

## Требуемые новые сценарии Qwen для v2

1. R5': тот же SID изготавливает DPAPI-конверт и подменяет публичные файлы → отказ
   `TRUST_ROOT_NOT_ENROLLED`/verification через TAS.
2. R7': `startTrusted` с любым `trustRoot`/`trustRootId`, не enrolled → отказ; файлы
   жертвы не меняются.
3. R8': попытка reseal/rotate из пользовательского SID/без UAC → отказ; подмена owner.pub
   не влияет на enrolled ownerKeyId.
4. R6': восстановление mtime/size → кэш не принимает; отказ по content-hash/registryVersion.
5. N13 (новый): поддельный IPC-запрос `issue-grant`/ `anchor` от пользовательского процесса
   без валидного approval/grant → отказ, без подписи и без мутации.
6. N14 (новый): двойной grant/replay после TTL → `GRANT_EXPIRED`/`GRANT_INVALID`.
