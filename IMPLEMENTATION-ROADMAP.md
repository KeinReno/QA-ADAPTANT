# План и критерии выхода

Ни один локальный gate не означает выпуск 0.1. При ограничении ресурса следующий исполнитель читает HANDOFF.md, затем свой workpack. Весь master-plan остаётся обязательным; в таблице отделены способности от очередности.

| Этап | Результат | Gate |
|---|---|---|
| 0 | Аудит архивов/трёх частей ЦИЗ, шесть машинных контрактов, границы | Luna не имеет неустранённых P0/P1 замечаний |
| 1 | Durable snapshots/journal, Control + Browser + Verification, localhost fixture | Реальный браузер, отдельный verifier, отсутствие false PASS и повторов |
| 2 | 12 управляемых отказов из master-plan §13, restart/cancel/idempotency | Матрица сценариев с фактическими командами и evidence, отрицательные ожидания |
| 3 | Read-only Dev сверка, безопасный набор данных, первый OP-B create-action | Независимое чтение созданного задания/родителя/отдела/адреса/исполнителя; выпуск 0.1 |
| 4 | Intelligence, source/runtime provenance, черновики/approval | Исходный пункт 7 диагностирован без исполнения, предложенная версия DRAFT, требуется утверждение |
| 5 | OP-A…F, multiple sessions, warehouse/close/manager follow-up | Утверждённая исправленная версия, все эффекты и причинная связь независимо доказаны |
| 6 | React Flow Scenario Studio, actual Execution Graph, Dockview, Live Browser, evidence/replay | Наблюдаемый фактический прогон, UI не управляет worker lifetime, русская навигация |
| 7 | Повторяемость, deployment change, resource/call metrics, recovery, независимая приёмка | Полный §20 мастер-плана, Luna вправе отклонить выпуск 1.0 |

Все OP сохраняются: A справочники/складская привязка; B create-action; C выполненная работа; D конкретное разрешённое оборудование; E платность/закрытие/2 часа; F правильная родительская задача, новое задание менеджерам и комментарий с роутером/часами. Task ID ≠ TaskAction ID ≠ TypeAction ID ≠ Action(work) ID ≠ progress ID ≠ equipment ID.

Экономия: модель только для неизвестного UI/текста/изменения. Execution replay без модели. Сохранять index hash и proven locator, обновлять затронутое. Сначала измерить preparation/replay time, model calls, repeat research, blocked/inconclusive долю, CPU/RAM. Не выдумывать целевые показатели и доступный остаток квоты: приложение не предоставило точный счётчик.

После принятия контрактов — заморозка. Расширение через docs/changes/NNN.md: проблема, минимальное изменение schema/API, migration, тесты, reviewer. Не пересобирать фундамент ради нового UI.
