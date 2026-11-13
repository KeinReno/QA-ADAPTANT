# 011 — ADAPTANT 0.3 prepared-run binding

Статус: принято для Execution Foundation 0.3 после независимого review Luna Stage C.
Область: внутренний контракт нового исполнительного слоя; Trust Foundation 0.2 не изменяется.

## Изменение

`DISPATCH_INTENT.preparedDigest` закрепляет canonical binding подготовленного запуска, а не только digest bundle. Binding включает `runId`, `taskId`, `planId`, канонический SHA утверждённого плана, точный `approvalRef` владельца, `stepId` и digest шага, `executionRef` и `bundleDigest`.

`prepare()` проверяет, что Task готова к запуску, указывает на тот же immutable plan и имеет owner approval; переданный шаг целиком совпадает с шагом плана, а execution ref — со ссылкой шага. План проверяется пересчётом canonical digest. `start()` повторяет проверки против сохранённого binding до создания durable launch marker.

Подготовленный файл и launch marker хранятся только в обычных каталогах внутри закреплённого run root. Adapter отклоняет symlink/junction для каталогов и файлов, которые выводят данные за этот root.

Финализация Task сравнивает revision и план. При конкурирующем cancel/recovery ответ берётся из терминального состояния, записанного в TaskStore; локальный кандидат результата не возвращается при конфликте.

## Причина

Независимое review выявило возможность передать `executionRef`, план или его approval, не совпадающие с owner-approved Task, а также гонку между наблюдением и терминальным commit. Новый digest и финальная CAS-проверка связывают запуск с конкретным утверждением владельца и не позволяют API сообщить исход, отличающийся от сохранённого Task.

## Миграция и влияние

- Только новый namespace `packages/execution` и `apps/orchestrator`; схемы и runtime API Trust Foundation 0.2 не изменяются.
- Существующие Stage B тесты используют поле `preparedDigest` как opaque 64-символьный digest; Stage C уточняет его содержимое.
- При неоднозначном результате старый intent наблюдается по прежнему `runId`; повторный dispatch запрещён.
