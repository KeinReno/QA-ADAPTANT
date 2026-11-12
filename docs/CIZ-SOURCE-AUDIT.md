# Аудит исходников ЦИЗ для сценария QA-ADAPTANT

Дата аудита: 2026-11-12. Проверены только актуальные корневые `task_manager_front`, `tasks_manager` и `micro_services`; каталоги `branches` исключены. Вложенные `AGENTS.md` в корнях этих компонентов не найдены; прочитан [task_manager_front/AGENTS.md](../../CIZ/task_manager_front/AGENTS.md). Исходный сценарий и обязательные OP-контракты прочитаны в QA-ADAPTANT: `docs/sources/scenario-original.ru.txt` и `docs/sources/master-plan.ru.txt`.

Ревизии локального исходника: `task_manager_front` — `d4fe0ca1` (2026-11-11), `tasks_manager` — `6ebf75c` (2026-11-11), `micro_services` — `c03b473` (2026-11-10). Это сведения о локальных копиях. Dev runtime и фактические данные БД не проверялись; этот отчёт не подтверждает соответствие локального кода текущему Dev.

## OP-A: расхождение шага 7 и форма справочника

Сценарий описывает OP-A в шагах 1–7, затем отдельно OP-B в шагах 8–12. По шагам 3–7 пользователь создаёт TypeAction («списание роутера»), затем связанную конкретную Action («списание роутера2») с флагом привязки к складу. Это не добавление выполненной работы к заданию: такая операция относится к OP-C по мастер-плану.

Актуальная форма справочника — `task_manager_front/src/components/ReferenceBook/TypeActionsPage.jsx`. При добавлении конкретной работы открывается контекст `type`; текущая модалка показывает поле «Выполненные работы» и компонент-флаг «Есть привязка к складу» (около строк 1499–1518). В форме и состоянии больше нет выбора «Категория». Создание отправляет `createAction(typeId, actionName, linkToWarehouse, false)` (1069). API `ReferenceBookApi.js:23–25` шлёт `POST /create-active` с `id_type_active`, `new_name_action`, `linkToWarehouse`, `paid`; Category в этом контракте отсутствует.

История исходников подтверждает конкретное удаление старого поля. В родительской ревизии `3ed7969c^` компонент импортировал `getEquipmentCategories`, имел состояние `categories` и `modal.categoryId`, показывал label «Категория» и options из `categories`, а форма вызывала `/warehouse/get-categories`. В коммите `3ed7969c` от 2026-10-13 этот dropdown и загрузка категорий удалены вместе с отправкой `category_id` при create/edit TypeAction. Сравнение подтверждено `git show 3ed7969c -- src/components/ReferenceBook/TypeActionsPage.jsx src/components/ReferenceBook/ReferenceBookApi.js`.

Что означало старое поле: `getEquipmentCategories` в историческом `task_manager_front/src/api.js` читал `/warehouse/get-categories`; backend proxy `tasks_manager/routes/routes_warehouse/routes_warehouse.py:250–261` вызывает warehouse `/equipment/categories`; `micro_services/warehouse/models/models.py:133–139` определяет `DictionaryCategory` как справочник категорий оборудования. Следовательно, `Общие` было значением справочника категорий склада, а не именем TypeAction и не видом конкретной Action. Какой ID имело «Общие» в runtime, исходники не доказывают: его надо было получать из фактического ответа справочника, не закреплять догадкой.

Есть нюанс в старом UI: категория была привязана к `TypeAction.category_id`, а создание Action под существующим TypeAction не передавало category_id в `createAction`. Поэтому выбор категории в контексте добавления конкретной работы мог отображаться, но код создания работы его не сохранял. Сейчас удалено и это старое поле формы. Не интерпретировать переход `Общие` как часть ID или свойства склада Action.

Схема подтверждает удаление: миграция `tasks_manager/alembic/versions/81eff06598ae_.py` (2026-07-17, revision `81eff06598ae`) добавила `type_action.category_id`, заполнила NULL значением `-1` и сделала колонку обязательной. Миграция `tasks_manager/alembic/versions/p6e1a3c5d7f9_drop_type_action_category_id.py` (2026-10-13, revision `p6e1a3c5d7f9`, down revision `o5d0f2a4b6c8`) удаляет эту колонку. Сопутствующий коммит backend `93bc1bf` также удалил поле из `TypeAction` модели, `/view-data` ответа, route и CRUD create/edit; фронтенд-коммит `3ed7969c` убрал dropdown/API параметр. В актуальной модели `tasks_manager/models/models.py:2064–2105` `TypeAction` не имеет `category_id`; `Action` отдельно имеет `type_action_id` и `link_to_warehouse`.

Итог OP-A: различие шага 7 локально подтверждено, причина в source — поле категории удалено из UI/API/схемы. Создание типа и Action всё ещё возможно, флаг склада по-прежнему есть. Утверждать, что так работает Dev, нельзя без runtime чтения формы и проверки установленной миграции.

## OP-B: создание задания через create-action

Мастер-план относит OP-B к шагам 8–12 (`master-plan.ru.txt:560–564`): выбрать существующую родительскую задачу, отдел, тип задания, адрес и исполнителя; создать задание через create-action и сохранить ID. Не смешивать родительский TaskManager.id с новым TaskAction.id, справочным TypeAction.id, конкретным Action.id и складским Equipment.id.

Frontend endpoint: `task_manager_front/src/components/TaskActions/TaskActions.jsx:35` читает `GET /tasks/{taskId}/create-action` для данных формы; строка 65 отправляет `POST /tasks/{taskId}/create-action` с `toCanonicalActionWritePayload(actionData)`. Backend route `tasks_manager/task_action/routes/routes_task_actions.py:91–111` передаёт payload в `crud_create_action`. CRUD `tasks_manager/task_action/crud/crud_task_actions.py:1154+` создаёт `models.TaskAction` с `task_id` из URL, сохраняет исполнителей, отделы, локации и связанные поля, коммитит и на строке 1394 возвращает `{"action_id": new_action.id}`. Значит, поле ответа для OP-B — `action_id`; это ID нового задания (TaskAction), а не родительской задачи.

Независимое чтение по известному ID: `GET /actions/{action_id}` в `routes_task_actions.py:161–187` загружает именно TaskAction по ID через `read_action_with_task_and_all_actions`. Ответ обёрнут в `{ "task": result }`; formatter формирует `task.actions` с ID запрошенного задания (`crud_task_actions.py:2059+`, formatter около 730–755). Рекомендуемый read-only запрос после POST: `GET /actions/{returned_action_id}?ack_notifications=false`. Параметр нужен потому, что у GET default `ack_notifications=true`, а ветка подтверждения помечает уведомления прочитанными — это нежелательная побочная мутация для верификации.

## Предлагаемый безопасный контракт runtime-сверки OP-B

1. До мутации независимо получить и проверить подходящую родительскую задачу, допустимый адрес/отдел/тип/исполнителя и сохранить её Task ID. До обращения к Dev подтвердить допустимые тестовые объекты и учётную запись согласно правилам QA-ADAPTANT.
2. Выполнить пользовательский путь OP-B и отправить ровно один `POST /tasks/{parent_task_id}/create-action`. Сопоставить тело запроса с видимым выбором: родительский task ID в URL, отдел, тип задания, адрес и выбранный исполнитель.
3. Зафиксировать status/response без auth headers и cookies. Из ответа извлечь только `action_id`; неопределённый исход не повторять.
4. Независимо выполнить `GET /actions/{action_id}?ack_notifications=false`; сверить `response.task.actions` содержит ровно новое задание с `id == action_id`, а его `task_id` совпадает с исходной родительской задачей. Сверить отделы, исполнителя, адрес и выбранные тип/данные с подтверждённым POST intent.
5. PASS возможен после совпадения независимого чтения, а не только успешного HTTP ответа или скриншота. Если чтение не находит ID или данные не совпадают — сохранить неопределённость/FAIL и не повторять create-action.
6. Коррелировать запрос, ответ и backend logs по `X-Ciz-Id`; не включать токены, cookies, auth headers и чувствительные данные клиента в артефакты.

`X-Ciz-Id`: frontend `src/utils/requestTrace.js:24–35` создаёт trace ID и добавляет заголовок, `httpClient.js` подключает `applyTraceHeaders` к исходящему запросу; tasks_manager `utils/logger/request_context.py:20,45–60` читает `X-Ciz-Id` либо генерирует новый. Nginx `micro_services/nginx_haproxy/nginx/configs/ciz-proxy-locations.inc` передаёт обычный путь в HAProxy gateway через proxy_pass и не удаляет этот заголовок. Фактическая сквозная передача в Dev — runtime-проверка, здесь не выполнена.

## Границы подтверждения

Подтверждено локальными исходниками/историей git: OP-A category UI/API/schema removal; связь старой категории с warehouse category dictionary; текущая форма Action и `link_to_warehouse`; OP-B маршрут, response field `action_id`, независимый GET и побочный эффект default GET ack.

Не подтверждено: форма и данные Dev, точное отображаемое имя/ID «Общие» в Dev, актуальность развернутых миграций Dev, доступность конкретных родителей/адресов/исполнителей, успешное создание OP-A/OP-B, складская позиция и фактический journal runtime. Браузер и локальный стенд не запускались; мутаций не выполнялось.
