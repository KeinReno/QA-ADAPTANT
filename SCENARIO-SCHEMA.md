# Сценарий

Машинная форма: ScenarioSchema. Оригинал docs/sources/scenario-original.ru.txt не является исполняемым сценарием. DRAFT не запускается. Утверждение привязано к hash содержимого; подмена даже одного equals/locator/input делает approval недействительным. Новый запуск фиксирует новую версию явно; старый прогон никогда не перечитывает изменённый реестр.

0.1: navigate по относительному пути, fill, click, verify. Контекстный локатор: container role/name + target role/name, exact=true. Перед действием контейнер и цель должны быть уникальными; 0/2+ — остановка без клика. Одноимённые кнопки в разных контейнерах допустимы только при однозначном контейнере. Один mutation click; никаких неявных retries. Разрешённые пути/формы контролируются адаптером. Клиентская декларация mutation=false не даёт права выполнять серверную мутацию: adapter allowlist должен классифицировать submit независимо.

Граф пока строго соответствует порядку nodes; ветвления/циклы отклоняются. Финальный verify ссылается на operation.id. Полный DAG, hover, multi-session и OP-A…F остаются обязательствами 1.0.

Уточнение gate: в 0.1 click mutation=false отклоняется. Единственный click содержит operationId и mutationName. validateBundleLinks требует exact scenario.inputs == operation.inputs, соответствие fixture/roles/mutation/версий. Fill может изменять только allowlisted поля локальной формы; до отправки /records Browser сверяет фактический body со всеми утверждёнными inputs + fixtureId. Несовпадение → request abort, не отправка. Таким образом неверное fill не меняет бизнес-ожидания и не создаёт неразрешённую сущность. Hash inputs записан в INTENT.
