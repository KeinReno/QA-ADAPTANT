# WP-04 — понимание поручения и адаптация

Исполнитель DeepSeek. Только packages/intelligence, tests/intelligence*. Входы: неизменённый scenario-original, source audit, observation API adapter. Выход: DRAFT + диагностические finding с provenance, никогда автоматическое approval/изменение run.

Разделить normalization разговорных слов и изменение требований. Построить OP-A…F с typed variables и неоднозначностями. Не кодировать «если номер7 — ошибка»: анализировать required field и доказанную форму, negative controls: переставленный пункт, действительная категория в другой форме, unknown Dev, противоречащие local/runtime версии. Подтверждённое отсутствие поля только для обследованного полного modal; отсутствие grep совпадения недостаточно.

Provenance каждого знания: файл+SHA/revision, component/handler/API, observation run/step+artifact hashes, timestamp, SOURCE_DISCOVERED/RUNTIME_OBSERVED/BEHAVIOR_VERIFIED/HUMAN_APPROVED. Кандидат локатора не становится proof. Semantic IDs для справочника/выполненной работы/склада различаются, scope обязателен. Поддержать SVG/CSS icon через accessible контекст, не только img.

Изменения index по content hash затронутых файлов. Исследование ограничено deadline/model-call budget. Approved replay zero model calls. Approve отдельной командой хранит digest конкретной версии. Тест: original остаётся byte-identical, draft недоступен Acceptance, stale revision блокирует applicability. Интеграция с WP-05 через public API; никаких импортов browser internals.
