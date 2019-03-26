# Textractor

![Как это выглядит](screenshot.png)

[English/Original](https://github.com/Artikash/Textractor/blob/master/README.md) ● [Español](https://github.com/Artikash/Textractor/blob/master/README_ES.md) ● [简体中文](https://github.com/Artikash/Textractor/blob/master/README_SC.md) ● 
[日本語](https://github.com/Artikash/Textractor/blob/master/README_JP.md)

**Textractor** (a.k.a. NextHooker) это проект x86/x64 Windows/Wine программы для захвата текста из видеоигр, основанный на [ITHVNR](http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).<br>
Смотреть [обучающее видео](https://youtu.be/eecEOacF6mw) для быстрого ознакомления.

[![Задонатить автору](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=akashmozumdar%40gmail.com&item_name=Textractor%20development&currency_code=USD)

## Загрузка

Выпуски Textractor могут быть найдены [здесь](https://github.com/Artikash/Textractor/releases).<br>
Последний выпуск ITHVNR может быть найден [здесь](https://drive.google.com/open?id=13aHF4uIXWn-3YML_k2YCDWhtGgn5-tnO).<br>
Установите библиотеки Visual C redist(vc_redist.x86.exe), если получаете ошибку при запуске Textractor.

## Возможности

- Высокая расширяемость
- Автозахват текста из множества игровых движков (включая некоторые, неподдерживаемые в VNR!)
- Захват текста с использованием /H "hook" кодов (поддерживается большинство AGTH кодов)
- Прямое извлечение текста с использованием /R "read" кодов

## Поддержка

Сообщайте о любых ошибках, играх, с которыми у Textractor проблемы, запросах о новых функциях или другие предложения.<br>
Если у вас возникают проблемы с захватом текста из какой либо игры, скиньте на электронную почту ссылку на её загрузку или киньте её подарком в [Steam](https://steamcommunity.com/profiles/76561198097566313/) , для тестирования.

## Расширения

Смотрите [Проект примера расширения](https://github.com/Artikash/ExampleExtension), чтобы узнать, как создать расширение.<br>
Также для примера того, что делают расширения, смотрите папку extensions. 

## Вклад

Любой вклад приветствуется! Пишите мне(автору)(нет, я не занят!) на akashmozumdar@gmail.com, если у вас есть любые вопросы о кодовой базе.<br>
Используйте стандартные действия для создания pull request (fork, branch, commit changes, создайте PR из своей ветки branch на мой master).<br>
Вклад в перевод совсем не сложен: просто переведите строки в text.cpp, также, как и этот README.

## Компиляция

Перед компиляцией *Textractor*, установите Visual Studio с поддержкой CMake, а также Qt версии 5.11<br>
Тогда вы сможете просто открыть и построить проект в Visual Studio. Запустите Textractor.exe.

## Архитектура проекта

Хост (смотрите папку GUI/host) внедряет texthook.dll (созданной из папки texthook) в целевой процесс и подключается к нему через два файла-канала (pipe).<br>
Хост пишет в hostPipe, texthook пишет в hookPipe.<br>
texthook ждет присоединения канала, тогда внедряет некоторые инструкции в любые выводящие текст функции (такие как TextOut, GetGlyphOutline), что вызывает пересылку поступающего в них текста черех канал.<br>
Дополнительная информация о хуках размещена через файл просмотра (a.k.a. section object), который сопоставленсо ссылкой на класс TextHook.<br>
Текст, который получает хост через канал, Текст, который хост получает через канал, затем немного обрабатывается перед отправкой обратно в графический интерфейс (GUI).<br>
Наконец, GUI откправляет текст расширениям, перед его отображением.

## Разработчики

Если вы в этом списке и хотите, чтобы ваша ссылка была изменена, сообщите об этом.
- Авторы Textractor: [Artikash](https://github.com/Artikash) и [DoumanAsh](https://github.com/DoumanAsh)
- Испанская локализация: [scese250](https://github.com/scese250)
- Турецкая локализация: niisokusu
- Китайская локализация: [tinyAdapter](https://github.com/tinyAdapter)
- Русская локализация: [TokcDK](https://github.com/TokcDK)
- Обновление ITHVNR: [mireado](https://github.com/mireado) and [Eguni](https://github.com/Eguni)
- Автор ITHVNR: [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- Автор движка VNR: [jichi](https://archive.is/prJwr)
- Обновление ITH: [Andys](https://github.com/AndyScull)
- Автор ITH: [kaosu](http://www.hongfire.com/forum/member/562651-kaosu)
- Автор библиотеки Locale Emulator: [xupefei](https://github.com/xupefei)
- Автор библиотеки MinHook: [TsudaKageyu](https://github.com/TsudaKageyu)

## Особая благодарность

- Всем, кто пишет о проблемах и предложения в секции Issues!
