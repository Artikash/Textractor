#include "defs.h"

#ifdef _WIN64
#define ARCH "x64"
#else
#define ARCH "x86"
#endif

const char* ATTACH = u8"Attach to game";
const char* LAUNCH = u8"Launch game";
const char* DETACH = u8"Detach from game";
const char* ADD_HOOK = u8"Add hook";
const char* REMOVE_HOOKS = u8"Remove hook(s)";
const char* SAVE_HOOKS = u8"Save hook(s)";
const char* SEARCH_FOR_HOOKS = u8"Search for hooks";
const char* SETTINGS = u8"Settings";
const char* EXTENSIONS = u8"Extensions";
const char* SELECT_PROCESS = u8"Select process";
const char* ATTACH_INFO = u8R"(If you don't see the process you want to attach, try running with admin rights
You can also type in the process id)";
const char* SEARCH_GAME = u8"Select from computer";
const char* PROCESSES = u8"Processes (*.exe)";
const char* CODE_INFODUMP = u8R"(Search for text
S[codepage#]text
OR
Enter read code
R{S|Q|V}[null_length<][codepage#]@addr
OR
Enter hook code
H{A|B|W|S|Q|V}[null_length<][N][codepage#][padding+]data_offset[*deref_offset][:split_offset[*deref_offset]]@addr[:module[:func]]
All numbers except codepage/null_length in hexadecimal
Default codepage is 932 (Shift-JIS) but this can be changed in settings
A/B: codepage char little/big endian
W: UTF-16 char
S/Q/V: codepage/UTF-16/UTF-8 string
N: don't use context
null_length: length of null terminator used for string
padding: length of padding data before string (C struct { int64_t size; char string[500]; } needs padding = 8)
Negatives for data_offset/split_offset refer to registers
-4 for EAX, -8 for ECX, -C for EDX, -10 for EBX, -14 for ESP, -18 for EBP, -1C for ESI, -20 for EDI
-C for RAX, -14 for RBX, -1C for RCX, -24 for RDX, and so on for RSP, RBP, RSI, RDI, R8-R15
* means dereference pointer+deref_offset)";
const char* SAVE_SETTINGS = u8"Save settings";
const char* EXTEN_WINDOW_INSTRUCTIONS = u8R"(Drag and drop extension (.dll) files here from your computer to add them
(Does not work if running as administrator)
Drag and drop within the list to reorder
(Extensions are used from top to bottom: order DOES matter)
Press delete with an extension selected to remove it)";
const char* INVALID_EXTENSION = u8"%1 is an invalid extension";
const char* CONFIRM_EXTENSION_OVERWRITE = u8"Another version of this extension already exists, do you want to delete and overwrite it?";
const char* EXTENSION_WRITE_ERROR = u8"Failed to save extension";
const char* USE_JP_LOCALE = u8"Emulate japanese locale?";
const char* HOOK_SEARCH_UNSTABLE_WARNING = u8"Searching for hooks is unstable! Be prepared for your game to crash!";
const char* SEARCH_CJK = u8"Search for Chinese/Japanese/Korean";
const char* SEARCH_PATTERN = u8"Search pattern (hex byte array)";
const char* SEARCH_DURATION = u8"Search duration (ms)";
const char* PATTERN_OFFSET = u8"Offset from pattern start";
const char* MIN_ADDRESS = u8"Minimum address (hex)";
const char* MAX_ADDRESS = u8"Maximum address (hex)";
const char* STRING_OFFSET = u8"String offset (hex)";
const char* HOOK_SEARCH_FILTER = u8"Results must match this regex";
const char* START_HOOK_SEARCH = u8"Start hook search";
const char* SAVE_SEARCH_RESULTS = u8"Save search results";
const char* TEXT_FILES = u8"Text (*.txt)";
const char* DOUBLE_CLICK_TO_REMOVE_HOOK = u8"Double click a hook to remove it";
const char* FILTER_REPETITION = u8"Repetition Filter";
const char* DEFAULT_CODEPAGE = u8"Default Codepage";
const char* FLUSH_DELAY = u8"Flush Delay";
const char* MAX_BUFFER_SIZE = u8"Max Buffer Size";
const wchar_t* CONSOLE = L"Console";
const wchar_t* CLIPBOARD = L"Clipboard";
const wchar_t* ABOUT = L"Textractor " ARCH L" v" VERSION LR"( made by me: Artikash (email: akashmozumdar@gmail.com)
Project homepage: https://github.com/Artikash/Textractor
Tutorial video: https://tinyurl.com/textractor-tutorial
Please contact me with any problems, feature requests, or questions relating to Textractor
You can do so via the project homepage (issues section) or via email
Source code available under GPLv3 at project homepage
I'm currently looking for a new job: email me if you know anyone hiring US software engineers
If you like this project, please tell everyone about it :))";
const wchar_t* CL_OPTIONS = LR"(usage: Textractor [-p{process id|"process name"}]...
example: Textractor -p4466 -p"My Game.exe" tries to inject processes with id 4466 or with name My Game.exe)";
const wchar_t* UPDATE_AVAILABLE = L"Update available: download it from https://github.com/Artikash/Textractor/releases";
const wchar_t* ALREADY_INJECTED = L"Textractor: already injected";
const wchar_t* NEED_32_BIT = L"Textractor: architecture mismatch: only Textractor x86 can inject this process";
const wchar_t* NEED_64_BIT = L"Textractor: architecture mismatch: only Textractor x64 can inject this process";
const wchar_t* INJECT_FAILED = L"Textractor: couldn't inject";
const wchar_t* LAUNCH_FAILED = L"Textractor: couldn't launch";
const wchar_t* INVALID_CODE = L"Textractor: invalid code";
const wchar_t* INVALID_CODEPAGE = L"Textractor: couldn't convert text (invalid codepage?)";
const char* PIPE_CONNECTED = u8"Textractor: pipe connected";
const char* INSERTING_HOOK = u8"Textractor: inserting hook: %s";
const char* REMOVING_HOOK = u8"Textractor: removing hook: %s";
const char* HOOK_FAILED = u8"Textractor: failed to insert hook";
const char* TOO_MANY_HOOKS = u8"Textractor: too many hooks: can't insert";
const char* STARTING_SEARCH = u8"Textractor: starting search";
const char* NOT_ENOUGH_TEXT = u8"Textractor: not enough text to search accurately";
const char* HOOK_SEARCH_INITIALIZED = u8"Textractor: search initialized with %zd hooks";
const char* HOOK_SEARCH_FINISHED = u8"Textractor: hook search finished, %d results found";
const char* FUNC_MISSING = u8"Textractor: function not present";
const char* MODULE_MISSING = u8"Textractor: module not present";
const char* GARBAGE_MEMORY = u8"Textractor: memory constantly changing, useless to read";
const char* SEND_ERROR = u8"Textractor: Send ERROR (likely an incorrect H-code)";
const char* READ_ERROR = u8"Textractor: Reader ERROR (likely an incorrect R-code)";
const char* HIJACK_ERROR = u8"Textractor: Hijack ERROR";
const char* COULD_NOT_FIND = u8"Textractor: could not find text";
const char* SELECT_LANGUAGE = u8"Select language";
const char* SELECT_LANGUAGE_MESSAGE = u8"What language should %1 translate to?";
const wchar_t* TOO_MANY_TRANS_REQUESTS = L"Too many translation requests: refuse to make more";
const wchar_t* TRANSLATION_ERROR = L"Error while translating";
const char* EXTRA_WINDOW_INFO = u8R"(Right click to change settings
Click and drag on window edges to move, or the bottom right corner to resize)";
const char* TOPMOST = u8"Always on Top";
const char* SHOW_ORIGINAL = u8"Original Text";
const char* SHOW_ORIGINAL_INFO = u8R"(Original text will not be shown
Only works if this extension is used directly after a translation extension)";
const char* SIZE_LOCK = u8"Size Locked";
const char* BG_COLOR = u8"Background Color";
const char* TEXT_COLOR = u8"Text Color";
const char* FONT = u8"Font";
const char* FONT_FAMILY = u8"Font Family";
const char* FONT_SIZE = u8"Font Size";
const char* FONT_WEIGHT = u8"Font Weight";
const char* LUA_INTRO = u8R"(--[[
ProcessSentence is called each time Textractor receives a sentence of text.

Param sentence: sentence received by Textractor (UTF-8).
Param sentenceInfo: table of miscellaneous info about the sentence.

If you return a string, the sentence will be turned into that string.
If you return nil, the sentence will be unmodified.

This extension uses several copies of the Lua interpreter for thread safety.
Modifications to global variables from ProcessSentence are not guaranteed to persist.

Properties in sentenceInfo:
"current select": 0 unless sentence is in the text thread currently selected by the user.
"process id": process id that the sentence is coming from. 0 for console and clipboard.
"text number": number of the current text thread. Counts up one by one as text threads are created. 0 for console, 1 for clipboard.
--]]
function ProcessSentence(sentence, sentenceInfo)
  --Your code here...
end)";
const char* LOAD_LUA_SCRIPT = u8"Load Script";
const wchar_t* LUA_ERROR = L"Lua error: %s";
const char* REGEX_FILTER = u8"Regex Filter";
const char* INVALID_REGEX = u8"Invalid regex";
const char* CURRENT_FILTER = u8"Currently filtering: %1";
const wchar_t* REPLACER_INSTRUCTIONS = LR"(This file only does anything when the "Replacer" extension is used.
Replacement commands must be formatted like this:
|ORIG|original_text|BECOMES|replacement_text|END|
All text in this file outside of a replacement command is ignored.
Whitespace in original_text is ignored, but replacement_text can contain spaces, newlines, etc.
This file must be encoded in Unicode (UTF-16 little endian).)";
const char* THREAD_LINKER = u8"Thread Linker";
const char* LINK = u8"Link";
const char* THREAD_LINK_FROM = u8"Thread number to link from";
const char* THREAD_LINK_TO = u8"Thread number to link to";
const char* HEXADECIMAL = u8"Hexadecimal";

static auto _ = []
{
#ifdef TURKISH
	ATTACH = u8"Oyuna bağla";
	DETACH = u8"Oyundan kopar";
	ADD_HOOK = u8"Kanca ekle";
	SAVE_HOOKS = u8"Kancaları kaydet";
	SETTINGS = u8"Ayarlar";
	EXTENSIONS = u8"Uzantılar";
	SELECT_PROCESS = u8"İşlem seçin";
	ATTACH_INFO = u8"Bağlanmak istediğiniz işlemi görmüyorsanız yönetici olarak çalıştırmayı deneyin";
	DEFAULT_CODEPAGE = u8"Varsayılan Kod Sayfası";
	FLUSH_DELAY = u8"Temizleme Gecikmesi";
	MAX_BUFFER_SIZE = u8"Maksimum Arabellek Boyu";
	ABOUT = L"Textractor " ARCH L" v" VERSION LR"( (proje ana sayfası: https://github.com/Artikash/Textractor)
Benim tarafımdan yapıldı: Artikash (e-posta: akashmozumdar@gmail.com)
Textractor ile ilgili tüm sorunlarınız, istekleriniz ve sorularınız için lütfen benimle iletişime geçin
Benimle, proje ana sayfasından (“issues” kısmından) ya da e-posta aracılığıyla iletişime geçebilirsiniz
Kaynak kodu GKLv3 koruması altında proje ana sayfasında mevcut
Şu anda iş aramaktayım: Eğer ABD’li yazılım mühendislerini işe alıyorsanız lütfen bana e-posta atın)";
	UPDATE_AVAILABLE = L"Güncelleme mevcut: https://github.com/Artikash/Textractor/releases adresinden indirin";
	ALREADY_INJECTED = L"Textractor: Zaten enjekte edili";
	NEED_32_BIT = L"Textractor: Mimari uyumsuzluğu: Lütfen Textractor’ın 32 bitlik sürümünü deneyin";
	INJECT_FAILED = L"Textractor: Enjekte edilemedi";
	INVALID_CODE = L"Textractor: Geçersiz kod";
	INVALID_CODEPAGE = L"Textractor: Metne dönüştürülemedi (geçersiz kod sayfası?)";
	PIPE_CONNECTED = u8"Textractor: Boru bağlandı";
	INSERTING_HOOK = u8"Textractor: Kanca ekleniyor: %s";
	REMOVING_HOOK = u8"Textractor: Kanca çıkarılıyor:: %s";
	HOOK_FAILED = u8"Textractor: Kanca eklenemedi";
	TOO_MANY_HOOKS = u8"Textractor: Çok fazla kanca var: Eklenemiyor";
	FUNC_MISSING = u8"Textractor: Fonksiyon mevcut değil";
	MODULE_MISSING = u8"Textractor: Modül mevcut değil";
	GARBAGE_MEMORY = u8"Textractor: Hafıza sürekli değişiyor, okumak boşa";
#endif // TURKISH

#ifdef SPANISH
	ATTACH = u8"Adjuntar juego";
	LAUNCH = u8"Iniciar juego";
	DETACH = u8"Desconectar juego";
	ADD_HOOK = u8"Añadir hook";
	SAVE_HOOKS = u8"Guardar hook(s)";
	SETTINGS = u8"Opciones";
	EXTENSIONS = u8"Extensiones";
	SELECT_PROCESS = u8"Seleccionar procreso";
	ATTACH_INFO = u8R"(Si no ves el proceso que quieras adjuntar, ejecuta este programa como administrador
También puedes escribir la ID del proceso)";
	SEARCH_GAME = u8"Seleccionar desde computadora";
	PROCESSES = u8"Procesos (*.exe)";
	SAVE_SETTINGS = u8"Guardar opciones";
	EXTEN_WINDOW_INSTRUCTIONS = u8R"(Arrrastra y suelta la extension (.dll) aquí desde tu computadora para añadirlos
Arrastra y suelta la lista para reordenar
Presiona supr en una extension seleccionada para removerla)";
	USE_JP_LOCALE = u8"¿Emular idioma japonés?";
	DEFAULT_CODEPAGE = u8"Default Codepage";
	FLUSH_DELAY = u8"Flush Delay";
	MAX_BUFFER_SIZE = u8"Max Buffer Size";
	CONSOLE = L"Consola";
	CLIPBOARD = L"Portapapeles";
	ABOUT = L"Textractor " ARCH L" v" VERSION LR"( hecho por mí: Artikash (correo: akashmozumdar@gmail.com)
Página del proyecto: https://github.com/Artikash/Textractor
Video tutorial: https://tinyurl.com/textractor-tutorial
No dudes en conectarme si tienes algún problema, petición de característica o preguntas relacionadas con Textractor
Puedes hacerlo en la página del proyecto (en el apartado de "Issues") o por correo. Usa el inglés para comunicarte.
Código fuente disponible bajo GPLv3 en la página del proyecto
Estoy buscando un nuevo trabajo: por favor envíame un correo si estás contratando ingenieros de software de EE.UU.)";
	UPDATE_AVAILABLE = L"Actualización disponible: descárguela en https://github.com/Artikash/Textractor/releases";
	ALREADY_INJECTED = L"Textractor: ya inyectado";
	INJECT_FAILED = L"Textractor: no se puede inyectar";
	LAUNCH_FAILED = L"Textractor: no se puede iniciar";
	INVALID_CODE = L"Textractor: código inválido";
	INVALID_CODEPAGE = L"Textractor: no se puede convertir texto (¿Codepage inválido?)";
	PIPE_CONNECTED = u8"Textractor: pipe connected";
	INSERTING_HOOK = u8"Textractor: insertando hook: %s";
	REMOVING_HOOK = u8"Textractor: removiendo hook: %s";
	HOOK_FAILED = u8"Textractor: no se puede insertar hook";
	TOO_MANY_HOOKS = u8"Textractor: demasiados hooks: no se puede insertar";
	NOT_ENOUGH_TEXT = u8"Textractor: no hay suficiente texto para buscar con precisión";
	FUNC_MISSING = u8"Textractor: función no presente";
	MODULE_MISSING = u8"Textractor: module not present";
	GARBAGE_MEMORY = u8"Textractor: memory constantly changing, useless to read";
	SEND_ERROR = u8"Textractor: Send ERROR (probablemente un H-code incorrecto)";
	READ_ERROR = u8"Textractor: Reader ERROR (probablemente un R-code incorrecto)";
	HIJACK_ERROR = u8"Textractor: Hijack ERROR";
	COULD_NOT_FIND = u8"Textractor: no se puede encontrar texto";
	SELECT_LANGUAGE = u8"Seleccionar lenguaje";
	SELECT_LANGUAGE_MESSAGE = u8"¿A qué idioma debe traducir %1?";
	TOO_MANY_TRANS_REQUESTS = L"Demasiadas peticiones de traducción: no se puede hacer más";
	TRANSLATION_ERROR = L"Error al traducir";
	EXTRA_WINDOW_INFO = u8R"(Clic derecho para configurar
Clic y arrastra los bordes de la ventana para moverla, o en la esquina inferior derecha para cambiar el tamaño)";
	BG_COLOR = u8"Color de fondo";
	TEXT_COLOR = u8"Color de texto";
	FONT_SIZE = u8"Tamaño de letra";
	TOPMOST = u8"Siempre visible";
	REGEX_FILTER = u8"Filtro Regex";
	INVALID_REGEX = u8"Regex inválido";
	CURRENT_FILTER = u8"Actualmente filtrando: %1";
#endif // SPANISH

#ifdef SIMPLIFIED_CHINESE
	ATTACH = u8"附加到游戏";
	LAUNCH = u8"启动游戏";
	DETACH = u8"从游戏分离";
	ADD_HOOK = u8"添加钩子";
	SAVE_HOOKS = u8"保存钩子";
	SETTINGS = u8"设置";
	EXTENSIONS = u8"扩展";
	SELECT_PROCESS = u8"选择进程";
	ATTACH_INFO = u8R"(如果没看见想要附加的进程，尝试使用管理员权限运行
也可以手动输入进程ID)";
	SEARCH_GAME = u8"从计算机中选择";
	PROCESSES = u8"进程 (*.exe)";
	SAVE_SETTINGS = u8"保存设置";
	EXTEN_WINDOW_INSTRUCTIONS = u8R"(从计算机拖拽扩展 (.dll) 文件到这里来添加
(如果使用超级管理员运行，则无法工作)
在列表中拖拽来重新排序
使用 delete 键移除选中的扩展)";
	USE_JP_LOCALE = u8"模拟日本区域设置?";
	DEFAULT_CODEPAGE = u8"默认代码页";
	FLUSH_DELAY = u8"刷新延迟";
	MAX_BUFFER_SIZE = u8"最大缓冲区长度";
	CONSOLE = L"控制台";
	CLIPBOARD = L"剪贴板";
	ABOUT = L"Textractor " ARCH L" v" VERSION LR"( 作者: Artikash (email: akashmozumdar@gmail.com)
项目主页: https://github.com/Artikash/Textractor
教程视频: https://tinyurl.com/textractor-tutorial
如果有任何关于 Textractor 的困难，功能请求或问题，请联系我
可以通过项目主页 (问题区) 或通过邮件来联系
项目主页提供基于 GPLv3 协议的源代码
我目前正在寻找新的工作: 如果你知道在美国招聘软件工程师岗位的人，请给我发邮件)";
	UPDATE_AVAILABLE = L"有可用的更新: 请从 https://github.com/Artikash/Textractor/releases 下载";
	ALREADY_INJECTED = L"Textractor: 已经注入";
	NEED_32_BIT = L"Textractor: 架构不匹配: 请尝试使用 Textractor x86";
	INJECT_FAILED = L"Textractor: 无法注入";
	LAUNCH_FAILED = L"Textractor: 无法启动";
	INVALID_CODE = L"Textractor: 无效代码";
	INVALID_CODEPAGE = L"Textractor: 无法转换文本 (无效的代码页?)";
	PIPE_CONNECTED = u8"Textractor: 管道已连接";
	INSERTING_HOOK = u8"Textractor: 注入钩子: %s";
	REMOVING_HOOK = u8"Textractor: 移除钩子: %s";
	HOOK_FAILED = u8"Textractor: 钩子注入失败";
	TOO_MANY_HOOKS = u8"Textractor: 钩子太多: 无法注入";
	NOT_ENOUGH_TEXT = u8"Textractor: 没有足够的文本来精确搜索";
	FUNC_MISSING = u8"Textractor: 函数不存在";
	MODULE_MISSING = u8"Textractor: 模块不存在";
	GARBAGE_MEMORY = u8"Textractor: 内存一直在变，读了也没用";
	SEND_ERROR = u8"Textractor: Sender 错误 (H码可能不正确)";
	READ_ERROR = u8"Textractor: Reader 错误 (R码可能不正确)";
	HIJACK_ERROR = u8"Textractor: Hijack 错误";
	COULD_NOT_FIND = u8"Textractor: 无法找到文本";
	SELECT_LANGUAGE = u8"选择语言";
	SELECT_LANGUAGE_MESSAGE = u8"想要使用 %1 翻译到哪种语言?";
	TOO_MANY_TRANS_REQUESTS = L"太多翻译请求: 拒绝生成更多";
	TRANSLATION_ERROR = L"翻译时出错";
	EXTRA_WINDOW_INFO = u8R"(右键修改设置
在窗口边缘点击并拖拽来移动，或在右下角点击并拖拽来调整大小)";
	BG_COLOR = u8"背景颜色";
	TEXT_COLOR = u8"文本颜色";
	FONT_SIZE = u8"字体大小";
	TOPMOST = u8"总是位于最上层";
	REGEX_FILTER = u8"正则表达式过滤器";
	INVALID_REGEX = u8"无效的正则表达式";
	CURRENT_FILTER = u8"当前过滤中: %1";
#endif // SIMPLIFIED_CHINESE

#ifdef RUSSIAN
	ATTACH = u8"Присоединить к игре";
	LAUNCH = u8"Запустить игру";
	DETACH = u8"Отсоединить от игры";
	ADD_HOOK = u8"Добавить хук";
	SAVE_HOOKS = u8"Сохранить хук(и)";
	SETTINGS = u8"Настройки";
	EXTENSIONS = u8"Расширения";
	SELECT_PROCESS = u8"Выберете процесс";
	ATTACH_INFO = u8R"(Если вы не видите процесс, к которому хотите присоединить, попробуйте запуск с правами администратора
Вы также можете ввести id процесса)";
	SEARCH_GAME = u8"Найти в проводнике";
	PROCESSES = u8"Процессы (*.exe)";
	SAVE_SETTINGS = u8"Сохранить настройки";
	EXTEN_WINDOW_INSTRUCTIONS = u8R"(Перетащите сюда (.dll) файлы расширений из проводника для их добавления
(Не работает при запуске от администратора)
Перетаскивайте по списку для изменения порядка
Нажмите клавишу удаления, чтобы удалить выбранное расширение)";
	USE_JP_LOCALE = u8"Симулировать японскую локаль";
	FILTER_REPETITION = u8"Фильтр повторений";
	DEFAULT_CODEPAGE = u8"Кодировка по умолчанию";
	FLUSH_DELAY = u8"Задержка сброса";
	MAX_BUFFER_SIZE = u8"Максимальный размер буфера";
	CONSOLE = L"Консоль";
	CLIPBOARD = L"Буфер обмена";
	ABOUT = L"Textractor " ARCH L" в." VERSION LR"( автор: Artikash (email: akashmozumdar@gmail.com)
Домашняя страница: https://github.com/Artikash/Textractor
Обучающее видео: https://tinyurl.com/textractor-tutorial
Сообщайте о любых проблемах, желаемых для добавления функциях, или задавайте вопросы, касающиеся Textractor
Сделать это вы можете на домашней странице (секция issues) или через электронную почту
Исходный код доступен по лицензии GPLv3 на домашней странице проекта
I'm currently looking for a new job: email me if you know anyone hiring US software engineers
Если эта программа вам понравилась, расскажите всем о ней :))";
	CL_OPTIONS = LR"(usage: Textractor [-p{process id|"process name"}]...)";
	UPDATE_AVAILABLE = L"Доступно обновление: загрузите его на https://github.com/Artikash/Textractor/releases";
	ALREADY_INJECTED = L"Textractor: уже присоединен";
	NEED_32_BIT = L"Textractor: несоответствие архитектуры: попробуйте Textractor x86 вместо этого";
	INJECT_FAILED = L"Textractor: невозможно присоединиться";
	LAUNCH_FAILED = L"Textractor: невозможно запустить";
	INVALID_CODE = L"Textractor: неверный код";
	INVALID_CODEPAGE = L"Textractor: невозможно конвертировать текст (неверная кодировка?)";
	PIPE_CONNECTED = u8"Textractor: канал присоединен";
	INSERTING_HOOK = u8"Textractor: вставка хука: %s";
	REMOVING_HOOK = u8"Textractor: удаление хука: %s";
	HOOK_FAILED = u8"Textractor: не удалось вставить хук";
	TOO_MANY_HOOKS = u8"Textractor: слишком много хуков: невозможно вставить";
	NOT_ENOUGH_TEXT = u8"Textractor: не достаточно текста для точного поиска";
	FUNC_MISSING = u8"Textractor: функция отсутствует";
	MODULE_MISSING = u8"Textractor: модуль отсутствует";
	GARBAGE_MEMORY = u8"Textractor: память постоянно изменяется, бесполезно читать";
	SEND_ERROR = u8"Textractor: Send ERROR (вероятно неверный H-code)";
	READ_ERROR = u8"Textractor: Reader ERROR (вероятно неверный R-code)";
	HIJACK_ERROR = u8"Textractor: Hijack ERROR";
	COULD_NOT_FIND = u8"Textractor: невозможно найти текст";
	SELECT_LANGUAGE = u8"Выберете язык";
	SELECT_LANGUAGE_MESSAGE = u8"На какой язык переводить в %1?";
	TOO_MANY_TRANS_REQUESTS = L"Слишком много запросов для перевода: отклонено";
	TRANSLATION_ERROR = L"Ошибка при переводе";
	EXTRA_WINDOW_INFO = u8R"(Правый клик для изменения настроек
Нажмите и перетащите за края - для перемещения, или за правый-нижний угол - для изменения размера)";
	TOPMOST = u8"Поверх всех окон";
    SHOW_ORIGINAL = u8"Исходный текст";
    SHOW_ORIGINAL_INFO = u8R"(Исходный текст будет скрыт
Работает только если это расширение используется после расширения перевода)";
	SIZE_LOCK = u8"Фиксированный размер";
	BG_COLOR = u8"Цвет заднего фона";
	TEXT_COLOR = u8"Цвет текста";
	FONT_SIZE = u8"Размер шрифта";
	LUA_INTRO = u8R"(--[[
ProcessSentence вызывается каждый раз, когда Textractor получает предложение с текстом.

Param sentence: предложение полученое в Textractor (UTF-8).
Param sentenceInfo: таблица различной информации о предложении.

При возвращении строки предложение будет изменено на эту строку.
При возвращении нуля, предложение останется без изменения.

Это расширение использует несколько копий интерпретатора Lua для безопасности нити.
Модификации глобальных переменных из ProcessSentence не обязательно сохраняется.

Параметры в sentenceInfo:
"current select": равно 0, если предложение не находится в текстовой нити, выбранной в данный момент пользователем.
"process id": id процесса, из которого предложение поступило. Равно 0, когда это консоль или буфер обмена.
"text number": номер текущей текстовой нити. Растет один за другим по мере создания текстовых нитей. 0 для консоли, 1 для буфера обмена.
--]]
function ProcessSentence(sentence, sentenceInfo)
  --Ваш код здесь...
end)";
	LOAD_LUA_SCRIPT = u8"Загрузить скрипт";
	LUA_ERROR = L"Ошибка Lua: %s";
	REGEX_FILTER = u8"Фильтр Regex";
	INVALID_REGEX = u8"Неверный regex";
	CURRENT_FILTER = u8"Сейчас фильтруется: %1";
	REPLACER_INSTRUCTIONS = LR"(Этот файл делает что-то только когда используется расширение "Replacer".
Команды для замены должны выглядеть так:
|ORIG|текст_оригинала|BECOMES|текст_замены|END|
Весь текст в этом файле вне команд заменителей будет проигнорирован.
Пробелы в текст_оригинала игнорируются, но текст_замены может содержать пробелы, новые строки и пр.
Этот файл должен быть в кодировке Unicode (UTF-16 little endian).)";
	THREAD_LINKER = u8"Связыватель нитей";
	LINK = u8"Связь";
	THREAD_LINK_FROM = u8"Номер нити, от которой связывать";
	THREAD_LINK_TO = u8"Номер нити, к которой привязывать";
#endif // RUSSIAN

#ifdef INDONESIAN
	ATTACH = u8"Tempelkan kedalam game";
	LAUNCH = u8"Mulai game";
	DETACH = u8"Lepaskan dari game";
	ADD_HOOK = u8"Tambahkan hook";
	SAVE_HOOKS = u8"Simpan hook";
	SETTINGS = u8"Pengaturan";
	EXTENSIONS = u8"Ekstensi";
	SELECT_PROCESS = u8"Pilih Proses";
	ATTACH_INFO = u8R"(Jika kamu tidak dapat melihat proses yang akan ditempelkan, coba menjalankan dengan mode administrator
Kamu juga dapat mengetik process id game yang akan ditempel)";
	SEARCH_GAME = u8"Pilih dari komputer";
	PROCESSES = u8"Proses (*.exe)";
	SAVE_SETTINGS = u8"Simpan pengaturan";
	EXTEN_WINDOW_INSTRUCTIONS = u8R"(Drag and drop file ekstensi (.dll) kedalam sini dari komputer kamu untuk menambah ekstensi
(Tidak bekerja dalam mode administrator)
Drag and drop ekstensi di dalam list untuk mengatur list
Tekan delete pada ekstensi yang dipilih untuk menghapus ekstensi)";
	USE_JP_LOCALE = u8"Gunakan locale jepang?";
	DEFAULT_CODEPAGE = u8"Codepage standar";
	FLUSH_DELAY = u8"Flush Delay";
	MAX_BUFFER_SIZE = u8"Max Buffer Size";
	CONSOLE = L"Konsol";
	CLIPBOARD = L"Papan clipboard";
	ABOUT = L"Textractor " ARCH L" v" VERSION LR"( dibuat oleh saya: Artikash (email: akashmozumdar@gmail.com)
Halaman project: https://github.com/Artikash/Textractor
Video tutorial : https://tinyurl.com/textractor-tutorial
Tolong hubungi saya jika kamu memiliki masalah terkait masalah, permintaan fitur, atau pertanyaan terkait Textractor
Kamu dapat melakukannya lewat halaman utama project (bagian issues) atau lewat email
Source code tersedia dibawah lisensi GPLv3 di halaman utama project
Saya sedang mencari pekerjaan baru : email saya jika kamu mengenal orang yang dapat memperkerjakan software engineer Amerika
Jika kamu menyukai project ini, tolong sebarluaskan project ini :))";
	UPDATE_AVAILABLE = L"Pembaharuan tersedia: pembaharuan dapat di unduh di https://github.com/Artikash/Textractor/releases";
	ALREADY_INJECTED = L"Textractor: sudah ditempelkan";
	INJECT_FAILED = L"Textractor: menempelkan gagal";
	LAUNCH_FAILED = L"Textractor: game tidak dapat dijalankan";
	INVALID_CODE = L"Textractor: kode tidak sesuai";
	INVALID_CODEPAGE = L"Textractor: tidak dapat mengkonversi teks (Codepage tidak sesuai?)";
	PIPE_CONNECTED = u8"Textractor: pipe tersambung";
	INSERTING_HOOK = u8"Textractor: memasukkan hook: %s";
	REMOVING_HOOK = u8"Textractor: menghapus hook: %s";
	HOOK_FAILED = u8"Textractor: gagal memasukkan hook";
	TOO_MANY_HOOKS = u8"Textractor: terlalu banyak hook: tidak dapat memasukkan hook";
	NOT_ENOUGH_TEXT = u8"Textractor: tidak cukup teks untuk melakukan pencarian secara akurat";
	FUNC_MISSING = u8"Textractor: tidak ada fungsi";
	MODULE_MISSING = u8"Textractor: tidak ada modul";
	GARBAGE_MEMORY = u8"Textractor: memory terus berganti, tidak dapat dibaca";
	SEND_ERROR = u8"Textractor: Send ERROR (kemungkinan H-Code salah)";
	READ_ERROR = u8"Textractor: Reader ERROR (Kemungkinan R-Code salah)";
	HIJACK_ERROR = u8"Textractor: Hijack ERROR";
	COULD_NOT_FIND = u8"Textractor: tidak dapat menemukan teks";
	SELECT_LANGUAGE = u8"Pilih bahasa";
	SELECT_LANGUAGE_MESSAGE = u8"Bahasa apakah yang %1 harus terjemahkan?";
	TOO_MANY_TRANS_REQUESTS = L"Terlalu banyak permintaan terjemahan: menolak untuk menerjemahkan";
	TRANSLATION_ERROR = L"Terjadi kesalahan ketika menerjemahkan";
	EXTRA_WINDOW_INFO = u8R"(Klik kanan untuk merubah pengaturan
Klik dan tarik pinggiran jendela untuk memindahkan, atau sudut kanan bawah untuk mengatur ukuran jendela)";
	BG_COLOR = u8"Warna latar";
	TEXT_COLOR = u8"Warna teks";
	FONT_SIZE = u8"Ukuran teks";
	TOPMOST = u8"Selalu berada di atas";
	REGEX_FILTER = u8"Filter regex";
	INVALID_REGEX = u8"Regex tidak sesuai";
	CURRENT_FILTER = u8"Regex yang digunakan sekarang: %1";
#endif // INDONESIAN

#ifdef PORTUGUESE_BR
	ATTACH = u8"Anexar ao Jogo";
	LAUNCH = u8"Iniciar Jogo";
	DETACH = u8"Desconectar do Jogo";
	ADD_HOOK = u8"Adicionar um Hook";
	SAVE_HOOKS = u8"Salvar Hook(s)";
	SETTINGS = u8"Opções";
	EXTENSIONS = u8"Extensões";
	SELECT_PROCESS = u8"Selecionar Processo";
	ATTACH_INFO = u8R"(Se você não encontrar o processo o qual deseja anexar a, tente iniciar com permissão de Administrador. Você também pode digitar a ID do processo)";
	SEARCH_GAME = u8"Selecione no Computador";
	PROCESSES = u8"Executaveis (*.exe)";
	SAVE_SETTINGS = u8"Salvar opções";
	EXTEN_WINDOW_INSTRUCTIONS = u8R"(Arraste e solte a extensão (.dll) aqui para adicioná-la.
(Não funciona se estiver rodando como Administrador)
Arraste e solte dentro da lista para reordená-la.
(As extensões são utilizadas de cima para baixo: a ORDEM IMPORTA.)
Pressione delete com uma extensão selecionada para removê-la.)";
	INVALID_EXTENSION = u8"%1 não é uma extensão válida.";
	CONFIRM_EXTENSION_OVERWRITE = u8"Outra versão dessa extensão já existe, você gostaria de deletar e reescrevê-la?";
	EXTENSION_WRITE_ERROR = u8"Falha na gravação da extensão";
	USE_JP_LOCALE = u8"Emular o idioma Japonês?";
	DEFAULT_CODEPAGE = u8"página de código padrão";
	FLUSH_DELAY = u8"Delay do Flush";
	MAX_BUFFER_SIZE = u8"Tamanho Máximo do Buffer";
	CONSOLE = L"Terminal";
	CLIPBOARD = L"Área de Transferência";
	ABOUT = L"Textractor " ARCH L" v" VERSION LR"( Feito por mim: Artikash (e-mail: akashmozumdar@gmail.com)
Homepage do Projeto: https://github.com/Artikash/Textractor
Vídeo Tutorial: https://tinyurl.com/textractor-tutorial
Por favor, em caso de problemas, requisição de recurso e/ou funções e de dúvidas, entrar em contato comigo. Use o Inglês para se comunicar.
Você pode fazê-lo por meio da Homepage do Projeto (na aba "Issues") ou via E-mail.
O código-fonte se encontra disponível na Homepage do projeto sob a licença GPLv3.
Estou a procura de um novo trabalho: por favor enviê-me uma mensagem de e-mail para mim se souber de alguém que esteja contratando um Engenheiro de Software dos USA.
Se você gostou desse projeto, divulgue a todos :))";
	UPDATE_AVAILABLE = L"Atualização disponível em: baixe em https://github.com/Artikash/Textractor/releases";
	ALREADY_INJECTED = L"Textractor: já está injetado";
  	NEED_32_BIT = L"Textractor: arquitetura errada: apenas o Textractor x86 pode injetar nesse processo";
 	NEED_64_BIT = L"Textractor: arquitetura errada: apenas o Textractor x64 pode injetar nesse processo";
	INJECT_FAILED = L"Textractor: não pode injetar";
	LAUNCH_FAILED = L"Textractor: não pode iniciar";
	INVALID_CODE = L"Textractor: código inválido";
	INVALID_CODEPAGE = L"Textractor: não pode converter o texto (página de código inválido?)";
	PIPE_CONNECTED = u8"Textractor: pipe conectado";
	INSERTING_HOOK = u8"Textractor: inserindo hook: %s";
	REMOVING_HOOK = u8"Textractor: removendo hook: %s";
	HOOK_FAILED = u8"Textractor: falha na inserção do hook";
	TOO_MANY_HOOKS = u8"Textractor: há hooks de mais: não é possível inserir mais";
	STARTING_SEARCH = u8"Textractor: iniciando busca ";
	NOT_ENOUGH_TEXT = u8"Textractor: não há texto suficiente para uma buscar precisa";
	HOOK_SEARCH_INITIALIZED = u8"Textractor: busca inicializada com %zd hooks";
	HOOK_SEARCH_FINISHED = u8"Textractor: busca por hooks finalizada, %d resultados encontrados";
	FUNC_MISSING = u8"Textractor: função não encontrada";
	MODULE_MISSING = u8"Textractor: módulo não presente";
	SEND_ERROR = u8"Textractor: ERRO no envio (provavelmente um H-code incorreto)";
	READ_ERROR = u8"Textractor:  ERRO na leitura (provavelmente um R-code incorreto)";
	COULD_NOT_FIND = u8"Textractor: não foi possível encontrar texto";
	SELECT_LANGUAGE = u8"Selecione a língua";
	SELECT_LANGUAGE_MESSAGE = u8"Qual língua deve o/a %1 traduzir para?";
	TOO_MANY_TRANS_REQUESTS = L"Foram feitos pedidos de tradução demais: recusa na feitura de mais pedidos";
	TRANSLATION_ERROR = L"Erro enquanto traduzindo";
 	EXTRA_WINDOW_INFO = u8R"(Clique com o botão direito para mudar as opções
Clique e arraste nas beiradas da janela para mover, ou no canto inferior direito para redimessionar)";
	TOPMOST = u8"Sempre em cima";
 	SHOW_ORIGINAL = u8"Texto original";
 	SHOW_ORIGINAL_INFO = u8R"(Texto original não será mostrado
Apenas funciona se essa extensão for usada diretamente após uma extensão de tradução)";
 	SIZE_LOCK = u8"Travar o Tamanho";
 	BG_COLOR = u8"Cor de fundo";
 	TEXT_COLOR = u8"Cor do Texto";
 	FONT = u8"Fonte";
 	FONT_FAMILY = u8"Família da Fonte";
 	FONT_SIZE = u8"Tamanho da Fonte";
 	FONT_WEIGHT = u8"Peso da Fonte";
 	REGEX_FILTER = u8"Fíltro regex";
  	INVALID_REGEX = u8"Regex inválido";
  	CURRENT_FILTER = u8"Atualmente filtrando: %1";
  	REPLACER_INSTRUCTIONS = LR"(Este arquivo apenas faz algo quando a extensão "Replacer" está sendo utilizada.
Comandos de substituição devem ser formatos da seguinte maneira:
|ORIG|texto_original|BECOMES|texto_substituido|END|
Todo texto fora de um comando de substituição é ignorado.
Espaços contidos no texto original é ignorado, mas o texto substituído pode conter espaços, novas línhas, etc.
Esse arquívo deve ser codifícado em (UTF-16 little endian).)";
  	THREAD_LINKER = u8"Ligador de Threads";
  	LINK = u8"Ligar";
  	THREAD_LINK_FROM = u8"Número do thread para ligar de";
  	THREAD_LINK_TO = u8"Número do thread para ligar para";
#endif // PORTUGUESE_BR

	return 0;
}();
