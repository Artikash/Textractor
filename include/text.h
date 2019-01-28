#pragma once

#define CURRENT_VERSION "1.2.0"

inline auto ATTACH = u8"Attach to game";
inline auto LAUNCH = u8"Launch game";
inline auto DETACH = u8"Detach from game";
inline auto ADD_HOOK = u8"Add hook";
inline auto SAVE_HOOKS = u8"Save hook(s)";
inline auto SETTINGS = u8"Settings";
inline auto EXTENSIONS = u8"Extensions";
inline auto SELECT_PROCESS = u8"Select Process";
inline auto ATTACH_INFO = u8R"(If you don't see the process you want to attach, try running with admin rights
You can also type in the process id)";
inline auto SEARCH_GAME = u8"Select from computer";
inline auto PROCESSES = u8"Processes (*.exe)";
inline auto CODE_INFODUMP = u8R"(Search for text
S[codepage#]text
OR
Enter read code
R{S|Q|V}[codepage#][*deref_offset]@addr
OR
Enter hook code
H{A|B|W|S|Q|V}[N][codepage#]data_offset[*deref_offset1][:split_offset[*deref_offset2]]@addr[:module[:func]]
All numbers except codepage in hexadecimal
Default codepage is 932 (Shift-JIS) but this can be changed in settings
A/B: codepage char little/big endian
W: UTF-16 char
S/Q/V: codepage/UTF-16/UTF-8 string
Negatives for data/split offset refer to registers
-4 for EAX, -8 for ECX, -C for EDX, -10 for EBX, -14 for ESP, -18 for EBP, -1C for ESI, -20 for EDI
* means dereference pointer+deref_offset)";
inline auto SAVE_SETTINGS = u8"Save settings";
inline auto EXTEN_WINDOW_INSTRUCTIONS = u8R"(Drag and drop extension (.dll) files here from your computer to add them
(Does not work if running as administrator)
Drag and drop within the list to reorder
Press delete with an extension selected to remove it)";
inline auto WINDOW = u8"Window";
inline auto USE_JP_LOCALE = u8"Emulate japanese locale?";
inline auto DEFAULT_CODEPAGE = u8"Default Codepage";
inline auto FLUSH_DELAY = u8"Flush Delay";
inline auto MAX_BUFFER_SIZE = u8"Max Buffer Size";
inline auto CONSOLE = L"Console";
inline auto CLIPBOARD = L"Clipboard";
inline auto ABOUT = L"Textractor v" CURRENT_VERSION LR"( made by me: Artikash (email: akashmozumdar@gmail.com)
Project homepage: https://github.com/Artikash/Textractor
Tutorial video: https://www.youtube.com/watch?v=eecEOacF6mw
Please contact me with any problems, feature requests, or questions relating to Textractor
You can do so via the project homepage (issues section) or via email
Source code available under GPLv3 at project homepage
I'm currently looking for a new job: email me if you know anyone hiring US software engineers)";
inline auto UPDATE_AVAILABLE = L"Update available: download it from https://github.com/Artikash/Textractor/releases";
inline auto ALREADY_INJECTED = L"Textractor: already injected";
inline auto ARCHITECTURE_MISMATCH = L"Textractor: architecture mismatch: try 32 bit Textractor instead";
inline auto INJECT_FAILED = L"Textractor: couldn't inject";
inline auto LAUNCH_FAILED = L"Textractor: couldn't launch";
inline auto INVALID_CODE = L"Textractor: invalid code";
inline auto INVALID_CODEPAGE = L"Textractor: couldn't convert text (invalid codepage?)";
inline auto PIPE_CONNECTED = u8"Textractor: pipe connected";
inline auto INSERTING_HOOK = u8"Textractor: inserting hook: %s";
inline auto REMOVING_HOOK = u8"Textractor: removing hook: %s";
inline auto HOOK_FAILED = u8"Textractor: failed to insert hook";
inline auto TOO_MANY_HOOKS = u8"Textractor: too many hooks: can't insert";
inline auto NOT_ENOUGH_TEXT = u8"Textractor: not enough text to search accurately";
inline auto FUNC_MISSING = u8"Textractor: function not present";
inline auto MODULE_MISSING = u8"Textractor: module not present";
inline auto GARBAGE_MEMORY = u8"Textractor: memory constantly changing, useless to read";
inline auto SEND_ERROR = u8"Textractor: Send ERROR (likely an incorrect H-code)";
inline auto READ_ERROR = u8"Textractor: Reader ERROR (likely an incorrect R-code)";
inline auto HIJACK_ERROR = u8"Textractor: Hijack ERROR";
inline auto COULD_NOT_FIND = u8"Textractor: could not find text";
inline auto SELECT_LANGUAGE = u8"Select Language";
inline auto BING_PROMPT = u8"What language should Bing translate to?";
inline auto GOOGLE_PROMPT = u8"What language should Google translate to?";
inline auto TOO_MANY_TRANS_REQUESTS = LR"(
Too many translation requests: refuse to make more)";
inline auto TRANSLATION_ERROR = L"Error while translating";
inline auto EXTRA_WINDOW_INFO = u8R"(Right click to change settings
Click and drag on window edges to move, or the bottom right corner to resize)";
inline auto BG_COLOR = u8"Background Color";
inline auto TEXT_COLOR = u8"Text Color";
inline auto FONT_SIZE = u8"Font Size";
inline auto TOPMOST = u8"Always on Top";
inline auto ALWAYS_ON_TOP = u8"Keep this window on top";
inline auto REGEX_FILTER = u8"Regex Filter";
inline auto INVALID_REGEX = u8"Invalid regex";
inline auto CURRENT_FILTER = u8"Currently filtering: ";
inline auto REPLACER_INSTRUCTIONS = LR"(This file only does anything when the "Replacer" extension is used.
Replacement commands must be formatted like this:
|ORIG|original_text|BECOMES|replacement_text|END|
All text in this file outside of a replacement command is ignored.
Whitespace in original_text is ignored, but replacement_text can contain spaces, newlines, etc.
This file must be encoded in Unicode (UTF-16 little endian).
)";
inline auto THREAD_LINKER = u8"Thread Linker";
inline auto LINK = u8"Link";
inline auto THREAD_LINK_FROM = u8"Thread number to link from";
inline auto THREAD_LINK_TO = u8"Thread number to link to";

inline auto LANG__INIT__DUMMY = std::invoke([]
{
#ifdef TURKISH
	ATTACH = u8"Oyuna bağla";
	DETACH = u8"Oyundan kopar";
	ADD_HOOK = u8"Kanca ekle";
	SAVE_HOOKS = u8"Kancaları kaydet";
	SETTINGS = u8"Ayarlar";
	EXTENSIONS = u8"Uzantılar";
	SELECT_PROCESS = u8"İşlem Seçin";
	ATTACH_INFO = u8"Bağlanmak istediğiniz işlemi görmüyorsanız yönetici olarak çalıştırmayı deneyin";
	WINDOW = u8"Pencere";
	DEFAULT_CODEPAGE = u8"Varsayılan Kod Sayfası";
	FLUSH_DELAY = u8"Temizleme Gecikmesi";
	MAX_BUFFER_SIZE = u8"Maksimum Arabellek Boyu";
	ABOUT = L"Textractor v" CURRENT_VERSION LR"( (proje ana sayfası: https://github.com/Artikash/Textractor)
Benim tarafımdan yapıldı: Artikash (e-posta: akashmozumdar@gmail.com)
Textractor ile ilgili tüm sorunlarınız, istekleriniz ve sorularınız için lütfen benimle iletişime geçin
Benimle, proje ana sayfasından (“issues” kısmından) ya da e-posta aracılığıyla iletişime geçebilirsiniz
Kaynak kodu GKLv3 koruması altında proje ana sayfasında mevcut
Şu anda iş aramaktayım: Eğer ABD’li yazılım mühendislerini işe alıyorsanız lütfen bana e-posta atın)";
	UPDATE_AVAILABLE = L"Güncelleme mevcut: https://github.com/Artikash/Textractor/releases adresinden indirin";
	ALREADY_INJECTED = L"Textractor: Zaten enjekte edili";
	ARCHITECTURE_MISMATCH = L"Textractor: Mimari uyumsuzluğu: Lütfen Textractor’ın 32 bitlik sürümünü deneyin";
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
	CODE_INFODUMP = u8R"(Buscar texto
S[codepage#]texto
O
Ingresar código de lectura
R{S|Q|V}[codepage#][*deref_offset]@addr
O
Ingresar hook code (H-code)
H{A|B|W|S|Q|V}[N][codepage#]data_offset[*deref_offset1][:split_offset[*deref_offset2]]@addr[:module[:func]]
Todos los números excepto codepage en hexedécimal
Codepage por defecto es 932 (Shift-JIS) pero se puede cambiar en opciones
A/B: codepage char little/big endian
W: UTF-16 char
S/Q/V: codepage/UTF-16/UTF-8 string
Negatives for data/split offset refer to registers
-4 for EAX, -8 for ECX, -C for EDX, -10 for EBX, -14 for ESP, -18 for EBP, -1C for ESI, -20 for EDI
* means dereference pointer+deref_offset)";
	SAVE_SETTINGS = u8"Guardar opciones";
	EXTEN_WINDOW_INSTRUCTIONS = u8R"(Arrrastra y suelta la extension (.dll) aquí desde tu computadora para añadirlos
Arrastra y suelta la lista para reordenar
Presiona supr en una extension seleccionada para removerla)";
	WINDOW = u8"Ventana";
	USE_JP_LOCALE = u8"¿Emular idioma japonés?";
	DEFAULT_CODEPAGE = u8"Default Codepage";
	FLUSH_DELAY = u8"Flush Delay";
	MAX_BUFFER_SIZE = u8"Max Buffer Size";
	CONSOLE = L"Consola";
	CLIPBOARD = L"Portapapeles";
	ABOUT = L"Textractor v" CURRENT_VERSION LR"( hecho por mí: Artikash (correo: akashmozumdar@gmail.com)
Página del proyecto: https://github.com/Artikash/Textractor
Video tutorial: https://www.youtube.com/watch?v=eecEOacF6mw
No dudes en conectarme si tienes algún problema, petición de característica o preguntas relacionadas con Textractor
Puedes hacerlo en la página del proyecto (en el apartado de "Issues") o por correo. Usa el inglés para comunicarte.
Código fuente disponible bajo GPLv3 en la página del proyecto
Estoy buscando un nuevo trabajo: por favor envíame un correo si estás contratando ingenieros de software de EE.UU.)";
	UPDATE_AVAILABLE = L"Actualización disponible: descárguela en https://github.com/Artikash/Textractor/releases";
	ALREADY_INJECTED = L"Textractor: ya inyectado";
	ARCHITECTURE_MISMATCH = L"Textractor: architecture mismatch: try 32 bit Textractor instead";
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
	BING_PROMPT = u8"¿A qué idioma debe traducir Bing?";
	GOOGLE_PROMPT = u8"¿A qué idioma debe traducir Google?";
	TOO_MANY_TRANS_REQUESTS = LR"(
Demasiadas peticiones de traducción: no se puede hacer más)";
	TRANSLATION_ERROR = L"Error al traducir";
	EXTRA_WINDOW_INFO = u8R"(Clic derecho para configurar
Clic y arrastra los bordes de la ventana para moverla, o en la esquina inferior derecha para cambiar el tamaño)";
	BG_COLOR = u8"Color de fondo";
	TEXT_COLOR = u8"Color de texto";
	FONT_SIZE = u8"Tamaño de letra";
	TOPMOST = u8"Siempre visible";
	ALWAYS_ON_TOP = u8"Matener esta ventana encima";
	REGEX_FILTER = u8"Filtro Regex";
	INVALID_REGEX = u8"Regex inválido";
	CURRENT_FILTER = u8"Actualmente filtrando: ";
#endif // SPANISH
	return 0;
});
