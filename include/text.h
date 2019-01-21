#pragma once

#define CURRENT_VERSION "1.0.2"
#define ENGLISH

#ifdef ENGLISH
constexpr auto ATTACH = u8"Attach to game";
constexpr auto LAUNCH = u8"Launch game";
constexpr auto DETACH = u8"Detach from game";
constexpr auto ADD_HOOK = u8"Add hook";
constexpr auto SAVE_HOOKS = u8"Save hook(s)";
constexpr auto SETTINGS = u8"Settings";
constexpr auto EXTENSIONS = u8"Extensions";
constexpr auto SELECT_PROCESS = u8"Select Process";
constexpr auto ATTACH_INFO = u8R"(If you don't see the process you want to attach, try running with admin rights
You can also type in the process id)";
constexpr auto SEARCH_GAME = u8"Select from computer";
constexpr auto PROCESSES = u8"Processes (*.exe)";
constexpr auto CODE_INFODUMP = u8R"(Search for text
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
constexpr auto SAVE_SETTINGS = u8"Save settings";
constexpr auto EXTEN_WINDOW_INSTRUCTIONS = u8R"(Drag and drop extension (.dll) files here from your computer to add them
Drag and drop within the list to reorder
Press delete with an extension selected to remove it)";
constexpr auto WINDOW = u8"Window";
constexpr auto USE_JP_LOCALE = u8"Emulate japanese locale?";
constexpr auto DEFAULT_CODEPAGE = u8"Default Codepage";
constexpr auto FLUSH_DELAY = u8"Flush Delay";
constexpr auto MAX_BUFFER_SIZE = u8"Max Buffer Size";
constexpr auto CONSOLE = L"Console";
constexpr auto CLIPBOARD = L"Clipboard";
constexpr auto ABOUT = L"Textractor v" CURRENT_VERSION LR"( made by me: Artikash (email: akashmozumdar@gmail.com)
Project homepage: https://github.com/Artikash/Textractor
Tutorial video: https://www.youtube.com/watch?v=eecEOacF6mw
Please contact me with any problems, feature requests, or questions relating to Textractor
You can do so via the project homepage (issues section) or via email
Source code available under GPLv3 at project homepage
I'm currently looking for a new job: please email me if you're hiring US software engineers)";
constexpr auto UPDATE_AVAILABLE = L"Update available: download it from https://github.com/Artikash/Textractor/releases";
constexpr auto ALREADY_INJECTED = L"Textractor: already injected";
constexpr auto ARCHITECTURE_MISMATCH = L"Textractor: architecture mismatch: try 32 bit Textractor instead";
constexpr auto INJECT_FAILED = L"Textractor: couldn't inject";
constexpr auto LAUNCH_FAILED = L"Textractor: couldn't launch";
constexpr auto INVALID_CODE = L"Textractor: invalid code";
constexpr auto INVALID_CODEPAGE = L"Textractor: couldn't convert text (invalid codepage?)";
constexpr auto PIPE_CONNECTED = u8"Textractor: pipe connected";
constexpr auto INSERTING_HOOK = u8"Textractor: inserting hook: %s";
constexpr auto REMOVING_HOOK = u8"Textractor: removing hook: %s";
constexpr auto HOOK_FAILED = u8"Textractor: failed to insert hook";
constexpr auto TOO_MANY_HOOKS = u8"Textractor: too many hooks: can't insert";
constexpr auto NOT_ENOUGH_TEXT = u8"Textractor: not enough text to search accurately";
constexpr auto FUNC_MISSING = u8"Textractor: function not present";
constexpr auto MODULE_MISSING = u8"Textractor: module not present";
constexpr auto GARBAGE_MEMORY = u8"Textractor: memory constantly changing, useless to read";
constexpr auto SEND_ERROR = u8"Textractor: Send ERROR (likely an incorrect H-code)";
constexpr auto READ_ERROR = u8"Textractor: Reader ERROR (likely an incorrect R-code)";
constexpr auto HIJACK_ERROR = u8"Textractor: Hijack ERROR";
constexpr auto COULD_NOT_FIND = u8"Textractor: could not find text";
constexpr auto SELECT_LANGUAGE = u8"Select Language";
constexpr auto BING_PROMPT = u8"What language should Bing translate to?";
constexpr auto GOOGLE_PROMPT = u8"What language should Google translate to?";
constexpr auto TOO_MANY_TRANS_REQUESTS = LR"(
Too many translation requests: refuse to make more)";
constexpr auto TRANSLATION_ERROR = L"Error while translating";
constexpr auto EXTRA_WINDOW_INFO = u8R"(Right click to change settings
Click and drag on window edges to move, or the bottom right corner to resize)";
constexpr auto BG_COLOR = u8"Background Color";
constexpr auto TEXT_COLOR = u8"Text Color";
constexpr auto FONT_SIZE = u8"Font Size";
constexpr auto TOPMOST = u8"Always on Top";
constexpr auto ALWAYS_ON_TOP = u8"Keep this window on top";
constexpr auto REGEX_FILTER = u8"Regex Filter";
constexpr auto INVALID_REGEX = u8"Invalid regex";
constexpr auto CURRENT_FILTER = u8"Currently filtering: ";
#endif // ENGLISH

#ifdef TURKISH
constexpr auto ATTACH = u8"Oyuna bağla";
constexpr auto DETACH = u8"Oyundan kopar";
constexpr auto ADD_HOOK = u8"Kanca ekle";
constexpr auto SAVE_HOOKS = u8"Kancaları kaydet";
constexpr auto SETTINGS = u8"Ayarlar";
constexpr auto EXTENSIONS = u8"Uzantılar";
constexpr auto SELECT_PROCESS = u8"İşlem Seçin";
constexpr auto ATTACH_INFO = u8"Bağlanmak istediğiniz işlemi görmüyorsanız yönetici olarak çalıştırmayı deneyin";
constexpr auto CODE_INFODUMP = u8"Kanca kodunu girin\n"
u8"/H{A|B|W|S|Q|V}[N][kod_sayfası#]göreli_veri_konumu[*göreli_referanstan_ayırma_konumu1][:göreli_ayırma_konumu[*göreli_referanstan_ayırma_konumu2]]@adres[:modül[:fonksiyon]]\n"
u8"YA DA\n"
u8"Okuma kodunu girin\n"
u8"/R{S|Q|V}[kod_sayfası#][*göreli_referanstan_ayırma_konumu|0]@adres\n"
u8"Kod sayfası hariç tüm sayılar onaltılı sayı sisteminde olmalı\n"
u8"A/B: Shift-JIS karakteri little/big endian\n"
u8"W: UTF-16 karakteri\n"
u8"S/Q/V: Shift-JIS/UTF-16/UTF-8 dizgisi\n"
u8"Negatif göreli_veri_konumları/alt_göreli_konumlar yazmaç\n"
u8"EAX için -4, ECX için -8, EDX için -C, EBX için -10, ESP için -14, EBP için -18, ESI için -1C, EDI için -20\n"
u8"* işareti referanstan_ayırma_işaretçisi+göreli_referanstan_ayırma_konumu demek";
constexpr auto SELECT_EXTENSION = u8"Uzantı Seçin";
constexpr auto EXTENSION_FILES = u8"Uzantılar (*.dll)";
constexpr auto WINDOW = u8"Pencere";
constexpr auto DEFAULT_CODEPAGE = u8"Varsayılan Kod Sayfası";
constexpr auto FLUSH_DELAY = u8"Temizleme Gecikmesi";
constexpr auto MAX_BUFFER_SIZE = u8"Maksimum Arabellek Boyu";
constexpr auto ABOUT = L"Textractor beta v" CURRENT_VERSION L" (proje ana sayfası: https://github.com/Artikash/Textractor)\n"
L"Benim tarafımdan yapıldı: Artikash (e-posta: akashmozumdar@gmail.com)\n"
L"Textractor ile ilgili tüm sorunlarınız, istekleriniz ve sorularınız için lütfen benimle iletişime geçin\n"
L"Benimle, proje ana sayfasından (“issues” kısmından) ya da e-posta aracılığıyla iletişime geçebilirsiniz\n"
L"Kaynak kodu GKLv3 koruması altında proje ana sayfasında mevcut\n"
L"Şu anda iş aramaktayım: Eğer ABD’li yazılım mühendislerini işe alıyorsanız lütfen bana e-posta atın";
constexpr auto UPDATE_AVAILABLE = L"Güncelleme mevcut: https://github.com/Artikash/Textractor/releases adresinden indirin";
constexpr auto ALREADY_INJECTED = L"Textractor: Zaten enjekte edili";
constexpr auto ARCHITECTURE_MISMATCH = L"Textractor: Mimari uyumsuzluğu: Lütfen Textractor’ın 32 bitlik sürümünü deneyin";
constexpr auto INJECT_FAILED = L"Textractor: Enjekte edilemedi";
constexpr auto INVALID_CODE = L"Textractor: Geçersiz kod";
constexpr auto NO_HOOKS = L"Textractor: Hiçbir kanca tespit edilemedi";
constexpr auto INVALID_CODEPAGE = L"Textractor: Metne dönüştürülemedi (geçersiz kod sayfası?)";
constexpr auto PIPE_CONNECTED = u8"Textractor: Boru bağlandı";
constexpr auto DISABLE_HOOKS = u8"Textractor: x64’te kancalar çalışmaz, yalnızca okuma kodları çalışır: Motor etkisizleştirildi";
constexpr auto INSERTING_HOOK = u8"Textractor: Kanca ekleniyor: %s";
constexpr auto REMOVING_HOOK = u8"Textractor: Kanca çıkarılıyor:: %s";
constexpr auto HOOK_FAILED = u8"Textractor: Kanca eklenemedi";
constexpr auto TOO_MANY_HOOKS = u8"Textractor: Çok fazla kanca var: Eklenemiyor";
constexpr auto FUNC_MISSING = u8"Textractor: Fonksiyon mevcut değil";
constexpr auto MODULE_MISSING = u8"Textractor: Modül mevcut değil";
constexpr auto GARBAGE_MEMORY = u8"Textractor: Hafıza sürekli değişiyor, okumak boşa";
#endif // TURKISH

#ifdef SPANISH
constexpr auto ATTACH = u8"Adjuntar juego";
constexpr auto LAUNCH = u8"Iniciar juego";
constexpr auto DETACH = u8"Desconectar juego";
constexpr auto ADD_HOOK = u8"Añadir hook";
constexpr auto SAVE_HOOKS = u8"Guardar hook(s)";
constexpr auto SETTINGS = u8"Opciones";
constexpr auto EXTENSIONS = u8"Extensiones";
constexpr auto SELECT_PROCESS = u8"Seleccionar procreso";
constexpr auto ATTACH_INFO = u8R"(Si no ves el proceso que quieras adjuntar, ejecuta este programa como administrador
También puedes escribir la ID del proceso)";
constexpr auto SEARCH_GAME = u8"Seleccionar desde computadora";
constexpr auto PROCESSES = u8"Procesos (*.exe)";
constexpr auto CODE_INFODUMP = u8R"(Buscar texto
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
constexpr auto SAVE_SETTINGS = u8"Guardar opciones";
constexpr auto EXTEN_WINDOW_INSTRUCTIONS = u8R"(Arrrastra y suelta la extension (.dll) aquí desde tu computadora para añadirlos
Arrastra y suelta la lista para reordenar
Presiona supr en una extension seleccionada para removerla)";
constexpr auto WINDOW = u8"Ventana";
constexpr auto USE_JP_LOCALE = u8"¿Emular idioma japonés?";
constexpr auto DEFAULT_CODEPAGE = u8"Default Codepage";
constexpr auto FLUSH_DELAY = u8"Flush Delay";
constexpr auto MAX_BUFFER_SIZE = u8"Max Buffer Size";
constexpr auto CONSOLE = L"Consola";
constexpr auto CLIPBOARD = L"Portapapeles";
constexpr auto ABOUT = L"Textractor v" CURRENT_VERSION LR"( hecho por mí: Artikash (correo: akashmozumdar@gmail.com)
Página del proyecto: https://github.com/Artikash/Textractor
Video tutorial: https://www.youtube.com/watch?v=eecEOacF6mw
No dudes en conectarme si tienes algún problema, petición de característica o preguntas relacionadas con Textractor
Puedes hacerlo en la página del proyecto (en el apartado de "Issues") o por correo. Usa el inglés para comunicarte.
Código fuente disponible bajo GPLv3 en la página del proyecto
Estoy buscando un nuevo trabajo: por favor envíame un correo si estás contratando ingenieros de software de EE.UU.)";
constexpr auto UPDATE_AVAILABLE = L"Actualización disponible: descárguela en https://github.com/Artikash/Textractor/releases";
constexpr auto ALREADY_INJECTED = L"Textractor: ya inyectado";
constexpr auto ARCHITECTURE_MISMATCH = L"Textractor: architecture mismatch: try 32 bit Textractor instead";
constexpr auto INJECT_FAILED = L"Textractor: no se puede inyectar";
constexpr auto LAUNCH_FAILED = L"Textractor: no se puede iniciar";
constexpr auto INVALID_CODE = L"Textractor: código inválido";
constexpr auto INVALID_CODEPAGE = L"Textractor: no se puede convertir texto (¿Codepage inválido?)";
constexpr auto PIPE_CONNECTED = u8"Textractor: pipe connected";
constexpr auto INSERTING_HOOK = u8"Textractor: insertando hook: %s";
constexpr auto REMOVING_HOOK = u8"Textractor: removiendo hook: %s";
constexpr auto HOOK_FAILED = u8"Textractor: no se puede insertar hook";
constexpr auto TOO_MANY_HOOKS = u8"Textractor: demasiados hooks: no se puede insertar";
constexpr auto NOT_ENOUGH_TEXT = u8"Textractor: no hay suficiente texto para buscar con precisión";
constexpr auto FUNC_MISSING = u8"Textractor: función no presente";
constexpr auto MODULE_MISSING = u8"Textractor: module not present";
constexpr auto GARBAGE_MEMORY = u8"Textractor: memory constantly changing, useless to read";
constexpr auto SEND_ERROR = u8"Textractor: Send ERROR (probablemente un H-code incorrecto)";
constexpr auto READ_ERROR = u8"Textractor: Reader ERROR (probablemente un R-code incorrecto)";
constexpr auto HIJACK_ERROR = u8"Textractor: Hijack ERROR";
constexpr auto COULD_NOT_FIND = u8"Textractor: no se puede encontrar texto";
constexpr auto SELECT_LANGUAGE = u8"Seleccionar lenguaje";
constexpr auto BING_PROMPT = u8"¿A qué idioma debe traducir Bing?";
constexpr auto GOOGLE_PROMPT = u8"¿A qué idioma debe traducir Google?";
constexpr auto TOO_MANY_TRANS_REQUESTS = LR"(
Demasiadas peticiones de traducción: no se puede hacer más)";
constexpr auto TRANSLATION_ERROR = L"Error al traducir";
constexpr auto EXTRA_WINDOW_INFO = u8R"(Clic derecho para configurar
Clic y arrastra los bordes de la ventana para moverla, o en la esquina inferior derecha para cambiar el tamaño)";
constexpr auto BG_COLOR = u8"Color de fondo";
constexpr auto TEXT_COLOR = u8"Color de texto";
constexpr auto FONT_SIZE = u8"Tamaño de letra";
constexpr auto TOPMOST = u8"Siempre visible";
constexpr auto ALWAYS_ON_TOP = u8"Matener esta ventana encima";
constexpr auto REGEX_FILTER = u8"Filtro Regex";
constexpr auto INVALID_REGEX = u8"Regex inválido";
constexpr auto CURRENT_FILTER = u8"Actualmente filtrando: ";
#endif // SPANISH
