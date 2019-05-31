# Textractor

![How it looks](screenshot.png)

[Español](https://github.com/Artikash/Textractor/blob/master/README_ES.md) ● [简体中文](https://github.com/Artikash/Textractor/blob/master/README_SC.md) ● 
[日本語](https://github.com/Artikash/Textractor/blob/master/README_JP.md) ● [Русский](https://github.com/Artikash/Textractor/blob/master/README_RU.md) ●
[Bahasa](https://github.com/Artikash/Textractor/blob/master/README_ID.md)


**Textractor** (a.k.a NextHooker) adalah text hooker video game untuk Windows/Wine x86/x64 berbasis open-source yang didasari oleh [ITHVNR](http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).<br>
Lihat [video tutorial](https://youtu.be/eecEOacF6mw) untuk mengetahui bagaimana cara menggunakannya.

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=akashmozumdar%40gmail.com&item_name=Textractor%20development&currency_code=USD)

## Pengunduhan

Rilisan Textractor dapat diunduh [disini](https://github.com/Artikash/Textractor/releases).<br>
Rilisan Terakhir ITHVNR dapat diunduh [disini](https://drive.google.com/open?id=13aHF4uIXWn-3YML_k2YCDWhtGgn5-tnO).<br>
Coba jalankan vc_redist.x86.exe jika kamu memiliki masalah ketika menjalankan Textractor.

## Fitur

- Sangat Ekstensibel
- Tempel otomatis banyak engine game (termasuk beberapa yang tidak didukung oleh VNR)
- Hook teks menggunakan "hook" /H (mendukung semua kode AGTH)
- Mengutip teks secara langsung menggunakan kode /R "read"

## Dukungan

Please let me know of any bugs, games that Textractor has trouble hooking, feature requests, or other suggestions.<br>
If you have trouble hooking a game please email me a place where I can freely download it, or gift it to me on [Steam](https://steamcommunity.com/profiles/76561198097566313/).

Tolong beritahu saya jika kamu menemukan bug, game yang tidak dapat di tempel oleh Textractor, permintaan fitur, atau usulan lain.<br>
Jika kamu memiliki masalah dalam menempelkan kedalam game tolong email saya link agar saya dapat mendownload game tersebut, atau gift game tersebut di [Steam](https://steamcommunity.com/profiles/76561198097566313/).

## Ekstensi

Lihat [project sampel ekstensi saya](https://github.com/Artikash/ExampleExtension) untuk melihat bagaimana cara membuat ekstensi.<br>
Lihat folder extensions untuk melihat sampel ekstensi.

## Kontribusi

Seluruh kontribusi diapresiasi! Tolong email (tidak, saya tidak sibuk!) saya di akashmozumdar@gmail.com jika kamu memiliki pertanyaan mengenai codebase nya.<br>
Kamu harus menggunakan proses standar dalam membuat permintaan pull(fork, branch, commit changes, membuat PR dari branch kamu ke master saya).<br>
Berkontribusi dalam penerjemahan dapat dilakukan dengan mudah : cukup terjemahkan string dari text.cpp lalu terjemahkan README ini.

## Compiling

Before compiling *Textractor*, you should get Visual Studio with CMake support, as well as Qt version 5.11<br>
You should then be able to simply open the folder in Visual Studio, and build. Run Textractor.exe.


## Project Architecture

The host (see GUI/host folder) injects texthook.dll (created from the texthook folder) into the target process and connects to it via 2 pipe files.<br>
Host writes to hostPipe, texthook writes to hookPipe.<br>
texthook waits for the pipe to be connected, then injects a few instructions into any text outputting functions (e.g. TextOut, GetGlyphOutline) that cause their input to be sent through the pipe.<br>
Additional information about hooks is exchanged via shared memory.<br>
The text that the host receives through the pipe is then processed a little before being dispatched back to the GUI.<br>
Finally, the GUI dispatches the text to extensions before displaying it.

## Developers

If you're on this list and want your link changed let me know.
- Textractor made by [Me](https://github.com/Artikash) and [DoumanAsh](https://github.com/DoumanAsh)
- Spanish translation by [scese250](https://github.com/scese250)
- Turkish translation by niisokusu
- Simplified Chinese translation by [tinyAdapter](https://github.com/tinyAdapter)
- Russian translation by [TokcDK](https://github.com/TokcDK)
- ITHVNR updated by [mireado](https://github.com/mireado) and [Eguni](https://github.com/Eguni)
- ITHVNR originally made by [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- VNR engine made by [jichi](https://archive.is/prJwr)
- ITH updated by [Andys](https://github.com/AndyScull)
- ITH originally made by [kaosu](http://www.hongfire.com/forum/member/562651-kaosu)
- Locale Emulator library made by [xupefei](https://github.com/xupefei)
- MinHook library made by [TsudaKageyu](https://github.com/TsudaKageyu)

## Special Thanks

- Everybody adding issues!
