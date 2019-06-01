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

Sebelum melakukan proses compile *Textractor*, kamu harus memiliki Visual Studio dengan dukungan Cmake, juga dengan Qt version 5.11<br>
Lalu kamu dapat membuka folder di Visual Studio, dan build. Run Textractor.exe.


## Arsitektur Project

Host (lihat folder GUI/host) menginject texthook.dll (dibuat dari folder texthook) kedalam target process dan disambungkan lewat 2 file pipe.<br>
Host menulis ke hostPipe, texthook menulis ke hookPipe.<br>
texthook menunggu pipe tersambung, lalu menginject beberapa instruksi ke teks yang menghasilkan fungsi (contoh: TextOut, GetGlyphOutline) yang membuat input dikirim melewati pipa.<br>
Informasi tambahan tentang hook dipindahkan melewati shared memory.<br>
Text yang diterima host melewati pipe lalu diproses lagi sebelum dikembalikan ke GUI.<br>
Dan pada akhirnya, GUI melepas text ke ekstensi sebelum menampilkan teks.

## Pengembang

Jika kamu berada di list ini dan ingin link kamu diganti, beritahu saya.
- Textractor dibuat oleh saya [Saya](https://github.com/Artikash) and [DoumanAsh](https://github.com/DoumanAsh)
- Terjemahan bahasa Spanyol oleh [scese250](https://github.com/scese250)
- Terjemahan bahasa Turki oleh niisokusu
- Terjemahan bahasa Mandarin oleh [tinyAdapter](https://github.com/tinyAdapter)
- Terjemahan bahasa Rusia oleh [TokcDK](https://github.com/TokcDK)
- ITHVNR diperbaharui oleh [mireado](https://github.com/mireado) and [Eguni](https://github.com/Eguni)
- ITHVNR dibuat oleh [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- VNR engine dibuat oleh [jichi](https://archive.is/prJwr)
- ITH diperbaharui oleh [Andys](https://github.com/AndyScull)
- ITH dibuat oleh [kaosu](http://www.hongfire.com/forum/member/562651-kaosu)
- Locale Emulator library dibuat oleh [xupefei](https://github.com/xupefei)
- MinHook library dibuat oleh [TsudaKageyu](https://github.com/TsudaKageyu)

## Special Thanks

- Semua yang berkontribusi pada bagian Issues!
