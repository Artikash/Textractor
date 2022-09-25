# Textractor

![Wie es aussieht](screenshot.png)

[English](README.md) ● [Español](README_ES.md) ● [简体中文](README_SC.md) ● [Русский](README_RU.md) ● [한국어](README_KR.md) ● [ภาษาไทย](README_TH.md) ● [Français](README_FR.md) ● [Italiano](README_IT.md) ● [日本語](README_JP.md) ● [Bahasa Indonesia](README_ID.md) ● [Português](README_PT.md)

**Textractor** (a.b.a. NextHooker) ist ein open-source x86/x64 video spiel text hooker für Windows 7+ (und Wine) basierend auf [ITHVNR](https://web.archive.org/web/20160202084144/http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).<br>
Schau das [tutorial video](docs/TUTORIAL.md) (auf Englisch) an für einen schnellen Überblick wie du Textractor vernwendest.
## Download

Der offizielle Release ist [hier](https://github.com/Artikash/Textractor/releases) zu finden.<br>
Der letzte Release von ITHVNR ist [hier](https://drive.google.com/open?id=13aHF4uIXWn-3YML_k2YCDWhtGgn5-tnO).<br>
Der exerimentelle Release von Textractor (mit debug informationen) ist [hier](https://ci.appveyor.com/project/Artikash/textractor/history) in der 'Artifacts' 
Kategorie des jeweiligen Jobs. 

## Features

- Modular und Anpassbar
- Automatischen 'hooken' von mehreren Engines (einige davon welche keine VNR support haben!)
- Text 'hooken' mithilfe von /H "hook" Codes (die meisten AGTH codes funktionieren)
- Automatische suche nach funktionierenden Hook's

## Support

Wenn ihr irgenwelche Fehler, Spiele bei denen Textractor nicht funktioniert, oder Fragen/Anmerkungen habt lasst es mich bitte wissen.<br>
Falls ihr Probleme mit einem Spiel habt, schickt mir einen kostenlosen download Link von dem Spiel oder schenkt es mir auf [Steam](https://steamcommunity.com/profiles/76561198097566313/).

## Erweiterungen

Siehe [Example Extension project](https://github.com/Artikash/ExampleExtension) für Anleitungen wie man eine Erweiterung erstellt.<br>
Im 'Extensions' Ordner sind Beispiele für Erweiterungen.

## Unterstützen

Ich bin dankbar für alle Unterstützungen! Schickt mir eine E-Mail an akashmozumdar@gmail.com falls ihr Fragen zur Codebasis habt.<br>
Verwendet bitte als Standard eine pull request (fork, branch, commit) zum Master Release.<br>
Zu Übersetzungen beizutragen ist einfach: text.ccp enthält alle text Strings welche übersetzt werden sollen. Übersetzungen der README oder des tutorial Video Transkripts sind ebenfalls willkommen.

## Compiling
Zum Compilen braucht ihr Qt version 5.13 und Visual Studio mit CMake unterstützung.
Erstellt einen Clone vom Quellcode und initialisiert die submodule mit `git clone https://github.com/Artikash/Textractor.git` und `git submodule update --init`.
Ihr solltet dannach in der Lage sein, den Quellordner in Visual Studio zu öffnen und anzufangen.


## Projekt Architektur

Der Host injiziert texthooks in den ziel Prozess und verbindet ihn mit 2 Pipe ateien.
Texthook wartet auf die pipe und injeziert Instruktionen für den text Output (z.b. TextOut, GetGlyphOutline) welche durch die Pipe gesendet werden.<br>
Weitere Informationen werden durch geteilten Speicher ausgetauscht.<br>
Der Text welchen der Host  durch die Pipe erhält wird dann verarbeitet, bevor er wieder an die GUI gesendet wird.<br>
Zu guter letzt, sendet die GUI den text an die Erweiterung welche einen lesbaren Output anzeigt.

## [Entwickler](docs/CREDITS.md)
