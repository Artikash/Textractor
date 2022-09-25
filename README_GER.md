# Textractor

![Wie es aussieht](screenshot.png)

[English](README.md) ● [Español](README_ES.md) ● [简体中文](README_SC.md) ● [Русский](README_RU.md) ● [한국어](README_KR.md) ● [ภาษาไทย](README_TH.md) ● [Français](README_FR.md) ● [Italiano](README_IT.md) ● [日本語](README_JP.md) ● [Bahasa Indonesia](README_ID.md) ● [Português](README_PT.md)

**Textractor** (a.b.a. NextHooker) ist ein open-source x86/x64 Video spiel Text hooker für Windows 7+ (und Wine) basierend auf [ITHVNR](https://web.archive.org/web/20160202084144/http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).<br&gt;
Schau das [Tutorial Video](docs/TUTORIAL.md) (auf Englisch) an für einen schnellen Überblick wie du Textractor verwendest.
## Download

Der offizielle Release ist [hier](https://github.com/Artikash/Textractor/releases) zu finden.<br&gt;
Der letzte Release von ITHVNR ist [hier](https://drive.google.com/open?id=13aHF4uIXWn-3YML_k2YCDWhtGgn5-tnO).<br&gt;
Der experimentelle Release von Textractor (mit debug Informationen) ist [hier](https://ci.appveyor.com/project/Artikash/textractor/history) in der 'Artifacts'
Kategorie des jeweiligen Jobs.

## Features

- Modular und Anpassbar
- Automatischen 'hooken' von mehreren Engines (einige davon welche keine VNR Support haben!)
- Text 'hooken' mithilfe von /H "hook" Codes (die meisten AGTH codes funktionieren)
- Automatische suche nach funktionierenden Hook's

## Support

Wenn ihr irgendwelche Fehler, Spiele bei denen Textractor nicht funktioniert, oder Fragen/Anmerkungen habt lasst es mich bitte wissen.<br&gt;
Falls ihr Probleme mit einem Spiel habt, schickt mir einen kostenlosen download Link von dem Spiel oder schenkt es mir auf [Steam](https://steamcommunity.com/profiles/76561198097566313/).

## Erweiterungen

Siehe [Example Extension project](https://github.com/Artikash/ExampleExtension) für Anleitungen, wie man eine Erweiterung erstellt.<br&gt;
Im 'Extensions' Ordner sind Beispiele für Erweiterungen.

## Unterstützen

Ich bin dankbar für alle Unterstützungen! Schickt mir eine E-Mail an akashmozumdar@gmail.com falls ihr Fragen zur Codebasis habt.<br&gt;
Verwendet bitte als Standard eine pull Request (fork, branch, commit) zum Master Release.<br&gt;
Zu Übersetzungen beizutragen ist einfach: text.ccp enthält alle text Strings welche übersetzt werden sollen. Übersetzungen der README oder des Tutorial Video Transkripts sind ebenfalls willkommen.

## Compiling
Zum Compilen braucht ihr Qt Version 5.13 und Visual Studio mit CMake Unterstützung.
Erstellt einen Clone vom Quellcode und initialisiert die submodule mit 'git clone https://github.com/Artikash/Textractor.git' und 'git submodule update --init'.
Ihr solltet danach in der Lage sein, den Quellordner in Visual Studio zu öffnen und anzufangen.

## Projekt Architektur

Der Host injiziert texthooks in den ziel Prozess und verbindet ihn mit 2 Pipe Dateien.
Texthook wartet auf die Pipe und injiziert Instruktionen für den Text Output (z.b. TextOut, GetGlyphOutline) welche durch die Pipe gesendet werden.<br&gt;
Weitere Informationen werden durch geteilten Speicher ausgetauscht.<br&gt;
Der Text, welchen der Host durch die Pipe erhält, wird dann verarbeitet, bevor er wieder an die GUI gesendet wird.<br&gt;
Zu guter Letzt, sendet die GUI den Text an die Erweiterung, welche einen lesbaren Output anzeigt.

## [Entwickler](docs/CREDITS.md)
