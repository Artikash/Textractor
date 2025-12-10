# Textractor

![How it looks](screenshot.png)

[English](README.md) ● [Español](README_ES.md) ● [简体中文](README_SC.md) ● [Русский](README_RU.md) ● [한국어](README_KR.md) ● [ภาษาไทย](README_TH.md) ● [Français](README_FR.md) ● [Italiano](README_IT.md) ● [日本語](README_JP.md) ● [Bahasa Indonesia](README_ID.md) ● [Português](README_PT.md) ● [Deutsch](README_DE.md)● [Tiếng Việt](README_VI.md)

**Textractor** (a.k.a. NextHooker) là dự án open-source x86/x64 video game text hooker dành cho Windows 7+ (và Wine) dựa trên [ITHVNR](https://web.archive.org/web/20160202084144/http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).<br>
Xem [video hướng dẫn](docs/TUTORIAL.md) để biết nhanh cách sử dụng.

## Tải về

Phiên bản ổn định của Textractor tải về ở [đây](https://github.com/Artikash/Textractor/releases).<br>
Phiên bản cuối cùng của ITHVNR tải về ở [đây](https://drive.google.com/open?id=13aHF4uIXWn-3YML_k2YCDWhtGgn5-tnO).<br>

## Các tính năng 

- Khả năng mở rộng và tùy chỉnh cao
- Tự động hook nhiều engine game (bao gồm một số engine không được VNR hỗ trợ!)
- Hook text bằng /H "hook" codes (Hỗ trợ đa số code AGTH!) 
- Tự động tìm codes có thể hook

## Hỗ trợ

Hãy tạo "issue" mới nếu trong quá trình sử dụng gặp lỗi, những game mà Textractor không thể hook, yêu cầu tính năng mới, hoặc đóng góp ý kiến cho dự án.<br>
Nếu bạn gặp vấn đề khi hook game, Vui lòng chỉ cho tôi cách tải game bị lỗi miễn phí hoặc tặng game đó cho tôi trên [Steam](https://steamcommunity.com/profiles/76561198097566313/).

## Extensions

Tham khảo qua [Extension project mẫu](https://github.com/Artikash/ExampleExtension) để biết cách tạo ra một extension.<br>
Thư mục extensions có chứa ví dụ về tính năng của từng extension.

## Đóng góp

Tất cả đóng góp của mọi người đều đáng trân trọng! Hãy gửi email cho tôi qua akashmozumdar@gmail.com nếu bạn có câu hỏi về codebase của dự án.<br>
Đóng góp cho dự án thông quy trình tạo pull request tiêu chuẩn (fork, branch, commit changes, tạo PR từ nhánh của bạn tới nhánh master của dự án).<br>
Cách đóng góp bản dịch: File [text.cpp](text.cpp) chứa tất cả các text mà bạn cần phải dịch. Bản dịch cho file README hoặc video hướng dẫn đều được chào đón.

## Compiling

Trước khi compile Textractor, bạn cần Qt version 5.13 và Visual Studio với CMake.<br>
Clone Textractor's source và init submodules với `git clone https://github.com/Artikash/Textractor.git` và `git submodule update --init`.<br>
Sau đó bạn có thể mở source folder trong Visual Studio và build.

## Project Architecture

The host injects texthook into the target process and connects to it via 2 pipe files.
texthook waits for the pipe to be connected, then injects a few instructions into any text outputting functions (e.g. TextOut, GetGlyphOutline) that cause their input to be sent through the pipe.<br>
Additional information about hooks is exchanged via shared memory.<br>
The text that the host receives through the pipe is then processed a little before being dispatched back to the GUI.<br>
Finally, the GUI dispatches the text to extensions before displaying it.

## [Các Dev của dự án](docs/CREDITS.md)
