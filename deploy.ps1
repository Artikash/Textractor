cd Builds/x86-Release/Build; 
Compress-Archive -Force -Path "Textractor.exe","styles","platforms","Qt5Core.dll","Qt5Gui.dll","Qt5Widgets.dll","vnrhook.dll","256_Remove Repetition.dll","512_Copy to Clipboard.dll","1024_Google Translate.dll","2048_Extra Newlines.dll" -DestinationPath Textractor;
cd ../../x64-Release/Build;
Compress-Archive -Force -Path "Textractor.exe","styles","platforms","Qt5Core.dll","Qt5Gui.dll","Qt5Widgets.dll","vnrhook.dll","256_Remove Repetition.dll","512_Copy to Clipboard.dll","1024_Google Translate.dll","2048_Extra Newlines.dll" -DestinationPath Textractor;
