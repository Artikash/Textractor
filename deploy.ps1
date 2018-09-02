cd Builds/x86-Release/Build; 
Compress-Archive -Force -Path "NextHooker.exe","styles","platforms","Qt5Core.dll","Qt5Gui.dll","Qt5Widgets.dll","vnrhook.dll","1_Remove Repetition.dll","2_Copy to Clipboard.dll","3_Google Translate.dll","4_Extra Newlines.dll" -DestinationPath NextHooker;
cd ../../x64-Release/Build;
Compress-Archive -Force -Path "NextHooker.exe","styles","platforms","Qt5Core.dll","Qt5Gui.dll","Qt5Widgets.dll","vnrhook.dll","1_Remove Repetition.dll","2_Copy to Clipboard.dll","3_Google Translate.dll","4_Extra Newlines.dll" -DestinationPath NextHooker;
