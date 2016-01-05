@echo off
setlocal
if [%1] == [] (
  echo usage: copy_vnr path_to_Sakura
  goto :EOF
)
xcopy %1\config.pri . /S /Y /I
xcopy %1\cpp\libs\ccutil ccutil /S /Y /I
xcopy %1\cpp\libs\cpputil cpputil /S /Y /I
xcopy %1\cpp\libs\disasm disasm /S /Y /I /EXCLUDE:exclude.txt
xcopy %1\cpp\libs\hashutil hashutil /S /Y /I
xcopy %1\cpp\plugins\ithsys ithsys /S /Y /I
xcopy %1\cpp\plugins\vnrhook vnrhook /S /Y /I
xcopy %1\cpp\plugins\texthook texthook /S /Y /I /EXCLUDE:exclude.txt
xcopy %1\cpp\libs\memdbg memdbg /S /Y /I
xcopy %1\cpp\libs\ntdll ntdll /S /Y /I
xcopy %1\cpp\libs\ntinspect ntinspect /S /Y /I
xcopy %1\cpp\libs\winkey winkey /S /Y /I
xcopy %1\cpp\libs\winmaker winmaker /S /Y /I
xcopy %1\cpp\libs\winmutex winmutex /S /Y /I
xcopy %1\cpp\libs\winversion winversion /S /Y /I
xcopy %1\cpp\libs\winseh winseh /S /Y /I
xcopy %1\cpp\libs\wintimer wintimer /S /Y /I
xcopy %1\cpp\libs\windbg windbg /S /Y /I
xcopy %1\cpp\libs\sakurakit sakurakit /S /Y /I
xcopy %1\cpp\libs\mono mono /S /Y /I

endlocal
