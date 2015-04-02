@echo off
setlocal
if [%1] == [] (
  echo usage: copy_vnr <path-to-Sakura-directory>
  goto :EOF
)
xcopy %1\config.pri . /S /Y /I
xcopy %1\cpp\libs\ccutil ccutil /S /Y /I
xcopy %1\cpp\libs\cpputil cpputil /S /Y /I
xcopy %1\cpp\libs\disasm disasm /S /Y /I /EXCLUDE:exclude.txt
xcopy %1\cpp\plugins\ith ith /S /Y /I
xcopy %1\cpp\libs\memdbg memdbg /S /Y /I
xcopy %1\cpp\libs\ntdll ntdll /S /Y /I
xcopy %1\cpp\libs\ntinspect ntinspect /S /Y /I
xcopy %1\cpp\libs\winmaker winmaker /S /Y /I
xcopy %1\cpp\libs\winmutex winmutex /S /Y /I
xcopy %1\cpp\libs\winversion winversion /S /Y /I
xcopy %1\cpp\libs\winseh winseh /S /Y /I

endlocal
