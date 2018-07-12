/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
const wchar_t* Warning=L"Warning!";
//command.cpp
const wchar_t* ErrorSyntax=L"Syntax error";
const wchar_t* Usage = L"Syntax:\r\n\
\r\n\
:H[ELP] - print help\r\n\
Loader options:\r\n\
/P[{process_id|Nprocess_name}] - attach to process\r\n\
\r\n\
Hook options:\r\n\
/H[X]{A|B|W|S|Q}[N][data_offset[*drdo]][:sub_offset[*drso]]@addr[:module[:{name|#ordinal}]]\r\n\
\r\n\
All numbers in /H (except ordinal) are hexadecimal without any prefixes";

const wchar_t* ExtendedUsage = L"/H[X]{A|B|W|S|Q}[N][data_offset[*drdo]][:sub_offset[*drso]]@addr[:[module[:{name|#ordinal}]]]\r\n\
\r\n\
Set additional custom hook\r\n\
\r\n\
Hook types :\r\n\
A - DBCS char\r\n\
B - DBCS char(big-endian)\r\n\
W - UCS2 char\r\n\
S - MBCS string\r\n\
Q - UTF-16 string\r\n\
\r\n\
Parameters:\r\n\
X - use hardware breakpoints\r\n\
N - don't use contexts\r\n\
data_offset - stack offset to char / string pointer\r\n\
drdo - add a level of indirection to data_offset\r\n\
sub_offset - stack offset to subcontext\r\n\
drso - add a level of indirection to sub_offset\r\n\
addr - address of the hook\r\n\
module - name of the module to use as base for 'addr'\r\n\
name - name of the 'module' export to use as base for 'addr'\r\n\
ordinal - number of the 'module' export ordinal to use as base for 'addr'\r\n\
\r\n\
Negative values of 'data_offset' and 'sub_offset' refer to registers: \r\n\
- 4 for EAX, -8 for ECX, -C for EDX, -10 for EBX, -14 for ESP, -18 for EBP, -1C for ESI, -20 for EDI\r\n\
\r\n\
\"Add a level of indirection\" means in C/C++ style: (*(ESP+data_offset)+drdo) instead of (ESP+data_offset)\r\n\
\r\n\
All numbers except ordinal are hexadecimal without any prefixes";

//inject.cpp
const wchar_t* ErrorRemoteThread=L"Can't create remote thread.";
const wchar_t* ErrorOpenProcess=L"Can't open process.";
const wchar_t* ErrorNoProcess=L"Process not found";
const wchar_t* SelfAttach=L"Please do not attach to ITH.exe";
const wchar_t* AlreadyAttach=L"Process already attached.";
const wchar_t* FormatInject=L"Inject process %d. Module base %.8X";
//main.cpp
const wchar_t* NotAdmin=L"Can't enable SeDebugPrevilege. ITH might malfunction.\r\n\
Please run ITH as administrator or turn off UAC.";
//pipe.cpp
const wchar_t* ErrorCreatePipe=L"Can't create text pipe or too many instance.";
const wchar_t* FormatDetach=L"Process %d detached.";
const wchar_t* ErrorCmdQueueFull=L"Command queue full.";
const wchar_t* ErrorNoAttach=L"No process attached.";

//profile.cpp
const wchar_t* ErrorMonitor=L"Can't monitor process.";
//utility.cpp
const wchar_t* InitMessage=L"Copyright (C) 2010-2012  kaosu\r\n\
Copyright(C) 2018 Artikash (akashmozumdar@gmail.com)\r\n\
Source code available at github.com/Artikash/NextHooker";
const wchar_t* BackgroundMsg=L"Type \":h\" or \":help\" for help.";
const wchar_t* ErrorLinkExist=L"Link exist.";
const wchar_t* ErrorCylicLink=L"Link failed. No cyclic link allowed.";
const wchar_t* FormatLink=L"Link from thread%.4x to thread%.4x.";
const wchar_t* ErrorLink=L"Link failed. Source or/and destination thread not found.";
const wchar_t* ErrorDeleteCombo=L"Error delete from combo.";

//window.cpp
const wchar_t* ClassName=L"NextHooker";
const wchar_t* ClassNameAdmin=L"NextHooker (Administrator)";
const wchar_t* ErrorNotSplit=L"Need to enable split first!";
const wchar_t* ErrorNotModule=L"Need to enable module first!";
//Main window buttons
const wchar_t* ButtonTitleProcess=L"Process";
const wchar_t* ButtonTitleThread=L"Thread";
const wchar_t* ButtonTitleHook=L"Hook";
const wchar_t* ButtonTitleProfile=L"Profile";
const wchar_t* ButtonTitleOption=L"Option";
const wchar_t* ButtonTitleClear=L"Clear";
const wchar_t* ButtonTitleSave=L"Save";
const wchar_t* ButtonTitleTop=L"Top";
//Hook window
const wchar_t* SpecialHook=L"Special hook, no AGTH equivalent.";
//Process window
const wchar_t* TabTitlePID=L"PID";
const wchar_t* TabTitleMemory=L"Memory";
const wchar_t* TabTitleName=L"Name";
const wchar_t* TabTitleTID=L"TID";
const wchar_t* TabTitleStart=L"Start";
const wchar_t* TabTitleModule=L"Module";
const wchar_t* TabTitleState=L"State";
const wchar_t* SuccessAttach=L"Attach ITH to process successfully.";
const wchar_t* FailAttach=L"Failed to attach ITH to process.";
const wchar_t* SuccessDetach=L"ITH detach from process.";
const wchar_t* FailDetach=L"Detach failed.";
//Profile window
const wchar_t* ProfileExist=L"Profile already exists.";
const wchar_t* SuccessAddProfile=L"Profile added.";
const wchar_t* FailAddProfile=L"Fail to add profile";
const wchar_t* TabTitleNumber=L"No.";
const wchar_t* NoFile=L"Can't find file.";
const wchar_t* PathDismatch=L"Process name dismatch, continue?";
const wchar_t* SuccessImportProfile=L"Import profile success";
//const wchar_t* SuccessAddProfile=L"Profile added.";