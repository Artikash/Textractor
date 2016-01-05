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
const wchar_t* Warning = L"경고!";
//command.cpp
const wchar_t* ErrorSyntax = L"명령어 오류";
const wchar_t* Usage = L"명령어:\r\n\
\r\n\
도움말 //도움말을 출력합니다\r\n\
출발 도착 // '출발'스레드에서 '도착'스레드로 연결합니다\r\n\
ㅎ출발 // '출발'스레드에 연결된 링크를 해제합니다\r\n\
\r\n\
'출발'과 '도착'에는 16진법(헥사코드) 스레드번호를 입력합니다. 스레드 번호는 맨 앞에 있는 첫 번째 숫자열입니다.\r\n\
\r\n\
로더 옵션:\r\n\
/P[{process_id|Nprocess_name}] //프로세스에 부착\r\n\
\r\n\
H코드 후킹 옵션:\r\n\
/H[X]{A|B|W|S|Q}[N][data_offset[*drdo]][:sub_offset[*drso]]@addr[:module[:{name|#ordinal}]]\r\n\
\r\n\
(서수를 제외한) /H코드의 모든 숫자는 아무것도 처리되지 않은 16진법(헥사코드)입니다";

const wchar_t* ExtendedUsage = L"/H[X]{A|B|W|S|Q}[N][data_offset[*drdo]][:sub_offset[*drso]]@addr[:[module[:{name|#ordinal}]]]\r\n\
\r\n\
추가 사용자정의 후킹설정\r\n\
\r\n\
후킹 종류 :\r\n\
A - DBCS 문자\r\n\
B - DBCS 문자(big-endian)\r\n\
W - UCS2 문자\r\n\
S - MBCS 문자열\r\n\
Q - UTF-16 문자열\r\n\
\r\n\
매개변수:\r\n\
X - 하드웨어 구획점 사용\r\n\
N - 문법을 사용하지 않음\r\n\
data_offset - stack offset to char / string pointer\r\n\
drdo - add a level of indirection to data_offset\r\n\
sub_offset - stack offset to subcontext\r\n\
drso - add a level of indirection to sub_offset\r\n\
addr - 후킹할 주소\r\n\
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
const wchar_t* ErrorRemoteThread = L"원격 스레드를 생성할 수 없음.";
const wchar_t* ErrorOpenProcess = L"프로세스를 열 수 없음.";
const wchar_t* ErrorNoProcess = L"프로세스를 찾을 수 없음";
const wchar_t* SelfAttach = L"ITH.exe에 부착하지 말아 주세요";
const wchar_t* AlreadyAttach = L"프로세스가 이미 부착됨.";
const wchar_t* FormatInject = L"프로세스 %d에 인젝션. 모듈 기반 %.8X";
//main.cpp
const wchar_t* NotAdmin = L"SeDebugPrevilege을 활성화 할 수 없습니다. ITH가 제대로 작동하지 못합니다.\r\n\
관리자 계정으로 실행하시거나 UAC를 끄시고 ITH를 실행해 주세요.";
//pipe.cpp
const wchar_t* ErrorCreatePipe = L"텍스트 파이프를 생성할 수 없거나, 요청이 너무 많습니다.";
const wchar_t* FormatDetach = L"프로세스 %d가 탈착됨.";
const wchar_t* ErrorCmdQueueFull = L"명령어 대기열이 가득참.";
const wchar_t* ErrorNoAttach = L"프로세스가 부착되지 않음.";

//profile.cpp
const wchar_t* ErrorMonitor = L"프로세스를 감시할 수 없음.";
//utility.cpp
const wchar_t* InitMessage = L"Copyright (C) 2010-2012  kaosu <qiupf2000@gmail.com>\r\n\
Copyright (C) 2015 zorkzero <zorkzero@hotmail.com>\r\n\
소스코드 <https://code.google.com/p/interactive-text-hooker/>\r\n\
일반토론 <https://groups.google.com/forum/?fromgroups#!forum/interactive-text-hooker>\r\n\
한글화 @mireado<https://twitter.com/mireado>";
const wchar_t* BackgroundMsg = L"도움말을 보시려면, \"help\", \"도움말\"이나 \"도움\"을 입력하세요.";
const wchar_t* ErrorLinkExist = L"연결이 존재함.";
const wchar_t* ErrorCylicLink = L"연결실패. 순환연결은 허용되지 않습니다.";
const wchar_t* FormatLink = L"출발스레드%.4x에서 도착스레드%.4x로 연결.";
const wchar_t* ErrorLink = L"연결실패. 출발/도착 스레드를 찾을 수 없음.";
const wchar_t* ErrorDeleteCombo = L"글상자에서 지우기 실패.";

//window.cpp
const wchar_t* ClassName = L"ITH";
const wchar_t* ClassNameAdmin = L"ITH (관리자)";
const wchar_t* ErrorNotSplit = L"먼저 문단 나누기를 활성화해주세요!";
const wchar_t* ErrorNotModule = L"먼저 모듈을 활성화해주세요!";
//Main window buttons
const wchar_t* ButtonTitleProcess = L"프로세스";
const wchar_t* ButtonTitleThread = L"스레드";
const wchar_t* ButtonTitleHook = L"후킹";
const wchar_t* ButtonTitleProfile = L"프로필";
const wchar_t* ButtonTitleOption = L"옵션";
const wchar_t* ButtonTitleClear = L"지우기";
const wchar_t* ButtonTitleSave = L"저장";
const wchar_t* ButtonTitleTop = L"항상위";
//Hook window
const wchar_t* SpecialHook = L"H코드 후킹, AGTH 코드는 지원하지 않습니다.";
//Process window
const wchar_t* TabTitlePID = L"PID";
const wchar_t* TabTitleMemory = L"메모리";
const wchar_t* TabTitleName = L"이름";
const wchar_t* TabTitleTID = L"TID";
const wchar_t* TabTitleStart = L"시작";
const wchar_t* TabTitleModule = L"모듈";
const wchar_t* TabTitleState = L"상태";
const wchar_t* SuccessAttach = L"프로세스에 ITH 부착성공.";
const wchar_t* FailAttach = L"프로세스에 ITH 부착실패.";
const wchar_t* SuccessDetach = L"프로세스에서 ITH 탈착성공.";
const wchar_t* FailDetach = L"ITH 탈착실패.";
//Profile window
const wchar_t* ProfileExist = L"프로필이 이미 존재함.";
const wchar_t* SuccessAddProfile = L"프로필 추가됨.";
const wchar_t* FailAddProfile = L"프로필 추가실패";
const wchar_t* TabTitleNumber = L"No.";
const wchar_t* NoFile = L"파일을 찾을 수 없음.";
const wchar_t* PathDismatch = L"프로세스 이름이 일치하지 않습니다, 계속하시겠습니까?";
const wchar_t* SuccessImportProfile = L"프로필 가져오기 성공";
//const wchar_t* SuccessAddProfile=L"Profile added.";