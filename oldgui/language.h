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
#pragma once

extern const wchar_t* Warning;
//command.cpp
extern const wchar_t* ErrorSyntax;
extern const wchar_t* Usage;
extern const wchar_t* ExtendedUsage;
//inject.cpp
extern const wchar_t* ErrorRemoteThread;
extern const wchar_t* ErrorOpenProcess;
extern const wchar_t* ErrorNoProcess;
extern const wchar_t* SelfAttach;
extern const wchar_t* AlreadyAttach;
extern const wchar_t* FormatInject;
//main.cpp
extern const wchar_t* NotAdmin;
//pipe.cpp
extern const wchar_t* ErrorCreatePipe;
extern const wchar_t* FormatDetach;
extern const wchar_t* ErrorCmdQueueFull;
extern const wchar_t* ErrorNoAttach;

//profile.cpp
extern const wchar_t* ErrorMonitor;

//utility.cpp
extern const wchar_t* InitMessage;
extern const wchar_t* BackgroundMsg;
extern const wchar_t* ErrorLinkExist;
extern const wchar_t* ErrorCylicLink;
extern const wchar_t* FormatLink;
extern const wchar_t* ErrorLink;
extern const wchar_t* ErrorDeleteCombo;

//window.cpp
extern const wchar_t* ClassName;
extern const wchar_t* ClassNameAdmin;
extern const wchar_t* ErrorNotSplit;
extern const wchar_t* ErrorNotModule;
//Main window buttons
extern const wchar_t* ButtonTitleProcess;
extern const wchar_t* ButtonTitleThread;
extern const wchar_t* ButtonTitleHook;
extern const wchar_t* ButtonTitleProfile;
extern const wchar_t* ButtonTitleOption;
extern const wchar_t* ButtonTitleClear;
extern const wchar_t* ButtonTitleSave;
extern const wchar_t* ButtonTitleTop;
//Hook window
extern const wchar_t* SpecialHook;
//Process window
extern const wchar_t* TabTitlePID;
extern const wchar_t* TabTitleMemory;
extern const wchar_t* TabTitleName;
extern const wchar_t* TabTitleTID;
extern const wchar_t* TabTitleStart;
extern const wchar_t* TabTitleModule;
extern const wchar_t* TabTitleState;
extern const wchar_t* SuccessAttach;
extern const wchar_t* FailAttach;
extern const wchar_t* SuccessDetach;
extern const wchar_t* FailDetach;
//Profile window
extern const wchar_t* ProfileExist;
extern const wchar_t* SuccessAddProfile;
extern const wchar_t* FailAddProfile;
extern const wchar_t* TabTitleNumber;
extern const wchar_t* NoFile;
extern const wchar_t* PathDismatch;
extern const wchar_t* SuccessImportProfile;