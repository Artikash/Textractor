// match.cc
// 8/9/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "src/engine/match.h"
#include "src/engine/engine.h"
#include "src/engine/pchooks.h"
#include "src/util/growl.h"
#include "src/util/util.h"
#include "src/main.h"
#include "src/except.h"
#include "ithsys/ithsys.h"
#include "ccutil/ccmacro.h"

//#define ConsoleOutput(...)  (void)0     // jichi 8/18/2013: I don't need ConsoleOutput

enum { MAX_REL_ADDR = 0x200000 }; // jichi 8/18/2013: maximum relative address

// - Global variables -

namespace Engine {

WCHAR process_name_[MAX_PATH], // cached
      process_path_[MAX_PATH]; // cached

DWORD module_base_,
      module_limit_;

//LPVOID trigger_addr;
trigger_fun_t trigger_fun_;

} // namespace Engine

// - Methods -

namespace Engine { namespace { // unnamed

bool DetermineGameHooks() // 7/19/2015
{
#if 0 // jichi 7/19/2015: Disabled as it will crash the game
  if (IthFindFile(L"UE3ShaderCompileWorker.exe") && IthFindFile(L"awesomium_process.exe")) {
    InsertLovaGameHook();
    return true;
  }
#endif // 0
  return false;
}

// jichi 7/17/2014: Disable GDI hooks for PPSSPP
bool DeterminePCEngine()
{
  if (DetermineGameHooks()) {
    ConsoleOutput("vnreng: found game-specific hook");
    return true;
  }

  if (IthFindFile(L"PPSSPP*.exe")) { // jichi 7/12/2014 PPSSPPWindows.exe, PPSSPPEX.exe PPSSPPSP.exe
    InsertPPSSPPHooks();
    return true;
  }

  if (IthFindFile(L"pcsx2*.exe")) { // jichi 7/19/2014 PCSX2.exe or PCSX2WX.exe
    InsertPCSX2Hooks();
    return true;
  }

  if (IthFindFile(L"Dolphin.exe")) { // jichi 7/20/2014
    InsertGCHooks();
    return true;
  }

  // jichi 5/14/2015: Skip hijacking BALDRSKY ZEROs
  if (IthCheckFile(L"bsz_Data\\Mono\\mono.dll") || IthCheckFile(L"bsz2_Data\\Mono\\mono.dll")) {
    ConsoleOutput("vnreng: IGNORE BALDRSKY ZEROs");
    return true;
  }
  if (::GetModuleHandleA("mono.dll")) {
    InsertMonoHooks();

    // 3/20/2015 jichi
    // Always insert GDI hooks even for Mono games
    // For example: 新世黙示録 need GetGlyphOutlineA
    PcHooks::hookGDIFunctions();
    return true;
  }

  // PC games
  PcHooks::hookGDIFunctions();
  EnableGDIPlusHooks();
  return false;
}

bool DetermineEngineByFile1()
{
  if (IthFindFile(L"*.xp3") || Util::SearchResourceString(L"TVP(KIRIKIRI)")) {
    if (Util::SearchResourceString(L"TVP(KIRIKIRI) Z ")) { // TVP(KIRIKIRI) Z CORE
      // jichi 11/24/2014: Disabled that might crash VBH
      //if (IthCheckFile(L"plugin\\KAGParser.dll"))
      //  InsertKAGParserHook();
      //else if (IthCheckFile(L"plugin\\KAGParserEx.dll"))
      //  InsertKAGParserExHook();
      if (InsertKiriKiriZHook())
        return true;
    }
    InsertKiriKiriHook();
    return true;
  }
  // 8/2/2014 jichi: Game name shown as 2RM - Adventure Engine, text also in GetGlyphOutlineA
  if (Util::SearchResourceString(L"2RM") && Util::SearchResourceString(L"Adventure Engine")) {
    Insert2RMHook();
    return true;
  }
  // 8/2/2014 jichi: Copyright is side-B, a conf.dat will be generated after the game is launched
  // It also contains lua5.1.dll and lua5.dll
  if (Util::SearchResourceString(L"side-B")) {
    InsertSideBHook();
    return true;
  }
  if (IthFindFile(L"bgi.*") || IthFindFile(L"BHVC.exe") || IthFindFile(L"sysgrp.arc")) {
    InsertBGIHook();
    return true;
  }
  if (IthCheckFile(L"Bootup.dat") && InsertBootupHook()) // 5/22/2015 Bootup
    // lstrlenW can also find text with repetition though
    return true;
  if (IthCheckFile(L"AGERC.DLL")) { // 6/1/2014 jichi: Eushully, AGE.EXE
    InsertEushullyHook();
    return true;
  }
  if (IthFindFile(L"data*.arc") && IthFindFile(L"stream*.arc")) {
    InsertMajiroHook();
    return true;
  }
  // jichi 5/31/2014
  if (//IthCheckFile(L"Silkys.exe") ||    // It might or might not have Silkys.exe
      // data, effect, layer, mes, music
      IthCheckFile(L"data.arc") && IthCheckFile(L"effect.arc") && IthCheckFile(L"mes.arc")) {
    InsertElfHook();
    return true;
  }
  // jichi 6/9/2015: Skip Silkys Sakura
  if ( // Almost the same as Silkys except mes.arc is replaced by Script.arc
      IthCheckFile(L"data.arc") && IthCheckFile(L"effect.arc") && IthCheckFile(L"Script.arc")) {
    InsertSilkysHook();
    return true;
  }
  if (IthFindFile(L"data\\pack\\*.cpz")) {
    InsertCMVSHook();
    return true;
  }
  // jichi 10/12/2013: Restore wolf engine
  // jichi 10/18/2013: Check for data/*.wolf
  if (IthFindFile(L"data.wolf") || IthFindFile(L"data\\*.wolf")) {
    InsertWolfHook();
    return true;
  }
  if (IthCheckFile(L"AdvData\\DAT\\NAMES.DAT")) {
    InsertCircusHook1();
    return true;
  }
  if (IthCheckFile(L"AdvData\\GRP\\NAMES.DAT")) {
    InsertCircusHook2();
    return true;
  }
  if (IthFindFile(L"*.noa") || IthFindFile(L"data\\*.noa")) {
    InsertCotophaHook();
    return true;
  }
  if (IthFindFile(L"*.pfs")) { // jichi 10/1/2013
    InsertArtemisHook();
    return true;
  }
  if (IthFindFile(L"*.int")) {
    InsertCatSystemHook();
    return true;
  }
  if (IthCheckFile(L"message.dat")) {
    InsertAtelierHook();
    return true;
  }
  if (IthCheckFile(L"Check.mdx")) { // jichi 4/1/2014: AUGame
    InsertTencoHook();
    return true;
  }
  // jichi 12/25/2013: It may or may not be QLIE.
  // AlterEgo also has GameData/sound.pack but is not QLIE
  if (IthFindFile(L"GameData\\*.pack") && InsertQLIEHook())
    return true;

  if (IthCheckFile(L"dll\\Pal.dll")) {
    InsertPalHook();
    return true;
  }

  if (IthFindFile(L"*.pac")) {
    // jichi 6/3/2014: AMUSE CRAFT and SOFTPAL
    // Selectively insert, so that lstrlenA can still get correct text if failed
    //if (IthCheckFile(L"dll\\resource.dll") && IthCheckFile(L"dll\\pal.dll") && InsertAmuseCraftHook())
    //  return true;

    if (IthCheckFile(L"Thumbnail.pac")) {
      //ConsoleOutput("vnreng: IGNORE NeXAS");
      InsertNeXASHook(); // jichi 7/6/2014: GIGA
      return true;
    }

    if (Util::SearchResourceString(L"SOFTPAL")) {
      ConsoleOutput("vnreng: IGNORE SoftPal UNiSONSHIFT");
      return true;
    }
  }
  // jichi 12/27/2014: LunaSoft
  if (IthFindFile(L"Pac\\*.pac")) {
    InsertLunaSoftHook();
    return true;
  }
  // jichi 9/16/2013: Add Gesen18
  if (IthFindFile(L"*.szs") || IthFindFile(L"Data\\*.szs")) {
    InsertUnicornHook();
    return true;
  }
  // jichi 12/22/2013: Add rejet
  if (IthCheckFile(L"gd.dat") && IthCheckFile(L"pf.dat") && IthCheckFile(L"sd.dat")) {
    InsertRejetHook();
    return true;
  }
  // Only examined with version 1.0
  //if (IthFindFile(L"Adobe AIR\\Versions\\*\\Adobe AIR.dll")) { // jichi 4/15/2014: FIXME: Wildcard not working
  if (IthCheckFile(L"Adobe AIR\\Versions\\1.0\\Adobe AIR.dll")) { // jichi 4/15/2014: Adobe AIR
    InsertAdobeAirHook();
    return true;
  }
  return false;
}

bool DetermineEngineByFile2()
{
  if (IthCheckFile(L"resident.dll")) {
    InsertRetouchHook();
    return true;
  }
  if (IthCheckFile(L"Malie.ini") || IthCheckFile(L"Malie.exe")) { // jichi: 9/9/2014: Add malie.exe in case malie.ini is missing
    InsertMalieHook();
    return true;
  }
  if (IthCheckFile(L"live.dll")) {
    InsertLiveHook();
    return true;
  }
  // 9/5/2013 jichi
  if (IthCheckFile(L"aInfo.db")) {
    InsertNextonHook();
    return true;
  }
  if (IthFindFile(L"*.lpk")) {
    InsertLucifenHook();
    return true;
  }
  if (IthCheckFile(L"cfg.pak")) {
    InsertWaffleHook();
    return true;
  }
  if (IthCheckFile(L"Arc00.dat")) {
    InsertTinkerBellHook();
    return true;
  }
  if (IthFindFile(L"*.vfs")) { // jichi 7/6/2014: Better to test AoiLib.dll? ja.wikipedia.org/wiki/ソフトハウスキャラ
    InsertSystemAoiHook();
    return true;
  }
  if (IthFindFile(L"*.mbl")) {
    InsertMBLHook();
    return true;
  }
  // jichi 8/1/2014: YU-RIS engine, lots of clockup game also has this pattern
  if (IthFindFile(L"pac\\*.ypf") || IthFindFile(L"*.ypf")) {
    // jichi 8/14/2013: CLOCLUP: "ノーブレスオブリージュ" would crash the game.
    if (!IthCheckFile(L"noblesse.exe"))
      InsertYurisHook();
    return true;
  }
  if (IthFindFile(L"*.npa")) {
    InsertNitroplusHook();
    return true;
  }
  return false;
}

bool DetermineEngineByFile3()
{
  //if (IthCheckFile(L"libscr.dll")) { // already checked
  //  InsertBrunsHook();
  //  return true;
  //}

  // jichi 10/12/2013: Sample args.txt:
  // See: http://tieba.baidu.com/p/2631413816
  // -workdir
  // .
  // -loadpath
  // .
  // am.cfg
  if (IthCheckFile(L"args.txt")) {
    InsertBrunsHook();
    return true;
  }
  if (IthCheckFile(L"emecfg.ecf")) {
    InsertEMEHook();
    return true;
  }
  if (IthCheckFile(L"rrecfg.rcf")) {
    InsertRREHook();
    return true;
  }
  if (IthFindFile(L"*.fpk") || IthFindFile(L"data\\*.fpk")) {
    InsertCandyHook();
    return true;
  }
  if (IthFindFile(L"arc.a*")) {
    InsertApricoTHook();
    return true;
  }
  if (IthFindFile(L"*.mpk")) {
    InsertStuffScriptHook();
    return true;
  }
  if (IthCheckFile(L"Execle.exe")) {
    InsertTriangleHook();
    return true;
  }
  // jichi 2/28/2015: No longer work for "大正×対称アリス episode I" from Primula
  //if (IthCheckFile(L"PSetup.exe")) {
  //  InsertPensilHook();
  //  return true;
  //}
  if (IthCheckFile(L"Yanesdk.dll")) {
    InsertAB2TryHook();
    return true;
  }
  if (IthFindFile(L"*.med")) {
    InsertMEDHook();
    return true;
  }
  return false;
}

bool DetermineEngineByFile4()
{
  if (IthCheckFile(L"EAGLS.dll")) { // jichi 3/24/2014: E.A.G.L.S
    //ConsoleOutput("vnreng: IGNORE EAGLS");
    InsertEaglsHook();
    return true;
  }
  if (IthCheckFile(L"bmp.pak") && IthCheckFile(L"dsetup.dll")) {
    // 1/1/2016 jich: skip izumo4 from studio ego that is not supported by debonosu
    if (IthFindFile(L"*izumo4*.exe")) {
      PcHooks::hookLstrFunctions();
      return true;
    }
    InsertDebonosuHook();
    return true;
  }
  if (IthCheckFile(L"C4.EXE") || IthCheckFile(L"XEX.EXE")) {
    InsertC4Hook();
    return true;
  }
  if (IthCheckFile(L"Rio.arc") && IthFindFile(L"Chip*.arc")) {
    InsertWillPlusHook();
    return true;
  }
  if (IthFindFile(L"*.tac")) {
    InsertTanukiHook();
    return true;
  }
  if (IthFindFile(L"*.gxp")) {
    InsertGXPHook();
    return true;
  }
  if (IthFindFile(L"*.aos")) { // jichi 4/2/2014: AOS hook
    InsertAOSHook();
    return true;
  }
  if (IthFindFile(L"*.at2")) { // jichi 12/23/2014: Mink, sample files: voice.at2, voice.det, voice.nme
    InsertMinkHook();
    return true;
  }
  if (IthFindFile(L"*.ykc")) { // jichi 7/15/2014: YukaSystem1 is not supported, though
    //ConsoleOutput("vnreng: IGNORE YKC:Feng/HookSoft(SMEE)");
    InsertYukaSystem2Hook();
    return true;
  }
  if (IthFindFile(L"model\\*.hed")) { // jichi 9/8/2014: EXP
    InsertExpHook();
    return true;
  }
  // jichi 2/6/2015 平安亭
  // dPi.dat, dPih.dat, dSc.dat, dSch.dat, dSo.dat, dSoh.dat, dSy.dat
  //if (IthCheckFile(L"dSoh.dat")) { // no idea why this file does not work
  if (IthCheckFile(L"dSch.dat")) {
    InsertSyuntadaHook();
    return true;
  }

  // jichi 2/28/2015: Delay checking Pensil in case something went wrong
  // File pattern observed in [Primula] 大正×対称アリス episode I
  // - PSetup.exe no longer exists
  // - MovieTexture.dll information shows MovieTex dynamic library, copyright Pensil 2013
  // - ta_trial.exe information shows 2XT - Primula Adventure Engine
  if (IthCheckFile(L"PSetup.exe") || IthFindFile(L"PENCIL.*") || Util::SearchResourceString(L"2XT -")) {
    InsertPensilHook();
    return true;
  }
  return false;
}

bool DetermineEngineByProcessName()
{
  WCHAR str[MAX_PATH];
  wcscpy(str, process_name_);
  _wcslwr(str); // lower case

  if (wcsstr(str,L"reallive") || IthCheckFile(L"Reallive.exe") || IthCheckFile(L"REALLIVEDATA\\Start.ini")) {
    InsertRealliveHook();
    return true;
  }

  // jichi 8/19/2013: DO NOT WORK for games like「ハピメア」
  //if (wcsstr(str,L"cmvs32") || wcsstr(str,L"cmvs64")) {
  //  InsertCMVSHook();
  //  return true;
  //}

  // jichi 8/17/2013: Handle "~"
  if (wcsstr(str, L"siglusengine") || !wcsncmp(str, L"siglus~", 7) || IthCheckFile(L"SiglusEngine.exe")) {
    InsertSiglusHook();
    return true;
  }

  if (wcsstr(str, L"taskforce2") || !wcsncmp(str, L"taskfo~", 7) || IthCheckFile(L"Taskforce2.exe")) {
    InsertTaskforce2Hook();
    return true;
  }

  if (wcsstr(str,L"rugp") || IthCheckFile(L"rugp.exe")) {
    InsertRUGPHook();
    return true;
  }

  // jichi 8/17/2013: Handle "~"
  if (wcsstr(str, L"igs_sample") || !wcsncmp(str, L"igs_sa~", 7) || IthCheckFile(L"igs_sample.exe")) {
    InsertIronGameSystemHook();
    return true;
  }

  if (wcsstr(str, L"bruns") || IthCheckFile(L"bruns.exe")) {
    InsertBrunsHook();
    return true;
  }

  if (wcsstr(str, L"anex86") || IthCheckFile(L"anex86.exe")) {
    InsertAnex86Hook();
    return true;
  }

  // jichi 8/17/2013: Handle "~"
  if (wcsstr(str, L"shinydays") || !wcsncmp(str, L"shinyd~", 7) || IthCheckFile(L"ShinyDays.exe")) {
    InsertShinyDaysGameHook();
    return true;
  }

  // jichi 10/3/2013: FIXME: Does not work
  // Raise C0000005 even with admin priv
  //if (wcsstr(str, L"bsz")) { // BALDRSKY ZERO
  //  InsertBaldrHook();
  //  return true;
  //}

  if (wcsstr(process_name_, L"SAISYS") || IthCheckFile(L"SaiSys.exe")) { // jichi 4/19/2014: Marine Heart
    InsertMarineHeartHook();
    return true;
  }

  DWORD len = wcslen(str);

  // jichi 8/24/2013: Checking for Rio.ini or $procname.ini
  //wcscpy(str+len-4, L"_?.war");
  //if (IthFindFile(str)) {
  //  InsertShinaHook();
  //  return true;
  //}
  if (InsertShinaHook())
    return true;

  // jichi 8/10/2013: Since *.bin is common, move CaramelBox to the end
  str[len - 3] = L'b';
  str[len - 2] = L'i';
  str[len - 1] = L'n';
  str[len] = 0;
  if ((IthCheckFile(str) || IthCheckFile(L"trial.bin")) // jichi 7/8/2014: add trial.bin
      && InsertCaramelBoxHook())
    return true;

  // jichi 7/23/2015  It also has gameexe.bin existed
  if (IthCheckFile(L"configure.cfg") && IthCheckFile(L"gfx.bin")) {
    InsertEscudeHook();
    return true;
  }

  // This must appear at last since str is modified
  wcscpy(str + len - 4, L"_checksum.exe");
  if (IthCheckFile(str)) {
    InsertRyokuchaHook();

    if (IthFindFile(L"*.iar") && IthFindFile(L"*.sec5")) // jichi 9/27/2014: For new Ryokucha games
      InsertScenarioPlayerHook();
    return true;
  }

  return false;
}

bool DetermineEngineOther()
{
  if (InsertAliceHook())
    return true;
  // jichi 1/19/2015: Disable inserting Lstr for System40
  // See: http://sakuradite.com/topic/618
  if (IthCheckFile(L"System40.ini")) {
    ConsoleOutput("vnreng: IGNORE old System40.ini");
    return true;
  }
  // jichi 12/26/2013: Add this after alicehook
  if (IthCheckFile(L"AliceStart.ini")) {
    InsertSystem43Hook();
    return true;
  }

  // jichi 8/24/2013: Move into functions
  static BYTE static_file_info[0x1000];
  if (IthGetFileInfo(L"*01", static_file_info))
    if (*(DWORD*)static_file_info == 0) {
      STATUS_INFO_LENGTH_MISMATCH;
      static WCHAR static_search_name[MAX_PATH];
      LPWSTR name=(LPWSTR)(static_file_info+0x5E);
      int len = wcslen(name);
      name[len-2] = L'.';
      name[len-1] = L'e';
      name[len] = L'x';
      name[len+1] = L'e';
      name[len+2] = 0;
      if (IthCheckFile(name)) {
        name[len-2] = L'*';
        name[len-1] = 0;
        wcscpy(static_search_name,name);
        IthGetFileInfo(static_search_name,static_file_info);
        union {
          FILE_BOTH_DIR_INFORMATION *both_info;
          DWORD addr;
        };
        both_info = (FILE_BOTH_DIR_INFORMATION *)static_file_info;
        //BYTE* ptr=static_file_info;
        len=0;
        while (both_info->NextEntryOffset) {
          addr += both_info->NextEntryOffset;
          len++;
        }
        if (len > 3) {
          InsertAbelHook();
          return true;
        }
      }
    }

  return false;
}

// jichi 8/17/2014
// Put the patterns that might break other games at last
bool DetermineEngineAtLast()
{
  if (IthCheckFile(L"MovieTexture.dll") && (InsertPensilHook() || Insert2RMHook())) // MovieTexture.dll also exists in 2RM games such as 母子愛2体験版, which is checked first
    return true;
  if (IthFindFile(L"system") && IthFindFile(L"system.dat")) { // jichi 7/31/2015
    InsertAbelHook();
    return true;
  }
  if (IthFindFile(L"data\\*.cpk")) { // jichi 12/2/2014
    Insert5pbHook();
    return true;
  }
  // jichi 7/6/2014: named as ScenarioPlayer since resource string could be: scenario player program for xxx
  // Do this at last as it is common
  if (IthFindFile(L"*.iar") && IthFindFile(L"*.sec5")) { // jichi 4/18/2014: Other game engine could also have *.iar such as Ryokucha
    InsertScenarioPlayerHook();
    return true;
  }
  //if (IthCheckFile(L"arc0.dat") && IthCheckFile(L"script.dat") // jichi 11/14/2014: too common
  if (Util::SearchResourceString(L"HorkEye")) { // appear in copyright: Copyright (C) HorkEye, http://horkeye.com
    InsertHorkEyeHook();
    return true;
  }
  if (IthCheckFile(L"comnArc.arc") // jichi 8/17/2014: this file might exist in multiple files
      && InsertNexton1Hook()) // old nexton game
    return true;
  if (IthCheckFile(L"arc.dat") // jichi 9/27/2014: too common
      && InsertApricoTHook())
    return true;
  if (IthFindFile(L"*.pak") // jichi 12/25/2014: too common
      && InsertLeafHook())
    return true;
  // jichi 10/31/2014
  // File description: Adobe Flash Player 10.2r153
  // Product name: Shockwave Flash
  // Original filename: SAFlashPlayer.exe
  // Legal trademarks: Adobe Flash Player
  // No idea why, this must appear at last or it will crash
  if (Util::SearchResourceString(L"Adobe Flash Player 10")) {
    InsertAdobeFlash10Hook(); // only v10 might be supported. Otherwise, fallback to Lstr hooks
    return true;
  }
  if (IthFindFile(L"dat\\*.arc")) { // jichi 2/6/2015
    InsertFocasLensHook(); // Touhou
    return true;
  }

  // jichi 8/23/2015: Tamamo
  if (IthCheckFile(L"data.pck") && IthCheckFile(L"image.pck") && IthCheckFile(L"script.pck")) {
    //if (IthCheckFile(L"QtGui.dll"))
    InsertTamamoHook();
    return true;
  }

  return false;
}

// jichi 6/1/2014
bool DetermineEngineGeneric()
{
  bool ret = false;

  if (IthCheckFile(L"AlterEgo.exe")) {
    ConsoleOutput("vnreng: AlterEgo, INSERT WideChar hooks");
    ret = true;
  }  else if (IthFindFile(L"data\\Sky\\*")) {
    ConsoleOutput("vnreng: TEATIME, INSERT WideChar hooks");
    ret = true;
  }
  //}  else if (IthFindFile(L"image\\*.po2") || IthFindFile(L"image\\*.jo2")) {
  //  ConsoleOutput("vnreng: HarukaKanata, INSERT WideChar hooks"); // はるかかなた
  //  ret = true;
  //}
  if (ret)
    PcHooks::hookWcharFunctions();
  return ret;
}

bool DetermineNoEngine()
{
  //if (IthFindFile(L"*\\Managed\\UnityEngine.dll")) { // jichi 12/3/2013: Unity (BALDRSKY ZERO)
  //  ConsoleOutput("vnreng: IGNORE Unity");
  //  return true;
  //}
  //if (IthCheckFile(L"bsz_Data\\Managed\\UnityEngine.dll") || IthCheckFile(L"bsz2_Data\\Managed\\UnityEngine.dll")) {
  //  ConsoleOutput("vnreng: IGNORE Unity");
  //  return true;
  //}

  // jichi 6/7/2015: RPGMaker v3
  if (IthFindFile(L"*.rgss3a")) {
    ConsoleOutput("vnreng: IGNORE RPGMaker RGSS3");
    return true;
  }

  // jichi 11/22/2015: 凍京NECRO 体験版
  if (IthFindFile(L"*.npk")) {
    ConsoleOutput("vnreng: IGNORE new Nitroplus");
    return true;
  }

  // 8/29/2015 jichi: minori, text in GetGlyphOutlineA
  if (IthFindFile(L"*.paz")) {
    ConsoleOutput("vnreng: IGNORE minori");
    return true;
  }

  // 7/28/2015 jichi: Favorite games
  if (IthFindFile(L"*.hcb")) {
    ConsoleOutput("vnreng: IGNORE FVP");
    return true;
  }

  // jichi 2/14/2015: Guilty+ ＲＩＮ×ＳＥＮ (PK)
  if (IthCheckFile(L"rio.ini") || IthFindFile(L"*.war")) {
    ConsoleOutput("vnreng: IGNORE unknown ShinaRio");
    return true;
  }

  if (IthCheckFile(L"AdvHD.exe") || IthCheckFile(L"AdvHD.dll")) {
    ConsoleOutput("vnreng: IGNORE Adv Player HD"); // supposed to be WillPlus
    return true;
  }

  if (IthCheckFile(L"ScrPlayer.exe")) {
    ConsoleOutput("vnreng: IGNORE ScrPlayer");
    return true;
  }

  if (IthCheckFile(L"nnnConfig2.exe")) {
    ConsoleOutput("vnreng: IGNORE Nya NNNConfig");
    return true;
  }

  // jichi 4/30/2015: Skip games made from らすこう, such as とある人妻のネトラレ事情
  // It has garbage from lstrlenW. Correct text is supposed to be in TabbedTextOutA.
  if (IthCheckFile(L"data_cg.dpm")) {
    ConsoleOutput("vnreng: IGNORE DPM data_cg.dpm");
    return true;
  }

  //if (IthCheckFile(L"AGERC.DLL")) { // jichi 3/17/2014: Eushully, AGE.EXE
  //  ConsoleOutput("vnreng: IGNORE Eushully");
  //  return true;
  //}

  if (IthCheckFile(L"game_sys.exe")) {
    ConsoleOutput("vnreng: IGNORE Atelier Kaguya BY/TH");
    return true;
  }

  if (IthFindFile(L"*.bsa")) {
    ConsoleOutput("vnreng: IGNORE Bishop");
    return true;
  }

  // jichi 3/19/2014: Escude game
  // Example: bgm.bin gfx.bin maou.bin script.bin snd.bin voc.bin
  if (IthCheckFile(L"gfx.bin") && IthCheckFile(L"snd.bin") && IthCheckFile(L"voc.bin")) {
    ConsoleOutput("vnreng: IGNORE Escude");
    return true;
  }

  // jichi 2/18/2015: Ignore if there is Nitro+ copyright
  if (Util::SearchResourceString(L"Nitro+")) {
    ConsoleOutput("vnreng: IGNORE unknown Nitro+");
    return true;
  }

  // jichi 12/28/2014: "Chartreux Inc." in Copyright.
  // Sublimary brands include Rosebleu, MORE, etc.
  // GetGlyphOutlineA already works.
  if (Util::SearchResourceString(L"Chartreux")) {
    ConsoleOutput("vnreng: IGNORE Chartreux");
    return true;
  }

  if (IthCheckFile(L"MovieTexture.dll")) {
    ConsoleOutput("vnreng: IGNORE MovieTexture");
    return true;
  }

  if (wcsstr(process_name_, L"lcsebody") || !wcsncmp(process_name_, L"lcsebo~", 7) || IthFindFile(L"lcsebody*")) { // jichi 3/19/2014: LC-ScriptEngine, GetGlyphOutlineA
    ConsoleOutput("vnreng: IGNORE lcsebody");
    return true;
  }

  wchar_t str[MAX_PATH];
  DWORD i;
  for (i = 0; process_name_[i]; i++) {
    str[i] = process_name_[i];
    if (process_name_[i] == L'.')
      break;
  }
  *(DWORD *)(str + i + 1) = 0x630068; //.hcb
  *(DWORD *)(str + i + 3) = 0x62;
  if (IthCheckFile(str)) {
    ConsoleOutput("vnreng: IGNORE FVP"); // jichi 10/3/2013: such like アトリエかぐや
    return true;
  }
  return false;
}

// 12/13/2013: Declare it in a way compatible to EXCEPTION_PROCEDURE
EXCEPTION_DISPOSITION ExceptHandler(PEXCEPTION_RECORD ExceptionRecord, LPVOID, PCONTEXT, LPVOID)
{
  if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
    module_limit_ = ExceptionRecord->ExceptionInformation[1];
    //OutputDWORD(module_limit_);
    __asm
    {
      mov eax,fs:[0x30] // jichi 12/13/2013: get PEB
      mov eax,[eax+0xc]
      mov eax,[eax+0xc]
      mov ecx,module_limit_
      sub ecx,module_base_
      mov [eax+0x20],ecx
    }
  }
  //ContextRecord->Esp = recv_esp;
  //ContextRecord->Eip = recv_eip;
  //return ExceptionContinueExecution; // jichi 3/11/2014: this will still crash. Not sure why ITH use this. Change to ExceptionContinueSearch
  return ExceptionContinueSearch; // an unwind is in progress,
}

// jichi 9/14/2013: Certain ITH functions like FindEntryAligned might raise exception without admin priv
// Return if succeeded.
bool UnsafeDetermineEngineType()
{
  return DeterminePCEngine()
    || DetermineEngineByFile1()
    || DetermineEngineByFile2()
    || DetermineEngineByFile3()
    || DetermineEngineByFile4()
    || DetermineEngineByProcessName()
    || DetermineEngineOther()
    || DetermineEngineAtLast()
    || DetermineEngineGeneric()
    || DetermineNoEngine()
  ;
}

// jichi 10/21/2014: Return whether found the game engine
bool DetermineEngineType()
{
  // jichi 9/27/2013: disable game engine for debugging use
#ifdef ITH_DISABLE_ENGINE
  PcHooks::hookLstrFunctions();
  PcHooks::hookCharNextFunctions();
  return false;
#else
  bool found = false;
#ifdef ITH_HAS_SEH
  __try { found = UnsafeDetermineEngineType(); }
  __except(ExceptHandler((GetExceptionInformation())->ExceptionRecord, 0, 0, 0)) {}
#else // use my own SEH
  seh_with_eh(ExceptHandler,
      found = UnsafeDetermineEngineType());
#endif // ITH_HAS_SEH
  if (::GDIPlusHooksEnabled())
    PcHooks::hookGDIPlusFunctions();
  if (!found) { // jichi 10/2/2013: Only enable it if no game engine is detected
    PcHooks::hookLstrFunctions();
    PcHooks::hookCharNextFunctions();
  } else
    ConsoleOutput("vnreng: found game engine, IGNORE non gui hooks");
  return found;
#endif // ITH_DISABLE_ENGINE
}

//  __asm
//  {
//    mov eax,seh_recover
//    mov recv_eip,eax
//    push ExceptHandler
//    push fs:[0]
//    mov fs:[0],esp
//    pushad
//    mov recv_esp,esp
//  }
//  DetermineEngineType();
//  status++;
//  __asm
//  {
//seh_recover:
//    popad
//    mov eax,[esp]
//    mov fs:[0],eax
//    add esp,8
//  }
//  if (status == 0)
//    ConsoleOutput("Fail to identify engine type.");
//  else
//    ConsoleOutput("Initialized successfully.");
//}
//

HANDLE hijackThread;
void hijackThreadProc(LPVOID lpThreadParameter)
{
  CC_UNUSED(lpThreadParameter);

  //static bool done = false;
  //if (done)
  //  return;
  //done = true;

  // jichi 12/18/2013: Though FillRange could raise, it should never raise for he current process
  // So, SEH is not used here.
  Util::GetProcessName(process_name_); // Initialize shared process name
  Util::GetProcessPath(process_path_); // Initialize shared process path

  FillRange(process_name_, &module_base_, &module_limit_);
  DetermineEngineType();
}

}} // namespace Engine unnamed

// - API -

DWORD Engine::InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{ return trigger_fun_ ? !trigger_fun_(addr, frame, stack) : 0; }

void Engine::hijack()
{
  if (!hijackThread) {
    ConsoleOutput("vnreng: hijack process");
    hijackThread = IthCreateThread(hijackThreadProc, 0);
  }
}

void Engine::terminate()
{
  if (hijackThread) {
    const LONGLONG timeout = -50000000; // in nanoseconds = 5 seconds
    NtWaitForSingleObject(hijackThread, 0, (PLARGE_INTEGER)&timeout);
    NtClose(hijackThread);
    hijackThread = 0;
  }
}

// EOF

/*
extern "C" {
  // http://gmogre3d.googlecode.com/svn-history/r815/trunk/OgreMain/src/WIN32/OgreMinGWSupport.cpp
  // http://forum.osdev.org/viewtopic.php?f=8&t=22352
  //#pragma data_seg()
  //#pragma comment(linker, "/merge:.CRT=.data") // works fine in visual c++ 6
  //#pragma data_seg()
  //#pragma comment(linker, "/merge:.CRT=.rdata")
    // MSVC libs use _chkstk for stack-probing. MinGW equivalent is _alloca.
  //void _alloca();
  //void _chkstk() { _alloca(); }

  // MSVC uses security cookies to prevent some buffer overflow attacks.
  // provide dummy implementations.
  //void _fastcall __security_check_cookie(intptr_t i) {}
  void __declspec(naked) __fastcall __security_check_cookie(UINT_PTR cookie) {}
}
*/
