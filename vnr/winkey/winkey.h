#pragma once

// winkey.h
// 7/21/2011

#include <windows.h>

#ifndef WINKEY_BEGIN_NAMESPACE
# define WINKEY_BEGIN_NAMESPACE namespace WinKey {
#endif
#ifndef WINKEY_END_NAMESPACE
# define WINKEY_END_NAMESPACE } // namespace WinKey
#endif


WINKEY_BEGIN_NAMESPACE

inline bool isKeyPressed(int vk) { return ::GetKeyState(vk) & 0xf0; }
inline bool isKeyToggled(int vk) { return ::GetKeyState(vk) & 0x0f; }

inline bool isKeyReturnPressed() { return isKeyPressed(VK_RETURN); }
inline bool isKeyControlPressed() { return isKeyPressed(VK_CONTROL); }
inline bool isKeyShiftPressed() { return isKeyPressed(VK_SHIFT); }
inline bool isKeyAltPressed() { return isKeyPressed(VK_MENU); }
//inline bool sKeyCapslockToggled() { return isKeyToggled(VK_CAPITAL); }
inline bool isKeyWinPressed() { return isKeyPressed(VK_LWIN) || isKeyPressed(VK_RWIN); }

inline bool isMouseLeftButtonPressed() { return isKeyPressed(VK_LBUTTON); }
inline bool isMouseMiddleButtonPressed() { return isKeyPressed(VK_MBUTTON); }
inline bool isMouseRightButtonPressed() { return isKeyPressed(VK_RBUTTON); }

WINKEY_END_NAMESPACE
