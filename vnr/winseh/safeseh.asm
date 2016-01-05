; safeseh.asm
; 12/13/2013 jichi
; see: http://stackoverflow.com/questions/12019689/custom-seh-handler-with-safeseh
; see: http://code.metager.de/source/xref/WebKit/Source/WebCore/platform/win/makesafeseh.asm
; see: http://jpassing.com/2008/05/20/fun-with-low-level-seh/
.386
.model flat, stdcall
option casemap :none

; The symbol name can be found out using: dumpbin /symbols winseh.obj
extern _seh_handler:near ; defined in winseh.cc

_seh_asm_handler proto
.safeseh _seh_asm_handler

.code
_seh_asm_handler proc
jmp _seh_handler
_seh_asm_handler endp

end
