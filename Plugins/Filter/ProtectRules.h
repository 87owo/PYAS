#pragma once
#include <ntifs.h>

extern wchar_t* g_Whitelist[];
extern wchar_t* g_WhitelistExcept[];

extern wchar_t* g_AttachDisk[];
extern wchar_t* g_BlockFile[];
extern wchar_t* g_BlockRansom[];
extern wchar_t* g_Blocksuffix[];

extern wchar_t* g_BlockReg[];

extern wchar_t* g_RemoteSuspectBins[];

extern wchar_t* g_RemoteCmdIndicatorsHttp[];
extern wchar_t* g_RemoteCmdIndicatorsGeneric[];
extern wchar_t* g_RemoteCmdFromCmdExe[];
extern wchar_t* g_RemoteCmdFromRundll32Exe[];
extern wchar_t* g_RemoteCmdRegsvr32Need[];
extern wchar_t* g_RemoteCmdFromMshtaExe[];

extern wchar_t* g_ScreenCapModules[];
extern wchar_t* g_ScreenUserSubdirs[];
extern wchar_t* g_ScreenOtherProcNeedles[];
