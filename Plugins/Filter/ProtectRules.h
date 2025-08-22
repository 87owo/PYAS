#pragma once
#include <ntifs.h>

wchar_t* GetMatchedBlockRegRule(PUNICODE_STRING s);
BOOLEAN MatchBlockReg(PUNICODE_STRING s);
BOOLEAN IsWhitelist(PUNICODE_STRING s);
BOOLEAN GetProcessImagePathByPid(HANDLE pid, PUNICODE_STRING ProcessImagePath);
BOOLEAN IsRegistryBlock(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING exe);

BOOLEAN MatchBlockFile(PUNICODE_STRING s);
BOOLEAN MatchBlockRansom(PUNICODE_STRING s);
BOOLEAN HasBlockedSuffix(PUNICODE_STRING s);
wchar_t* GetMatchedBlockFileRule(PUNICODE_STRING s);

extern wchar_t* g_AttachDisk[];
