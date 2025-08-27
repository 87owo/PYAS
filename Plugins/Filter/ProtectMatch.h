#pragma once
#include <ntifs.h>

wchar_t* GetMatchedBlockRegRule(PUNICODE_STRING s);
wchar_t* GetMatchedBlockFileRule(PUNICODE_STRING s);
BOOLEAN GetProcessImagePathByPid(HANDLE pid, PUNICODE_STRING ProcessImagePath);

BOOLEAN IsWhitelist(PUNICODE_STRING s);
BOOLEAN IsWhitelistExcept(PUNICODE_STRING img);

BOOLEAN MatchBlockReg(PUNICODE_STRING s);
BOOLEAN IsRegistryBlock(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING exe);

BOOLEAN MatchBlockFile(PUNICODE_STRING s);
BOOLEAN MatchBlockRansom(PUNICODE_STRING s);
BOOLEAN HasBlockedSuffix(PUNICODE_STRING s);

BOOLEAN MatchRemoteSuspectBin(PUNICODE_STRING img);
BOOLEAN MatchRemoteCommand(PUNICODE_STRING cmd, PUNICODE_STRING img);

BOOLEAN MatchScreenCapModule(PUNICODE_STRING mod);
BOOLEAN MatchSuspiciousProcPath(PUNICODE_STRING img);
BOOLEAN MatchClrFromNonFramework(PUNICODE_STRING fullImageName);
