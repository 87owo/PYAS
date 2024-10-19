import "pe"

rule A1_1 {
   meta:
      description = "1"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "System.Object, mscorlib, Version=" ascii
      $x2 = ".pdb" ascii
      $x3 = "System.Drawing" ascii
      $s1 = "a2VybmVsMzIuZGxs" fullword wide
      $s2 = "RnJlZUNvbnNvbGU=" fullword wide
      $s3 = "Paleozoologist Timpanist Troubling" ascii
      $s4 = "Paleozoologist Timpanist Troubling" wide
      $s5 = "Levitating" fullword ascii
      $s6 = ".Properties" ascii
      $s7 = "PublicKeyToken" ascii
      $s8 = "helpToolStripButton.Image" fullword wide
      $s9 = "newToolStripButton.Image" fullword wide
      $s10 = "openToolStripButton.Image" fullword wide
      $s11 = "printToolStripButton.Image" fullword wide
      $s12 = "printPreviewToolStripButton.Image" fullword wide
      $s13 = "Extractor" ascii
      $s14 = "Congratulations" fullword ascii
      $s15 = "Byrnies" fullword wide
      $s16 = "showString" fullword ascii
      $s17 = "AScsrhgtr" fullword ascii
      $s18 = "ZknciocoiAw" fullword ascii
      $s19 = "Volute Transitions" fullword wide
      $s20 = "IOasuoihciujo" fullword ascii
      $s21 = "labelComp" wide
      $s22 = "ErrorImage" wide
      $s23 = "get_QuestCompletionItems" fullword ascii
      $s24 = "get_DropPercentage" fullword ascii
      $s25 = "PlayerData.xml" fullword wide
      $s26 = "get_LootTable" fullword ascii
      $s27 = "get_Potions" ascii
      $s28 = "get_CurrentMonster" fullword ascii
      $s29 = "MONSTER_ID_RAT" fullword ascii
      $s30 = "get_AddExtraNewLine" fullword ascii
      $s31 = "get_LootItems" fullword ascii
      $s32 = "get_HasAMonster" fullword ascii
      $s33 = "get_MinimumDamage" fullword ascii
      $s34 = "get_RewardGold" fullword ascii
      $s35 = "get_VendorWorkingHere" fullword ascii
      $s36 = "get_RewardItem" fullword ascii
      $s37 = "get_MaximumDamage" fullword ascii
      $s38 = "get_RewardExperiencePoints" fullword ascii
      $s39 = "imgur.com" wide
      $s40 = "CURD_ALUNOS.md" wide
      $s41 = "Parametros.xml" fullword wide
      $s42 = "dgEditar_CellContentClick" fullword ascii
      $s43 = "dgDados_CellContentClick" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 8 of them
}

rule A1_2 {
   meta:
      description = "2"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "You walk into the" wide
      $s2 = "_unprocessedInterAgentMessages" fullword ascii
      $s3 = "ProcessAllInterAgentMessages" fullword ascii
      $s4 = "AgentsComunnicationExecution" fullword ascii
      $s5 = "SendExecuteMessage" fullword ascii
      $s6 = "TemporarySetAgentModel" fullword ascii
      $s7 = "immediatelyProcess" fullword ascii
      $s8 = "ProcessTheMessage" fullword ascii
      $s9 = "HoldTarget" ascii nocase
      $s10 = "SimulationEngine." ascii
      $s11 = "FindAddresseeAgent" ascii
      $s12 = "AgentIsAlreadyRegistredException" fullword ascii
      $s13 = "MessageTimestampComparer" fullword ascii
      $s14 = "startcombat" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule A1_3 {
   meta:
      description = "3"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "GrapeCity.ActiveReports.Chart.Win" ascii
      $s1 = "ComponentlessCollectionEditor" ascii
      $s2 = "LabelsCollectionEditorGrapeCity" ascii
      $s3 = "AxesEditor" ascii
      $s4 = "AnnotationEditor" ascii
      $s5 = "GradientEditor" ascii
      $s6 = "DoubleArrayEditor" ascii
      $s7 = "LegendsEditor" ascii
      $s8 = "DataPointsEditor" ascii
      $s9 = "ChartAreasEditor" ascii
      $s10 = "AxesSelectEditor" ascii
      $s11 = "StyleEditor" ascii
      $s12 = "PatternEditor" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      $x1 and 8 of them
}

rule A1_4 {
   meta:
      description = "PYAS_Rules_A4"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = ".Properties" ascii nocase
      $x2 = ".Resources" ascii nocase
      $s1 = "ListenToAll" fullword ascii
      $s2 = "Abberant" fullword ascii
      $s3 = "Shlyber" fullword ascii
      $s4 = ".exe" wide
      $s5 = ".pdb" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ($x1 and $x2) and 5 of them
}

rule A1_5 {
   meta:
      description = "5"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "Microsoft.VSDesigner.DataSource.Design" ascii
      $s1 = "columnPostcode" fullword ascii
      $s2 = "GetRealUpdatedRows" fullword ascii
      $s3 = "set_Postcode" fullword ascii
      $s4 = "System.Drawing.Design.UITypeEditor" fullword ascii
      $s5 = "postcodeDataGridViewTextBoxColumn" fullword wide
      $s6 = "get_AlexandraDBConnectionString" fullword ascii
      $s7 = "SELECT [Number]" wide
      $s8 = "Original_Postcode" fullword wide
      $s9 = "get_CellPhone" fullword ascii
      $s10 = "get_CellPhoneColumn" fullword ascii
      $s11 = "postcodeTextBox" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      $x1 and 3 of them
}

rule A1_6 {
   meta:
      description = "6"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "System.Drawing" ascii
      $x2 = "PublicKeyToken" ascii
      $x3 = "System.Security.Permissions.SecurityPermission" wide
      $x4 = "urn:schemas-microsoft-com:asm" ascii
      $s1 = "feffeeffeef" ascii
      $s2 = "fefefeffefe" ascii
      $s3 = "feffefeeffe" ascii
      $s4 = "ffeefeffeefa" ascii
      $s5 = "ffeeffefeef" ascii
      $s6 = "ffeeffeeffe" ascii
      $s7 = "ffefeeffefe" ascii
      $s8 = "feffefefe" ascii
      $s9 = "fefefeffea" ascii
      $s10 = "supercommerce@example.com" fullword wide
      $s11 = "btnLogin" fullword ascii
      $s12 = "loginToolStripMenuItem" fullword wide
      $s13 = "loginToolStripMenuItem_Click" fullword ascii
      $s14 = "LoginController" fullword ascii
      $s15 = "Erro: login Mal Sucedido" fullword wide
      $s16 = "Erro de Login" fullword wide
      $s17 = "supermercado.Login.resources" fullword ascii
      $s18 = "get_Cordinations" fullword ascii
      $s19 = "get_Utgivnings" fullword ascii
      $s20 = "The Dark Knight" fullword wide
      $s21 = "get_Both_Shiled_and_Sword_Hero" fullword ascii
      $s22 = "get_Empty_handed_Hero" fullword ascii
      $s23 = "LogicValues1" fullword ascii
      $s24 = "by adguard" fullword wide
      $s25 = "ErrorImage" wide
      $s26 = "thedarkknight.jpg" fullword wide
      $s27 = "terkomst.jpg" fullword wide
      $s28 = "rymdimperiet.jpg" fullword wide
      $s29 = "get_Hero_with_shield" fullword ascii
      $s30 = "get_PowerOfDistraction" fullword ascii
      $s31 = "operationPressed" fullword ascii
      $s32 = "get_RadiusOfAttack" fullword ascii
      $s33 = "get_FilmNamn" fullword ascii
      $s34 = "operatorClick" fullword ascii
      $s35 = "get_Hero_with_sword" fullword ascii
      $s36 = "CustomImageFormat.txt" wide
      $s37 = "get_BeatsPerSecond" fullword ascii
      $s38 = "get_BeatPerSecond" fullword ascii
      $s39 = "DJ Control" fullword wide
      $s40 = "add_BeatChanged" fullword ascii
      $s41 = "_presenterModel" fullword ascii
      $s42 = "set_BeatsPerSecond" fullword ascii
      $s43 = "HandleBeat" fullword ascii
      $s44 = "BeatEventArgs" fullword ascii
      $s45 = ".NET Framework 4.6l" fullword ascii
      $s46 = ".?AV?$IListEnum@PAVECChildEvent@@@bd@@" fullword ascii
      $s47 = ".?AV?$_Func_impl_no_alloc@V<lambda_d43bfa6363a0258b5d083dd2b690cdbc>@@_NABUDllProtectEvent@@@std@@" fullword ascii
      $s48 = ".?AV?$_Func_base@_NABUDllProtectEvent@@@std@@" fullword ascii
      $s49 = ".?AV?$ListEnum@PAVECChildEvent@@@bd@@" fullword ascii
      $s50 = ".?AV?$IConstListEnum@PAVECChildEvent@@@bd@@" fullword ascii
      $s51 = ".?AV?$ConstListEnum@PAVECChildEvent@@@bd@@" fullword ascii
      $s52 = "labelComp" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and 5 of them
}

rule A1_7 {
   meta:
      description = "7"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "python3" ascii nocase
      $s2 = "_:@:P:H:X:D:T:L:\\:B:R:J:Z:F:V:N:^:A:Q:I:Y:E:U:M:]:C:S:K:[:G:W:O:_" fullword ascii
      $s3 = "KkdgJiVj1" fullword ascii
      $s4 = "2V1V5V3V7" fullword ascii
      $s5 = "Cxz.Yfc" fullword ascii
      $s6 = "'7 7$7\"7&7!7%7#7'" fullword ascii
      $s7 = "* %\\5?" fullword ascii
      $s8 = "xezygjy" fullword ascii
      $s9 = "tgkvdjv" fullword ascii
      $s10 = "bfDs /nU," fullword ascii
      $s11 = "zktmxjuxjeh" fullword ascii
      $s12 = "indljaj" fullword ascii
      $s13 = "Z t:\"-" fullword ascii
      $s14 = "o^EX:\"" fullword ascii
      $s15 = "rjF.tNb" fullword ascii
      $s16 = "pynput.keyboard._dummy)" fullword ascii
      $s17 = "pynput.keyboard._darwin)" fullword ascii
      $s18 = "pynput.keyboard)" fullword ascii
      $s19 = "pynput.keyboard._uinput)" fullword ascii
      $s20 = "pynput.keyboard._win32)" fullword ascii
      $s21 = "pynput.keyboard._xorg)" fullword ascii
      $s22 = "pynput.keyboard._base)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50000KB and
      10 of them
}

rule A1_8 {
   meta:
      description = "8"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "TASKKILL /F /IM" wide nocase
      $x2 = "processhacker" wide nocase
      $x3 = "cmd.exe /" wide nocase
      $s1 = "SHELL32.dll" wide nocase
      $s2 = "mmc.exe" wide nocase
      $s3 = "Execute ERROR" fullword wide
      $s4 = "WindowsServiceMode.exe" fullword wide
      $s5 = "ping 0" wide nocase
      $s6 = "Microsoft" wide nocase
      $s7 = "shutdown" wide nocase
      $s8 = "Download ERROR" fullword wide
      $s9 = "Executed As " fullword wide
      $s10 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
      $s11 = "ScanProcess" fullword ascii
      $s12 = "HKEY_CURRENT_USER\\Software\\" wide nocase
      $s13 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\" wide nocase
      $s14 = "TerminateProcessPath" ascii nocase
      $s15 = "svchost.exe" wide nocase
      $s16 = "wscript.exe" wide nocase
      $s17 = "Application.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      2 of ($x*) and 6 of them
}

rule A1_9 {
   meta:
      description = "9"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "SignalEventHandler" fullword ascii
      $s2 = "get_CrossTraffic" fullword ascii
      $s3 = "get_BeforeIntersection" fullword ascii
      $s4 = "get_InIntersection" fullword ascii
      $s5 = "get_CloseToIntersection" fullword ascii
      $s6 = "TrafficSignal.Settings" fullword ascii
      $s7 = "TrafficSignal.Strategy" fullword ascii
      $s8 = "TrafficSignal.Serializers" fullword ascii
      $s9 = "lblComputerName" fullword wide
      $s10 = "TrafficSignal.Properties.Resources.resources" fullword ascii
      $s11 = "TrafficSignal.TrafficSignalForm.resources" fullword ascii
      $s12 = "TrafficSignal.Properties" fullword ascii
      $s13 = "TrafficSignal.Properties.Resources" fullword wide
      $s14 = "get_pmYK" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      6 of them
}

rule A1_10 {
   meta:
      description = "10"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "DQuasar.Common" ascii
      $x2 = "PublicKeyToken" ascii
      $s1 = "GetKeyShareHelloRetryRequest" ascii
      $s2 = "GetKeyShareServerHello" ascii
      $s3 = "Process already elevated." fullword wide
      $s4 = "get_PotentiallyVulnerablePasswords" ascii
      $s5 = "GetKeyloggerLogsDirectory" ascii
      $s6 = "Gma.System.MouseKeyHook.KeyPressEventArgsExt" ascii
      $s7 = "GetKeyloggerLogsDirectoryResponse" ascii
      $s8 = "Quasar.Common.Models.FileChunk" ascii
      $s12 = "set_PotentiallyVulnerablePasswords" ascii
      $s13 = "potentiallyVulnerablePasswords" ascii
      $s16 = "getBytesProcessed" ascii
      $s17 = "GetPreSharedKeyClientHello" ascii
      $s18 = "GetKeyShareClientHello" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      ($x1 and $x2) and 6 of them
}

rule A1_11 {
   meta:
      description = "11"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide
      $s2 = "get_SendSync" fullword ascii
      $s3 = "get_SslClient" fullword ascii
      $s4 = "kpTBNFtPhayeH" fullword ascii
      $s5 = "get_ActivatePong" fullword ascii
      $s6 = "Pastebin" fullword wide
      $s7 = "GetUtf8Bytes" fullword ascii
      $s8 = "Plugin.Plugin" fullword wide
      $s9 = "RunAntiAnalysis" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      6 of them
}

rule A1_12 {
   meta:
      description = "12"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "-ExecutionPolicy Bypass" wide
      $s1 = "shutdown" wide nocase
      $s2 = "OfflineKeylogger Not Enabled" fullword wide
      $s3 = "Win32_Processor.deviceid" wide
      $s4 = "CloseMutex" fullword ascii
      $s5 = "AES_Encryptor" fullword ascii
      $s6 = "POST / HTTP/1.1" fullword wide
      $s7 = "GetHashT" fullword ascii
      $s8 = "AES_Decryptor" fullword ascii
      $s9 = "PCLogoff" fullword wide
      $s10 = "RunShell" fullword wide
      $s11 = "HostsMSG" fullword wide
      $s12 = "HostsErr" fullword wide
      $s13 = "OfflineGet" fullword wide
      $s14 = "Content-length:" wide
      $s15 = "Mozilla/5.0" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      1 of ($x*) and 5 of them
}

rule A1_13 {
   meta:
      description = "13"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "xehook.exe" fullword wide
      $s2 = "System.Collections.Generic" ascii
      $s3 = "<xehook.Classes.LogRecord>" ascii
      $s7 = "Confuser.Core 1.6.0+447341964f" fullword ascii
      $s8 = "rsqypuz" fullword ascii
      $s9 = "scyt6m$!k-}qbwu|ud6m#!k-sctbqs6m\"!k-u}q~s`6 -cbud|yv6m!!k-dhu6m !k-~u{" fullword ascii
      $s10 = "s6m%k-u}q~buce6m$k-cuy{" fullword ascii
      $s11 = "ETALUME" fullword ascii
      $s12 = "EYKLLGJCYEHBODMAHOGOCDNCJABEGNCG" fullword ascii
      $s13 = "JGVIWIWIPUVG" fullword ascii
      $s14 = "BAAD10E40DF6B5D52A22FCCE498BBD641EBB2377BB7DA4FE04EE26F084647F69" ascii
      $s15 = "(&'(/- /.,$ $, &  */! .('% ,#$+(" fullword ascii
      $s16 = "xehook" fullword ascii
      $s17 = "#+- +e,:'?;;)8" fullword ascii
      $s18 = "\\DVzVCRz " fullword ascii
      $s19 = "gv8)  -" fullword ascii
      $s20 = "[oBxxnhdy[" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      6 of them
}

rule A1_14 {
   meta:
      description = "14"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "jdownloader" wide nocase
      $s2 = "cmdvrt32.dll" fullword wide
      $s3 = "accounts.dat" fullword wide
      $s4 = "SxIn.dll" fullword wide
      $s5 = "Paltalk NG" wide
      $s6 = "encrypted" fullword wide
      $s7 = "ip-api.com" wide
      $s8 = "mRzIs.exe" fullword wide
      $s9 = "SmtpPassword" fullword wide
      $s10 = "FTP Commander" wide
      $s14 = "privateinternetaccess.com" fullword wide
      $s15 = "paltalk.com" fullword wide
      $s16 = "discord.com" fullword wide
      $s17 = "Sf2.dll" fullword wide
      $s18 = "account.dyn.com" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule A1_15 {
   meta:
      description = "15"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "aGVpbWdsaWduZGRramdvZmtjYmdla2hlbmJofE94eWdlbgptZ2Zma2ZiaWRpaGpwb2FvbWFqbGJnY2hkZGxpY2dwbnxQYWxpV2FsbGV0CmFvZGtrYWduYWRjYm9iZnBn" wide
      $s2 = "Could not list processes locking resource." wide
      $s3 = "Failed to get size of result." wide
      $s4 = "DownloadAndExecuteUpdate" fullword ascii
      $s5 = "loginusers.vdf" fullword wide
      $s7 = "ProcessInfo" wide
      $s8 = "get_encrypted_key" fullword ascii
      $s9 = "Tokens.txt" fullword wide
      $s10 = "DisplayDown" wide
      $s11 = "VisualPlus-Debug.log" fullword wide
      $s12 = "Total of RAMExecutablePath" fullword wide
      $s13 = "loginPairs" fullword ascii
      $s15 = "Software\\Valve\\SteamLogin Data" fullword wide
      $s16 = "SELSystem" wide
      $s17 = "FRSystem" wide
      $s18 = "WinSystem" wide
      $s19 = "%localappdata%\\" fullword wide
      $s20 = "NoEngrdVpEngn.exe*" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule A1_16 {
   meta:
      description = "16"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "LoginForm." ascii
      $x2 = ".pdb" ascii
      $s1 = "btnLogin" fullword ascii
      $s2 = "Wrong ID or Password" fullword wide
      $s3 = "Log In" wide
      $s4 = "CodiNauts" wide
      $s5 = "btnclear" fullword ascii
      $s6 = "GridFactura.Factura.resources" fullword ascii
      $s7 = "txtUserID_Validating" fullword ascii
      $s8 = "TrabajoPractico.GridFactura.resources" fullword ascii
      $s9 = "txtUserPass" fullword wide
      $s10 = "txtUserID" fullword wide
      $s11 = "Please Enter User ID" fullword wide
      $s12 = "Properties.Resources" ascii
      $s13 = "Log In Successfully" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ($x1 and $x2) and 6 of them
}

rule A1_17 {
   meta:
      description = "17"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "select * from user" wide nocase
      $s1 = "ltromatic.ttf" wide
      $s2 = "password mismatch issue" fullword wide
      $s3 = "tada.wav" wide
      $s4 = "GetAllIncome" fullword ascii
      $s5 = "getIcomeData" fullword ascii
      $s6 = "execQueryForStoredProcedure" fullword ascii
      $s7 = "GetAllIncomeValues" fullword ascii
      $s8 = "GetTotalIncomeSum" fullword ascii
      $s9 = "getAllUser" fullword ascii
      $s10 = "The password must include letters and numbers both" fullword wide
      $s11 = "Passwords not mathced" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      $x1 and 8 of them
}

rule A1_18 {
   meta:
      description = "18"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "WINDESCRIPTION" fullword wide
      $s2 = "2#2?2a2{2" fullword ascii
      $s3 = "CWM_GETCONTROLNAME" fullword wide
      $s4 = ":%:=:C:L:R:\\:g:" fullword ascii
      $s5 = ":-:I:T:\\:g:o:{:" fullword ascii
      $s6 = "C@COM_EVENTOBJ" fullword wide
      $s7 = "ISTABLE" fullword wide
      $s8 = "Cstatic" fullword wide
      $s9 = "HtZHtEHt2" fullword ascii
      $s10 = "tgHuM95" fullword ascii
      $s11 = "EEnvironment" fullword wide
      $s12 = "Invalid characters behind Object assignment!" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      6 of them
}

rule A1_19 {
   meta:
      description = "19"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "step executed succcessfully" wide
      $x2 = "NurseWorkstationDemo" wide
      $s1 = "get_ObejctOperation" fullword ascii
      $s2 = "man.png" wide
      $s3 = "woman.png" fullword wide
      $s4 = "get_AUTHORITY_ALL" fullword ascii
      $s5 = "GetDataTableInfo_CommonGood" fullword ascii
      $s6 = "from CommonGood where user_name=@user_Name" wide
      $s7 = "PSYCHOLOGY" fullword ascii
      $s8 = "GYNECOLOGY" fullword ascii
      $s9 = "Workstation_Library.Common" fullword ascii
      $s10 = "get_DataColumn1" fullword ascii
      $s11 = "get_DataColumn1Column" fullword ascii
      $s12 = "get_DataTable1" fullword ascii
      $s13 = "get_Status_R" fullword ascii
      $s14 = "GetAllBedNum" fullword ascii
      $s15 = "GetDataTableInfo_PatientName" fullword ascii
      $s16 = "get_Major_Doctor" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ($x1 and $x2) and 8 of them
}

rule A1_20 {
   meta:
      description = "20"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Log_Clientes.txt" wide
      $s2 = "Log_Produtos.txt" wide
      $s3 = "Log_Vendas.txt" wide
      $s4 = "SCV - Sistema de Cadastro e Vendas" fullword wide
      $s5 = "SCV - Novo Cliente" fullword wide
      $s6 = "SCV - Lista de Clientes" fullword wide
      $s7 = "SCV - Lista de Produtos" fullword wide
      $s8 = "SCV - Listar Vendas" fullword wide
      $s9 = "SCV - Novo Produto" fullword wide
      $s10 = "SCV - Nova Venda" fullword wide
      $s11 = "dgvListaClientes_CellContentClick" fullword ascii
      $s12 = "Comprador" fullword wide
      $s13 = "LogProdutos" fullword ascii
      $s14 = "LogVendas" fullword ascii
      $s15 = "dgvListaProdutos_CellContentClick" fullword ascii
      $s16 = "LogClientes" fullword ascii
      $s17 = "Compras" fullword ascii
      $s18 = "dgvProdutos_CellContentClick" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule A1_21 {
   meta:
      description = "21"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "xeno rat client" wide
      $s2 = "Windows Functionality" wide
      $s3 = "mutex_string" fullword ascii
      $s4 = "<getdll>5__2" fullword ascii
      $s5 = "xeno_rat_client" ascii
      $s6 = "_EncryptionKey" fullword ascii
      $s7 = "/query /v /fo csv" fullword wide
      $s8 = "<hasdll>5__3" fullword ascii
      $s9 = "<tempXmlFile>5__2" fullword ascii
      $s10 = "GetIdleTimeAsync" ascii
      $s11 = "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" wide
      $s12 = "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsICI=" fullword wide
      $s13 = "<GetAndSendInfo>d__5" fullword ascii
      $s14 = "<dllname>5__7" fullword ascii
      $s15 = "_dllhandler" fullword ascii
      $s16 = "<DllNodeHandler>d__3" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule A1_22 {
   meta:
      description = "22"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Single.exe" fullword wide
      $s2 = "Single.pdb" fullword ascii
      $s3 = "Overchills" fullword wide
      $s4 = "Single.g.resources" fullword ascii
      $s5 = "dYuVXzkLLVWbcxpNkzwMQNycwFrMShzJDdw" fullword ascii
      $s6 = "ZtrbobDfRVDVSYJDbiTjJYMtnApmznZIIGm" fullword ascii
      $s7 = "OmmLUOYnOXYPbQacJiJgtIiOzIZqtuzkkZYgGzISElssPeGNll" fullword wide
      $s8 = "RuJwfBUCLwnFkjrsmBeNtwwSyNBZKewfylZFqqPiXRqujAEskL" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      6 of them
}

rule A1_23 {
   meta:
      description = "23"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
      $s2 = "-ItemProperty -Path" wide
      $s3 = "Kutc64InaW" fullword ascii
      $s4 = "Cronos-Crypter" fullword wide
      $s5 = "PrivateImplementationDetails" ascii
      $s6 = "SetProcessSecurityDescriptor" ascii
      $s7 = "Systemhost" fullword wide
      $s8 = "decKey" fullword ascii
      $s9 = "StartupInformation" fullword ascii
      $s10 = "InstallRegistry" fullword ascii
      $s11 = "EEC0C451-6B9A-45A0-A879-90E70D3033F5" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      7 of them
}

rule A1_24 {
   meta:
      description = "24"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "LcD$`Mi" fullword ascii
      $s2 = "yBZh11AY&SYS" fullword ascii
      $s3 = "+HcD$DHcL$DH" fullword ascii
      $s4 = "D$P9D$@}0" fullword ascii
      $s5 = "tkHcD$8H" fullword ascii
      $s6 = "BHcD$D" fullword ascii
      $s7 = "|$(2t%" fullword ascii
      $s8 = "D$ 9D$(}z" fullword ascii
      $s9 = "D$ 9D$$}w" fullword ascii
      $s10 = "|$02t\"" fullword ascii
      $s11 = "L$P9H$s" fullword ascii
      $s12 = "L$P9H$|uH" fullword ascii
      $s13 = "D$89D$(}," fullword ascii
      $s14 = " `l;Vig" fullword ascii
      $s15 = "D$@HcL$\\H" fullword ascii
      $s16 = "L$p9A<r" fullword ascii
      $s17 = "D$T9D$D}0" fullword ascii
      $s18 = "L$\\9H8|" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      6 of them
}

rule A1_25 {
   meta:
      description = "25"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "Storm ddos" ascii nocase
      $s1 = "StormServer.dll" fullword ascii
      $s2 = "%SystemRoot%\\System32\\" fullword ascii
      $s3 = "ServiceDLL" fullword ascii
      $s4 = "SppHostParameterUniqueGraceTimer" fullword wide
      $s5 = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" fullword ascii
      $s6 = "x2IewLL49ZGPwaBBKatfGEtAFT9g327lJCkLLIoJXpM=" fullword wide
      $s7 = "stubpath" fullword ascii
      $s8 = "pYm2nwOxGc6z7lSognw0yFDwAvT6vw19fUA6AgZO2X4=" fullword wide
      $s9 = "pcdWYYb9DmAfsyF2r5F3eZ8d90dxwbNrwv3g3w7zeG4=" fullword wide
      $s10 = "pwsgLvKPxCIWaZdkJ81sXVaE8Ymalx/SRYktvM2Dh2k=" fullword wide
      $s11 = "oLq+2/XBPbG84P21eK0nQshRCgrb7+zrQ0qm8iOu75M=" fullword wide
      $s12 = "pBeoAt+o4LduQNgbijEgrAwSFIGNV9An96aBd5EQdAE=" fullword wide
      $s13 = "cde4d5c7-2f36-dfac-49ee-b4ef7966706a" fullword wide
      $s14 = "4a69babc-79ff-d8d0-e21f-1ad764610ba5" fullword wide
      $s15 = "7e746adc-aded-b4e0-f905-958045b82a91" fullword wide
      $s16 = "c4ddee78-55b7-8e06-319f-e099efa3c9f5" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      $x1 and 5 of them
}

rule A1_26 {
   meta:
      description = "26"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "<InitializeComponent>b__22_0" fullword ascii
      $s2 = "get_JpaO" fullword ascii
      $s3 = "GetPrevName" fullword ascii
      $s4 = "GetStepByName" fullword ascii
      $s5 = "_BindTreeView" fullword ascii
      $s6 = "get__AllSteps" fullword ascii
      $s7 = "get__CurrentTreeNode" fullword ascii
      $s8 = "StepNavigationWizard.Properties" fullword ascii
      $s9 = "System.Reflection.AssemblyA" fullword ascii
      $s10 = "StepNavigationWizard.Properties.Resources" fullword wide
      $s11 = "StepNavigationWizard.StepFormBase.resources" fullword ascii
      $s12 = "StepNavigationWizard.Home.resources" fullword ascii
      $s13 = "StepNavigationWizard.Properties.Resources.resources" fullword ascii
      $s14 = "StepNavigationWizard.Helpers" fullword ascii
      $s15 = "StepNavigationWizard.StepForms" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule A1_27 {
   meta:
      description = "27"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "TrackerUI.Properties" fullword ascii
      $s2 = "TrackerUI.Properties.Resources" fullword wide
      $s3 = "get_TeamCompeting" fullword ascii
      $s4 = "get_EnteredTeams" fullword ascii
      $s5 = "get_EntryFee" fullword ascii
      $s6 = "get_PrizeAmount" fullword ascii
      $s7 = "get_PrizePercentage" fullword ascii
      $s8 = "get_MatchupRound" fullword ascii
      $s9 = "get_ParentMatchup" fullword ascii
      $s10 = "get_TournamentName" fullword ascii
      $s11 = "get_PriceNumber" fullword ascii
      $s14 = "<TeamCompeting>k__BackingField" fullword ascii
      $s15 = "TrackerUI.TournamentViewerForm.resources" fullword ascii
      $s17 = "set_TeamCompeting" fullword ascii
      $s18 = "TrackerUI.Properties.Resources.resources" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      6 of them
}

rule A1_28 {
   meta:
      description = "28"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "GNU C11 6.3.0" ascii
      $s2 = "GCC: (MinGW.org GCC-6.3.0-1) 6.3.0" fullword ascii
      $s3 = "___mingw_readdir" fullword ascii
      $s4 = "___mingw_closedir" fullword ascii
      $s5 = "___mingw_seekdir" fullword ascii
      $s6 = "%d is not a prime number." fullword ascii
      $s7 = "___mingw_rewinddir" fullword ascii
      $s8 = "__mingw32_init_mainargs" fullword ascii
      $s9 = "___mingw_telldir" fullword ascii
      $s10 = "Enter an integer: " fullword ascii
      $s11 = "___mingw_opendir" fullword ascii
      $s12 = "/home/keith/" ascii
      $s13 = "../../../src/gcc-6.3.0/libgcc" ascii
      $s14 = "___mingw_dirname" fullword ascii
      $s15 = "_isPrime`" fullword ascii
      $s16 = "%d is a prime number." fullword ascii
      $s17 = ".weak.__Jv_RegisterClasses.___EH_FRAME_BEGIN__" fullword ascii
      $s18 = "-mtune=generic" ascii
      $s19 = "-march=i586" ascii
      $s20 = "-g -g -g -O2 -O2 -O2" ascii
      $s21 = "-fbuilding-libgcc" ascii
      $s22 = "-fno-stack-protector" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule A1_29 {
   meta:
      description = "29"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "* qH('" fullword ascii
      $s2 = "EYeijVu" fullword ascii
      $s3 = "zSEoS\\` -~" fullword ascii
      $s4 = "iumsyue" fullword ascii
      $s5 = "pqwwwww" fullword ascii
      $s6 = "bengwfvfw" fullword ascii
      $s7 = "exoowono" fullword ascii
      $s8 = "Mzs.Cff=" fullword ascii
      $s9 = "P7sq.FFH" fullword ascii
      $s10 = "gSh.UKc" fullword ascii
      $s11 = "uP$O:\"" fullword ascii
      $s12 = "0skCOM.b" fullword ascii
      $s13 = "T.^y8i:\"[" fullword ascii
      $s14 = "oymL@R>%j-" fullword ascii
      $s15 = "HOFKWMGQU" fullword ascii
      $s16 = "Ly(loge" fullword ascii
      $s17 = "diRcS|" fullword ascii
      $s18 = "\\%G%*;J#_" fullword ascii
      $s19 = "$x%Dllx" fullword ascii
      $s20 = "Lunqnuns" fullword ascii
      $s21 = "- &DNB" fullword ascii
      $s22 = "tlpyp49" fullword ascii
      $s23 = "xrarreg.key" fullword ascii
      $s24 = "xblank.aes" fullword ascii
      $s25 = "S^%ggvWrvfo%gg" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      6 of them
}

rule A1_30 {
   meta:
      description = "30"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Robah luj cerizunerGGiwuvayasaye melexeye beculepub holumojore vosuxurikube jenuxafejifamoh=Fub hasobucuwuwu zamojibuw wujenuji " wide
      $s2 = "paminiwiyisivifo" fullword ascii
      $s3 = "pipovozulememokutefoseyo" fullword ascii
      $s4 = "keminivefayosexerukugufebaponif" fullword wide
      $s5 = "GNNNNNNNNNNNN" ascii
      $s6 = "Slupido" fullword wide
      $s7 = "Torchok" fullword wide
      $s8 = "mukozewiba nirocemerese tukolaraxamefapage" fullword wide
      $s9 = "renej luwoyisawopab dadabayegutenecisufoba wozonotuwugewiropoxu vogiwipeladoxakanahotucucuwi" fullword wide
      $s10 = "12.3.3.193" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      6 of them
}

rule A1_31 {
   meta:
      description = "31"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Form_Data_Transfer" ascii
      $s2 = "frmGetData" fullword wide
      $s3 = "get_xveG" fullword ascii
      $s4 = "ZorgPe0" fullword ascii
      $s5 = "tBHgbZ6" fullword ascii
      $s6 = "KsFcPdQ" fullword ascii
      $s7 = "c3bbecb66bae" ascii
      $s8 = "Forms_app_looping" fullword ascii
      $s9 = "get_bHV" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      6 of them
}

rule A1_32 {
   meta:
      description = "32"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "Cryptodome" ascii
      $s1 = "_ghash_portable.pyd" ascii
      $s2 = "_ec_ws.pyd" ascii
      $s3 = "_ed25519.pyd" ascii
      $s4 = "_ed448.pyd" ascii
      $s5 = "_x25519.pyd" ascii
      $s6 = "Hash.CMAC)" ascii
      $s7 = "Hash.SHA3_512" ascii
      $s8 = "Hash.SHA1" ascii
      $s9 = "Protocol.KDF" ascii
      $s10 = "_SHA512.pyd" ascii
      $s11 = "SHA3_256" ascii
      $s12 = "HMAC" ascii
      $s13 = "_SHA384.pyd" ascii
      $s14 = "_SHA256.pyd" ascii
      $s15 = "SHA3_384" ascii
      $s16 = "_MD2.pyd" ascii
      $s17 = "SHA512" ascii
      $s18 = "Util.py3compat" ascii
      $s19 = "_ghash_clmul.pyd" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50000KB and
      $x1 and 8 of them
}

rule A1_33 {
   meta:
      description = "33"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "FileBackuper" ascii nocase
      $s1 = "dev.neptuo.com" wide
      $s2 = "BackuperConsole" ascii
      $s3 = "{0:yyyy-MM-dd}" ascii
      $s4 = "TRACE LoggerFactory config" fullword wide
      $s5 = "Configuration" wide
      $s6 = "Logging" ascii
      $s7 = "Logic" ascii
      $s8 = "Config.xml" ascii
      $s9 = "Settings.LogDirPath" fullword wide
      $s10 = "hadn't been processed, do you want to backup now?" fullword wide
      $s11 = "get_LogDirPath" fullword ascii
      $s12 = "Wrong data in LoggerSetup!" fullword wide
      $s13 = "ConfigurationForm" ascii
      $s14 = "get_compress" fullword ascii
      $s15 = "get_VersionsNames" fullword ascii
      $s16 = "GetUIComponentsValues" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      $x1 and 8 of them
}

rule A1_34 {
   meta:
      description = "34"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "www.zeustech.net" ascii
      $s2 = "Copyright 1996 Adam Twiss, Zeus Technology Ltd" ascii
      $s3 = "content-type" ascii nocase
      $s4 = "Display usage information" ascii nocase
      $s5 = "Use HEAD instead of GET" ascii nocase
      $s6 = "File containing data to POST" ascii nocase
      $s7 = "Use HTTP KeepAlive feature" ascii nocase
      $s8 = "Don't exit on socket receive errors" ascii nocase
      $s9 = "Proxyserver and port number to use" ascii nocase
      $s10 = "Add Arbitrary header line" ascii nocase
      $s11 = "Output collected data to gnuplot format file" ascii nocase
      $s12 = "Size of TCP send/receive buffer" ascii nocase
      $s13 = "Number of multiple requests to make" ascii nocase
      $s14 = "How much troubleshooting info to print" ascii nocase
      $s15 = "String to insert as tr attributes" ascii nocase
      $s16 = "are a colon separated username and password" ascii nocase
      $s17 = "Do not show percentiles served table" ascii nocase
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule A1_35 {
   meta:
      description = "35"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Data Source=" wide
      $s2 = "Initial Catalog=ECRS" wide
      $s3 = "ExecutarConsulta" fullword ascii
      $s4 = "System.Data.MySqlClient" fullword wide
      $s5 = "Persist Security Info=True" fullword wide
      $s6 = "get_SysShopStringConnection" fullword ascii
      $s7 = "get_ShipAddress" fullword ascii
      $s8 = "ExecutarTransacao" fullword ascii
      $s9 = "PDF files (*.txt)|*.txt" fullword wide
      $s10 = "SysShop.BLL" fullword ascii
      $s11 = "SysShop.DTO" fullword ascii
      $s12 = "SysShop.DAL" fullword ascii
      $s13 = "SysShop.BLL.Excecoes" fullword ascii
      $s14 = "get_ProdutoId" fullword ascii
      $s15 = "get_ShipCity" fullword ascii
      $s16 = "Get_Customer_And_Orders" fullword ascii
      $s17 = "GetTipoProduto" fullword ascii
      $s18 = "get_SysShopProviderFactory" fullword ascii
      $s19 = "GetWordLenth" fullword ascii
      $s20 = "GetDiscountByRule" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      6 of them
}

rule A1_36 {
   meta:
      description = "36"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "btnlimpiar" fullword wide
      $s2 = "Liquidacion.txt" fullword wide
      $s3 = "GetColumn2Sum" fullword ascii
      $s4 = "get_CuotaModerada" fullword ascii
      $s5 = "get_ListaLiquidaciones" fullword ascii
      $s6 = "panelprice" fullword wide
      $s7 = "get_Label15Text" fullword ascii
      $s8 = "get_Mensaje" fullword ascii
      $s9 = "get_liquidacion" fullword ascii
      $s10 = "GetExistingRowIndex" fullword ascii
      $s11 = "get_SalarioDevengado" fullword ascii
      $s12 = "get_ValorServicio" fullword ascii
      $s13 = "Error al Consultar: " fullword wide
      $s14 = "cmbtipo" fullword wide
      $s15 = "Kurunegala" fullword wide
      $s16 = "Trincomalee" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      6 of them
}

rule A1_37 {
   meta:
      description = "37"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "GogMagogIsraelVsPalestine" fullword wide
      $s1 = "JitInstrumentationDataKeywordResolveFieldHandle" fullword wide
      $s2 = "getDaylightNameFlowExecutionContext" fullword wide
      $s3 = "GetRandomizedEqualityComparer" fullword ascii
      $s4 = "GetEqualityComparerForSerialization" fullword ascii
      $s5 = "LookForThreadgetIsTypeDefinition" fullword wide
      $s6 = "SemaphoreGetEnumeratord17" fullword ascii
      $s7 = "RtlNtStatusToDosErrorRootDirectory" fullword wide
      $s8 = "TryGetArrayPhi" fullword ascii
      $s9 = "ResourceEnumeratorgetAsyncWaitHandle" fullword ascii
      $s10 = "AmsiDll" fullword ascii
      $s11 = "PopgetNativeDigits" fullword wide
      $s12 = "RevokeObjectBoundGetObjectParam" fullword wide
      $s13 = "FinalizeHash32" fullword ascii
      $s14 = "Properties.Resources.resources" fullword ascii
      $s15 = "VARFLAGFREADONLYSetCheckSum" fullword ascii
      $s16 = "TimeSpanFormatConfiguredTaskAwaiter" fullword wide
      $s17 = "TYPEFLAGFREVERSEBINDDefineEnum" fullword ascii
      $s18 = "InitBlockUnalignedWaitForFullGCComplete" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      6 of them
}

rule A1_38 {
   meta:
      description = "38"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Stream write error" wide
      $s2 = "'%s' is not a valid integer value" wide
      $s3 = "Write$Error creating variant or safe array!" wide
      $s4 = "Vevalcomp" fullword ascii
      $s7 = "archiveint" fullword ascii
      $s8 = "tscreenps" fullword ascii
      $s9 = "9 :0:<:@:H:L:P:T:X:\\:`:d:h:l:p:t:|:" fullword ascii
      $s10 = "archive__version_string" fullword ascii
      $s11 = "No help found for context" wide
      $s12 = "KeyPreview," fullword ascii
      $s13 = "TThreadListT" fullword ascii
      $s14 = ":<:D:H:L:P:T:X:\\:`:d:x:" fullword ascii
      $s15 = "93:?:L:\\:|:" fullword ascii
      $s16 = ":4:<:@:D:H:L:P:T:X:\\:l:" fullword ascii
      $s17 = "BCDFGHJKLMNPQRSTVWXZ" fullword ascii
      $s18 = "Unable to find a Table of Contents" wide
      $s19 = "CTDDTEV" fullword ascii
      $s20 = "_4%i;h" fullword ascii
      $s21 = "No topic-based help system installed" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      6 of them
}

rule A1_39 {
   meta:
      description = "39"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "amsimg32.dll" fullword wide
      $s2 = "70.49.20.77" fullword wide
      $s3 = "YYYYLLL" fullword ascii
      $s4 = "666%%%%3|" fullword ascii
      $s5 = "``%6666%%%%" fullword ascii
      $s6 = "alezecebesijorabifovihapida" fullword ascii
      $s7 = "folemajamivujogi" fullword ascii
      $s8 = "YYYYLL" fullword ascii
      $s9 = "PLLLLQQQC" fullword ascii
      $s10 = "juyutopewotucisutolok gokikicenifejoyoxeruzi kibewozaneferigov" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      6 of them
}

rule A1_40 {
   meta:
      description = "40"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "cekuduzupuwuhoxixomagahimuvecigicucesuhayoxoyo" fullword ascii
      $s2 = " -f$FFFFFFFFFFFFFFFF$v~\"" fullword ascii
      $s3 = "xzilehipizireyujexazav" fullword wide
      $s4 = "Slupido" fullword wide
      $s5 = "Torchok" fullword wide
      $s6 = "Skkkkkkkkkkkkkkkkk" fullword ascii
      $s7 = "Wgggggggggguuuuuggggggggg" fullword ascii
      $s8 = "89.49.84.33" fullword wide
      $s9 = "B* fn4E3k" fullword ascii
      $s10 = "\\%|RJJq$OC" fullword ascii
      $s11 = "jomak" ascii
      $s12 = "LegalCopyrights" fullword wide
      $s13 = "vayusupogisoxewememuvapobahekot" ascii
      $s14 = "yifasupuvuvetaduwa" ascii
      $s15 = "difocusarijigobuco" ascii
      $s16 = "remotoxevuketorigosukiduve" ascii
      $s17 = "durudaxo" wide
      $s18 = "payuyafelamelokeyir" wide
      $s19 = "tacadasevow" wide
      $s20 = "kipazoci" wide
      $s21 = "kanorowawacasolicalotija" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1500KB and
      8 of them
}

rule A1_41 {
   meta:
      description = "41"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "cmd /c  mysql.exe -u" fullword wide
      $s2 = "MSVBVM60.DLL" ascii
      $s3 = "AxeDB VBTool" wide
      $s4 = "lblshell" ascii
      $s5 = "Command9" ascii
      $s6 = "Command7" ascii
      $s7 = "Restore.sql" wide
      $s8 = "Update.sql" wide
      $s9 = "fk.exe" wide
      $s10 = "CREATE TABLE `user`" wide
      $s11 = "www.ja2inn.com" wide
      $s12 = "Commandb" ascii
      $s13 = "ntory.vbp" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      6 of them
}

rule A1_42 {
   meta:
      description = "42"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Extractor.pdb" fullword ascii
      $s2 = "Congratulations" fullword ascii
      $s3 = "Byrnies" fullword wide
      $s4 = "showString" fullword ascii
      $s5 = "AScsrhgtr" fullword ascii
      $s6 = "ZknciocoiAw" fullword ascii
      $s7 = "Volute Transitions" fullword wide
      $s8 = "IOasuoihciujo" fullword ascii
      $s9 = "ParamOnMove" fullword ascii
      $s10 = "AINsuiciA" fullword ascii
      $s11 = "AUIsbcoA" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      6 of them
}

rule A1_43 {
   meta:
      description = "43"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "Arbyter Copy Run Started" wide
      $s2 = "ExecuteUnregisteredTextUpdate" fullword ascii
      $s3 = "get_UnauthorizedAccesAppology" fullword ascii
      $s4 = "Arbyter_Log.txt" wide
      $s6 = "get_IOExceptionAppology" fullword ascii
      $s7 = "IOExceptionAppology" fullword wide
      $s8 = "UnauthorizedAccesAppology" fullword wide
      $s9 = "Appologise" fullword ascii
      $s10 = "get_GenericAppology_ExceptionMessage" fullword ascii
      $s11 = "ARBAErrorManager.Resources" fullword wide
      $s12 = "CopyModifiedContent" fullword ascii
      $s13 = "GetArbyterClean" fullword ascii
      $s14 = "DialogFilters" fullword ascii
      $s15 = "DeleteExtraContent" fullword ascii
      $s16 = "GetArbyterCopy" fullword ascii
      $s17 = "ResetDocumentContent" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule A1_44 {
   meta:
      description = "44"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "System.Windows.Forms" ascii
      $s2 = "PublicKeyToken" fullword wide
      $s3 = "Forward.png" fullword wide
      $s4 = "get_GlobalDialog" fullword ascii
      $s5 = "Unable to save file {0} - {1}" fullword wide
      $s6 = "{0} - MyPhotos" wide
      $s7 = "get_HasEdits" fullword ascii
      $s8 = "Save.png" fullword wide
      $s9 = "Back.png" fullword wide
      $s10 = "Notes.png" fullword wide
      $s11 = "notebook.png" fullword wide
      $s12 = "boot.png" fullword wide
      $s13 = "traffic.png" fullword wide
      $s14 = "gwenview.png" fullword wide
      $s15 = "open1.png" fullword wide
      $s16 = "get_AlbumFile" fullword ascii
      $s17 = "pnlPhoto_DragEnter" fullword ascii
      $s18 = "get_CurrentPhoto" fullword ascii
      $s19 = "get_GlobalMdiParent" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule A1_45 {
   meta:
      description = "45"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "myData.json" wide
      $s2 = "bFLv.exe" fullword wide
      $s3 = "Water elevation" fullword wide
      $s4 = "Polder elevation" fullword wide
      $s5 = "Queens Puzzle  - Deven Dayal" fullword wide
      $s6 = "getPositionInRow" fullword ascii
      $s7 = "getSumXY" fullword ascii
      $s8 = "cmdExport" wide
      $s9 = "get_TotalSalary" fullword ascii
      $s10 = "get_PhilHealth" fullword ascii
      $s11 = "GetTotalDeductions" fullword ascii
      $s12 = "GetPhilHealth" fullword ascii
      $s13 = "get_LongPay" fullword ascii
      $s14 = "get_TotalDeductions" fullword ascii
      $s15 = "get_HireDate" fullword ascii
      $s16 = "get_GrossPay" fullword ascii
      $s17 = "getSquareSum" fullword ascii
      $s18 = "* utxL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule A1_46 {
   meta:
      description = "46"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "rating_browser" wide
      $s1 = "remove_SerialPortStateChangedEvent" fullword ascii
      $s2 = "samskip" ascii
      $s3 = "Clients.APIClien" ascii
      $s4 = "get_Jirakey" fullword ascii
      $s5 = "jirakey" fullword ascii
      $s6 = "SerialPortStringSender" ascii
      $s7 = "SelectedIndexChanged" ascii
      $s8 = "comPortComboBox" wide
      $s9 = "setComPort" fullword ascii
      $s10 = "dataGridViewResult_CellContentClick" fullword ascii
      $s11 = "MainView.resources" fullword ascii
      $s12 = "Open Connection" fullword wide
      $s13 = "initialiseConnection" fullword ascii
      $s14 = "rating-browser" wide
      $s15 = "Properties.Resources" ascii
      $s16 = "MainForm.resources" ascii
      $s17 = "openConnectionButton_Click" fullword ascii
      $s18 = "serialPort" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      $x1 and 8 of them
}

rule A1_47 {
   meta:
      description = "47"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "Microsoft.Windows.Common-Controls" ascii
      $s2 = "sfxelevation" fullword wide
      $s3 = "ExecuteOnLoad" fullword wide
      $s4 = "www.sysdevlabs.com" ascii
      $s5 = "Error in command line:" fullword ascii
      $s6 = "processorArchitecture" ascii
      $s7 = "7-Zip.SfxMod" ascii
      $s8 = "Never.bat" ascii
      $s9 = "RunProgram=" ascii
      $s11 = "Alice" ascii
      $s12 = "Oleg Scherbakov" fullword ascii
      $s13 = "SfxVarSystemPlatform" fullword wide
      $s14 = "SfxVarCmdLine1" fullword wide
      $s15 = "SfxVarCmdLine0" fullword wide
      $s16 = "The archive is corrupted, or invalid password was entered." fullword ascii
      $s17 = " \"setup.exe\" " fullword ascii
      $s18 = "*.sfx.config.*" fullword ascii
      $s19 = "T:\\HfVdT(l8'" fullword ascii
      $s20 = ";Heading Longest Desperate " fullword ascii
      $s21 = "Gardens" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 5 of them
}

rule A1_48 {
   meta:
      description = "48"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "passportRadioButton" wide
      $x2 = "computerGuess" wide
      $x3 = "get_Data" ascii
      $s1 = "panelcolors" fullword wide
      $s2 = "generateRandomComputerGuess" fullword ascii
      $s3 = "ConfirmArrowAndResults" fullword ascii
      $s4 = "FlightBookingApp" fullword ascii
      $s5 = "Properties" fullword ascii
      $s6 = "i_ComputerGeneratedColors" fullword ascii
      $s7 = "NumberOfGuessesForm" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      2 of ($x*) and 6 of them
}

rule A1_49 {
   meta:
      description = "49"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "Microsoft.Windows.Common-Controls" ascii
      $x2 = "Unable to get" wide
      $x3 = "avsupport@autoitscript.com" ascii
      $x4 = "function call" wide
      $x5 = "Failed to create the" wide
      $s1 = "#NoAutoIt3Execute" fullword wide
      $s2 = "WINDESCRIPTION" fullword wide
      $s3 = "AutoIt" wide
      $s4 = "AU3_GetPluginDetails" fullword ascii
      $s5 = "DSeAssignPrimaryTokenPrivilege" fullword wide
      $s6 = "@COM_EVENTOBJ" fullword wide
      $s7 = "Failed to create the Event Object." fullword wide
      $s8 = "WRPQCSV" fullword ascii
      $s9 = "%s (%d) : ==> %s:" fullword wide
      $s10 = "PLUGINOPEN" fullword wide
      $s11 = "PLUGINCLOSE" fullword wide
      $s12 = "DMUILANG" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      3 of ($x*) and 5 of them
}

rule A1_50 {
   meta:
      description = "50"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "System.Collections.Generic" ascii
      $s1 = "JsonFx.Serialization.DataName" ascii
      $s2 = "JsonFx.Model.ModelToken" ascii
      $s3 = "JsonFx.Serialization.Token" ascii
      $s4 = "JsonFx.Serialization.Resolvers.MemberMap" ascii
      $s5 = "KeyValuePair" ascii
      $s6 = "IEnumerator" ascii
      $s7 = "Unable to find a suitable constructor for instantiating the target Type" wide
      $s8 = "1d0d5de7-1c32-4ecd-bde7-6965263fbc6b" wide
      $s9 = "PublicKeyToken" wide
      $s10 = "Selected compression algorithm is not supported" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      $x1 and 6 of them
}

rule A1_51 {
   meta:
      description = "51"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "System.Diagnostics.DiagnosticSource" ascii
      $x2 = "PublicKeyToken" ascii
      $s1 = "launcher.exe" fullword wide
      $s2 = "CleanerNatives.dll" fullword ascii
      $s3 = "costura" wide
      $s4 = "MindCleaner.Login.resources" fullword ascii
      $s5 = "start cmd /C" wide nocase
      $s6 = "InetCpl.cpl" wide
      $s7 = "ClearMyTracksByProcess" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule A1_52 {
   meta:
      description = "52"
      author = "PYAS Security"
      date = "2024-06-13"
   strings:
      $s1 = "avghook" wide
      $s2 = "tab_url from downloads" fullword ascii
      $s3 = "cmdvrt64.dll" wide
      $s4 = "passwords.txt" fullword ascii
      $s5 = "SELECT target_path" fullword ascii
      $s6 = "recentservers.xml" ascii
      $s7 = "[Processes]" fullword ascii
      $s8 = "steam_tokens.txt" ascii
      $s9 = "information.txt" ascii
      $s10 = "UseMasterPassword" ascii
      $s11 = "Opera GX" ascii
      $s12 = "Opera Crypto" ascii
      $s13 = "DRIVE_FIXED" ascii
      $s14 = "DRIVE_REMOVABLE" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule A1_53 {
   meta:
      description = "53"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "schemas.microsoft.com" wide
      $x2 = "Client Worker Thread" ascii
      $s1 = "A6BFEA43-501F-456F-A845-983D3AD7B8F0" wide
      $s2 = "upgrader" wide
      $s3 = "rtvscan.exe" wide
      $s4 = "Enable-WindowsOptionalFeature -FeatureName" wide
      $s5 = "remupd.exe" fullword wide
      $s6 = "Mcshield.exe" fullword wide
      $s7 = "mssecess.exe" fullword wide
      $s8 = "RavMonD.exe" fullword wide
      $s9 = "KvMonXP.exe" fullword wide
      $s10 = "baiduSafeTray.exe" fullword wide
      $s11 = "Qavanijeb.exe" fullword wide
      $s12 = "%s --> Error: %d, EC: %d" fullword ascii
      $s13 = "wscript.exe //E:vbscript" wide
      $s14 = "upgrader_64" wide
      $s15 = "Process Data Error" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 6 of them
}
