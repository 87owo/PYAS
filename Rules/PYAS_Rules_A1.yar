import "pe"

rule PYAS_Rules_A_1 {
   meta:
      description = "PYAS_Rules_A_1"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "System.Object, mscorlib, Version=" ascii
      $x2 = ".pdb" ascii
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
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 5 of them
}

rule PYAS_Rules_A_2 {
   meta:
      description = "PYAS_Rules_A_2"
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

rule PYAS_Rules_A_3 {
   meta:
      description = "PYAS_Rules_A_3"
      author = "PYAS Security"
      date = "2024-06-12"
      hash1 = "0ecf129dfa4e7b5da78c249a38d3e2ca3009aaf2e0203ec779d12aa122904f43"
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
      uint16(0) == 0x5a4d and filesize < 22000KB and
      $x1 and 8 of them
}

rule PYAS_Rules_A_4 {
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
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ($x1 and $x2) and 5 of them
}

rule PYAS_Rules_A_5 {
   meta:
      description = "PYAS_Rules_A_5"
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
      uint16(0) == 0x5a4d and filesize < 2000KB and
      $x1 and 3 of them
}

rule PYAS_Rules_A_6 {
   meta:
      description = "PYAS_Rules_A_6"
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
      $s4 = "afeffefeeffea" ascii
      $s5 = "ffeefeffeefa" ascii
      $s6 = "ffeeffefeef" ascii
      $s7 = "ffeeffeeffe" ascii
      $s8 = "ffefeeffefe" ascii
      $s9 = "feffefefe" ascii
      $s10 = "feffeefeffea" ascii
      $s11 = "affeefefeffe" ascii
      $s12 = "fefefeffefe" ascii
      $s13 = "feffefeeffe" ascii
      $s14 = "ffeeffeefef" ascii
      $s15 = "fefefeffefea" ascii
      $s16 = "feffefeeffe" ascii
      $s17 = "afeffefeeffea" ascii
      $s18 = "ffeefeffeefa" ascii
      $s19 = "afefefeffefe" ascii
      $s20 = "vffefeeffe" fullword ascii
      $s21 = "afeffefefe" ascii
      $s22 = "fefefeffea" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      1 of ($x*) and 5 of them
}

rule PYAS_Rules_A_7 {
   meta:
      description = "PYAS_Rules_A_462"
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
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      6 of them
}

rule PYAS_Rules_A_8 {
   meta:
      description = "PYAS_Rules_A_8"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "TASKKILL /F /IM" wide nocase
      $x2 = "cmd.exe /c ping 0" wide nocase
      $x3 = "cmd.exe /k ping 0" wide nocase
      $s1 = "system32\\SHELL32.dll" wide nocase
      $s2 = "system32\\mmc.exe" wide nocase
      $s3 = "Execute ERROR" fullword wide
      $s4 = "WindowsServiceMode.exe" fullword wide
      $s5 = "processhacker" fullword wide
      $s6 = "Microsoft" wide nocase
      $s7 = "shutdown" wide nocase
      $s8 = "Download ERROR" fullword wide
      $s9 = "Executed As " fullword wide
      $s10 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
      $s11 = "ScanProcess" fullword ascii
      $s12 = "HKEY_CURRENT_USER\\Software\\" wide nocase
      $s13 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\" wide nocase
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 5 of them
}

rule PYAS_Rules_A_9 {
   meta:
      description = "PYAS_Rules_A_9"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "$GETPASSWORD1:IDOK" fullword ascii
      $s2 = "$GETPASSWORD1:SIZE" fullword ascii
      $s3 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii
      $s4 = "$GETPASSWORD1:CAPTION" fullword ascii
      $s5 = "$GETPASSWORD1:IDCANCEL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      5 of them
}

rule PYAS_Rules_A_10 {
   meta:
      description = "PYAS_Rules_A_10"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $x1 = "DQuasar.Common" ascii
      $x2 = "PublicKeyToken" ascii
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
      $s19 = "GetKeyShareHelloRetryRequest" ascii
      $s20 = "GetKeyShareServerHello" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      1 of ($x*) and 5 of them
}

rule PYAS_Rules_A_11 {
   meta:
      description = "PYAS_Rules_A_11"
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
      uint16(0) == 0x5a4d and filesize < 100KB and
      6 of them
}

rule PYAS_Rules_A_12 {
   meta:
      description = "PYAS_Rules_A_12"
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
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 5 of them
}

rule PYAS_Rules_A_13 {
   meta:
      description = "PYAS_Rules_A_13"
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
      uint16(0) == 0x5a4d and filesize < 4000KB and
      6 of them
}

rule PYAS_Rules_A_14 {
   meta:
      description = "PYAS_Rules_A_14"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "jdownloader" wide nocase
      $s2 = "cmdvrt32.dll" fullword wide
      $s3 = "accounts.dat" fullword wide
      $s4 = "SxIn.dll" fullword wide
      $s5 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" fullword wide
      $s6 = "\\\"(hostname|encryptedPassword|encryptedUsername)\":\"(.*?)\"" fullword wide
      $s7 = "http://ip-api.com/" wide
      $s8 = "mRzIs.exe" fullword wide
      $s9 = "SmtpPassword" fullword wide
      $s10 = "\\Program Files (x86)\\FTP Commander" wide
      $s14 = "privateinternetaccess.com" fullword wide
      $s15 = "paltalk.com" fullword wide
      $s16 = "discord.com" fullword wide
      $s17 = "Sf2.dll" fullword wide
      $s18 = "https://account.dyn.com/" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      6 of them
}

rule PYAS_Rules_A_15 {
   meta:
      description = "PYAS_Rules_A_15"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "aGVpbWdsaWduZGRramdvZmtjYmdla2hlbmJofE94eWdlbgptZ2Zma2ZiaWRpaGpwb2FvbWFqbGJnY2hkZGxpY2dwbnxQYWxpV2FsbGV0CmFvZGtrYWduYWRjYm9iZnBn" wide
      $s2 = "Could not list processes locking resource." wide
      $s3 = "Failed to get size of result." wide
      $s4 = "DownloadAndExecuteUpdate" fullword ascii
      $s5 = "loginusers.vdf" fullword wide
      $s7 = "SELProcessInfoECT * FRProcessInfoOM Win32_PrProcessInfoocess Where SProcessInfoessionId='" fullword wide
      $s8 = "get_encrypted_key" fullword ascii
      $s9 = "Tokens.txt" fullword wide
      $s10 = "AntiDisplayDownvirusProDisplayDownduct|ADisplayDownntiSpyDisplayDownWareProdDisplayDownuct|FirewaDisplayDownllProdDisplayDownuct" wide
      $s11 = "VisualPlus-Debug.log" fullword wide
      $s12 = "Total of RAMExecutablePath" fullword wide
      $s13 = "loginPairs" fullword ascii
      $s15 = "Software\\Valve\\SteamLogin Data" fullword wide
      $s16 = "SELSystem.Windows.FormsECT * FRSystem.Windows.FormsOM WinSystem.Windows.Forms32_ProcSystem.Windows.Formsessor" fullword wide
      $s17 = "SELSystem.LinqECT * FRSystem.LinqOM WinSystem.Linq32_VideoCoSystem.Linqntroller" fullword wide
      $s18 = "SELESystem.ManagementCT * FRSystem.ManagementOM WiSystem.Managementn32_DisSystem.ManagementkDrivSystem.Managemente" fullword wide
      $s19 = "%localappdata%\\" fullword wide
      $s20 = "NoEngrdVpEngn.exe*" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      6 of them
}

rule PYAS_Rules_A_16 {
   meta:
      description = "PYAS_Rules_A_16"
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
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ($x1 and $x2) and 6 of them
}
