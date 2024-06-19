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
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 6 of them
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
      uint16(0) == 0x5a4d and filesize < 30000KB and
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
      uint16(0) == 0x5a4d and filesize < 4000KB and
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
      uint16(0) == 0x5a4d and filesize < 5000KB and
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
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
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
      uint16(0) == 0x5a4d and filesize < 50000KB and
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
      uint16(0) == 0x5a4d and filesize < 15000KB and
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
      uint16(0) == 0x5a4d and filesize < 1000KB and
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
      uint16(0) == 0x5a4d and filesize < 30000KB and
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
      uint16(0) == 0x5a4d and filesize < 2000KB and
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
      uint16(0) == 0x5a4d and filesize < 2000KB and
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
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ($x1 and $x2) and 6 of them
}

rule PYAS_Rules_A_17 {
   meta:
      description = "PYAS_Rules_A_17"
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

rule PYAS_Rules_A_18 {
   meta:
      description = "PYAS_Rules_A_18"
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

rule PYAS_Rules_A_19 {
   meta:
      description = "PYAS_Rules_A_19"
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

rule PYAS_Rules_A_20 {
   meta:
      description = "PYAS_Rules_A_20"
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

rule PYAS_Rules_A_21 {
   meta:
      description = "PYAS_Rules_A_21"
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

rule PYAS_Rules_A_22 {
   meta:
      description = "PYAS_Rules_A_22"
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

import "pe"
rule PYAS_Rules_A_23 {
   meta:
      description = "PYAS_Rules_A_23"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "ttt.exe" fullword wide
      $s2 = "-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '" wide
      $s3 = "Kutc64InaW" fullword ascii
      $s4 = "Cronos-Crypter" fullword wide
      $s5 = "<PrivateImplementationDetails>{EEC0C451-6B9A-45A0-A879-90E70D3033F5}" fullword ascii
      $s6 = "SetProcessSecurityDescriptor" fullword ascii
      $s7 = "Systemhost" fullword wide
      $s8 = "decKey" fullword ascii
      $s9 = "StartupInformation" fullword ascii
      $s10 = "InstallRegistry" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      6 of them
}

import "pe"
rule PYAS_Rules_A_24 {
   meta:
      description = "PYAS_Rules_A_24"
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

rule PYAS_Rules_A_25 {
   meta:
      description = "PYAS_Rules_A_25"
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

rule PYAS_Rules_A_26 {
   meta:
      description = "PYAS_Rules_A_26"
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

rule PYAS_Rules_A_27 {
   meta:
      description = "PYAS_Rules_A_27"
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

rule PYAS_Rules_A_28 {
   meta:
      description = "PYAS_Rules_A_28"
      author = "PYAS Security"
      date = "2024-06-12"
   strings:
      $s1 = "GNU C11 6.3.0 -mtune=generic -march=i586 -g -g -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" fullword ascii
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
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      6 of them
}

rule PYAS_Rules_A_29 {
   meta:
      description = "PYAS_Rules_A_29"
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
