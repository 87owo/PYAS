private rule Script_Text_Reasonable
{
    condition:
        filesize >= 20 and filesize < 20MB and uint16(0) != 0x5A4D
}

rule TrojanDownloader_JS_Nemucod
{
    meta:
        description = "Nemucod downloader with characteristic WinHTTP, environment and rundll32 execution workflow"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host files; high-confidence family cluster"
        evidence = "compound condition requires WSH object construction plus at least two Nemucod-associated WinHTTP, architecture, environment-expansion or rundll32 workflow signals"
        attribution = "family label follows corpus taxonomy and the jointly observed execution workflow; no single marker is sufficient"
    strings:
        $host = "WScript" ascii wide nocase
        $create_1 = "CreateObject(" ascii wide nocase
        $create_2 = "ActiveXObject(" ascii wide nocase
        $family_1 = "WinHttp.WinHttpRequest.5.1" ascii wide nocase
        $family_2 = "WScript.Quit" ascii wide nocase
        $family_3 = "PROCESSOR_ARCHITECTURE" ascii wide nocase
        $family_4 = "System32\\rundll32.exe" ascii wide nocase
        $family_5 = "SysWOW64\\rundll32.exe" ascii wide nocase
        $family_6 = "ExpandEnvironmentStrings" ascii wide nocase
        $network_1 = "http://" ascii wide nocase
        $network_2 = "https://" ascii wide nocase
        $network_3 = ".Send(" ascii wide nocase
    condition:
        Script_Text_Reasonable and $host and 1 of ($create_*) and
        $family_1 and $family_2 and 1 of ($family_3, $family_4, $family_5, $family_6) and
        1 of ($network_*)
}

rule Trojan_JS_FragmentedWSH
{
    meta:
        description = "Fragmented Windows Script Host loader reconstructing network, stream and execution objects"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host files; cross-family capability cluster"
        evidence = "compound condition requires fragmented object vocabulary, reconstruction logic and execution syntax"
        attribution = "generic fragmented-loader capability; deliberately not attributed to Nemucod without its stronger workflow signals"
    strings:
        $frag_1 = "WScrip" ascii wide
        $frag_2 = "reateO" ascii wide
        $frag_3 = "ADODB." ascii wide
        $frag_4 = "saveT" ascii wide
        $frag_5 = "Resp" ascii wide
        $frag_6 = "XML" ascii wide
        $frag_7 = "HTTP" ascii wide
        $frag_8 = "%TE" ascii wide
        $build_1 = "new Array" ascii wide
        $build_2 = "fromCharCode" ascii wide
        $build_3 = "charCodeAt" ascii wide
        $indexed = /\[[0-9]{1,4}\][ \t]*=[ \t]*['\"][^'\"]{1,12}['\"]/
        $exec_1 = ".Run(" ascii wide
        $exec_2 = "ShellExecute" ascii wide
        $exec_3 = "WScript" ascii wide
    condition:
        Script_Text_Reasonable and
        ((6 of ($frag_*) and 1 of ($build_*) and 1 of ($exec_*)) or
         (#indexed >= 80 and 4 of ($frag_*) and 1 of ($build_*))) and
        not TrojanDownloader_JS_Nemucod
}

rule TrojanDownloader_JS_WSHLoader
{
    meta:
        description = "Windows Script Host downloader that retrieves, writes and executes a payload"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and JavaScript files executed by Windows Script Host"
        evidence = "compound condition requires WSH object creation, HTTP client, ADODB stream persistence, response-body access and process execution"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $host_1 = "WScript.Shell" ascii wide nocase
        $host_2 = "Shell.Application" ascii wide nocase
        $create = "ActiveXObject" ascii wide nocase
        $net_1 = "MSXML2.XMLHTTP" ascii wide nocase
        $net_2 = "Microsoft.XMLHTTP" ascii wide nocase
        $net_3 = "WinHttp.WinHttpRequest" ascii wide nocase
        $stream = "ADODB.Stream" ascii wide nocase
        $save = "SaveToFile" ascii wide nocase
        $body = "responseBody" ascii wide nocase
        $exec_1 = ".Run(" ascii wide nocase
        $exec_2 = "ShellExecute" ascii wide nocase
    condition:
        Script_Text_Reasonable and $create and 1 of ($host_*) and 1 of ($net_*) and
        $stream and $save and $body and 1 of ($exec_*)
}

rule Trojan_Script_WSHDownloader
{
    meta:
        description = "WSH script downloader that retrieves, persists and launches an external payload"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript, JScript, VBE-decoded text and mixed WSF script files"
        evidence = "compound condition requires VB CreateObject syntax, WSH execution, HTTP retrieval, binary stream writing and payload launch"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $vbs_1 = "CreateObject(" ascii wide nocase
        $vbs_2 = "On Error Resume Next" ascii wide nocase
        $host = "WScript.Shell" ascii wide nocase
        $net_1 = "MSXML2.XMLHTTP" ascii wide nocase
        $net_2 = "Microsoft.XMLHTTP" ascii wide nocase
        $net_3 = "WinHttp.WinHttpRequest" ascii wide nocase
        $stream = "ADODB.Stream" ascii wide nocase
        $save = "SaveToFile" ascii wide nocase
        $body = "responseBody" ascii wide nocase
        $exec_1 = ".Run " ascii wide nocase
        $exec_2 = ".Run(" ascii wide nocase
        $exec_3 = "ShellExecute" ascii wide nocase
    condition:
        Script_Text_Reasonable and all of ($vbs_*) and $host and 1 of ($net_*) and
        $stream and $save and $body and 1 of ($exec_*)
}

rule TrojanDownloader_PS_WebClient
{
    meta:
        description = "PowerShell downloader with payload retrieval, local staging and concealed or bypassed execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell and command scripts containing PowerShell payloads"
        evidence = "compound condition requires network client, download method, execution primitive, remote URI, staging path and concealment or policy bypass"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $client_1 = "System.Net.WebClient" ascii wide nocase
        $client_2 = "New-Object Net.WebClient" ascii wide nocase
        $client_3 = "Invoke-WebRequest" ascii wide nocase
        $download_1 = "DownloadString" ascii wide nocase
        $download_2 = "DownloadFile" ascii wide nocase
        $download_3 = "DownloadData" ascii wide nocase
        $exec_1 = "Invoke-Expression" ascii wide nocase
        $exec_2 = "Start-Process" ascii wide nocase
        $exec_3 = "IEX(" ascii wide nocase
        $stage_1 = "$env:TEMP" ascii wide nocase
        $stage_2 = "\\Users\\Public\\" ascii wide nocase
        $stage_3 = "GetTempPath" ascii wide nocase
        $stealth_1 = "WindowStyle Hidden" ascii wide nocase
        $stealth_2 = "ExecutionPolicy Bypass" ascii wide nocase
        $stealth_3 = "-NoProfile" ascii wide nocase
        $uri_1 = "http://" ascii wide nocase
        $uri_2 = "https://" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($client_*) and 1 of ($download_*) and
        1 of ($exec_*) and 1 of ($stage_*) and 1 of ($stealth_*) and 1 of ($uri_*)
}

rule Trojan_PS_MemoryLoader
{
    meta:
        description = "PowerShell in-memory loader combining encoded data, transformation and managed assembly invocation"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell and embedded PowerShell script content"
        evidence = "compound condition requires Base64 decoding, assembly loading, decompression or decryption, dynamic invocation and stealth"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $decode = "FromBase64String" ascii wide nocase
        $load_1 = "Reflection.Assembly]::Load" ascii wide nocase
        $load_2 = "Reflection.Assembly::Load" ascii wide nocase
        $transform_1 = "GZipStream" ascii wide nocase
        $transform_2 = "DeflateStream" ascii wide nocase
        $transform_3 = "CreateDecryptor" ascii wide nocase
        $invoke_1 = "EntryPoint.Invoke" ascii wide nocase
        $invoke_2 = "Invoke-Expression" ascii wide nocase
        $stealth_1 = "WindowStyle Hidden" ascii wide nocase
        $stealth_2 = "ExecutionPolicy Bypass" ascii wide nocase
        $stealth_3 = "CreateNoWindow" ascii wide nocase
    condition:
        Script_Text_Reasonable and $decode and 1 of ($load_*) and 1 of ($transform_*) and
        1 of ($invoke_*) and 1 of ($stealth_*)
}

rule Trojan_PS_AmsiBypass
{
    meta:
        description = "PowerShell reflection-based AMSI state tampering followed by dynamic payload execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell and command scripts containing PowerShell code"
        evidence = "compound condition requires AMSI identifiers, non-public static reflection, field mutation and a decode or execution primitive"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $amsi_1 = "AmsiUtils" ascii wide nocase
        $amsi_2 = "amsiInitFailed" ascii wide nocase
        $amsi_3 = "amsiContext" ascii wide nocase
        $reflect_1 = "NonPublic,Static" ascii wide nocase
        $reflect_2 = "GetField(" ascii wide nocase
        $mutate_1 = "SetValue(" ascii wide nocase
        $mutate_2 = "Marshal.Copy" ascii wide nocase
        $exec_1 = "Invoke-Expression" ascii wide nocase
        $exec_2 = "FromBase64String" ascii wide nocase
        $exec_3 = "DownloadString" ascii wide nocase
    condition:
        Script_Text_Reasonable and 2 of ($amsi_*) and all of ($reflect_*) and
        1 of ($mutate_*) and 1 of ($exec_*)
}

rule Trojan_BAT_CommandObfuscator
{
    meta:
        description = "Batch command reconstruction through large single-character variable dictionaries and delayed expansion"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "batch-compatible text, including mislabeled script-extension content"
        evidence = "structural condition requires many one-character definitions and expansions plus delayed, CALL-based or substring reconstruction and an execution anchor"
        attribution = "generic obfuscation capability; not a verified malware-family attribution"
    strings:
        $set_char = /[\r\n][ \t]*@?set[ \t]+[a-zA-Z0-9_]{6,}=[!-~][\r\n]/
        $expand = /%[a-zA-Z0-9_]{6,}%/
        $substring = /%[a-zA-Z0-9_]{2,}:~[-0-9]+,[-0-9]+%/
        $rebuild_1 = "EnableDelayedExpansion" ascii wide nocase
        $rebuild_2 = "call set" ascii wide nocase
        $rebuild_3 = "call %" ascii wide nocase
        $exec_1 = "powershell" ascii wide nocase
        $exec_2 = "cmd /c" ascii wide nocase
        $exec_3 = "mshta" ascii wide nocase
        $exec_4 = "wscript" ascii wide nocase
        $exec_5 = "cscript" ascii wide nocase
        $exec_6 = "rundll32" ascii wide nocase
    condition:
        Script_Text_Reasonable and #set_char >= 15 and #expand >= 20 and
        ($substring or 1 of ($rebuild_*)) and 1 of ($exec_*)
}

rule Trojan_BAT_LOLDownloader
{
    meta:
        description = "Batch downloader chaining a native transfer utility to staged payload execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "Windows batch, command and embedded command-line scripts"
        evidence = "compound condition requires native transfer, remote URI, writable staging, execution and cleanup or concealment"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $fetch_1 = "certutil" ascii wide nocase
        $fetch_2 = "bitsadmin" ascii wide nocase
        $fetch_3 = "curl.exe" ascii wide nocase
        $fetch_4 = "Invoke-WebRequest" ascii wide nocase
        $uri_1 = "http://" ascii wide nocase
        $uri_2 = "https://" ascii wide nocase
        $stage_1 = "%TEMP%" ascii wide nocase
        $stage_2 = "%APPDATA%" ascii wide nocase
        $stage_3 = "\\Users\\Public\\" ascii wide nocase
        $exec_1 = "start " ascii wide nocase
        $exec_2 = "cmd /c" ascii wide nocase
        $exec_3 = "powershell" ascii wide nocase
        $exec_4 = "rundll32" ascii wide nocase
        $cleanup_1 = " del " ascii wide nocase
        $cleanup_2 = "attrib +h" ascii wide nocase
        $cleanup_3 = "WindowStyle Hidden" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($fetch_*) and 1 of ($uri_*) and
        1 of ($stage_*) and 1 of ($exec_*) and 1 of ($cleanup_*)
}

rule Trojan_Linux_MultiArch
{
    meta:
        description = "Linux multi-architecture malware deployment with redundant fetch, execution and cleanup chains"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "POSIX shell scripts and mislabeled batch-extension shell content"
        evidence = "compound condition requires redundant download tools, executable permissions, multiple CPU labels and repeated remote references"
        attribution = "botnet deployment capability cluster; not a verified malware-family attribution"
    strings:
        $fetch_1 = "wget " ascii nocase
        $fetch_2 = "curl " ascii nocase
        $fetch_3 = "busybox wget" ascii nocase
        $permission_1 = "chmod 777" ascii nocase
        $permission_2 = "chmod +x" ascii nocase
        $arch_1 = "x86_64" ascii nocase
        $arch_2 = "i686" ascii nocase
        $arch_3 = "mipsel" ascii nocase
        $arch_4 = "mips" ascii nocase
        $arch_5 = "armv4" ascii nocase
        $arch_6 = "armv7" ascii nocase
        $arch_7 = "powerpc" ascii nocase
        $arch_8 = "sparc" ascii nocase
        $arch_9 = "m68k" ascii nocase
        $uri_1 = "http://" ascii nocase
        $uri_2 = "https://" ascii nocase
        $cleanup_1 = ";rm " ascii nocase
        $cleanup_2 = "rm -f" ascii nocase
    condition:
        Script_Text_Reasonable and 2 of ($fetch_*) and 1 of ($permission_*) and
        4 of ($arch_*) and (#uri_1 + #uri_2 >= 4) and 1 of ($cleanup_*)
}

rule Trojan_Linux_ArchDeploy
{
    meta:
        description = "Linux shell deployment script downloading and directly executing a broad set of architecture-specific payload binaries"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "POSIX shell scripts; multi-architecture payload deployment"
        evidence = "compound condition requires remote transfer, executable permission assignment, direct local execution and at least five architecture-specific filename suffixes"
        attribution = "generic IoT multi-architecture deployment capability; not a verified malware-family attribution"
    strings:
        $fetch_1 = "wget " ascii nocase
        $fetch_2 = "curl " ascii nocase
        $fetch_3 = "busybox wget" ascii nocase
        $remote_1 = "http://" ascii nocase
        $remote_2 = "https://" ascii nocase
        $permission_1 = "chmod 777" ascii nocase
        $permission_2 = "chmod +x" ascii nocase
        $execute = /;[ \t]*\.\/[A-Za-z0-9_.-]{3,}/
        $arch_1 = ".arm" ascii nocase
        $arch_2 = ".arm5" ascii nocase
        $arch_3 = ".arm6" ascii nocase
        $arch_4 = ".arm7" ascii nocase
        $arch_5 = ".m68k" ascii nocase
        $arch_6 = ".mips" ascii nocase
        $arch_7 = ".mpsl" ascii nocase
        $arch_8 = ".ppc" ascii nocase
        $arch_9 = ".sh4" ascii nocase
        $arch_10 = ".x86" ascii nocase
    condition:
        Script_Text_Reasonable and 1 of ($fetch_*) and 1 of ($remote_*) and
        1 of ($permission_*) and $execute and 5 of ($arch_*)
}

rule TrojanDownloader_Linux_Stager
{
    meta:
        description = "Linux shell stager that downloads into a temporary location, grants execution and removes artifacts"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "POSIX shell scripts"
        evidence = "compound condition requires remote retrieval, temporary staging, permission change, direct execution and cleanup"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $fetch_1 = "wget " ascii nocase
        $fetch_2 = "curl " ascii nocase
        $fetch_3 = "tftp " ascii nocase
        $stage_1 = "/tmp/" ascii
        $stage_2 = "/var/tmp/" ascii
        $stage_3 = "cd /tmp" ascii
        $perm_1 = "chmod +x" ascii nocase
        $perm_2 = "chmod 777" ascii nocase
        $exec_1 = "./" ascii
        $exec_2 = "sh " ascii nocase
        $cleanup_1 = "rm -f" ascii nocase
        $cleanup_2 = "rm -rf" ascii nocase
        $remote_1 = "http://" ascii nocase
        $remote_2 = "https://" ascii nocase
    condition:
        Script_Text_Reasonable and 1 of ($fetch_*) and 1 of ($stage_*) and
        1 of ($perm_*) and 1 of ($exec_*) and 1 of ($cleanup_*) and 1 of ($remote_*)
}

rule Backdoor_Linux_IRCBot
{
    meta:
        description = "Scripted IRC bot with protocol registration, command-channel handling and operating-system command execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "Perl, Python, PHP and shell-based IRC bots"
        evidence = "compound condition requires multiple IRC verbs, socket connectivity, channel messaging and an OS command primitive"
        attribution = "family cluster consistent with IRCBot behavior; not tied to a single implementation"
    strings:
        $irc_1 = "PRIVMSG" ascii nocase
        $irc_2 = "PING :" ascii nocase
        $irc_3 = "PONG :" ascii nocase
        $irc_4 = "NICK " ascii nocase
        $irc_5 = "USER " ascii nocase
        $irc_6 = "JOIN " ascii nocase
        $net_1 = "socket(" ascii nocase
        $net_2 = "IO::Socket" ascii nocase
        $net_3 = "fsockopen" ascii nocase
        $cmd_1 = "system(" ascii nocase
        $cmd_2 = "exec(" ascii nocase
        $cmd_3 = "/bin/sh" ascii nocase
        $cmd_4 = "shell_exec" ascii nocase
    condition:
        Script_Text_Reasonable and 4 of ($irc_*) and 1 of ($net_*) and 1 of ($cmd_*) and $irc_1
}

rule Backdoor_PHP_WebShell
{
    meta:
        description = "PHP web shell accepting request-controlled commands through layered decoding or direct process execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PHP and mixed server-side web files"
        evidence = "compound condition requires request input, decoding or dynamic evaluation, command execution and output handling"
        attribution = "web-shell capability cluster; not a verified malware-family attribution"
    strings:
        $php_tag = "<?php" ascii nocase
        $input_1 = "$_POST" ascii nocase
        $input_2 = "$_REQUEST" ascii nocase
        $input_3 = "$_COOKIE" ascii nocase
        $indexed_1 = "$_POST[" ascii nocase
        $indexed_2 = "$_REQUEST[" ascii nocase
        $indexed_3 = "$_COOKIE[" ascii nocase
        $upload = "$_FILES[" ascii nocase
        $env_1 = "php_uname" ascii nocase
        $env_2 = "getcwd(" ascii nocase
        $env_3 = "get_current_user" ascii nocase
        $env_4 = "move_uploaded_file" ascii nocase
        $setup_1 = "set_time_limit(" ascii nocase
        $setup_2 = "ini_set(" ascii nocase
        $setup_3 = "error_reporting(" ascii nocase
        $decode_1 = "base64_decode" ascii nocase
        $decode_2 = "gzinflate" ascii nocase
        $decode_3 = "str_rot13" ascii nocase
        $dynamic_1 = "eval(" ascii nocase
        $dynamic_2 = "assert(" ascii nocase
        $exec_1 = "shell_exec(" ascii nocase
        $exec_2 = "passthru(" ascii nocase
        $exec_3 = "proc_open(" ascii nocase
        $exec_4 = "popen(" ascii nocase
        $exec_5 = "system(" ascii nocase
        $output_1 = "echo " ascii nocase
        $output_2 = "print " ascii nocase
    condition:
        Script_Text_Reasonable and $php_tag and 1 of ($input_*) and
        1 of ($indexed_*) and $upload and 2 of ($env_*) and 1 of ($setup_*) and
        ((1 of ($decode_*) and 1 of ($dynamic_*)) or 2 of ($exec_*)) and
        1 of ($exec_*) and 1 of ($output_*)
}

rule Backdoor_JSP_WebShell
{
    meta:
        description = "JSP web shell executing request-controlled operating-system commands and returning process output"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JSP and Java server-side script files"
        evidence = "compound condition requires request parameter access, Java process creation, command execution and output-stream handling"
        attribution = "web-shell capability cluster; not a verified malware-family attribution"
    strings:
        $input_1 = "request.getParameter" ascii nocase
        $input_2 = "getParameter(" ascii nocase
        $exec_1 = "Runtime.getRuntime" ascii nocase
        $exec_2 = "ProcessBuilder" ascii nocase
        $command_1 = ".exec(" ascii nocase
        $command_2 = "cmd.exe" ascii nocase
        $command_3 = "/bin/sh" ascii nocase
        $output_1 = "getInputStream" ascii nocase
        $output_2 = "getOutputStream" ascii nocase
        $output_3 = "BufferedReader" ascii nocase
    condition:
        Script_Text_Reasonable and 1 of ($input_*) and 1 of ($exec_*) and
        1 of ($command_*) and 2 of ($output_*)
}

rule Backdoor_ASP_WebShell
{
    meta:
        description = "Classic ASP web shell invoking commands supplied through an HTTP request"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "ASP, HTML and mixed IIS server-side script files"
        evidence = "compound condition requires ASP request input, server COM creation, WSH command execution and response output"
        attribution = "web-shell capability cluster; not a verified malware-family attribution"
    strings:
        $input_1 = "Request.Form(" ascii nocase
        $input_2 = "Request(" ascii nocase
        $server = "Server.CreateObject" ascii nocase
        $shell = "WScript.Shell" ascii nocase
        $exec_1 = ".Exec(" ascii nocase
        $exec_2 = ".Run(" ascii nocase
        $cmd_1 = "cmd.exe" ascii nocase
        $cmd_2 = "cmd /c" ascii nocase
        $output_1 = "Response.Write" ascii nocase
        $output_2 = "StdOut.ReadAll" ascii nocase
    condition:
        Script_Text_Reasonable and 1 of ($input_*) and $server and $shell and
        1 of ($exec_*) and 1 of ($cmd_*) and all of ($output_*)
}

rule TrojanSpy_Python_BrowserStealer
{
    meta:
        description = "Python browser credential stealer combining database access, DPAPI decryption and external exfiltration"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "Python scripts and embedded Python source"
        evidence = "compound condition requires browser stores, SQLite, Windows credential decryption, secret fields and external reporting"
        attribution = "credential-stealer capability cluster; not a verified malware-family attribution"
    strings:
        $store_1 = "Login Data" ascii wide nocase
        $store_2 = "Local State" ascii wide nocase
        $store_3 = "Cookies" ascii wide nocase
        $db = "sqlite3" ascii wide nocase
        $crypto_1 = "win32crypt" ascii wide nocase
        $crypto_2 = "CryptUnprotectData" ascii wide nocase
        $secret_1 = "password_value" ascii wide nocase
        $secret_2 = "encrypted_value" ascii wide nocase
        $exfil_1 = "requests.post" ascii wide nocase
        $exfil_2 = "discord.com/api/webhooks" ascii wide nocase
        $exfil_3 = "api.telegram.org/bot" ascii wide nocase
        $exfil_4 = "sendDocument" ascii wide nocase
    condition:
        Script_Text_Reasonable and 2 of ($store_*) and $db and 1 of ($crypto_*) and
        1 of ($secret_*) and 1 of ($exfil_*)
}

rule TrojanSpy_Python_Keylogger
{
    meta:
        description = "Python keylogger that captures keyboard events and transmits or stores collected keystrokes"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "Python scripts and embedded Python source"
        evidence = "compound condition requires keyboard hooks, press and release callbacks, context capture and a reporting or storage sink"
        attribution = "keylogging capability cluster; not a verified malware-family attribution"
    strings:
        $hook_1 = "pynput" ascii nocase
        $hook_2 = "keyboard.Listener" ascii nocase
        $event_1 = "on_press" ascii nocase
        $event_2 = "on_release" ascii nocase
        $context_1 = "GetForegroundWindow" ascii nocase
        $context_2 = "clipboard" ascii nocase
        $sink_1 = "requests.post" ascii nocase
        $sink_2 = "smtplib" ascii nocase
        $sink_3 = "sendmail" ascii nocase
        $sink_4 = "open(" ascii nocase
    condition:
        Script_Text_Reasonable and all of ($hook_*) and all of ($event_*) and
        1 of ($context_*) and 1 of ($sink_*)
}

rule Backdoor_PS_ReverseShell
{
    meta:
        description = "PowerShell TCP reverse shell with bidirectional stream command execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell and embedded PowerShell scripts"
        evidence = "compound condition requires TCP client, network stream, byte-buffer loop, shell execution and response writing"
        attribution = "reverse-shell capability cluster; not a verified malware-family attribution"
    strings:
        $net_1 = "System.Net.Sockets.TCPClient" ascii wide nocase
        $net_2 = "Net.Sockets.TCPClient" ascii wide nocase
        $stream = "GetStream(" ascii wide nocase
        $read_1 = ".Read(" ascii wide nocase
        $read_2 = "New-Object Byte[]" ascii wide nocase
        $shell_1 = "Invoke-Expression" ascii wide nocase
        $shell_2 = "iex " ascii wide nocase
        $shell_3 = "cmd.exe /c" ascii wide nocase
        $write_1 = ".Write(" ascii wide nocase
        $write_2 = "ASCIIEncoding" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($net_*) and $stream and all of ($read_*) and
        1 of ($shell_*) and all of ($write_*)
}

rule VirTool_PS_ShellcodeLoader
{
    meta:
        description = "PowerShell native-memory shellcode runner using dynamic API resolution and unmanaged execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell and embedded PowerShell scripts"
        evidence = "compound condition requires allocation, memory copy, unmanaged execution, wait semantics, payload material and API resolution"
        attribution = "shellcode-loader capability cluster; may include Meterpreter and related frameworks"
    strings:
        $alloc_1 = "VirtualAlloc" ascii wide nocase
        $alloc_2 = "VirtualAllocEx" ascii wide nocase
        $copy_1 = "Marshal.Copy" ascii wide nocase
        $copy_2 = "WriteProcessMemory" ascii wide nocase
        $exec_1 = "CreateThread" ascii wide nocase
        $exec_2 = "GetDelegateForFunctionPointer" ascii wide nocase
        $exec_3 = "CreateRemoteThread" ascii wide nocase
        $wait_1 = "WaitForSingleObject" ascii wide nocase
        $wait_2 = "WaitForExit" ascii wide nocase
        $payload_1 = "FromBase64String" ascii wide nocase
        $payload_2 = "[Byte[]]" ascii wide nocase
        $resolve_1 = "GetProcAddress" ascii wide nocase
        $resolve_2 = "GetModuleHandle" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($alloc_*) and 1 of ($copy_*) and
        1 of ($exec_*) and 1 of ($wait_*) and 1 of ($payload_*) and 1 of ($resolve_*)
}

rule TrojanSpy_Script_ClipBanker
{
    meta:
        description = "Clipboard cryptocurrency address replacement loop"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell, Python and mixed scripts"
        evidence = "compound condition requires clipboard read and write, continuous polling, cryptocurrency terminology and replacement"
        attribution = "clip-banker capability cluster; not a verified malware-family attribution"
    strings:
        $read_1 = "Get-Clipboard" ascii wide nocase
        $read_2 = "clipboard_get" ascii wide nocase
        $read_3 = "paste(" ascii wide nocase
        $write_1 = "Set-Clipboard" ascii wide nocase
        $write_2 = "clipboard_set" ascii wide nocase
        $write_3 = "copy(" ascii wide nocase
        $loop_1 = "while ($true)" ascii wide nocase
        $loop_2 = "while True" ascii wide nocase
        $loop_3 = "Start-Sleep" ascii wide nocase
        $coin_1 = "bitcoin" ascii wide nocase
        $coin_2 = "ethereum" ascii wide nocase
        $coin_3 = "monero" ascii wide nocase
        $coin_4 = "wallet" ascii wide nocase
        $replace_1 = "Replace(" ascii wide nocase
        $replace_2 = "re.sub(" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($read_*) and 1 of ($write_*) and
        1 of ($loop_*) and 1 of ($coin_*) and 1 of ($replace_*)
}

rule Exploit_RTF_Equation
{
    meta:
        description = "RTF embedded Equation Editor object carrying exploit-oriented object data"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "RTF documents exploiting Equation Editor vulnerabilities such as CVE-2017-11882 and related variants"
        evidence = "compound condition requires RTF structure, embedded object data, Equation identity and automatic update or a large hex-data run"
        attribution = "exploit technique cluster; exact CVE attribution depends on object payload details"
    strings:
        $rtf = "{\\rtf1" ascii nocase
        $object = "\\object" ascii nocase
        $objdata = "\\objdata" ascii nocase
        $class_1 = "Equation.3" ascii wide nocase
        $class_2 = "Equation.DSMT4" ascii wide nocase
        $class_3 = "EqnEdt32" ascii wide nocase
        $update_1 = "\\objupdate" ascii nocase
        $update_2 = "\\objautlink" ascii nocase
        $layout_1 = "\\objw" ascii nocase
        $layout_2 = "\\objh" ascii nocase
    condition:
        filesize < 10MB and $rtf and $object and $objdata and 1 of ($class_*) and
        (1 of ($update_*) or all of ($layout_*))
}

rule Exploit_RTF_OLELink
{
    meta:
        description = "RTF OLE link object referencing a remote resource for code or payload retrieval"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "RTF documents using OLE link exploitation, including CVE-2017-0199-style delivery"
        evidence = "compound condition requires RTF object data, OLE link identity, remote URI and automatic object update"
        attribution = "exploit technique cluster; exact CVE attribution depends on object payload details"
    strings:
        $rtf = "{\\rtf1" ascii nocase
        $objdata = "\\objdata" ascii nocase
        $class_1 = "OLE2Link" ascii wide nocase
        $class_2 = "Package" ascii wide nocase
        $remote_1 = "http://" ascii wide nocase
        $remote_2 = "https://" ascii wide nocase
        $update_1 = "\\objupdate" ascii nocase
        $update_2 = "\\objautlink" ascii nocase
    condition:
        filesize < 10MB and $rtf and $objdata and 1 of ($class_*) and
        1 of ($remote_*) and 1 of ($update_*)
}

rule Trojan_LNK_ScriptLauncher
{
    meta:
        description = "Windows shortcut launching an interpreter or LOLBin with remote, encoded or temporary payload material"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "Windows LNK files and shortcut-like binary content"
        evidence = "compound condition requires LNK header, interpreter or LOLBin, payload location or encoding and concealment or execution arguments"
        attribution = "shortcut-loader capability cluster; not a verified malware-family attribution"
    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $host_1 = "powershell" ascii wide nocase
        $host_2 = "cmd.exe" ascii wide nocase
        $host_3 = "mshta" ascii wide nocase
        $host_4 = "rundll32" ascii wide nocase
        $host_5 = "wscript" ascii wide nocase
        $payload_1 = "http://" ascii wide nocase
        $payload_2 = "https://" ascii wide nocase
        $payload_3 = "%TEMP%" ascii wide nocase
        $payload_4 = "%APPDATA%" ascii wide nocase
        $payload_5 = "EncodedCommand" ascii wide nocase
        $arg_1 = "WindowStyle Hidden" ascii wide nocase
        $arg_2 = "ExecutionPolicy Bypass" ascii wide nocase
        $arg_3 = " /c " ascii wide nocase
        $arg_4 = "javascript:" ascii wide nocase
    condition:
        filesize >= 76 and filesize < 5MB and $lnk_header at 0 and
        1 of ($host_*) and 1 of ($payload_*) and 1 of ($arg_*)
}

rule Ransom_Script_RecoverySabotage
{
    meta:
        description = "Scripted ransomware combining an extortion message, recovery destruction and file-encryption workflow"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell, batch, Python, JavaScript and VBScript ransomware"
        evidence = "compound condition requires ransom language, recovery sabotage, file traversal, cryptographic behavior and payment or contact instructions"
        attribution = "ransomware capability cluster; not a verified malware-family attribution"
    strings:
        $note_1 = "files have been encrypted" ascii wide nocase
        $note_2 = "your files are encrypted" ascii wide nocase
        $note_3 = "decrypt your files" ascii wide nocase
        $sabotage_1 = "delete shadows" ascii wide nocase
        $sabotage_2 = "shadowcopy delete" ascii wide nocase
        $sabotage_3 = "recoveryenabled no" ascii wide nocase
        $sabotage_4 = "delete catalog" ascii wide nocase
        $traverse_1 = "Get-ChildItem" ascii wide nocase
        $traverse_2 = "os.walk(" ascii wide nocase
        $traverse_3 = "FileSystemObject" ascii wide nocase
        $crypto_1 = "CreateEncryptor" ascii wide nocase
        $crypto_2 = "Fernet(" ascii wide nocase
        $crypto_3 = "CryptEncrypt" ascii wide nocase
        $crypto_4 = "AES" ascii wide nocase
        $pay_1 = "bitcoin" ascii wide nocase
        $pay_2 = ".onion" ascii wide nocase
        $pay_3 = "wallet" ascii wide nocase
        $pay_4 = "contact us" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($note_*) and 1 of ($sabotage_*) and
        1 of ($traverse_*) and 1 of ($crypto_*) and 1 of ($pay_*)
}

rule Trojan_JS_ObfuscatedLoader
{
    meta:
        description = "Heavily obfuscated JavaScript loader with dynamic decoding and WSH or network-backed execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JavaScript, JScript, HTML and WSF script content"
        evidence = "structural condition requires repeated hexadecimal identifiers or indexed fragments, character decoding, dynamic evaluation and WSH or network anchors"
        attribution = "generic obfuscated-loader cluster; not a verified malware-family attribution"
    strings:
        $hex_id = /_0x[0-9a-fA-F]{4,}/
        $indexed = /\[[0-9]{1,4}\][ \t]*=[ \t]*['\"][^'\"]{1,12}['\"]/
        $decode_1 = "fromCharCode" ascii wide nocase
        $decode_2 = "charCodeAt" ascii wide nocase
        $decode_3 = "decodeURIComponent" ascii wide nocase
        $decode_4 = "unescape(" ascii wide nocase
        $dynamic_1 = "eval(" ascii wide nocase
        $dynamic_2 = "Function(" ascii wide
        $dynamic_3 = "constructor(" ascii wide nocase
        $anchor_1 = "ActiveXObject" ascii wide nocase
        $anchor_2 = "WScript" ascii wide nocase
        $anchor_3 = "XMLHTTP" ascii wide nocase
        $anchor_4 = "ADODB.Stream" ascii wide nocase
        $anchor_5 = "http://" ascii wide nocase
        $anchor_6 = "https://" ascii wide nocase
    condition:
        Script_Text_Reasonable and (#hex_id >= 12 or #indexed >= 40) and
        2 of ($decode_*) and 1 of ($dynamic_*) and
        1 of ($anchor_1, $anchor_2, $anchor_4) and 1 of ($anchor_3, $anchor_5, $anchor_6)
}

rule Trojan_VBS_ObfuscatedLoader
{
    meta:
        description = "Obfuscated VBScript loader reconstructing commands through character functions before dynamic execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript, VBE-decoded text and mixed WSF content"
        evidence = "structural condition requires high-volume Chr reconstruction, dynamic execution, COM creation and network, stream or shell anchors"
        attribution = "generic obfuscated-loader cluster; not a verified malware-family attribution"
    strings:
        $chr_1 = /ChrW?\([0-9]{2,3}\)/ nocase
        $chr_2 = /ChrW?\(&H[0-9a-fA-F]{2,4}\)/ nocase
        $dynamic_1 = "ExecuteGlobal" ascii wide nocase
        $dynamic_2 = "Execute(" ascii wide nocase
        $dynamic_3 = "Eval(" ascii wide nocase
        $object = "CreateObject(" ascii wide nocase
        $anchor_1 = "WScript.Shell" ascii wide nocase
        $anchor_2 = "XMLHTTP" ascii wide nocase
        $anchor_3 = "ADODB.Stream" ascii wide nocase
        $anchor_4 = "powershell" ascii wide nocase
        $anchor_5 = "http://" ascii wide nocase
        $anchor_6 = "https://" ascii wide nocase
    condition:
        Script_Text_Reasonable and (#chr_1 + #chr_2 >= 40) and
        1 of ($dynamic_*) and $object and 2 of ($anchor_*)
}

rule Trojan_HTA_ScriptLoader
{
    meta:
        description = "HTML Application loader instantiating a scriptable shell to launch concealed remote or encoded content"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "HTA, HTML and mixed script files"
        evidence = "compound condition requires HTA identity, COM shell creation, command interpreter, payload source and concealment or decoding"
        attribution = "HTA loader capability cluster; not a verified malware-family attribution"
    strings:
        $hta_1 = "<hta:application" ascii wide nocase
        $hta_2 = "applicationName=" ascii wide nocase
        $object_1 = "ActiveXObject" ascii wide nocase
        $object_2 = "CreateObject(" ascii wide nocase
        $shell_1 = "WScript.Shell" ascii wide nocase
        $shell_2 = "Shell.Application" ascii wide nocase
        $host_1 = "powershell" ascii wide nocase
        $host_2 = "cmd.exe" ascii wide nocase
        $host_3 = "mshta" ascii wide nocase
        $payload_1 = "http://" ascii wide nocase
        $payload_2 = "https://" ascii wide nocase
        $payload_3 = "FromBase64String" ascii wide nocase
        $payload_4 = "unescape(" ascii wide nocase
        $stealth_1 = "window.close" ascii wide nocase
        $stealth_2 = "showInTaskBar=\"no\"" ascii wide nocase
        $stealth_3 = "WindowStyle Hidden" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($hta_*) and 1 of ($object_*) and
        1 of ($shell_*) and 1 of ($host_*) and 1 of ($payload_*) and 1 of ($stealth_*)
}

rule TrojanSpy_HTML_CredentialExfil
{
    meta:
        description = "HTML credential-harvesting page sending password input to an external messaging or webhook endpoint"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "HTML, HTA and JavaScript phishing content"
        evidence = "compound condition requires password collection, form interception, scripted submission, external exfiltration and navigation control"
        attribution = "credential-phishing capability cluster; not a verified malware-family attribution"
    strings:
        $credential_1 = "type=\"password\"" ascii wide nocase
        $credential_2 = "type='password'" ascii wide nocase
        $intercept_1 = "preventDefault(" ascii wide nocase
        $intercept_2 = "addEventListener('submit" ascii wide nocase
        $send_1 = "fetch(" ascii wide nocase
        $send_2 = "XMLHttpRequest" ascii wide nocase
        $send_3 = "axios.post" ascii wide nocase
        $exfil_1 = "discord.com/api/webhooks" ascii wide nocase
        $exfil_2 = "discordapp.com/api/webhooks" ascii wide nocase
        $exfil_3 = "api.telegram.org/bot" ascii wide nocase
        $control_1 = "return false" ascii wide nocase
        $control_2 = "window.location" ascii wide nocase
        $control_3 = "location.replace" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($credential_*) and 1 of ($intercept_*) and
        1 of ($send_*) and 1 of ($exfil_*) and 1 of ($control_*)
}

rule Worm_Script_RemovableSpread
{
    meta:
        description = "Script worm propagating through removable drives with copied payloads and autorun or shortcut artifacts"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript, JScript and mixed WSF content"
        evidence = "compound condition requires filesystem drive enumeration, removable selection, self-copy, autorun or shortcut creation and hidden attributes"
        attribution = "removable-media worm capability cluster; not a verified malware-family attribution"
    strings:
        $fs = "Scripting.FileSystemObject" ascii wide nocase
        $drive_1 = ".Drives" ascii wide nocase
        $drive_2 = "DriveType" ascii wide nocase
        $drive_3 = "IsReady" ascii wide nocase
        $copy_1 = "CopyFile" ascii wide nocase
        $copy_2 = "CopyFolder" ascii wide nocase
        $artifact_1 = "autorun.inf" ascii wide nocase
        $artifact_2 = "CreateShortcut" ascii wide nocase
        $artifact_3 = ".lnk" ascii wide nocase
        $hide_1 = "Attributes = 2" ascii wide nocase
        $hide_2 = "Attributes = 6" ascii wide nocase
        $hide_3 = "attrib +h" ascii wide nocase
    condition:
        Script_Text_Reasonable and $fs and 2 of ($drive_*) and 1 of ($copy_*) and
        2 of ($artifact_*) and 1 of ($hide_*)
}

rule Worm_JS_RemovableSpread
{
    meta:
        description = "JScript worm propagating through removable drives using copied payloads and deceptive shortcuts"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host JavaScript files"
        evidence = "compound condition requires WSH filesystem access, drive enumeration, removable-media logic, copying, shortcuts and hidden attributes"
        attribution = "removable-media worm capability cluster; not a verified malware-family attribution"
    strings:
        $create = "ActiveXObject" ascii wide nocase
        $fs = "Scripting.FileSystemObject" ascii wide nocase
        $drive_1 = ".Drives" ascii wide nocase
        $drive_2 = "DriveType" ascii wide nocase
        $drive_3 = "IsReady" ascii wide nocase
        $copy_1 = "CopyFile" ascii wide nocase
        $copy_2 = "Copy(" ascii wide nocase
        $shortcut_1 = "CreateShortcut" ascii wide nocase
        $shortcut_2 = ".lnk" ascii wide nocase
        $hide_1 = "Attributes" ascii wide nocase
        $hide_2 = "Hidden" ascii wide nocase
    condition:
        Script_Text_Reasonable and $create and $fs and 2 of ($drive_*) and
        1 of ($copy_*) and all of ($shortcut_*) and all of ($hide_*)
}

rule Obfuscated_Script_CharDictionary
{
    meta:
        description = "Batch or hybrid script reconstructing commands from a large randomized single-character dictionary"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "batch and mislabeled JavaScript or shell-extension text"
        evidence = "structural condition requires many randomized character assignments, heavy variable expansion and chained definitions or high-entropy junk lines"
        attribution = "generic command-obfuscation cluster; not a verified malware-family attribution"
    strings:
        $set_line = /[\r\n][ \t]*set[ \t]+[a-zA-Z0-9_]{4,}=[!-~]/ nocase
        $set_chain = /&&[ \t]*set[ \t]+[a-zA-Z0-9_]{4,}=[!-~]/ nocase
        $expand = /%[a-zA-Z0-9_]{4,}%/
        $js_dict = /[a-zA-Z0-9_]{4,}\[['\"][a-zA-Z0-9_]{4,}['\"]\][ \t]*=[ \t]*['\"][!-~]['\"]/ nocase
        $junk = /[\r\n][a-z]{4,}( [a-z]{3,}){6,}[\r\n]/ nocase
    condition:
        Script_Text_Reasonable and
        ((#set_chain >= 20 and #expand >= 35) or
         (#set_line >= 15 and #expand >= 35 and #junk >= 2) or
         (#set_line >= 20 and #js_dict >= 20))
}

rule Trojan_JS_CharMapLoader
{
    meta:
        description = "JavaScript command reconstruction using a large randomized character map and hidden shell launch"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and hybrid script cross-family capability cluster"
        evidence = "structural condition requires a large single-character object dictionary, extensive concatenation lookups and hidden non-blocking shell launch arguments"
        attribution = "generic char-map loader capability; corpus comparison did not support reliable Acsogenixx-only attribution"
    strings:
        $dict = /[a-zA-Z0-9_]{4,}\[['\"][a-zA-Z0-9_]{4,}['\"]\][ \t]*=[ \t]*['\"][!-~]['\"]/ nocase
        $lookup = /\+[a-zA-Z0-9_]{4,}\[['\"][a-zA-Z0-9_]{4,}['\"]\]/ nocase
        $launch_1 = ", 0, false" ascii wide nocase
        $launch_2 = ",0,false" ascii wide nocase
    condition:
        Script_Text_Reasonable and #dict >= 30 and #lookup >= 30 and 1 of ($launch_*)
}

rule TrojanDropper_JS_XMLDom
{
    meta:
        description = "Obfuscated JScript dropper decoding Base64 through XML DOM and writing it with ADODB stream"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host JavaScript files"
        evidence = "compound condition requires XML DOM typed-value decoding, Base64 data type, stream or COM creation, dynamic evaluation and string-level obfuscation"
        attribution = "dropper capability cluster; not a verified malware-family attribution"
    strings:
        $dom_1 = "nodeTypedValue" ascii wide nocase
        $base64 = "bin.base64" ascii wide nocase
        $stream_1 = "ADODB.Stream" ascii wide nocase
        $stream_2 = "CreateObject" ascii wide nocase
        $eval_1 = "eval(" ascii wide nocase
        $eval_2 = "Function(" ascii wide nocase
        $obf_1 = "\\x6D\\x69\\x63\\x72\\x6F\\x73\\x6F\\x66\\x74" ascii nocase
        $obf_2 = "\\u0070\\u0072\\u006f\\u0074\\u006f\\u0074\\u0079\\u0070\\u0065" ascii nocase
        $obf_3 = "String[\"prototype\"]" ascii nocase
    condition:
        Script_Text_Reasonable and $dom_1 and $base64 and 1 of ($stream_*) and
        1 of ($eval_*) and 1 of ($obf_*)
}

rule Trojan_VBS_GuLoader
{
    meta:
        description = "GuLoader script combining a decoy-function surface with a distinctive multilingual filler lexicon"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript files; high-confidence family cluster"
        evidence = "compound condition requires multiple uncommon decoy intrinsics, delayed or error-suppressed launch and at least five independently recurring family-cluster filler tokens"
        attribution = "family label follows corpus taxonomy and a high-specificity recurring lexicon; generic decoy loaders are excluded"
    strings:
        $decoy_1 = "FormatCurrency(" ascii wide nocase
        $decoy_2 = "FormatPercent(" ascii wide nocase
        $decoy_3 = "TimeSerial(" ascii wide nocase
        $decoy_4 = "TimeValue(" ascii wide nocase
        $decoy_5 = "RightB(" ascii wide nocase
        $decoy_6 = "FileLen(" ascii wide nocase
        $decoy_7 = "FreeFile" ascii wide nocase
        $delay_1 = "WScript.Sleep" ascii wide nocase
        $delay_2 = "On Error Resume Next" ascii wide nocase
        $launch_1 = "Shell.Application" ascii wide nocase
        $launch_2 = "WScript.Shell" ascii wide nocase
        $launch_3 = "GetObject(" ascii wide nocase
        $launch_4 = "winmgmts:" ascii wide nocase
        $family_1 = "substrin" ascii wide nocase
        $family_2 = "filmcensurernes" ascii wide nocase
        $family_3 = "azophosphore" ascii wide nocase
        $family_4 = "fyringssedlen" ascii wide nocase
        $family_5 = "sunward" ascii wide nocase
        $family_6 = "melampsora" ascii wide nocase
        $family_7 = "kinkajous" ascii wide nocase
        $family_8 = "elevraads" ascii wide nocase
        $family_9 = "volumette" ascii wide nocase
        $family_10 = "oligocene" ascii wide nocase
    condition:
        Script_Text_Reasonable and 4 of ($decoy_*) and 1 of ($delay_*) and
        1 of ($launch_*) and 5 of ($family_*)
}

rule Trojan_VBS_DecoyLoader
{
    meta:
        description = "Obfuscated VBScript loader with a large decoy-function surface and delayed COM-based launch"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript and mixed WSF content; cross-family capability cluster"
        evidence = "compound condition requires multiple uncommon decoy intrinsics, timing or error suppression and COM, WMI or shell launch behavior"
        attribution = "generic decoy-loader capability; high-confidence GuLoader workflows are reported separately"
    strings:
        $decoy_1 = "FormatCurrency(" ascii wide nocase
        $decoy_2 = "FormatPercent(" ascii wide nocase
        $decoy_3 = "TimeSerial(" ascii wide nocase
        $decoy_4 = "TimeValue(" ascii wide nocase
        $decoy_5 = "RightB(" ascii wide nocase
        $decoy_6 = "FileLen(" ascii wide nocase
        $decoy_7 = "FreeFile" ascii wide nocase
        $delay_1 = "WScript.Sleep" ascii wide nocase
        $delay_2 = "On Error Resume Next" ascii wide nocase
        $launch_1 = "Shell.Application" ascii wide nocase
        $launch_2 = "WScript.Shell" ascii wide nocase
        $launch_3 = "GetObject(" ascii wide nocase
        $launch_4 = "winmgmts:" ascii wide nocase
        $family_1 = "ws4q8x66sc" ascii wide nocase
        $family_2 = "bin.base64" ascii wide nocase
    condition:
        Script_Text_Reasonable and 3 of ($decoy_*) and 1 of ($delay_*) and
        1 of ($launch_*) and (1 of ($family_*) or #decoy_1 + #decoy_2 + #decoy_3 + #decoy_4 >= 8) and
        not Trojan_VBS_GuLoader
}

rule TrojanDropper_VBS_PowerShell
{
    meta:
        description = "VBScript dropper staging an encoded PowerShell payload with registry or filesystem persistence"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript and mixed WSF files"
        evidence = "compound condition requires WSH shell use, explicit PowerShell path or encoded command, environment expansion, persistence or stream writing and execution"
        attribution = "dropper capability cluster; not a verified malware-family attribution"
    strings:
        $shell = "WScript.Shell" ascii wide nocase
        $ps_1 = "SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" ascii wide nocase
        $ps_2 = "EncodedCommand" ascii wide nocase
        $ps_3 = "-ExecutionPolicy Bypass" ascii wide nocase
        $env = "ExpandEnvironmentStrings" ascii wide nocase
        $persist_1 = "RegWrite" ascii wide nocase
        $persist_2 = "CurrentVersion\\Run" ascii wide nocase
        $persist_3 = "Startup" ascii wide nocase
        $stage_1 = "ADODB.Stream" ascii wide nocase
        $stage_2 = "bin.base64" ascii wide nocase
        $exec_1 = "ShellExecute" ascii wide nocase
        $exec_2 = ".Run " ascii wide nocase
        $exec_3 = ".Run(" ascii wide nocase
    condition:
        Script_Text_Reasonable and $shell and 2 of ($ps_*) and $env and
        1 of ($persist_*) and 1 of ($stage_*) and 1 of ($exec_*)
}

rule TrojanDownloader_JS_EncodedPowerShell
{
    meta:
        description = "JScript loader reconstructing a Base64 PowerShell download, archive extraction and persistence chain"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript family cluster"
        evidence = "compound condition requires encoded PowerShell vocabulary, Base64 decode, byte writing, archive handling, process launch and registry persistence"
        attribution = "family-dependent loader cluster; not a verified single-family attribution"
    strings:
        $ps_1 = "frombase64string" ascii wide nocase
        $ps_2 = "writeallbytes" ascii wide nocase
        $archive_1 = "system.io.compression.zipfile" ascii wide nocase
        $archive_2 = "compression.filesystem" ascii wide nocase
        $exec_1 = "start-process" ascii wide nocase
        $exec_2 = "powershell.exe" ascii wide nocase
        $persist_1 = "new-itemproperty" ascii wide nocase
        $persist_2 = "currentversion" ascii wide nocase
        $encoding_1 = "\\x20" ascii nocase
        $encoding_2 = "\\x27" ascii nocase
        $encoding_3 = "\\x5c" ascii nocase
    condition:
        Script_Text_Reasonable and all of ($ps_*) and 1 of ($archive_*) and
        1 of ($exec_*) and 1 of ($persist_*) and 2 of ($encoding_*)
}

rule Backdoor_Linux_SSHSpread
{
    meta:
        description = "Linux bot script spreading with default credentials over SSH while establishing boot persistence"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "POSIX shell bot and worm scripts"
        evidence = "compound condition requires sshpass and SCP propagation, disabled host-key checks, default-device credentials, rc.local persistence and competing-process termination"
        attribution = "Linux bot propagation cluster; corpus may label members as IRCBot"
    strings:
        $spread_1 = "sshpass" ascii nocase
        $spread_2 = " scp " ascii nocase
        $spread_3 = "StrictHostKeyChecking=no" ascii nocase
        $cred_1 = "pi@$IP" ascii nocase
        $cred_2 = "raspberry" ascii nocase
        $persist_1 = "/etc/rc.local" ascii nocase
        $persist_2 = "sudo reboot" ascii nocase
        $kill_1 = "killall minerd" ascii nocase
        $kill_2 = "killall zmap" ascii nocase
        $kill_3 = "killall kaiten" ascii nocase
    condition:
        Script_Text_Reasonable and all of ($spread_*) and all of ($cred_*) and
        all of ($persist_*) and 2 of ($kill_*)
}

rule Exploit_RTF_EmbeddedObject
{
    meta:
        description = "RTF exploit document containing an automatically updated embedded binary object with abnormal object-data padding"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "RTF documents carrying Equation Editor or related OLE exploit objects"
        evidence = "compound condition requires RTF object and objdata controls, automatic update, binary data, explicit object dimensions and repeated zero padding"
        attribution = "exploit technique cluster covering CVE-2017-11882, CVE-2018-0798 and related object-delivery variants"
    strings:
        $rtf = "{\\rtf1" ascii nocase
        $object = "\\object" ascii nocase
        $objdata = "\\objdata" ascii nocase
        $update = "\\objupdate" ascii nocase
        $binary = "\\bin" ascii nocase
        $width = "\\objw" ascii nocase
        $height = "\\objh" ascii nocase
    condition:
        filesize > 8KB and filesize < 10MB and all of them
}

rule TrojanDownloader_PS_StagedExecution
{
    meta:
        description = "PowerShell network retrieval followed by direct script or process execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell and embedded PowerShell command content"
        evidence = "compound condition requires PowerShell networking, a download method, remote URI, execution primitive and staging, delay or stealth behavior"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $client_1 = "Net.WebClient" ascii wide nocase
        $client_2 = "Invoke-WebRequest" ascii wide nocase
        $client_3 = "Start-BitsTransfer" ascii wide nocase
        $download_1 = "DownloadFile" ascii wide nocase
        $download_2 = "DownloadString" ascii wide nocase
        $download_3 = "-OutFile" ascii wide nocase
        $remote_1 = "http://" ascii wide nocase
        $remote_2 = "https://" ascii wide nocase
        $exec_1 = "Start-Process" ascii wide nocase
        $exec_2 = "Invoke-Expression" ascii wide nocase
        $exec_3 = "IEX(" ascii wide nocase
        $evasion_1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $evasion_2 = "-EncodedCommand" ascii wide nocase
        $evasion_3 = "-enc " ascii wide nocase
        $evasion_4 = "FromBase64String" ascii wide nocase
        $context_1 = "Start-Sleep" ascii wide nocase
        $context_2 = "WindowStyle" ascii wide nocase
        $context_3 = "$env:APPDATA" ascii wide nocase
        $context_4 = "$env:TEMP" ascii wide nocase
        $context_5 = "ExecutionPolicy" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($client_*) and 1 of ($download_*) and
        1 of ($remote_*) and 1 of ($context_*) and
        (($exec_2 or $exec_3) or ($exec_1 and 1 of ($evasion_*)))
}

rule TrojanDownloader_JS_MalBehav
{
    meta:
        description = "MalBehav-style JavaScript loader using generated hexadecimal identifiers, embedded decoders and dynamic execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and heavily obfuscated JavaScript family cluster"
        evidence = "structural condition requires dense generated identifiers or conditional-compilation arrays, character and URI decoding, dynamic evaluation and a WSH or network anchor"
        attribution = "family label follows corpus taxonomy and stable decoder grammar; embedded provenance not required"
    strings:
        $hex_id = /_0x[0-9a-fA-F]{4,}/
        $alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=" ascii
        $decode_1 = "fromCharCode" ascii wide nocase
        $decode_2 = "charCodeAt" ascii wide nocase
        $decode_3 = "decodeURIComponent" ascii wide nocase
        $dynamic_1 = "eval(" ascii wide nocase
        $dynamic_2 = "Function(" ascii wide nocase
        $conditional = "/*@cc_on" ascii nocase
        $array = "new Array" ascii wide nocase
        $anchor_1 = "WScript" ascii wide nocase
        $anchor_2 = "ActiveXObject" ascii wide nocase
        $anchor_3 = "XMLHTTP" ascii wide nocase
        $anchor_4 = "http://" ascii wide nocase
        $anchor_5 = "https://" ascii wide nocase
    condition:
        Script_Text_Reasonable and
        ((#hex_id >= 20 and $alphabet and all of ($decode_*) and 1 of ($dynamic_*) and 1 of ($anchor_*)) or
         ($conditional and $array and 1 of ($decode_*) and 1 of ($dynamic_*) and 1 of ($anchor_*)))
}

rule Trojan_JS_WSHDynamicEval
{
    meta:
        description = "Obfuscated Windows Script Host JavaScript using runtime string reconstruction and dynamic evaluation"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript, JavaScript and mixed WSF content"
        evidence = "compound condition requires WSH context, dynamic evaluation, character or escape decoding, and COM, shell or network behavior"
        attribution = "generic obfuscated-loader capability; not a verified malware-family attribution"
    strings:
        $host_1 = "WScript" ascii wide nocase
        $hex_id = /_0x[0-9a-fA-F]{4,}/
        $dynamic_1 = "eval(" ascii wide nocase
        $dynamic_2 = "Function(" ascii wide nocase
        $decode_1 = "fromCharCode" ascii wide nocase
        $decode_2 = "charCodeAt" ascii wide nocase
        $decode_3 = "decodeURIComponent" ascii wide nocase
        $com = "ActiveXObject" ascii wide nocase
        $behavior_2 = "XMLHTTP" ascii wide nocase
    condition:
        Script_Text_Reasonable and $host_1 and 1 of ($dynamic_*) and
        #hex_id >= 12 and 2 of ($decode_*) and $com and $behavior_2
}

rule Trojan_JS_TypedValue
{
    meta:
        description = "JScript loader using XML DOM typed values and dynamic code execution to materialize payload data"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host JavaScript files"
        evidence = "compound condition requires XML typed-value access, dynamic evaluation, payload execution and Base64, stream or COM object handling"
        attribution = "typed-value loader capability cluster; not a verified malware-family attribution"
    strings:
        $typed = "nodeTypedValue" ascii wide nocase
        $dynamic_1 = "eval(" ascii wide nocase
        $dynamic_2 = "Function(" ascii wide nocase
        $run_1 = ".Run(" ascii wide nocase
        $run_2 = "ShellExecute" ascii wide nocase
        $material_1 = "bin.base64" ascii wide nocase
        $material_2 = "ADODB.Stream" ascii wide nocase
        $material_3 = "CreateObject" ascii wide nocase
        $material_4 = "createElement" ascii wide nocase
    condition:
        Script_Text_Reasonable and $typed and 1 of ($dynamic_*) and 1 of ($run_*) and
        2 of ($material_*)
}

rule Trojan_Script_COMNetLoader
{
    meta:
        description = "WSH script network loader combining COM retrieval with payload execution"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript, JScript and mixed WSF content"
        evidence = "compound condition requires COM object creation, WSH shell, remote URI, payload execution and HTTP response, stream or XML client behavior"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $create_1 = "CreateObject(" ascii wide nocase
        $create_2 = "GetObject(" ascii wide nocase
        $shell = "WScript.Shell" ascii wide nocase
        $remote_1 = "http://" ascii wide nocase
        $remote_2 = "https://" ascii wide nocase
        $exec_1 = ".Run " ascii wide nocase
        $exec_2 = ".Run(" ascii wide nocase
        $exec_3 = "ShellExecute" ascii wide nocase
        $net_1 = "XMLHTTP" ascii wide nocase
        $net_2 = "responseBody" ascii wide nocase
        $net_3 = "ADODB.Stream" ascii wide nocase
        $net_4 = "WinHttpRequest" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($create_*) and $shell and 1 of ($remote_*) and
        1 of ($exec_*) and 2 of ($net_*)
}

rule Trojan_JS_WSHEvalLoader
{
    meta:
        description = "Windows Script Host JavaScript dynamically evaluating code around COM shell construction"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and mixed WSF content"
        evidence = "compound condition requires WSH context, dynamic evaluation, COM object creation, shell or network behavior and an obfuscation marker"
        attribution = "generic WSH loader capability; not a verified malware-family attribution"
    strings:
        $host = "WScript" ascii wide nocase
        $hex_id = /_0x[0-9a-fA-F]{4,}/
        $dynamic_1 = "eval(" ascii wide nocase
        $dynamic_2 = "Function(" ascii wide nocase
        $com_1 = "CreateObject" ascii wide nocase
        $com_2 = "ActiveXObject" ascii wide nocase
        $behavior_2 = "XMLHTTP" ascii wide nocase
        $obf_1 = "fromCharCode" ascii wide nocase
        $obf_2 = "charCodeAt" ascii wide nocase
        $obf_3 = "String.prototype" ascii wide nocase
        $obf_4 = "\\u00" ascii nocase
    condition:
        Script_Text_Reasonable and $host and 1 of ($dynamic_*) and 1 of ($com_*) and
        #hex_id >= 12 and $behavior_2 and 1 of ($obf_*)
}

rule Trojan_JS_DOMDecoder
{
    meta:
        description = "JScript payload decoder using XML typed values, dynamic evaluation and COM-backed materialization"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host JavaScript files"
        evidence = "compound condition requires nodeTypedValue, dynamic execution, and two independent Base64, stream, COM or XML DOM materialization signals"
        attribution = "DOM-decoder capability cluster; not a verified malware-family attribution"
    strings:
        $typed = "nodeTypedValue" ascii wide nocase
        $dynamic_1 = "eval(" ascii wide nocase
        $dynamic_2 = "Function(" ascii wide nocase
        $material_1 = "bin.base64" ascii wide nocase
        $material_2 = "ADODB.Stream" ascii wide nocase
        $material_3 = "CreateObject" ascii wide nocase
        $material_4 = "createElement" ascii wide nocase
        $material_5 = "Microsoft.XMLDOM" ascii wide nocase
    condition:
        Script_Text_Reasonable and $typed and 1 of ($dynamic_*) and 2 of ($material_*)
}

rule Trojan_VBS_ObfuscatedCOM
{
    meta:
        description = "Obfuscated VBScript loader combining COM retrieval, response handling, shell execution and decoy intrinsics"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript and mixed WSF content"
        evidence = "compound condition requires COM creation, WSH shell execution, response data and multiple uncommon decoy or anti-analysis intrinsics"
        attribution = "obfuscated-loader capability cluster; includes GuLoader-related scripts"
    strings:
        $create = "CreateObject(" ascii wide nocase
        $shell = "WScript.Shell" ascii wide nocase
        $response_1 = "responseBody" ascii wide nocase
        $response_2 = "responseText" ascii wide nocase
        $exec_1 = ".Run " ascii wide nocase
        $exec_2 = ".Run(" ascii wide nocase
        $decoy_1 = "FormatCurrency(" ascii wide nocase
        $decoy_2 = "FormatPercent(" ascii wide nocase
        $decoy_3 = "TimeSerial(" ascii wide nocase
        $decoy_4 = "TimeValue(" ascii wide nocase
        $decoy_5 = "RightB(" ascii wide nocase
        $decoy_6 = "FileLen(" ascii wide nocase
        $decoy_7 = "FreeFile" ascii wide nocase
    condition:
        Script_Text_Reasonable and $create and $shell and 1 of ($response_*) and
        1 of ($exec_*) and 2 of ($decoy_*)
}

rule TrojanDownloader_JS_WSHNetLoader
{
    meta:
        description = "WSH JavaScript loader using ActiveX shell execution around an encoded or reconstructed network stage"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host JavaScript files"
        evidence = "compound condition requires WScript, ActiveX, WSH shell, process launch, function-based reconstruction and an encoded or network payload marker"
        attribution = "capability cluster; not a verified malware-family attribution"
    strings:
        $host = "WScript" ascii wide nocase
        $activex = "ActiveXObject" ascii wide nocase
        $shell = "WScript.Shell" ascii wide nocase
        $run_1 = ".Run(" ascii wide nocase
        $run_2 = ".Run " ascii wide nocase
        $construct_1 = "Function(" ascii wide nocase
        $construct_2 = "fromCharCode" ascii wide nocase
        $payload_1 = "FromBase64String" ascii wide nocase
        $payload_2 = "XMLHTTP" ascii wide nocase
        $payload_3 = "http://" ascii wide nocase
        $payload_4 = "https://" ascii wide nocase
    condition:
        Script_Text_Reasonable and $host and $activex and $shell and 1 of ($run_*) and
        1 of ($construct_*) and 1 of ($payload_*)
}

rule Trojan_Script_EncodedAssembly
{
    meta:
        description = "PowerShell encoded assembly or byte payload reconstructed and executed from memory or a staged file"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "PowerShell plus JScript, VBScript or command files embedding PowerShell content"
        evidence = "compound condition requires PowerShell-qualified Base64 conversion plus qualified reflection or byte writing and explicit execution syntax"
        attribution = "encoded-loader capability cluster; not a verified malware-family attribution"
    strings:
        $decode_1 = "[Convert]::FromBase64String" ascii wide nocase
        $decode_2 = "[System.Convert]::FromBase64String" ascii wide nocase
        $material_1 = "[Reflection.Assembly]::Load" ascii wide nocase
        $material_2 = "[System.Reflection.Assembly]::Load" ascii wide nocase
        $material_3 = "[IO.File]::WriteAllBytes" ascii wide nocase
        $material_4 = "[System.IO.File]::WriteAllBytes" ascii wide nocase
        $exec_1 = "Start-Process" ascii wide nocase
        $exec_2 = ".EntryPoint.Invoke" ascii wide nocase
        $exec_3 = "::Load(" ascii wide nocase
        $ps_1 = "powershell" ascii wide nocase
        $ps_2 = "New-Object" ascii wide nocase
        $ps_3 = "$env:" ascii wide nocase
    condition:
        Script_Text_Reasonable and 1 of ($decode_*) and 1 of ($material_*) and
        1 of ($exec_*) and 1 of ($ps_*)
}

rule Trojan_JS_FragmentedCOM
{
    meta:
        description = "JScript loader reconstructing Windows Script Host, COM network and stream object names from fragmented literals"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host files; cross-family capability cluster"
        evidence = "structural condition requires seven independently meaningful fragments spanning WSH, COM creation, HTTP retrieval, response handling, stream persistence and temporary staging"
        attribution = "fragmented COM-loader capability; compatible with but not exclusively attributed to Nemucod"
    strings:
        $frag_1 = "WScrip" ascii wide nocase
        $frag_2 = "reateO" ascii wide nocase
        $frag_3 = "ADODB." ascii wide nocase
        $frag_4 = "saveT" ascii wide nocase
        $frag_5 = "Resp" ascii wide nocase
        $frag_6 = "MSXML" ascii wide nocase
        $frag_7 = "HTTP" ascii wide nocase
        $frag_8 = "%TE" ascii wide nocase
        $split_1 = "Create" ascii wide nocase
        $split_2 = "saveTo" ascii wide nocase
        $split_3 = "TEMP%" ascii wide nocase
        $split_4 = ".XMLHT" ascii wide nocase
    condition:
        Script_Text_Reasonable and
        (7 of ($frag_*) or ($frag_1 and $frag_3 and $frag_6 and all of ($split_*)))
}

rule Trojan_JS_ResponseEval
{
    meta:
        description = "JScript downloader retrieving a remote response through an ActiveX HTTP client and directly evaluating the returned code"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host files; downloader capability cluster"
        evidence = "compound condition requires ActiveX construction, an XMLHTTP or WinHTTP client, request open and send operations, response-text access and dynamic evaluation"
        attribution = "generic response-evaluation downloader; compatible with several script malware families"
    strings:
        $activex = "ActiveXObject" ascii wide nocase
        $client_1 = "Msxml2.XMLHTTP" ascii wide nocase
        $client_2 = "Microsoft.XMLHTTP" ascii wide nocase
        $client_3 = "WinHttp.WinHttpRequest" ascii wide nocase
        $open = ".open(" ascii wide nocase
        $get_fragment = "\"G\"+\"E\"+\"T\"" ascii wide nocase
        $send = ".send(" ascii wide nocase
        $response = "responseText" ascii wide nocase
        $eval = "eval(" ascii wide nocase
        $eval_wrapper = /function[ \t]+[A-Za-z_][A-Za-z0-9_]{2,}\([A-Za-z_][A-Za-z0-9_]{2,}\)[ \t]*\{[ \t\r\n]*eval\([A-Za-z_][A-Za-z0-9_]{2,}\);[ \t\r\n]*\}/ nocase
        $scheme_1 = "http" ascii wide nocase
        $scheme_2 = "https" ascii wide nocase
    condition:
        Script_Text_Reasonable and $activex and 1 of ($client_*) and 1 of ($open, $get_fragment) and $send and
        $response and $eval and $eval_wrapper and 1 of ($scheme_*)
}

rule Trojan_VBS_StagedEncoder
{
    meta:
        description = "VBScript staged encoder using repeated long encoded-call arguments, randomized constants and byte-length padding"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript and mixed WSF content; obfuscated loader capability cluster"
        evidence = "structural condition requires repeated encoded function calls plus independently repeated randomized constant declarations and LenB-based padding"
        attribution = "generic staged VBScript encoder; not a verified malware-family attribution"
    strings:
        $lenb = "LenB(" ascii wide nocase
        $encoded_call = /Call[ \t]+[A-Za-z][A-Za-z0-9_]{5,20}\([ \t]*["'][A-Za-z0-9#]{60,}["']\)/ nocase
        $random_const = /Const[ \t]+[A-Za-z][A-Za-z0-9_]{5,20}[ \t]*=[ \t]*["'][A-Za-z]{6,20}["']/ nocase
    condition:
        Script_Text_Reasonable and $lenb and #encoded_call >= 10 and #random_const >= 10
}

rule Trojan_VBS_DecoyCorpus
{
    meta:
        description = "VBScript loader padded with long randomized procedure names, multilingual comment corpus and inert formatting branches"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "VBScript and mixed WSF content; obfuscated loader capability cluster"
        evidence = "structural condition requires a long multi-argument procedure signature, a dense comment-word corpus, multiple formatting decoys and stringified numeric comparison logic"
        attribution = "generic decoy-corpus capability; related to GuLoader-style padding but not family-exclusive"
    strings:
        $procedure = /[\r\n]Sub[ \t]+[A-Za-z][A-Za-z0-9]{12,}\([A-Za-z][A-Za-z0-9]{12,},[A-Za-z][A-Za-z0-9]{12,},[A-Za-z][A-Za-z0-9]{12,}/ nocase
        $comment_words = /[\r\n]'[A-Za-z]{5,}( [A-Za-z][A-Za-z0-9]{4,}){2,}/ nocase
        $decoy_1 = "FormatPercent(" ascii wide nocase
        $decoy_2 = "FormatDateTime(" ascii wide nocase
        $decoy_3 = "TimeValue(" ascii wide nocase
        $cstr = "cstr(" ascii wide nocase
    condition:
        Script_Text_Reasonable and $procedure and #comment_words >= 20 and
        2 of ($decoy_*) and $cstr
}

rule Trojan_BAT_SubstringRebuild
{
    meta:
        description = "Batch payload reconstruction through a dense sequence of one-character environment substring expansions"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "batch and command-script content; obfuscated loader capability cluster"
        evidence = "structural condition requires command-shell setup, more than one hundred one-character substring expansions and an echoed reconstructed command"
        attribution = "generic batch reconstruction capability; not a verified malware-family attribution"
    strings:
        $echo_off = "@echo off" ascii wide nocase
        $slice = /%[A-Za-z0-9_]{6,}:~[0-9]{1,4},1%/
        $echo = "echo %%" ascii wide nocase
    condition:
        Script_Text_Reasonable and $echo_off and #slice >= 100 and $echo
}

rule Trojan_JS_UnicodeShiftDecoder
{
    meta:
        description = "JavaScript loader decoding a Unicode payload through per-character arithmetic shifting before dynamic evaluation"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JavaScript and JScript files; obfuscated decoder capability cluster"
        evidence = "compound condition requires dynamic evaluation, character-code decoding, empty-string splitting and an explicit numeric subtraction shift"
        attribution = "generic Unicode shift-decoder capability; not a verified malware-family attribution"
    strings:
        $eval = "eval(" ascii wide nocase
        $from_char = "String.fromCharCode" ascii wide nocase
        $char_code = "charCodeAt(0)" ascii wide nocase
        $split = ".split(\"\")" ascii wide nocase
        $shift = /\+[A-Za-z][A-Za-z0-9_]{0,12}[ \t]*-[ \t]*\+[0-9]{3,5}/ wide
    condition:
        Script_Text_Reasonable and all of them
}

rule Trojan_LNK_WildcardPowerShell
{
    meta:
        description = "Windows shortcut invoking PowerShell to retrieve a remote payload through wildcard-obfuscated command syntax"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "Windows LNK files and shortcut-like binary content"
        evidence = "compound condition requires a valid Shell Link header, PowerShell, a remote HTTP URI and a literal wildcard path fragment used for command obfuscation"
        attribution = "shortcut PowerShell-loader capability; not a verified malware-family attribution"
    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $powershell = "powershell.exe" ascii wide nocase
        $remote_1 = "http://" ascii wide nocase
        $remote_2 = "https://" ascii wide nocase
        $wildcard = "\\*" ascii wide
    condition:
        filesize >= 76 and filesize < 5MB and $lnk_header at 0 and $powershell and
        1 of ($remote_*) and $wildcard
}

rule Trojan_JS_HashDelimitedLoader
{
    meta:
        description = "JScript loader restoring hash-delimited source code before dynamically constructing a COM download and execution chain"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and Windows Script Host files; obfuscated downloader capability cluster"
        evidence = "compound condition requires hash-delimiter removal with dynamic evaluation and at least three restored ActiveX, HTTP, stream persistence or rundll32 execution fragments"
        attribution = "generic hash-delimited loader capability; compatible with MalBehav-style decoder variants"
    strings:
        $eval = "eval(" ascii wide nocase
        $strip_hash = ".split(\"#\").join(\"\")" ascii wide nocase
        $activex = "A#c#t#i#v#e#X#O#b#j#e#c#t" ascii wide nocase
        $http = "h#t#t#p#:#/#/" ascii wide nocase
        $adodb = "A#D#O#D#B#.#S#t#r#e#a#m" ascii wide nocase
        $msxml = "M#S#X#M#L#2#.#X#M#L#H#T#T#P" ascii wide nocase
        $save = "S#a#v#e#T#o#F#i#l#e" ascii wide nocase
        $rundll32 = "r#u#n#d#l#l#3#2" ascii wide nocase
    condition:
        Script_Text_Reasonable and $eval and $strip_hash and 3 of ($activex, $http, $adodb, $msxml, $save, $rundll32)
}

rule Trojan_JS_TrigTableDecoder
{
    meta:
        description = "JScript decoder reconstructing payload code from dense two-dimensional tables with trigonometric identity control flow"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and JavaScript files; obfuscated decoder capability cluster"
        evidence = "structural condition requires dense short-value two-dimensional assignments, paired sine and cosine arithmetic, numeric-base conversion, looping and dynamic evaluation"
        attribution = "generic trigonometric table-decoder capability; compatible with Swabfex-style obfuscation"
    strings:
        $table = /[A-Za-z][A-Za-z0-9_]{0,20}\[[0-9]{1,3}\]\[[0-9]{1,5}\][ \t]*=[ \t]*['"][0-9a-z]{1,4}['"]/ nocase
        $sin = "Math.sin(" ascii wide nocase
        $cos = "Math.cos(" ascii wide nocase
        $parse_int = "parseInt(" ascii wide nocase
        $to_string = ".toString(" ascii wide nocase
        $loop = "while(true)" ascii wide nocase
        $eval = "eval(" ascii wide nocase
    condition:
        Script_Text_Reasonable and #table >= 100 and all of ($sin, $cos, $parse_int, $to_string, $loop, $eval)
}

rule Trojan_JS_SparseArrayDecoder
{
    meta:
        description = "JScript payload decoder assembling source from a dense sparse numeric array before joining and evaluating it"
        author = "PYAS Security"
        date = "2026-09-21"
        scope = "JScript and JavaScript files; obfuscated decoder capability cluster"
        evidence = "structural condition requires at least 250 sparse numeric string assignments together with array construction, string joining and dynamic evaluation"
        attribution = "generic sparse-array decoder capability; compatible with several legacy script downloader families"
    strings:
        $assignment = /[A-Za-z_$][A-Za-z0-9_$]{0,20}\[[0-9]{1,5}\][ \t]*=[ \t]*['"][^'"\r\n]{1,16}['"]/ nocase
        $array = "new Array()" ascii wide nocase
        $join = ".join(\"\")" ascii wide nocase
        $eval = "eval(" ascii wide nocase
    condition:
        Script_Text_Reasonable and #assignment >= 250 and all of ($array, $join, $eval)
}
