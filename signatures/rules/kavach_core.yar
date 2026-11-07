/*
   Kavach Antivirus — core detection rules
   Written in YARA syntax. Kavach's own rule engine reads them.
   Supported: text strings (nocase, wide, ascii, fullword), hex strings (?? wildcards, [n] jumps),
              regex, and / or / not, "N of them", "any of ($a*)", filesize, uint16/uint32.
   meta: severity = low | medium | high | critical, threat = name shown to the user
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (harmless)"
        threat = "EICAR-Test-File"
        severity = "high"
    strings:
        $start = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 }
        $name  = { 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 }
    condition:
        $start at 0 and $name and filesize < 128
}

rule Ransomware_Backup_Destruction
{
    meta:
        description = "Deletes Windows shadow copies / recovery - typical ransomware step"
        threat = "Ransom.ShadowCopyDelete"
        severity = "critical"
    strings:
        $a = "delete shadows" nocase ascii wide
        $b = "shadowcopy delete" nocase ascii wide
        $c = "recoveryenabled no" nocase ascii wide
        $d = "delete catalog -quiet" nocase ascii wide
        $e = "resize shadowstorage" nocase ascii wide
        $x1 = "vssadmin" nocase ascii wide
        $x2 = "wmic" nocase ascii wide
        $x3 = "bcdedit" nocase ascii wide
        $x4 = "wbadmin" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of ($a, $b, $c, $d, $e) and any of ($x*)
}

rule Ransomware_Ransom_Note
{
    meta:
        description = "Program containing a ransom note"
        threat = "Ransom.Generic.Note"
        severity = "critical"
    strings:
        $n1 = "your files have been encrypted" nocase ascii wide
        $n2 = "all your files are encrypted" nocase ascii wide
        $n3 = "your important files" nocase ascii wide
        $p1 = "bitcoin" nocase ascii wide
        $p2 = "tor browser" nocase ascii wide
        $p3 = ".onion" nocase ascii wide
        $p4 = "decrypt" nocase ascii wide
        $p5 = "private key" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and any of ($n*) and 2 of ($p*)
}

rule HackTool_Mimikatz
{
    meta:
        description = "Mimikatz password-stealing tool"
        threat = "HackTool.Mimikatz"
        severity = "critical"
    strings:
        $a = "sekurlsa::logonpasswords" nocase ascii wide
        $b = "gentilkiwi" nocase ascii wide
        $c = "mimikatz" nocase ascii wide fullword
        $d = "kerberos::golden" nocase ascii wide
        $e = "lsadump::sam" nocase ascii wide
    condition:
        2 of them
}

rule Stealer_Browser_Credentials
{
    meta:
        description = "Small program that reads saved browser passwords and cookies"
        threat = "Trojan.Stealer.Browser"
        severity = "high"
    strings:
        $f1 = "Login Data" ascii wide
        $f2 = "Web Data" ascii wide
        $f3 = "Local State" ascii wide
        $f4 = "encrypted_key" ascii wide
        $f5 = "Cookies" ascii wide
        $w1 = "wallet.dat" nocase ascii wide
        $w2 = "Exodus" ascii wide
        $w3 = "Telegram Desktop" ascii wide
        $w4 = "discord" nocase ascii wide
        $u1 = "api.telegram.org/bot" nocase ascii wide
        $u2 = "discord.com/api/webhooks" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 8MB and 4 of ($f*) and (any of ($u*) or 2 of ($w*))
}

rule Stealer_Discord_Token
{
    meta:
        description = "Steals Discord login tokens"
        threat = "Trojan.Stealer.DiscordToken"
        severity = "high"
    strings:
        $a = "Local Storage\\leveldb" nocase ascii wide
        $b = "discord" nocase ascii wide
        $c = /mfa\.[\w-]{20,}|[\w-]{24}\.[\w-]{6}\.[\w-]{27}/ ascii
        $d = "discord.com/api/webhooks" nocase ascii wide
        $e = "token" nocase ascii wide
    condition:
        $a and $b and $e and ($c or $d)
}

rule Keylogger_Generic
{
    meta:
        description = "Records key presses and sends them away"
        threat = "Spyware.Keylogger"
        severity = "high"
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookEx" ascii
        $l1 = "[ENTER]" nocase ascii wide
        $l2 = "[BACKSPACE]" nocase ascii wide
        $l3 = "[SHIFT]" nocase ascii wide
        $l4 = "[CAPSLOCK]" nocase ascii wide
        $l5 = "keylog" nocase ascii wide
        $s1 = "smtp." nocase ascii wide
        $s2 = "api.telegram.org" nocase ascii wide
        $s3 = "ftp://" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and any of ($k*) and 2 of ($l*) and any of ($s*)
}

rule Miner_XMRig
{
    meta:
        description = "Hidden cryptocurrency miner (uses your CPU to make money for attackers)"
        threat = "CoinMiner.XMRig"
        severity = "medium"
    strings:
        $a = "stratum+tcp://" nocase ascii wide
        $b = "stratum+ssl://" nocase ascii wide
        $c = "xmrig" nocase ascii wide
        $d = "randomx" nocase ascii wide
        $e = "--donate-level" ascii wide
        $f = "cryptonight" nocase ascii wide
    condition:
        3 of them
}

rule Backdoor_CobaltStrike_Beacon
{
    meta:
        description = "Cobalt Strike beacon (remote control tool used by attackers)"
        threat = "Backdoor.CobaltStrike"
        severity = "critical"
    strings:
        $p1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii
        $p2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $b1 = "beacon.dll" ascii
        $b2 = "ReflectiveLoader" ascii
        $b3 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
    condition:
        any of ($p*) or ($b2 and $b1) or ($b2 and $b3 and filesize < 1MB)
}

rule Webshell_PHP_Generic
{
    meta:
        description = "PHP web shell (gives attackers control of a web server)"
        threat = "Backdoor.WebShell.PHP"
        severity = "high"
    strings:
        $php = "<?php" nocase
        $a = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ nocase
        $b = /(system|shell_exec|passthru|exec|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $c = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $d = /preg_replace\s*\(\s*['"].*\/e['"]/ nocase
    condition:
        $php at 0 and filesize < 512KB and any of ($a, $b, $c, $d)
}

rule Downloader_Embedded_PowerShell
{
    meta:
        description = "Program that secretly starts PowerShell to download more malware"
        threat = "Trojan.Downloader.PowerShell"
        severity = "high"
    strings:
        $ps = "powershell" nocase ascii wide
        $h1 = "-w hidden" nocase ascii wide
        $h2 = "-windowstyle hidden" nocase ascii wide
        $h3 = "-nop" nocase ascii wide
        $d1 = "DownloadString" nocase ascii wide
        $d2 = "DownloadFile" nocase ascii wide
        $d3 = "Invoke-WebRequest" nocase ascii wide
        $e1 = "-enc " nocase ascii wide
        $e2 = "IEX" ascii wide fullword
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and $ps and any of ($h*) and any of ($d*) and any of ($e*)
}

rule Office_Macro_Downloader
{
    meta:
        description = "Office macro that runs automatically and downloads or starts programs"
        threat = "Trojan.Macro.Downloader"
        severity = "high"
    strings:
        $auto1 = "AutoOpen" nocase ascii wide
        $auto2 = "Document_Open" nocase ascii wide
        $auto3 = "Workbook_Open" nocase ascii wide
        $auto4 = "Auto_Open" nocase ascii wide
        $run1 = "WScript.Shell" nocase ascii wide
        $run2 = "Shell(" nocase ascii wide
        $run3 = "URLDownloadToFile" nocase ascii wide
        $run4 = "MSXML2.XMLHTTP" nocase ascii wide
        $run5 = "powershell" nocase ascii wide
        $run6 = "CreateObject" nocase ascii wide
    condition:
        any of ($auto*) and 3 of ($run*)
}

rule RAT_Generic_Indicators
{
    meta:
        description = "Remote access trojan (lets attackers control your PC)"
        threat = "Backdoor.RAT.Generic"
        severity = "high"
    strings:
        $a1 = "AsyncRAT" nocase ascii wide
        $a2 = "njRAT" nocase ascii wide
        $a3 = "QuasarRAT" nocase ascii wide
        $a4 = "DcRat" ascii wide
        $a5 = "Remcos" ascii wide fullword
        $b1 = "Anti_Analysis" ascii wide
        $b2 = "Pastebin" ascii wide
        $b3 = "ClientSocket" ascii wide
        $b4 = "Keylogger" ascii wide
        $b5 = "RemoteDesktop" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of ($a*) and 2 of ($b*))
}

rule Suspicious_Autorun_Inf
{
    meta:
        description = "autorun.inf that starts a program (USB worm)"
        threat = "Worm.Autorun"
        severity = "high"
    strings:
        $h = "[autorun]" nocase
        $o1 = /\bopen\s*=/ nocase
        $o2 = /shellexecute\s*=/ nocase
        $o3 = /shell\\\w+\\command\s*=/ nocase
    condition:
        $h at 0 and any of ($o*) and filesize < 4KB
}

rule Kavach_Script_Memory_Test
{
    meta:
        description = "Harmless test marker for Kavach script memory scanning (like EICAR, but for PowerShell)"
        threat = "Test.ScriptMemory.Kavach"
        severity = "high"
    strings:
        $t = "KAVACH-SCRIPT-MEMORY-TEST"
    condition:
        $t
}
