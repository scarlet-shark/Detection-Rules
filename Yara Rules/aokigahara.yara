rule aokigahara {
    meta:
        author = "@Tera0017/Check Point Research"
        description = "Aokigahara Stealer"
        reference = "https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/"
        creation_date = "2026-10-23"
        date = "2026-10-23"
        hash = "ff402e64bc42222c8a4ee703123903c2a2117dd9"

    strings:
        $str1 = "X-Chunk-Index: %u" ascii fullword
        $str2 = "X-Build-ID: %s" ascii fullword
        $str3 = "AKGRES" ascii fullword
        $str4 = "AISessions/" ascii
        $str5 = "\\\\.\\pipe\\akg_%lx_%lx" ascii fullword
        $str6 = "sysinfo\x00screenshot\x00clipboard"
        $str7 = "aokigahara" ascii fullword
        $str8 = "kamidere" ascii fullword
        $str9 = "/chunk" ascii fullword
        $str10 = "%s\\kmd_w_%d_%d.db" ascii fullword
        $str11 = ".ROBLOSECURITY" ascii fullword
        $code1 = {45 69 ED B1 79 37 9E 48 C1 EF 11 48 C1 EA 20 41 31 D6 41 31 C6 41 31 FD 45 89 77 04 45 89 6F 08}
        $code2 = {41 4B 47 52 45 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EF BE AD DE }

    condition:
        uint16(0) == 0x5A4D and 3 of them
}
