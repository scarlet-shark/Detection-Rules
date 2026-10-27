rule yoba_dropper {
    meta:
        author = "@Tera0017/Check Point Research"
        description = "YobaDropper"
        reference = "https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/"
        date = "2026-10-27"
        hash = "17e8639a00bb32b10cb9cf0d292e9441456ce4bb"

    strings:
        $code1 = {00 BB 40 0D 03 00 B9 7C 15 00 00 FF D6 31 C0}
        $code2 = {BA 05 15 00 00 0F BE 08 84 C9 74 0A 6B D2 21}
        $code3 = {53 B9 75 EE 40 70 48 83 EC 20}
        $code4 = {BA 5C CD 17 E5 48 89 C1 E8 73 00 00 00}
        $code5 = {0F C8 89 C0 4? 39 ?? 74 1? (49 0F AF C0| 48 69 C0 ?? ?? ?? ??) (4C 01 C8| 48 05 ?? ?? ?? ??) 49 89 C? 49 C1 E? 18 45 30 [2] 4? FF ?? EB}

    condition:
        uint16(0) == 0x5A4D and 2 of them
}
