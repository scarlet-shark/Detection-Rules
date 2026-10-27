rule yoba_loader {
    meta:
        author = "@Tera0017/Check Point Research"
        description = "YobaLoader"
        reference = "https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/"
        date = "2026-10-27"
        hash = "22661f4bada8167fa0f410b75e53184998990abb"

    strings:
        $code1 = {B9 80 A8 12 01 FF ?? ?? E9}
        $code2 = {BA EB 1D 00 00 0F BE 08 84 C9 74 0A 6B D2 21}
        $code3 = {B9 5B 80 EF B7 E8}
        $code4 = {BA F5 8B 2E F2 48 89 C1}
        $code5 = {B5 C2 D2 06 23 D4 E6 64 7D 06 A4 28 64 ED D8 62 9F 82 C5 C3 84 B2 43 FD AE EE CA 24 B3 87 3D 64}
        $code6 = {1D 0D 13 68 B4 D5 3F 3A 63 22 CF 40 E8 4E 63 DB}
        $code7 = {40 80 FE 32 74 42 40 80 FE 33 74 66 40 80 FE 31}
        $code8 = {41 81 F8 A5 DE 6C C2}

    condition:
        uint16(0) == 0x5A4D and 2 of them
}
