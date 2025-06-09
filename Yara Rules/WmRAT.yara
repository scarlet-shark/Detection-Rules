import "pe"

rule WmRAT : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf, Threatray)"
        description = "Detects WmRAT used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        creation_date = "2025-06-01"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "4e3e4d476810c95c34b6f2aa9c735f8e57e85e3b7a97c709adc5d6ee4a5f6ccc"
        hash = "10cec5a84943f9b0c635640fad93fd2a2469cc46aae5e43a4604c903d139970f"

    strings:
        $s1  = "%s%ld M" ascii fullword
        $s2  = "%s%ld K" ascii fullword
        $s3  = "%s%ld MB" ascii fullword
        $s4  = "%s%ld KB" ascii fullword
        $s5  = "--,." ascii fullword
        $s6  = "RFOX" ascii fullword
        $s7  = "1llll" ascii fullword
        $s8  = "exit" ascii fullword
        $s9  = "Path=" ascii fullword
        $s10 = "  %d result(s)" ascii fullword
        $s11 = "%02d-%02d-%d %02d:%02d" ascii fullword

        $code_sleep = {
            6A 64                 // push    64h ; 'd'       ; dwMilliseconds
            FF ??                 // call    esi ; Sleep
            6A 01                 // push    1               ; unsigned int
            E8 ?? ?? ?? ??        // call    ??2@YAPAXI@Z    ; operator new(uint)
            83 C4 04              // add     esp, 4
            3B ??                 // cmp     eax, edi
            74 ??                 // jz      short loc_4019E5
        }
        $code_dec_str = {
            83 7C 24 ?? 10        // cmp     dword ptr [esp+44h], 10h
            8B 44 24 ??           // mov     eax, [esp+30h]
            73 ??                 // jnb     short loc_4086B2
            8D 44 24 ??           // lea     eax, [esp+30h]
            8A 0C 37              // mov     cl, [edi+esi]
            80 ?? ??              // sub     cl, 2Eh ; '.'
            88 0C 30              // mov     [eax+esi], cl
            46                    // inc     esi
            3B F5                 // cmp     esi, ebp
            7C ??                 // jl      short loc_408680
        }
        $code_fill_logs = {
            BD E8 03 00 00        // mov     ebp, 1000
            83 ?? FF              // or      edi, 0FFFFFFFFh
            E8 ?? ?? ?? ??        // call    Get_ComputerName_and_Username
            66 A1 ?? ?? ?? ??     // mov     ax, ds:word_40D82C
            8A 0D ?? ?? ?? ??     // mov     cl, ds:byte_40D82E
            66 89 44 24 ??        // mov     [esp+14h], ax
            88 4C 24 ??           // mov     [esp+16h], cl
            FF 15 ?? ?? ?? ??     // call    ds:GetLogicalDrives
            89 44 24 ??           // mov     [esp+18h], eax
            3B ??                 // cmp     eax, esi
            74 ??                 // jz      short loc_4091E1
            8D ?? 00 00 00 00     // lea     ebx, [ebx+0]
            A8 01                 // test    al, 1
            74 ??                 // jz      short loc_4091D5
        }

    condition:
        pe.is_pe and
        filesize < 300KB and
        10 of ($s*) or all of ($code*)
}
