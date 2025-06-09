import "pe"

rule MiyaRAT : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects MiyaRAT used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        creation_date = "2025-06-01"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "df5c0d787de9cc7dceeec3e34575220d831b5c8aeef2209bcd81f58c8b3c08ed"
        hash = "c7ab300df27ad41f8d9e52e2d732f95479f4212a3c3d62dbf0511b37b3e81317"
        hash = "0953d4cc6861082c079935918c63cd71df30e5e6854adf608a8b8f5254be8e99"
        hash = "c2c92f2238bc20a7b4d4c152861850b8e069c924231e2fa14ea09e9dcd1e9f0a"

    strings:
        $x1 = "] GB FREE\r\n" ascii fullword
        $x2 = "<||>\r\n" wide fullword

        $s1  = "<SZ>" wide
        $s2  = "<FIL>" wide
        $s3  = "UPL1" wide
        $s4  = "DWNL" wide
        $s5  = ",filesize==" wide
        $s6  = "[DIR]<||>" wide
        $s7  = "[FILE]<||>" wide
        $s8  = "[END]~!@" wide
        $s9  = "GDIR" wide
        $s10 = "DELz" wide
        $s11 = "GFS" wide
        $s12 = "SH1" wide
        $s13 = "SH2" wide
        $s14 = "SFS" wide
        $s15 = "GSS" wide
        $s16 = "SH1cmd" wide
        $s17 = "SH1start_cmd" wide
        $s18 = "SH1start_ps" wide
        $s19 = "SH1exit_client" wide

        $code_init_c2_conn = {
            68 00 00 00 80               // push    80000000h       ; esFlags
            FF 15 ?? ?? ?? ??            // call    ds:SetThreadExecutionState
            68 E9 FD 00 00               // push    0FDE9h          ; wCodePageID
            FF 15 ?? ?? ?? ??            // call    ds:SetConsoleOutputCP
            68 E9 FD 00 00               // push    0FDE9h          ; wCodePageID
            FF 15 ?? ?? ?? ??            // call    ds:SetConsoleCP
            [0-1]
            8D 85 ?? ?? ?? ??            // lea     eax, [ebp+WSAData]
            50                           // push    eax             ; lpWSAData
            68 02 02 00 00               // push    202h            ; wVersionRequested
            FF 15 ?? ?? ?? ??            // call    ds:WSAStartup
            85 C0                        // test    eax, eax
        }
        $code_collect_user_info = {
            68 00 20 00 00                       //  push    2000h           ; Size
            [0-6]
            6A 00                                //  push    0               ; Val
            [0-6]
            5?                                   //  push    eax             ; void *
            E8 ?? ?? ?? ??                       //  call    _memset         ; Connection successful. Start gathering system information.
            83 C4 0C                             //  add     esp, 0Ch
            C7 85 ?? ?? ?? ?? 10 00 00 00        //  mov     [ebp+pcbBuffer], 10h
            8D 8? ?? ?? ?? ??                    //  lea     eax, [ebp+pcbBuffer] ; Get username.
            5?                                   //  push    eax             ; pcbBuffer
            8D 4? ??                             //  lea     eax, [ebp+Buffer]
            5?                                   //  push    eax             ; lpBuffer
            FF 15 ?? ?? ?? ??                    //  call    ds:GetUserNameW
            [0-6]
            C7 85 ?? ?? ?? ?? 10 00 00 00        //   mov     [ebp+pcbBuffer], 10h
            [0-6]
            5?                                   //  push    eax             ; nSize
            8D 4? ??                             //  lea     eax, [ebp+var_34]
            5?                                   //  push    eax             ; lpBuffer
            FF 15 ?? ?? ?? ??                    //  call    ds:GetComputerNameW
            6A 00                                //  push    0               ; lpModuleName
            FF 15 ?? ?? ?? ??                    //  call    ds:GetModuleHandleW ; Get current module file path.
        }

    condition:
        pe.is_pe and
        all of ($x*) and
        (10 of ($s*) or 2 of ($code*))
}
