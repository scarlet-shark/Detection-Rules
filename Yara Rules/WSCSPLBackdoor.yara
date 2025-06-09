rule WSCSPLBackdoor : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects WSCSPL backdoor used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        license = "Detection Rule License (DRL) 1.1"
        license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "a241cfcd60942ea401d53d6e02ec3dfb5f92e8f4fda0aef032bee7bb5a344c35"
        hash = "096e6546b5ca43adbe34bbedc84b002bbf399d2ecf08e83966757b88c5c0d2a2"

    strings:
        $code_main = {
            6A 64                            // push    64h ; 'd'       ; cchBufferMax
            68 ?? ?? ?? ??                   // push    offset WindowName ; lpBuffer
            6A 67                            // push    67h ; 'g'       ; uID
            5?                               // push    esi             ; hInstance
            FF D?                            // call    edi ; LoadStringA
            6A 64                            // push    64h ; 'd'       ; cchBufferMax
            68 ?? ?? ?? ??                   // push    offset ClassName ; lpBuffer
            6A 6D                            // push    6Dh ; 'm'       ; uID
            5?                               // push    esi             ; hInstance
            FF D?                            // call    edi ; LoadStringA
        }
        $code_xor_c2_data = {
            8A 8? 17 ?? ?? ?? ??             // mov     al, byte_4520D8[edi+edx]
            32 8? ?? ?? ?? ??                // xor     al, byte_406078[ecx]
            4?                               // inc     ecx
            88 8? ?? ?? ?? ??                // mov     byte_4520D8[edx], al
            4?                               // inc     edx
            3? ??                            // cmp     ecx, esi
            75 ??                            // jnz     short loc_401C2B
            3? ??                            // xor     ecx, ecx
            3? ??                            // cmp     edx, ebp
            7C ??                            // jl      short loc_401C10
        }
        $code_handle_c2_commands = {
            8D ?? 24 10                      // lea     edx, [esp+10h]
            5?                               // push    edx             ; lpParameter
            68 ?? ?? ?? ??                   // push    offset mw_get_victim_info ; lpStartAddress
            6A 00                            // push    0               ; dwStackSize
            6A 00                            // push    0               ; lpThreadAttributes
            C7 05 ?? ?? ?? ?? A0 0F 00 00    // mov     dword_406090, 4000
            C7 05 ?? ?? ?? ?? ?? ?? 00 00    // mov     dword_45EA98, 3000
            FF 15 ?? ?? ?? ??                // call    ds:CreateThread
            A3 ?? ?? ?? ??                   // mov     dword_45EA64, eax
            E9 ?? ?? 00 00                   // jmp     def_401CEE
        }

    condition:
        pe.is_pe and
        filesize < 200KB and
        all of them
}
