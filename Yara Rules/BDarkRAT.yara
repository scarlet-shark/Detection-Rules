import "pe"

rule BDarkRAT : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects BDarkRAT used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        creation_date = "2025-06-01"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "e07e8cbeeddc60697cc6fdb5314bd3abb748e3ac5347ff108fef9eab2f5c89b8"
        hash = "bf169e4dacda653c367b015a12ee8e379f07c5728322d9828b7d66f28ee7e07a"
        hash = "e599c55885a170c7ae5c7dfdb8be38516070747b642ac21194ad6d322f28c782"

    strings:
        $s1 = "Process started successfully" wide fullword
        $s2 = "No process to send input to" wide fullword

        $code_initialize_commands = {
            73 ?? 00 00 0A    // IL_0000: newobj    ::.ctor()
            80 ?? 00 00 04    // IL_0005: stsfld    ::packetList
            72 ?? ?? 00 70    // IL_000A: ldstr     "1"
            [1-2]             // IL_000F: ldc.i4.2
            D0 ?? ?? 00 02    // IL_0010: ldtoken   R_DeleteFile
            28 ?? ?? 00 0A    // IL_0015: call      ::GetTypeFromHandle
            73 ?? ?? 00 06    // IL_001A: newobj    ::.ctor
            28 ?? ?? 00 06    // IL_001F: call      ::RegisterPacket
            72 ?? ?? 00 70    // IL_0024: ldstr     "12"
            [1-2]             // IL_0029: ldc.i4.s  18
            D0 ?? ?? 00 02    // IL_002B: ldtoken   R_FileMgrGetDrives
            28 ?? ?? 00 0A    // IL_0030: call      ::GetTypeFromHandle
            73 ?? ?? 00 06    // IL_0035: newobj    ::.ctor
            28 ?? ?? 00 06    // IL_003A: call      ::RegisterPacket
            72 ?? ?? 00 70    // IL_003F: ldstr     "13"
        }
        $code_connect_ip = {
            26                // IL_0071: pop
            02                // IL_0072: ldarg.0
            7B ?? ?? 00 04    // IL_0073: ldfld     ::random
            17                // IL_0078: ldc.i4.1
            1?                // IL_0079: ldc.i4.4
            6F ?? ?? 00 0A    // IL_007A: callvirt  Random::Next
            20 E8 03 00 00    // IL_007F: ldc.i4    1000
            5A                // IL_0084: mul
            28 ?? ?? 00 0A    // IL_0085: call      Thread::Sleep
            DE ??             // IL_008A: leave.s   IL_00CE
            02                // IL_008C: ldarg.0
            7B ?? ?? 00 04    // IL_008D: ldfld     ::random
            17                // IL_0092: ldc.i4.1
            1?                // IL_0093: ldc.i4.2
            6F ?? ?? 00 0A    // IL_0094: callvirt  Random::Next
            20 E8 03 00 00    // IL_0099: ldc.i4    1000
            5A                // IL_009E: mul
            28 ?? ?? 00 0A    // IL_009F: call      Thread::Sleep
            7E ?? ?? 00 04    // IL_00A4: ldsfld    Settings::ConnectIP
            28 ?? ?? 00 0A    // IL_00A9: call      ::IsNullOrEmpty
            2D 19             // IL_00AE: brtrue.s  IL_00C9
            7E ?? ?? 00 04    // IL_00B0: ldsfld    ClientConnect::clientSocket
            7E ?? ?? 00 04    // IL_00B5: ldsfld    Settings::ConnectIP
            28 ?? ?? 00 0A    // IL_00BA: call      IPAddress::Parse
            7E ?? ?? 00 04    // IL_00BF: ldsfld    Settings::ConnectPort
            6F ?? ?? 00 0A    // IL_00C4: callvirt  Socket::Connect
            DE ??             // IL_01EE: leave.s   IL_01F3
        }
        $code_packet_crypt = {
            16                // IL_0000: ldc.i4.0
            0A                // IL_0001: stloc.0
            2B 16             // IL_0002: br.s      IL_001A
            02                // IL_0004: ldarg.0
            06                // IL_0005: ldloc.0
            8F ?? ?? 00 01    // IL_0006: ldelema   System.Byte
            25                // IL_000B: dup
            47                // IL_000C: ldind.u1
            7E ?? ?? 00 04    // IL_000D: ldsfld    CryptEngine::_key
            D2                // IL_0012: conv.u1
            61                // IL_0013: xor
            D2                // IL_0014: conv.u1
            52                // IL_0015: stind.i1
            06                // IL_0016: ldloc.0
            17                // IL_0017: ldc.i4.1
            58                // IL_0018: add
            0A                // IL_0019: stloc.0
            06                // IL_001A: ldloc.0
            02                // IL_001B: ldarg.0
            8E                // IL_001C: ldlen
            69                // IL_001D: conv.i4
            32 E4             // IL_001E: blt.s     IL_0004
            02                // IL_0020: ldarg.0
            2A                // IL_0021: ret
        }

    condition:
        pe.is_pe and
        filesize < 200KB and
        all of ($s*) and 2 of ($code*)
}
