import "pe"

rule turla_kazuar_v3 {

    meta:
        author = "Dominik Reichel"
        description = "Detects Turla's KERNEL, WORKER and BRIDGE Kazuar v3"
        date = "2026-01-12"
        reference = "https://r136a1.dev/2026/01/14/command-and-evade-turlas-kazuar-loader/"
        hash = "c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9"
        
    strings:
        $a0 = "FxResources.System.Buffers"
        $a1 = "FxResources.System.Numerics.Vectors"
        $a2 = "Google.Protobuf.Reflection"
        $a3 = "Google.Protobuf.WellKnownTypes"
        $a4 = "Microsoft.CodeAnalysis"
        $a5 = "System.Diagnostics.CodeAnalysis"
        $a6 = "System.Runtime.InteropServices"

        $b0 = "RequestElection"
        $b1 = "LeaderShutdown"
        $b2 = "ClientAnnouncement"
        $b3 = "LeaderAnnouncement"
        $b4 = "Silence"

        $c0 = "ExchangeWebServices"
        $c1 = "WebSocket"
        $c2 = "HTTP"

        $d0 = "AUTOS"
        $d1 = "GET_CONFIG"
        $d2 = "PEEP"
        $d3 = "CHECK"
        $d4 = "KEYLOG"
        $d5 = "SYN"
        $d6 = "TASK_RESULT"
        $d7 = "CHECK_RESULT"
        $d8 = "CONFIG"
        $d9 = "SEND"
        $d10 = "TASK_KILL"
        $d11 = "SEND_RESULT"
        $d12 = "TASK"

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        pe.imports("mscoree.dll", "_CorExeMain") and
        (
            (
                4 of ($a*) and
                2 of ($b*)
            ) or
            (
                5 of ($a*) and
                all of ($c*)
            ) or
            (
                5 of ($a*) and
                9 of ($d*)
            ) or
            (
                2 of ($b*) and
                2 of ($c*)
            ) or
            (
                2 of ($b*) and
                6 of ($d*)
            ) or
            (
                all of ($b*)
            ) or
            (
                10 of ($d*)
            )
        )
}
