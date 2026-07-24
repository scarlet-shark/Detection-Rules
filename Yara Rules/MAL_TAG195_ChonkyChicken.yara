rule MAL_TAG195_ChonkyChicken {
    meta:
        author = "Insikt Group, Recorded Future"
        date = "2026-05-14"
        description = "Detects ChonkyChicken used by TAG-195."
        version = "1.0"
        reference = "https://tria.ge/260428-mhxf1agt7w"
        reference = "https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem"
        hash = "5d585f2b24503a96011bbe928f42b1b663946e822b309f8496573c66b5ee834c"

    strings:
        $s1 = "Koki cmd=["
        $s2 = "Blat path=["
        $s3 = "lg.txt" fullword
        $s4 = "wpad_capture.ocx" fullword
        $s5 = "output\\hashes.json"
        $s6 = "schtasks /create /s "
        $s7 = "token_run" fullword
        $s8 = "whoami" fullword
        $s9 = "chrome_ready" fullword
        $s10 = "chrome_result" fullword
        $s11 = "cdp_send" fullword
        $s12 = "cred_exec" fullword

    condition:
        uint16(0) == 0x5A4D and
        all of ($s*)
}
