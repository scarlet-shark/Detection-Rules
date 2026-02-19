rule G_Hunting_BackdoorToehold_GRIMBOLT_1 {

    meta:
        description = "Detects GRIMBOLT Backdoor."
        malware = "GRIMBOLT"
        intrusion_set = "UNC6201"
        tags = "UNC6201, GRIMBOLT"        
        author = "Google Threat Intelligence Group (GTIG)"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day"
        date = "2026-02-17"
        hash = "24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c"

    strings:
        $s1 = "[!] Error : Plexor is nul" ascii wide
        $s2 = "port must within 0~6553" ascii wide
        $s3 = "[*] Disposing.." ascii wide
        $s4 = "[!] Connection error. Kill Pty" ascii wide
        $s5 = "[!] Unkown message type" ascii wide
        $s6 = "[!] Bad dat" ascii wide

    condition:
        (
            (uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550) or
            uint32(0) == 0x464c457f or
            uint32(0) == 0xfeedface or
            uint32(0) == 0xcefaedfe or
            uint32(0) == 0xfeedfacf or
            uint32(0) == 0xcffaedfe or
            uint32(0) == 0xcafebabe or
            uint32(0) == 0xbebafeca or
            uint32(0) == 0xcafebabf or
            uint32(0) == 0xbfbafeca
        ) and any of them
}
