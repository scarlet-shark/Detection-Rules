rule PolarEdgeBackdoor{
    meta:
        description = "Detects PolarEdge Backdoor"
        author = "Sekoia.io"
        creation_date = "2025-07-10"
        date = "2025-07-10"
        classification = "TLP:GREEN"
        reference = "https://blog.sekoia.io/polaredge-backdoor-qnap-cve-2023-20118-analysis/"
        malware = "PolarEdge Backdoor"
        source = "Sekoia.io"
        id = "c3749828-4345-424e-a1f4-d13ed227e6d2"
        version = "1.0"
        hash = "a3e2826090f009691442ff1585d07118c73c95e40088c47f0a16c8a59c9d9082"        

    strings:
        $marker1 = {41 82 01 67 42 22 04 17}
        $marker2 = {21 12 01 47 51 13 81 15}
        $s1 = "mode"
        $s2 = "query_str"
        $s3 = "server_port"
        $s4 = "m:h:e:f:q:d:"
        $PresentInvSBOX = {05 00 0E 00 0F 00 08 00
                           0C 00 01 00 02 00 0D 00
                           0B 00 04 00 06 00 03 00
                           00 00 07 00 09 00 0a 00}

    condition:
        uint32be(0) == 0x7f454c46 and $PresentInvSBOX and
        (all of ($marker*) or all of ($s*)) and
        filesize < 2MB
}
