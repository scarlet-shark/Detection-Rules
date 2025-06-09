import "pe"

rule ArtraDownloader : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects ArtraDownloader used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        license = "Detection Rule License (DRL) 1.1"
        license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"        
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "ef0cb0a1a29bcdf2b36622f72734aec8d38326fc8f7270f78bd956e706a5fd57"
        hash = "0b2a794bac4bf650b6ba537137504162520b67266449be979679afbb14e8e5c0"
        hash = "f0ef4242cc6b8fa3728b61d2ce86ea934bd59f550de9167afbca0b0aaa3b2c22"

    strings:
        $v1_s1 = "BCDEF=%s&MNOPQ=%s&GHIJ=%s&UVWXYZ=%s&st=%d" ascii fullword
        $v1_s2 = "%s %s %s\r\n%s %s\r\n%s%s\r\n%s%s\r\nContent-length: %d\r\n\r\n%s" ascii fullword
        $v1_s3 = "DFCB=" ascii fullword
        $v1_s4 = "DWN" ascii fullword
        $v1_s5 = "<br>" ascii fullword

        $v2_s1 ="GET %s HTTP/1.0" ascii fullword
        $v2_s2 ="Host: %s" ascii fullword
        $v2_s3 ="?a=\x00&b=\x00&c=\x00&d=\x00&e=\x00" ascii fullword
        $v2_s4 ="%s%s%s%s%s%s%s%s" ascii fullword
        $v2_s5 ="Yes file" ascii fullword

        $v3_s1 = "AXE: #" ascii fullword
        $v3_s2 = "%s*%s*%s" ascii fullword
        $v3_s3 = "Bld: %s.%s.%s" ascii fullword
        $v3_s4 = "%s@%s %s" ascii fullword
        $v3_s5 = "%s%s\r\n\r\n" ascii fullword

    condition:
        pe.is_pe and
        filesize < 400KB and
        all of ($v1_*) or all of ($v2_*) or all of ($v3_*)
}
