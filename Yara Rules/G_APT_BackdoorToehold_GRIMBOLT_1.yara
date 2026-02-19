rule G_APT_BackdoorToehold_GRIMBOLT_1 {

  meta:
    description = "Detects GRIMBOLT Backdoor."
    malware = "GRIMBOLT"
    intrusion_set = "UNC6201"
    tags = "UNC6201, GRIMBOLT"
    author = "Google Threat Intelligence Group (GTIG)"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day"
    date = "2026-02-17"
    hash = "dfb37247d12351ef9708cb6631ce2d7017897503657c6b882a711c0da8a9a591"

  strings:
    $s1 = { 40 00 00 00 41 18 00 00 00 4B 21 20 C2 2C 08 23 02 }
    $s2 = { B3 C3 BB 41 0D ?? ?? ?? 00 81 02 0C ?? ?? ?? 00 }
    $s3 = { 39 08 01 49 30 A0 52 30 00 00 00 DB 40 09 00 02 00 80 65 BC 98 }
    $s4 = { 2F 00 72 00 6F 00 75 00 74 00 65 79 23 E8 03 0E 00 00 00 2F 00 70 00 72 00 6F 00 63 00 2F 00 73 00 65 00 6C 00 66 00 2F 00 65 00 78 00 65 }

  condition:
    (uint32(0) == 0x464c457f) //linux
    and all of ($s*)
}
