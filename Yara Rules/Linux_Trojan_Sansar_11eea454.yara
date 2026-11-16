rule Linux_Trojan_Sansar_11eea454 {
    meta:
        author = "Elastic Security"
        description = "Sansar Malware"
        os = "Linux"
        category_type = "Trojan"
        family = "Sansar"
        threat_name = "Linux.Trojan.Sansar"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        date = "2026-11-12"
        hash = "00c9ac44291f83c72d54302e99d155a3e26d02225a3e516764d5833a99657c9e"

    strings:
        $a1 = { 8A 0A 88 4C 24 ?? 44 8A 5C 24 ?? 8D 48 01 44 89 DB D2 EB 34 07 89 C1 41 D2 E3 41 08 DB 89 F0 83 E0 1F 46 32 1C 10 44 88 1C 37 48 FF C6 48 FF C2 }
    condition:
        all of them
}
