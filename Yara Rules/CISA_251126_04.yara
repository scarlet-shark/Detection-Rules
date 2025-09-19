rule CISA_251126_04 : trojan hides_artifacts {

  meta:
    author = "CISA Code & Media Analysis"
    description = "Detects malicious jar Tomcat listener shell samples"
    reference = "https://www.cisa.gov/news-events/analysis-reports/ar25-261a"
    date = "2025-07-23"
    last_modified = "20250724_1615"
    actor = "unknown"
    family = "tomshell"
    capabilities = "hides-artifacts"
    malware_type = "trojan"
    tool_type = "webshel"
    incident = "251126"
    sha256_1 = "b618057de9a8bba95440f23b9cf6374cc66f2acd127b3d478684b22d8f11e00b"
    hahs = "b618057de9a8bba95440f23b9cf6374cc66f2acd127b3d478684b22d8f11e00b"

  strings:
    $s0 = { 63 6F 6D 2F 6D 6F 62 69 6C 65 69 72 6F 6E 2F 73 65 72 76 69 63 65 2F }
    $s1 = { 57 65 62 41 6E 64 72 6F 69 64 41 70 70 49 6E 73 74 61 6C 6C 65 72 2E 63 6C 61 73 73 }
    $s2 = { 5A 5D BB 33 C0 43 31 B0 2D DC 58 F2 75 44 CE E5 }
    $s3 = { 97 DC AC 0F A7 69 97 A4 5A 72 E8 96 AC 43 9E 01 }
    $s4 = { E0 E0 7E 40 F3 F8 87 30 C5 83 30 C5 43 14 E7 67 }
    $s5 = { DB E6 F7 F9 BD FC BE 75 00 BF 6F B3 59 B7 28 07 }
    $s6 = { C6 BF A4 1D 28 AB 7A B9 3E 09 B1 D8 E2 FA 09 36 }
    $s7 = { B8 0E 8E 0B 97 2D AE CF B4 B8 6E CD E5 E6 BA 92 }

  condition:
    all of them
}
