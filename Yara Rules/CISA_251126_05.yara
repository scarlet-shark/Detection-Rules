rule CISA_251126_05 : trojan installs_other_components exfiltrates_data {

  meta:
    author = "CISA Code & Media Analysis"
    description = "Detects malicious Tomcat listener shell class samples"
    reference = "https://www.cisa.gov/news-events/analysis-reports/ar25-261a"
    date = "2025-07-23"
    last_modified = "20250724_1615"
    actor = "unknown"
    family = "tomshell"
    capabilities = "installs-other-components exfiltrates-data"
    malware_type = "trojan"
    tool_type = "webshel"
    incident = "251126"
    sha256_1 = "df501b238854d6579cafebeba82581a728e89ed1f6cd0da54c79ef4eb6f4f9fd"
    hash = "df501b238854d6579cafebeba82581a728e89ed1f6cd0da54c79ef4eb6f4f9fd"

  strings:
    $s0 = { 43 6C 61 73 73 4C 6F 61 64 65 72 }
    $s1 = { 6D 6F 62 69 6C 65 69 72 6F 6E 2F 73 65 72 76 69 63 65 }
    $s2 = { 57 65 62 41 6E 64 72 6F 69 64 41 70 70 49 6E 73 74 61 6C 6C 65 72 }
    $s3 = { 61 64 64 4C 69 73 74 65 6E 65 72 }
    $s4 = { 73 65 72 76 6C 65 74 52 65 71 75 65 73 74 4C 69 73 74 65 6E 65 72 43 6C 61 73 73 }
    $s5 = { 61 64 64 41 70 70 6C 69 63 61 74 69 6F 6E 45 76 65 6E 74 4C 69 73 74 65 6E 65 72 4D 65 74 68 6F 64 }
    $s6 = { 62 61 73 65 36 34 44 65 63 6F 64 65 }
    $s7 = { 63 6F 6E 74 65 6E 74 54 79 70 65 }
    $s8 = { 08 72 65 73 70 6F 6E 73 65 }
    $s9 = { 33 63 36 65 30 62 38 61 39 63 31 35 32 32 34 61 }
    $s10 = { 6B 70 61 73 73 6C 6F 67 69 6E }
    $s11 = { 53 65 72 76 6C 65 74 52 65 71 75 65 73 74 4C 69 73 74 65 6E 65 72 }
    $s12 = { 53 65 63 72 65 74 4B 65 79 53 70 65 63 }

  condition:
    all of them
}
