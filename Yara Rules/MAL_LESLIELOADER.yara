rule MAL_LESLIELOADER {
  meta:
    author = "Insikt Group, Recorded Future"
    description = "Detects LESLIELOADER Malware used by RedNovember"
    reference = "https://assets.recordedfuture.com/insikt-report-pdfs/2025/cta-cn-2025-0924.pdf"
    date = "2024-11-14"
    version = "1.0"
    hash = "8679a25c78e104c6e74996b75882e378f420614fe1379ee9c1e266a11ffa096d"
    hash = "06e87a03507213322d876b459194021f876ba90f85c5faa401820954045cd1d2"
    malware = "LESLIELOADER"
    malware_id = "u-6JwI"
    category = "MALWARE"

  strings:
    $s1 = ".DecrptogAES"
    $s2 = ".UnPaddingText1"
    // AES key 1
    $k1a = "LeslieCh"
    $k1b = "eungKwok"
    // AES key 2
    $k2a = { 33 44 37 35 45 34 43 39 }
    $k2b = { 42 33 32 41 42 45 31 37 }

  condition:
    uint16be(0) == 0x4d5a
    and all of ($s*)
    and 2 of ($k*)
}
