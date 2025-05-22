rule APT28_STEELHOOK {
  meta:
    description = "Detects APT28's STEELHOOK powershell script"
    author = "Joint Government Cybersecurity Advisory"
    creation_date = "2025-05-21"
    reference = "https://media.defense.gov/2025/May/21/2003719846/-1/-1/0/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.PDF"
    tags = "APT28, STEELHOOK"  

  strings:
    $s_1 = "$($env:LOCALAPPDATA\\\\Google\\\\Chrome\\\\User Data\\\\Local State)"
    $s_2 = "$($env:LOCALAPPDATA\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login
    Data)"
    $s_3 = "$($env:LOCALAPPDATA\\\\Microsoft\\\\Edge\\\\User Data\\\\Local State)"
    $s_4 = "$($env:LOCALAPPDATA\\\\Microsoft\\\\Edge\\\\User
    Data\\\\Default\\\\Login Data)"
    $s_5 = "os_crypt.encrypted_key"
    $s_6 = "System.Security.Cryptography.DataProtectionScope"
    $s_7 = "[system.security.cryptography.protectdata]::Unprotect"
    $s_8 = "Invoke-RestMethod"

  condition:
    all of them
}
