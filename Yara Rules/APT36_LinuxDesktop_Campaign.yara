rule APT36_LinuxDesktop_Campaign {
  meta:
    description = "Detects artifacts related to APT36 .desktop file campaign"
    author = "CYFIRMA Research"
    date = "2025-08-18"
    creation_date = "2025-08-18"
    reference = "https://www.cyfirma.com/research/apt36-targets-indian-boss-linux-systems-with-weaponized-autostart-files/"
    version = "1.0"
    tags = "APT36"
    hash = "508a2bcaa4c511f7db2d4491bb76effaa7231d66110c28632b95c77be40ea6b1"
    hash = "8f8da8861c368e74b9b5c1c59e64ef00690c5eff4a95e1b4fcf386973895bef1"
    hash = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"

  strings:
    // Malware file hashes (sha256)
    $hash1 = "508a2bcaa4c511f7db2d4491bb76effaa7231d66110c28632b95c77be40ea6b1"
    $hash2 = "8f8da8861c368e74b9b5c1c59e64ef00690c5eff4a95e1b4fcf386973895bef1"
    $hash3 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"

    // Malicious domains and IP
    $domain1 = "securestore.cv"
    $domain2 = "modgovindia.space"
    $ip1 = "45.141.58.199"

    // Suspicious command patterns used in payload
    $cmd1 = "/curl.*xxd.*chmod/s" nocase
    $cmd2 = "/.desktop/" nocase

  condition:
    any of ($hash*) or
    any of ($domain*,$ip*) or
    2 of ($cmd*)
}
