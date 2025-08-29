rule SALT_TYPHOON_CMD1_SFTP_CLIENT {
  meta:
    description = "Detects the Salt Typhoon Cmd1 SFTP client. Rule is meant for threat hunting."
    date = "2025-08-26"
    creation_date = "2025-08-26"
    reference = "https://media.defense.gov/2025/Aug/22/2003786665/-1/-1/0/CSA_COUNTERING_CHINA_STATE_ACTORS_COMPROMISE_OF_NETWORKS.PDF"
    version = "1.0"
    tags = "Salt Typhoon"
    hash = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"

  strings:
    $s1 = "monitor capture CAP"
    $s2 = "export ftp://%s:%s@%s%s"
    $s3 = "main.CapExport"
    $s4 = "main.SftpDownload"
    $s5 = ".(*SSHClient).CommandShell"
    $aes = "aes.decryptBlockGo"
    $buildpath = "C:/work/sync_v1/cmd/cmd1/main.go"

  condition:
    (uint32(0) == 0x464c457f or (uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550) or ((uint32(0) == 0xcafebabe)
    or (uint32(0) == 0xfeedface) or (uint32(0) == 0xfeedfacf)
    or (uint32(0) == 0xbebafeca) or (uint32(0) == 0xcefaedfe)
    or (uint32(0) == 0xcffaedfe)))
    and 5 of them
}
