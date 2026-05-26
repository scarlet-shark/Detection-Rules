rule Lazarus_RemotePE_DPAPI_Encrypted_config {
  meta:
    description = "Detects RemotePE DPAPI-encrypted config on disk"
    author      = "Fox-IT Security Research Team"
    reference   = "https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/"
    hash        = "4f6ae0110cf652264293df571d66955f7109e3424a070423b5e50edc3eb43874"
    date        = "2026-05-22"

  condition:
    filesize == 3094
    and uint32(0) == 0x00000001      // DPAPI blob version = 1
    and uint32(0x8E) == 0x00000B40   // dwDataLen = 0xB40 (padded config)
}
