rule Lazarus_RemotePE_C2_strings {
  meta:
    description = "RemotePE strings used for C2."
    author      = "Fox-IT / NCC Group"
    reference   = "https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/"
    hash        = "710f15302859c7af1c1e25219d704841b3fdbc48f16a5a574d5ab6cf4f4842e8"
    date        = "2026-05-22"

  strings:
    $a = "MicrosoftApplicationsTelemetryDeviceId" wide ascii xor(0x00-0xff)
    $b = "armAuthorization" wide ascii xor(0x00-0xff)
    $c = "ai_session" wide ascii xor(0x00-0xff)

  condition:
    uint16(0) == 0x5A4D and all of them
}
