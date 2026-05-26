import "pe"

rule Lazarus_RemotePE_class_strings {
  meta:
    description = "RemotePE class strings."
    author      = "Fox-IT / NCC Group"
    reference   = "https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/"
    hash        = "710f15302859c7af1c1e25219d704841b3fdbc48f16a5a574d5ab6cf4f4842e8"
    date        = "2026-05-22"

  strings:
    $a = "IMiddleController" ascii wide xor(0x00-0xff)
    $b = "IChannelController" ascii wide xor(0x00-0xff)
    $c = "IConfigProfile" ascii wide xor(0x00-0xff)
    $d = "IKernelModule" ascii wide xor(0x00-0xff)

  condition:
    all of them
}
